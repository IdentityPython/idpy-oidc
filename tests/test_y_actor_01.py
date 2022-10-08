
import copy
import os

import pytest
from cryptojwt.jwt import JWT
from cryptojwt.key_jar import KeyJar
from cryptojwt.key_jar import init_key_jar

from idpyoidc.actor import CIBAClient
from idpyoidc.actor import CIBAServer
from idpyoidc.client.entity import Entity
from idpyoidc.message.oidc.backchannel_authentication import AuthenticationRequest
from idpyoidc.server import OPConfiguration
from idpyoidc.server import Server
from idpyoidc.server.authn_event import create_authn_event
from idpyoidc.server.client_authn import verify_client
from idpyoidc.server.oidc.backchannel_authentication import BackChannelAuthentication
from idpyoidc.server.oidc.backchannel_authentication import ClientNotification
from idpyoidc.server.oidc.token import Token
from idpyoidc.server.user_authn.authn_context import MOBILETWOFACTORCONTRACT
from idpyoidc.util import rndstr
from tests import CRYPT_CONFIG
from tests import SESSION_PARAMS

BASEDIR = os.path.abspath(os.path.dirname(__file__))
ISSUER_1 = "https://example.com/actor1"
ISSUER_2 = "https://example.com/actor2"

KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

RESPONSE_TYPES_SUPPORTED = [
    ["code"],
    ["token"],
    ["id_token"],
    ["code", "token"],
    ["code", "id_token"],
    ["id_token", "token"],
    ["code", "token", "id_token"],
    ["none"],
]

CAPABILITIES = {
    "response_types_supported": [" ".join(x) for x in RESPONSE_TYPES_SUPPORTED],
    "token_endpoint_auth_methods_supported": [
        "client_secret_post",
        "client_secret_basic",
        "client_secret_jwt",
        "private_key_jwt",
    ],
    "response_modes_supported": ["query", "fragment", "form_post"],
    "subject_types_supported": ["public", "pairwise", "ephemeral"],
    "grant_types_supported": [
        "authorization_code",
        "implicit",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
    ],
    "claim_types_supported": ["normal", "aggregated", "distributed"],
    "claims_parameter_supported": True,
    "request_parameter_supported": True,
    "request_uri_parameter_supported": True,
}

SERVER_CONFIG = {
    "httpc_params": {"verify": False, "timeout": 1},
    "capabilities": CAPABILITIES,
    "keys": {"uri_path": "jwks.json", "key_defs": KEYSPEC},
    "token_handler_args": {
        "jwks_file": "private/token_jwks.json",
        "code": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
        "token": {
            "class": "idpyoidc.server.token.jwt_token.JWTToken",
            "kwargs": {
                "lifetime": 3600,
                "base_claims": {"eduperson_scoped_affiliation": None},
                "add_claims_by_scope": True,
            },
        },
        "refresh": {
            "class": "idpyoidc.server.token.jwt_token.JWTToken",
            "kwargs": {"lifetime": 3600},
        },
        "id_token": {
            "class": "idpyoidc.server.token.id_token.IDToken",
            "kwargs": {
                "base_claims": {
                    "email": {"essential": True},
                    "email_verified": {"essential": True},
                }
            },
        },
    },
    "endpoint": {
        "token": {"path": "token", "class": Token, "kwargs": {}},
    },
    "client_authn": verify_client,
    "session_params": SESSION_PARAMS,
}


def _create_client(issuer, client_id, service):
    client_config = {
        "issuer": issuer,
        "client_id": client_id,
        "client_secret": rndstr(24),
        "redirect_uris": [f"https://example.com/{client_id}/authz_cb"],
        "behaviour": {"response_types": ["code"]},
        "client_authn_methods": {
            "client_notification_authn": "idpyoidc.client.oidc.backchannel_authentication.ClientNotificationAuthn"
        },
    }
    _services = {
        "discovery": {
            "class": "idpyoidc.client.oidc.provider_info_discovery.ProviderInfoDiscovery"
        },
        "registration": {"class": "idpyoidc.client.oidc.registration.Registration"},
    }
    _services.update(service)

    _cli_1_key = init_key_jar(key_defs=KEYSPEC)

    return Entity(config=client_config, services=_services, keyjar=_cli_1_key)


def _create_server(issuer, endpoint, port, extra_conf=None):
    _config = copy.deepcopy(SERVER_CONFIG)
    _config["issuer"] = issuer
    _config["endpoint"].update(endpoint)
    if extra_conf:
        _config.update(extra_conf)

    return Server(OPConfiguration(conf=_config, base_path=BASEDIR, domain="127.0.0.1", port=port))


# Locally defined
def parse_login_hint_token(keyjar: KeyJar, login_hint_token: str, context=None) -> str:
    _jwt = JWT(keyjar)
    _info = _jwt.unpack(login_hint_token)
    # here comes the special knowledge
    _sub_id = _info.get("sub_id")
    _sub = ""
    if _sub_id:
        if _sub_id["format"] == "phone":
            _sub = "tel:" + _sub_id["phone"]
        elif _sub_id["format"] == "mail":
            _sub = "mail:" + _sub_id["mail"]

        if _sub and context and context.login_hint_lookup:
            try:
                _sub = context.login_hint_lookup(_sub)
            except KeyError:
                _sub = ""

    return _sub


class TestPushActor:
    @pytest.fixture(autouse=True)
    def create_actor(self):
        # ============== ACTOR 1 ==============
        # Actor 1 can use Authentication Service and provides a Client Notification Endpoint
        actor_1 = CIBAClient()
        actor_1.client = _create_client(
            ISSUER_2,
            "actor1",
            {
                "authentication": {
                    "class": "idpyoidc.client.oidc.backchannel_authentication.BackChannelAuthentication"
                }
            },
        )

        endpoint = {
            "client_notify": {
                "path": "notify",
                "class": ClientNotification,
                "kwargs": {"client_authn_method": ["client_notification_authn"]},
            }
        }
        extra = {
            "client_authn_methods": {
                "client_notification_authn": "idpyoidc.server.oidc.backchannel_authentication.ClientNotificationAuthn"
            }
        }

        actor_1.server = _create_server(ISSUER_1, endpoint, 6000, extra_conf=extra)

        self.actor_1 = actor_1

        # ============== ACTOR 2 ==============
        # Provides Authentication endpoint and can use the Client notification service
        actor_2 = CIBAServer()
        actor_2.client = _create_client(
            ISSUER_1,
            "actor2",
            {
                "notification": {
                    "class": "idpyoidc.client.oidc.backchannel_authentication.ClientNotification"
                }
            },
        )
        endpoint = {
            "backchannel_authentication": {
                "path": "authentication",
                "class": BackChannelAuthentication,
                "kwargs": {
                    "client_authn_method": [
                        "client_secret_basic",
                        "client_secret_post",
                        "client_secret_jwt",
                        "private_key_jwt",
                    ],
                    "parse_login_hint_token": {"func": parse_login_hint_token},
                },
            }
        }
        extra = {
            "login_hint_lookup": {"class": "idpyoidc.server.login_hint.LoginHintLookup"},
            "userinfo": {
                "class": "idpyoidc.server.user_info.UserInfo",
                "kwargs": {"db_file": "users.json"},
            },
        }
        actor_2.server = _create_server(ISSUER_2, endpoint, 7000, extra)

        # register clients with servers.
        _server_context = actor_1.server.server_get("context")
        _client_context = actor_2.client.client_get("service_context")
        _server_context.cdb = {
            _client_context.client_id: {
                "client_secret": _client_context.client_secret,
            },
            actor_2.server.server_get("context").issuer: {
                "client_secret": _client_context.client_secret
            },
        }
        _server_context = actor_2.server.server_get("context")
        _client_context = actor_1.client.client_get("service_context")
        _server_context.cdb = {
            _client_context.client_id: {"client_secret": _client_context.client_secret},
            actor_1.server.server_get("context").issuer: {
                "client_secret": _client_context.client_secret
            },
        }

        # Transfer provider metadata 1->2 and 2->1
        _client_context = actor_2.client.client_get("service_context")
        _server_context = actor_1.server.server_get("context")
        _client_context.provider_info = _server_context.provider_info

        _client_context = actor_1.client.client_get("service_context")
        _server_context = actor_2.server.server_get("context")
        _client_context.provider_info = _server_context.provider_info

        _server_context.parse_login_hint_token = parse_login_hint_token

        # keys
        _client_keyjar = actor_2.client.client_get("service_context").keyjar
        _server_keyjar = actor_1.server.server_get("context").keyjar
        _server_keyjar.import_jwks(_client_keyjar.export_jwks(), "actor2")
        _client_keyjar.import_jwks(_server_keyjar.export_jwks(), ISSUER_1)

        _client_keyjar = actor_1.client.client_get("service_context").keyjar
        _server_keyjar = actor_2.server.server_get("context").keyjar
        _server_keyjar.import_jwks(_client_keyjar.export_jwks(), "actor1")
        _client_keyjar.import_jwks(_server_keyjar.export_jwks(), ISSUER_2)

        self.actor_1 = actor_1
        self.actor_2 = actor_2

    def _create_session(
        self, server, user_id, auth_req, sub_type="public", sector_identifier="", authn_info=""
    ):
        if sector_identifier:
            authz_req = auth_req.copy()
            authz_req["sector_identifier_uri"] = sector_identifier
        else:
            authz_req = auth_req
        client_id = authz_req["client_id"]
        ae = create_authn_event(user_id, authn_info=authn_info)
        _session_manager = server.endpoint_context.session_manager
        return _session_manager.create_session(
            ae, authz_req, user_id, client_id=client_id, sub_type=sub_type
        )

    def test_init(self):
        assert self.actor_1.client
        assert self.actor_2.client
        assert self.actor_1.server
        assert self.actor_2.server

    def test_query(self):
        _req = self.actor_1.create_authentication_request(
            scope="openid email example-scope",
            binding_message="W4SCT",
            login_hint="mail:diana@example.org",
        )
        assert _req
        assert _req["method"] == "GET"
        assert isinstance(_req["request"], AuthenticationRequest)
        assert _req["request"]["login_hint"] == "mail:diana@example.org"

        # On the CIBA server side
        _endpoint = self.actor_2.server.server_get("endpoint", "backchannel_authentication")
        _request = _endpoint.parse_request(_req["request"].to_urlencoded())
        assert _request
        # If ping mode
        assert "client_notification_token" in _request
        req_user = _endpoint.do_request_user(_request)
        assert req_user == "diana"
        # Construct response to the authentication request
        _info = _endpoint.process_request(_request)
        assert _info

        # User interaction with the authentication device returns some authentication info

        session_id_2 = self._create_session(
            self.actor_2.server, req_user, _request, authn_info=MOBILETWOFACTORCONTRACT
        )

        # Create fake token response
        token_request = {
            "grant_type": "urn:openid:params:grant-type:ciba",
            "auth_req_id": _info["response_args"]["auth_req_id"],
            "client_id": "actor1",
        }
        _token_endpoint = self.actor_2.server.server_get("endpoint", "token")
        _treq = _token_endpoint.parse_request(token_request)
        # Construct response to the authentication request
        _tinfo = _token_endpoint.process_request(_treq)
        assert _tinfo

        # Send the response to the client notification endpoint

        _tinfo["response_args"]["client_notification_token"] = _request["client_notification_token"]
        _notification_service = self.actor_2.client.client_get("service", "client_notification")
        _not_req = _notification_service.get_request_parameters(
            request_args=_tinfo["response_args"], authn_method="client_notification_authn"
        )

        assert _not_req

        # The receiver of the notification

        _ninfo = self.actor_1.do_client_notification(
            _not_req["body"], http_info={"headers": _not_req["headers"]}
        )
        assert _ninfo is None