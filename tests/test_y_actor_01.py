import copy
import os
from uuid import uuid4

from cryptojwt.jwt import JWT
from cryptojwt.key_jar import KeyJar
from cryptojwt.key_jar import init_key_jar
from idpyoidc.actor import Actor
from idpyoidc.client.entity import Entity
from idpyoidc.message.oidc.backchannel_authentication import AuthenticationRequest
from idpyoidc.server import OPConfiguration
from idpyoidc.server import Server
from idpyoidc.server.client_authn import verify_client
from idpyoidc.server.oidc.backchannel_authentication import BackChannelAuthentication
from idpyoidc.server.oidc.backchannel_authentication import ClientNotification
from idpyoidc.server.oidc.token import Token
import pytest

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
        "code": {"lifetime": 600},
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
        "token": {
            "path": "token",
            "class": Token,
            "kwargs": {}
        },
    },
    "client_authn": verify_client,
}


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
        actor_1 = Actor()
        client_config = {
            "issuer": ISSUER_2,
            'client_id': 'actor1',
            'client_secret': 'a longesh password',
            'redirect_uris': ['https://example.com/actor1/authz_cb'],
            'behaviour': {'response_types': ['code']}
        }
        OIDC_SERVICES = {
            'discovery': {
                'class': 'idpyoidc.client.oidc.provider_info_discovery.ProviderInfoDiscovery'
            },
            'registration': {'class': 'idpyoidc.client.oidc.registration.Registration'},
            'authentication': {
                'class': 'idpyoidc.client.oidc.backchannel_authentication.BackChannelAuthentication'
            }
        }

        _cli_1_key = init_key_jar(key_defs=KEYSPEC)

        actor_1["client"] = Entity(config=client_config, services=OIDC_SERVICES, keyjar=_cli_1_key)
        _context = actor_1['client'].client_get("service_context")
        _context.provider_info = {
            "issuer": ISSUER_2,
            'backchannel_authentication_endpoint': f"{ISSUER_2}/bae"
        }

        server_1_config = copy.deepcopy(SERVER_CONFIG)
        server_1_config["issuer"] = ISSUER_1
        server_1_config["endpoint"]["client_notify"] = {
            "path": "notify",
            "class": ClientNotification,
            "kwargs": {
                "client_authn_method": ["client_secret_basic", "client_secret_post",
                                        "client_secret_jwt", "private_key_jwt"]
            }
        }

        configuration = OPConfiguration(conf=server_1_config, base_path=BASEDIR, domain="127.0.0.1",
                                        port=443)
        actor_1["server"] = Server(configuration)
        self.actor_1 = actor_1

        # ============== ACTOR 2 ==============
        # Provides Authentication endpoint and can use the Client notification service
        actor_2 = Actor()

        client_config = {
            "issuer": ISSUER_1,
            'client_id': 'actor2',
            'client_secret': 'a longesh password',
            'redirect_uris': ['https://example.com/actor2/authz_cb'],
            'behaviour': {'response_types': ['code']}
        }
        OIDC_SERVICES = {
            'discovery': {
                'class': 'idpyoidc.client.oidc.provider_info_discovery.ProviderInfoDiscovery'
            },
            'registration': {'class': 'idpyoidc.client.oidc.registration.Registration'},
            'notification': {
                'class': 'idpyoidc.client.oidc.backchannel_authentication.ClientNotification'
            }
        }

        _cli_key = init_key_jar(key_defs=KEYSPEC)

        actor_2["client"] = Entity(config=client_config, services=OIDC_SERVICES, keyjar=_cli_key)

        server_2_config = copy.deepcopy(SERVER_CONFIG)
        server_2_config["issuer"] = ISSUER_2
        server_2_config["endpoint"]["backchannel_authentication"] = {
            "path": "authentication",
            "class": BackChannelAuthentication,
            "kwargs": {
                "client_authn_method": ["client_secret_basic", "client_secret_post",
                                        "client_secret_jwt", "private_key_jwt"],
                "parse_login_hint_token": {
                    "func": parse_login_hint_token
                }
            },
        }

        configuration = OPConfiguration(conf=server_2_config, base_path=BASEDIR, domain="127.0.0.1",
                                        port=443)
        actor_2["server"] = Server(configuration)
        self.actor_2 = actor_2

        # Transfer provider metadata 1->2 and 2->1
        _client_context = actor_2['client'].client_get("service_context")
        _server_context = actor_1["server"].server_get("endpoint_context")
        _client_context.provider_info = _server_context.provider_info

        _client_context = actor_1['client'].client_get("service_context")
        _server_context = actor_2["server"].server_get("endpoint_context")
        _client_context.provider_info = _server_context.provider_info

        # keys
        _client_keyjar = actor_2['client'].client_get("service_context").keyjar
        _server_keyjar = actor_1["server"].server_get("endpoint_context").keyjar
        _server_keyjar.import_jwks(_client_keyjar.export_jwks(), "actor2")
        _client_keyjar.import_jwks(_server_keyjar.export_jwks(), ISSUER_1)

        _client_keyjar = actor_1['client'].client_get("service_context").keyjar
        _server_keyjar = actor_2["server"].server_get("endpoint_context").keyjar
        _server_keyjar.import_jwks(_client_keyjar.export_jwks(), "actor1")
        _client_keyjar.import_jwks(_server_keyjar.export_jwks(), ISSUER_2)

    def test_init(self):
        assert set(self.actor_1.roles()) == {"client", "server"}

    def test_query(self):
        _service = self.actor_1["client"].client_get("service", "backchannel_authentication")
        request = {
            "scope": "openid email example-scope",
            "client_notification_token": uuid4().hex,
            "binding_message": "W4SCT",
            "login_hint": "mail:diana@example.org"
        }
        _req = _service.get_request_parameters(request_args=request,
                                               authn_method="private_key_jwt")

        assert _req
        assert _req["method"] == "GET"
        assert isinstance(_req["request"], AuthenticationRequest)
        assert _req["request"]["login_hint"] == "mail:diana@example.org"

        # On the CIBA server side
        _endpoint = self.actor_2["server"].server_get("endpoint", "backchannel_authentication")
        _request = _endpoint.parse_request(_req["request"].to_urlencoded())
        assert _request
        # If ping mode
        assert "client_notification_token" in _request
        req_user = _endpoint.do_request_user(_request)
        assert req_user == "diana"
