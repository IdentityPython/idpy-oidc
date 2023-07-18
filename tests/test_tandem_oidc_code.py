import json
import os

from cryptojwt.key_jar import build_keyjar

import pytest

from idpyoidc.client.oidc import RP
from idpyoidc.message.oauth2 import is_error_message
from idpyoidc.message.oidc import AccessTokenRequest
from idpyoidc.message.oidc import AuthorizationRequest
from idpyoidc.message.oidc import RefreshAccessTokenRequest
from idpyoidc.server import Server
from idpyoidc.server.authz import AuthzHandling
from idpyoidc.server.client_authn import verify_client
from idpyoidc.server.configure import OPConfiguration
from idpyoidc.server.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from idpyoidc.server.user_info import UserInfo
from idpyoidc.util import rndstr
from tests import CRYPT_CONFIG
from tests import SESSION_PARAMS

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

CLIENT_KEYJAR = build_keyjar(KEYDEFS)

COOKIE_KEYDEFS = [
    {"type": "oct", "kid": "sig", "use": ["sig"]},
    {"type": "oct", "kid": "enc", "use": ["enc"]},
]

AUTH_REQ = AuthorizationRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    scope=["openid"],
    state="STATE",
    response_type="code",
)

TOKEN_REQ = AccessTokenRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    state="STATE",
    grant_type="authorization_code",
    client_secret="hemligt",
)

REFRESH_TOKEN_REQ = RefreshAccessTokenRequest(
    grant_type="refresh_token", client_id="https://example.com/", client_secret="hemligt"
)

TOKEN_REQ_DICT = TOKEN_REQ.to_dict()

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


USERINFO = UserInfo(json.loads(open(full_path("users.json")).read()))

_OIDC_SERVICES = {
    "provider_info": {
        "class": "idpyoidc.client.oidc.provider_info_discovery.ProviderInfoDiscovery"
    },
    "registration": {"class": "idpyoidc.client.oidc.registration.Registration"},
    "authorization": {"class": "idpyoidc.client.oidc.authorization.Authorization"},
    "access_token": {"class": "idpyoidc.client.oidc.access_token.AccessToken"},
    "userinfo": {"class": "idpyoidc.client.oidc.userinfo.UserInfo"},
}


class TestFlow(object):
    @pytest.fixture(autouse=True)
    def create_entities(self):
        server_conf = {
            "issuer": "https://op.example.com/",
            "httpc_params": {"verify": False, "timeout": 1},
            "subject_types_supported": ["public", "pairwise", "ephemeral"],
            "keys": {"uri_path": "jwks.json", "key_defs": KEYDEFS},
            "endpoint": {
                "provider_info": {
                    "path": ".well-known/openid-configuration",
                    "class": "idpyoidc.server.oidc.provider_config.ProviderConfiguration",
                    "kwargs": {},
                },
                "register": {
                    "path": "authorization",
                    "class": "idpyoidc.server.oidc.registration.Registration",
                    "kwargs": {},
                },
                "authorization": {
                    "path": "authorization",
                    "class": "idpyoidc.server.oidc.authorization.Authorization",
                    "kwargs": {},
                },
                "token": {
                    "path": "token",
                    "class": "idpyoidc.server.oidc.token.Token",
                    "kwargs": {},
                },
                "userinfo": {
                    "path": "user",
                    "class": "idpyoidc.server.oidc.userinfo.UserInfo",
                    "kwargs": {},
                },
            },
            "authentication": {
                "anon": {
                    "acr": INTERNETPROTOCOLPASSWORD,
                    "class": "idpyoidc.server.user_authn.user.NoAuthn",
                    "kwargs": {"user": "diana"},
                }
            },
            "userinfo": {"class": UserInfo, "kwargs": {"db_file": "users.json"}},
            "client_authn": verify_client,
            "authz": {
                "class": AuthzHandling,
                "kwargs": {
                    "grant_config": {
                        "usage_rules": {
                            "authorization_code": {
                                "supports_minting": ["access_token", "refresh_token"],
                                "max_usage": 1,
                            },
                            "access_token": {
                                "supports_minting": ["access_token", "refresh_token"],
                                "expires_in": 600,
                            },
                            "refresh_token": {
                                "supports_minting": ["access_token"],
                                "audience": ["https://example.com", "https://example2.com"],
                                "expires_in": 43200,
                            },
                        },
                        "expires_in": 43200,
                    }
                },
            },
            "token_handler_args": {
                "jwks_file": "private/token_jwks.json",
                "code": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
                "token": {
                    "class": "idpyoidc.server.token.jwt_token.JWTToken",
                    "kwargs": {
                        "lifetime": 3600,
                        "add_claims_by_scope": True,
                        "aud": ["https://example.org/appl"],
                    },
                },
                "refresh": {
                    "class": "idpyoidc.server.token.jwt_token.JWTToken",
                    "kwargs": {
                        "lifetime": 3600,
                        "aud": ["https://example.org/appl"],
                    },
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
            "session_params": SESSION_PARAMS,
        }
        self.server = Server(OPConfiguration(conf=server_conf, base_path=BASEDIR), cwd=BASEDIR)

        client_config = {
            "issuer": server_conf["issuer"],
            # "client_secret": "hemligtlösenord",
            # "client_id": "client_1",
            # "client_salt": "salted_peanuts_cooking",
            "redirect_uris": ["https://example.com/cb"],
            "token_endpoint_auth_methods_supported": ["client_secret_post"],
            "response_types_supported": ["code", "id_token", "id_token token"],
        }
        self.rp = RP(config=client_config, keyjar=build_keyjar(KEYDEFS), services=_OIDC_SERVICES)

        self.context = self.server.context
        # self.context.cdb["client_1"] = client_config
        # self.context.keyjar.import_jwks(self.rp.keyjar.export_jwks(), "client_1")

        self.context.set_provider_info()
        # self.session_manager = self.context.session_manager
        # self.user_id = "diana"

    def do_query(self, service_type, endpoint_type, request_args, state):
        _client_service = self.rp.get_service(service_type)
        req_info = _client_service.get_request_parameters(request_args=request_args, state=state)

        areq = req_info.get("request")
        headers = req_info.get("headers")

        _server_endpoint = self.server.get_endpoint(endpoint_type)

        if headers:
            argv = {"http_info": {"headers": headers}}
        else:
            argv = {}

        if areq:
            areq.lax = True
            _req = areq.serialize(_server_endpoint.request_format)
            _pr_req = _server_endpoint.parse_request(_req, **argv)
        else:
            _pr_req = _server_endpoint.parse_request(areq, **argv)

        if is_error_message(_pr_req):
            return areq, _pr_req

        _resp = _server_endpoint.process_request(_pr_req)
        if is_error_message(_resp):
            return areq, _resp

        _response = _server_endpoint.do_response(**_resp)

        resp = _client_service.parse_response(_response["response"], state=state)
        _client_service.update_service_context(_resp["response_args"], key=state)
        # Fake key import
        if service_type == "provider_info":
            _client_service.upstream_get("attribute", "keyjar").import_jwks(
                _server_endpoint.upstream_get("attribute", "keyjar").export_jwks(),
                issuer_id=_server_endpoint.upstream_get("attribute", "issuer"),
            )
        return areq, resp

    def process_setup(self, token=None, scope=None):
        # ***** Discovery *********
        _req, _resp = self.do_query("provider_info", "provider_config", {}, "")

        # ***** Client Registration **********

        _req, _resp = self.do_query("registration", "registration", {}, "")

        # ***** Authorization Request **********

        _nonce = rndstr(24)
        _context = self.rp.get_service_context()
        # Need a new state for a new authorization request
        _state = _context.cstate.create_state(iss=_context.get("issuer"))
        _context.cstate.bind_key(_nonce, _state)

        req_args = {"response_type": ["code"], "nonce": _nonce, "state": _state}

        if scope:
            _scope = scope
        else:
            _scope = ["openid"]

            if token and list(token.keys())[0] == "refresh_token":
                _scope = ["openid", "offline_access"]

        req_args["scope"] = _scope

        areq, auth_response = self.do_query("authorization", "authorization", req_args, _state)

        # ***** Token Request **********

        req_args = {
            "code": auth_response["code"],
            "state": auth_response["state"],
            "redirect_uri": areq["redirect_uri"],
            "grant_type": "authorization_code",
            "client_id": self.rp.get_client_id(),
            "client_secret": _context.get_usage("client_secret"),
        }

        _token_request, resp = self.do_query("accesstoken", "token", req_args, _state)

        return resp, _state, _scope

    def test_flow(self):
        """
        Test that token exchange requests work correctly
        """

        resp, _state, _scope = self.process_setup(
            token="access_token",
            scope=["openid", "profile", "email", "address", "phone", "offline_access"],
        )

        # The User Info request

        _request, resp = self.do_query("userinfo", "userinfo", {}, _state)

        assert resp
