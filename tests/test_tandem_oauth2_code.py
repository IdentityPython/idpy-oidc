import json
import os

import pytest
from cryptojwt.key_jar import build_keyjar

from idpyoidc.client.oauth2 import Client
from idpyoidc.message.oauth2 import is_error_message
from idpyoidc.message.oidc import AccessTokenRequest
from idpyoidc.message.oidc import AuthorizationRequest
from idpyoidc.message.oidc import RefreshAccessTokenRequest
from idpyoidc.server import Server
from idpyoidc.server.authz import AuthzHandling
from idpyoidc.server.client_authn import verify_client
from idpyoidc.server.configure import ASConfiguration
from idpyoidc.server.cookie_handler import CookieHandler
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

_OAUTH2_SERVICES = {
    "metadata": {"class": "idpyoidc.client.oauth2.server_metadata.ServerMetadata"},
    "authorization": {"class": "idpyoidc.client.oauth2.authorization.Authorization"},
    "access_token": {"class": "idpyoidc.client.oauth2.access_token.AccessToken"},
    "resource": {"class": "idpyoidc.client.oauth2.resource.Resource"},
}


class TestFlow(object):
    @pytest.fixture(autouse=True)
    def create_entities(self):
        server_conf = {
            "issuer": "https://example.com/",
            "httpc_params": {"verify": False, "timeout": 1},
            "subject_types_supported": ["public", "pairwise", "ephemeral"],
            "keys": {"uri_path": "jwks.json", "key_defs": KEYDEFS},
            "endpoint": {
                "metadata": {
                    "path": ".well-known/oauth-authorization-server",
                    "class": "idpyoidc.server.oauth2.server_metadata.ServerMetadata",
                    "kwargs": {},
                },
                "authorization": {
                    "path": "authorization",
                    "class": "idpyoidc.server.oauth2.authorization.Authorization",
                    "kwargs": {},
                },
                "token": {
                    "path": "token",
                    "class": "idpyoidc.server.oauth2.token.Token",
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
            "userinfo": {"class": UserInfo, "kwargs": {"db": {}}},
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
            },
            "session_params": SESSION_PARAMS,
        }
        self.server = Server(ASConfiguration(conf=server_conf, base_path=BASEDIR), cwd=BASEDIR)

        client_1_config = {
            "issuer": server_conf["issuer"],
            "client_secret": "hemligtlösenord",
            "client_id": "client_1",
            "redirect_uris": ["https://example.com/cb"],
            "client_salt": "salted_peanuts_cooking",
            "token_endpoint_auth_methods_supported": ["client_secret_post"],
            "response_types_supported": ["code"],
        }
        client_services = _OAUTH2_SERVICES
        self.client = Client(
            client_type="oauth2",
            config=client_1_config,
            keyjar=build_keyjar(KEYDEFS),
            services=_OAUTH2_SERVICES,
        )

        self.context = self.server.context
        self.context.cdb["client_1"] = client_1_config
        self.context.keyjar.import_jwks(self.client.keyjar.export_jwks(), "client_1")

        self.context.set_provider_info()
        self.session_manager = self.context.session_manager
        self.user_id = "diana"

    def do_query(self, service_type, endpoint_type, request_args, state):
        _client_service = self.client.get_service(service_type)
        req_info = _client_service.get_request_parameters(request_args=request_args)

        areq = req_info.get("request")
        headers = req_info.get("headers")

        _server_endpoint = self.server.get_endpoint(endpoint_type)
        if areq:
            if headers:
                argv = {"http_info": {"headers": headers}}
            else:
                argv = {}
            areq.lax = True
            _req = areq.serialize(_server_endpoint.request_format)
            _pr_resp = _server_endpoint.parse_request(_req, **argv)
        else:
            _pr_resp = _server_endpoint.parse_request(areq)

        if is_error_message(_pr_resp):
            return areq, _pr_resp

        _resp = _server_endpoint.process_request(_pr_resp)
        if is_error_message(_resp):
            return areq, _resp

        _response = _server_endpoint.do_response(**_resp)

        resp = _client_service.parse_response(_response["response"])
        _client_service.update_service_context(_resp["response_args"], key=state)
        return areq, resp

    def process_setup(self, token=None, scope=None):
        # ***** Discovery *********

        _req, _resp = self.do_query("server_metadata", "server_metadata", {}, "")

        # ***** Authorization Request **********
        _nonce = (rndstr(24),)
        _context = self.client.get_service_context()
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
            "client_id": self.client.get_client_id(),
            "client_secret": _context.get_usage("client_secret"),
        }

        _token_request, resp = self.do_query("accesstoken", "token", req_args, _state)

        return resp, _state, _scope

    def test_flow(self):
        """
        Test that token exchange requests work correctly
        """

        resp, _state, _scope = self.process_setup(token="access_token", scope=["foobar"])

        # Construct the resource request

        _client_service = self.client.get_service("resource")
        req_info = _client_service.get_request_parameters(
            authn_method="bearer_header", state=_state, endpoint="https://resource.example.com"
        )

        assert req_info["url"] == "https://resource.example.com"
        assert "Authorization" in req_info["headers"]
        assert req_info["headers"]["Authorization"].startswith("Bearer")
