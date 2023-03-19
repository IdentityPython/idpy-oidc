import os

import pytest
from cryptojwt.key_jar import build_keyjar

from idpyoidc.client.oauth2 import Client
from idpyoidc.message.oauth2 import is_error_message
from idpyoidc.server import ASConfiguration
from idpyoidc.server import Server
from idpyoidc.server.authz import AuthzHandling
from idpyoidc.server.client_authn import verify_client
from idpyoidc.server.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from idpyoidc.server.user_info import UserInfo
from idpyoidc.util import rndstr
from tests import CRYPT_CONFIG
from tests import SESSION_PARAMS

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]
BASEDIR = os.path.abspath(os.path.dirname(__file__))


class TestClient(object):

    def create_client(self):
        self.redirect_uri = "http://example.com/redirect"

    @pytest.fixture(autouse=True)
    def create_entities(self):
        # -------------- Server -----------------------

        server_conf = {
            "issuer": "https://example.com/",
            "httpc_params": {"verify": False, "timeout": 1},
            "subject_types_supported": ["public", "pairwise", "ephemeral"],
            "grant_types_supported": [
                "authorization_code",
                "implicit",
                "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "refresh_token",
            ],
            "client_authn_method": [
                "client_secret_basic",
                "client_secret_post",
                "client_secret_jwt",
                "private_key_jwt",
            ],
            # "cookie_handler": {
            #     "class": CookieHandler,
            #     "kwargs": {"keys": {"key_defs": COOKIE_KEYDEFS}},
            # },
            "keys": {"uri_path": "jwks.json", "key_defs": KEYDEFS},
            "endpoint": {
                'discovery': {
                    'path': "/.well-known/oauth-authorization-server",
                    'class': "idpyoidc.server.oauth2.server_metadata.ServerMetadata",
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
                "token_revocation": {
                    'path': 'revocation',
                    "class": "idpyoidc.server.oauth2.token_revocation.TokenRevocation",
                    "kwargs": {},
                },
                'introspection': {
                    'path': 'introspection',
                    'class': "idpyoidc.server.oauth2.introspection.Introspection"
                }
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
            "template_dir": "template",
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
            },
            "session_params": SESSION_PARAMS,
        }
        self.server = Server(ASConfiguration(conf=server_conf, base_path=BASEDIR), cwd=BASEDIR)

        # -------------- Client -----------------------

        client_conf = {
            "redirect_uris": ["https://example.com/cli/authz_cb"],
            "client_id": "client_1",
            "client_secret": "abcdefghijklmnop",
            'issuer': 'https://example.com/',
            "response_types_supported": ["code", "code id_token", "id_token"],
        }
        services = {
            "server_metadata": {"class": "idpyoidc.client.oauth2.server_metadata.ServerMetadata"},
            "authorization": {"class": "idpyoidc.client.oauth2.authorization.Authorization"},
            "access_token": {"class": "idpyoidc.client.oauth2.access_token.AccessToken"},
            'token_revocation': {
                'class': 'idpyoidc.client.oauth2.token_revocation.TokenRevocation'
            },
            'introspection': {
                'class': 'idpyoidc.client.oauth2.introspection.Introspection'
            }
        }
        self.client = Client(config=client_conf, keyjar=build_keyjar(KEYDEFS), services=services)

        # ------- tell the server about the client ----------------
        self.context = self.server.context
        self.context.cdb["client_1"] = client_conf
        self.context.keyjar.import_jwks(self.client.keyjar.export_jwks(), "client_1")

    def do_query(self, service_type, endpoint_type, request_args, state):
        _client = self.client.get_service(service_type)
        req_info = _client.get_request_parameters(request_args=request_args)

        areq = req_info.get("request")
        headers = req_info.get("headers")

        _server = self.server.get_endpoint(endpoint_type)
        if areq:
            if headers:
                argv = {"http_info": {"headers": headers}}
            else:
                argv = {}
            areq.lax = True
            if _server.request_format == 'json':
                _pr_req = _server.parse_request(areq.to_json(), **argv)
            else:
                _pr_req = _server.parse_request(areq.to_urlencoded(), **argv)
        else:
            _pr_req = _server.parse_request(areq)

        if is_error_message(_pr_req):
            return areq, _pr_req

        _resp = _server.process_request(_pr_req)
        if is_error_message(_resp):
            return areq, _resp

        _response = _server.do_response(**_resp)

        resp = _client.parse_response(_response["response"])
        if "response_args" in _resp:
            _client.update_service_context(_resp["response_args"], key=state)

        return areq, resp

    def process_setup(self, token=None, scope=None):
        # ***** Discovery *********

        _req, _resp = self.do_query('server_metadata', 'server_metadata', {}, '')

        # ***** Authorization Request **********
        _context = self.client.get_service_context()
        # Need a new state for a new authorization request
        _state = _context.cstate.create_state(iss=_context.get("issuer"))
        _nonce = rndstr(24),
        # bind nonce to state
        _context.cstate.bind_key(_nonce, _state)

        req_args = {
            "response_type": ["code"],
            "nonce": _nonce,
            "state": _state
        }

        if scope:
            _scope = scope
        else:
            _scope = ["foobar"]

        req_args["scope"] = _scope

        areq, auth_response = self.do_query('authorization', 'authorization', req_args, _state)

        # ***** Token Request **********

        req_args = {
            "code": auth_response["code"],
            "state": auth_response["state"],
            "redirect_uri": areq["redirect_uri"],
            # "grant_type": "authorization_code",
            # "client_id": self.client_.get_client_id(),
            # "client_secret": _context.get_usage("client_secret"),
        }

        _token_request, resp = self.do_query("accesstoken", 'token', req_args, _state)

        return resp, _state, _scope

    def test_revoke(self):
        resp, _state, _scope = self.process_setup()

        _context = self.client.get_context()
        _state = _context.cstate.get(_state)

        req_args = {
            "token": _state['access_token'],
            "token_type_hint": 'access_token'
        }

        # Check that I have an active token

        _request, _resp = self.do_query("introspection", "introspection", req_args, _state)

        assert _resp['active'] == True

        # ****** Token Revocation Request **********

        _request, _resp = self.do_query("token_revocation", "token_revocation", req_args, _state)
        assert _resp == 'OK'

        # Test if it's really revoked

        _request, _resp = self.do_query("introspection", "introspection", req_args, _state)

        assert _resp.to_dict() == {'active': False}