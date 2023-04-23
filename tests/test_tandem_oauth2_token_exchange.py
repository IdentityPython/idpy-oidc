import json
import os

from cryptojwt.key_jar import build_keyjar
import pytest

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
    "claims": {"class": "idpyoidc.client.oauth2.server_metadata.ServerMetadata"},
    "authorization": {"class": "idpyoidc.client.oauth2.authorization.Authorization"},
    "access_token": {"class": "idpyoidc.client.oauth2.access_token.AccessToken"},
    "refresh_access_token": {
        "class": "idpyoidc.client.oauth2.refresh_access_token.RefreshAccessToken"
    },
    "token_exchange": {
        "class": "idpyoidc.client.oauth2.token_exchange.TokenExchange"
    }
}


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        server_conf = {
            "issuer": "https://example.com/",
            "httpc_params": {"verify": False, "timeout": 1},
            "subject_types_supported": ["public", "pairwise", "ephemeral"],
            "client_authn_method": [
                "client_secret_basic",
                "client_secret_post",
                "client_secret_jwt",
                "private_key_jwt",
            ],
            "cookie_handler": {
                "class": CookieHandler,
                "kwargs": {"keys": {"key_defs": COOKIE_KEYDEFS}},
            },
            "keys": {"uri_path": "jwks.json", "key_defs": KEYDEFS},
            "endpoint": {
                "provider_config": {
                    "path": ".well-known/openid-configuration",
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
            "response_types_supported": ["code", "code id_token", "id_token"],
            "allowed_scopes": ["openid", "profile", "offline_access"],
        }
        client_2_config = {
            "issuer": server_conf["issuer"],
            "client_id": "client_2",
            "client_secret": "hemligtlösenord",
            "redirect_uris": ["https://example.com/cb"],
            "client_salt": "salted_peanuts_cooking",
            "token_endpoint_auth_methods_supported": ["client_secret_post"],
            "response_types_supported": ["code", "code id_token", "id_token"],
            "allowed_scopes": ["openid", "profile", "offline_access"],
        }
        self.client_1 = Client(client_type='oauth2', config=client_1_config,
                               keyjar=build_keyjar(KEYDEFS),
                               services=_OAUTH2_SERVICES)
        self.client_2 = Client(client_type='oauth2', config=client_2_config,
                               keyjar=build_keyjar(KEYDEFS),
                               services=_OAUTH2_SERVICES)

        self.context = self.server.context
        self.context.cdb["client_1"] = client_1_config
        self.context.cdb["client_2"] = client_2_config
        self.context.keyjar.import_jwks(
            self.client_1.keyjar.export_jwks(), "client_1")
        self.context.keyjar.import_jwks(
            self.client_2.keyjar.export_jwks(), "client_2")

        self.context.set_provider_info()

        # self.endpoint = self.server.upstream_get("endpoint", "token")
        # self.introspection_endpoint = self.server.upstream_get("endpoint", "introspection")
        self.session_manager = self.context.session_manager
        self.user_id = "diana"

    def do_query(self, service_type, endpoint_type, request_args, state):
        _client = self.client_1.get_service(service_type)
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
            _req = areq.serialize(_server.request_format)
            _pr_resp = _server.parse_request(_req, **argv)
        else:
            _pr_resp = _server.parse_request(areq)

        if is_error_message(_pr_resp):
            return areq, _pr_resp

        _resp = _server.process_request(_pr_resp)
        if is_error_message(_resp):
            return areq, _resp

        _response = _server.do_response(**_resp)

        resp = _client.parse_response(_response["response"])
        _client.update_service_context(_resp["response_args"], key=state)
        return areq, resp

    def process_setup(self, token=None, scope=None):
        # ***** Discovery *********

        _req, _resp = self.do_query('server_metadata', 'server_metadata', {}, '')

        # ***** Authorization Request **********
        _nonce = rndstr(24),
        _context = self.client_1.get_service_context()
        # Need a new state for a new authorization request
        _state = _context.cstate.create_state(iss=_context.get("issuer"))
        _context.cstate.bind_key(_nonce, _state)

        req_args = {
            "response_type": ["code"],
            "nonce": _nonce,
            "state": _state
        }

        if scope:
            _scope = scope
        else:
            _scope = ["openid"]

            if token and list(token.keys())[0] == "refresh_token":
                _scope = ["openid", "offline_access"]

        req_args["scope"] = _scope

        areq, auth_response = self.do_query('authorization', 'authorization', req_args, _state)

        # ***** Token Request **********

        req_args = {
            "code": auth_response["code"],
            "state": auth_response["state"],
            "redirect_uri": areq["redirect_uri"],
            "grant_type": "authorization_code",
            "client_id": self.client_1.get_client_id(),
            "client_secret": _context.get_usage("client_secret"),
        }

        _token_request, resp = self.do_query("accesstoken", 'token', req_args, _state)

        return resp, _state, _scope

    @pytest.mark.parametrize(
        "token",
        [
            {"access_token": "urn:ietf:params:oauth:token-type:access_token"},
            {"refresh_token": "urn:ietf:params:oauth:token-type:refresh_token"},
        ],
    )
    def test_token_exchange(self, token):
        """
        Test that token exchange requests work correctly
        """

        resp, _state, _scope = self.process_setup(token)

        # ****** Token Exchange Request **********

        req_args = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "requested_token_type": token[list(token.keys())[0]],
            "subject_token": resp["access_token"],
            "subject_token_type": 'urn:ietf:params:oauth:token-type:access_token',
            "state": _state
        }

        _token_exchange_request, _te_resp = self.do_query("token_exchange", "token", req_args,
                                                          _state)

        assert set(_te_resp.keys()) == {
            "access_token",
            "token_type",
            "scope",
            "expires_in",
            "issued_token_type",
        }

        assert _te_resp["issued_token_type"] == token[list(token.keys())[0]]
        assert set(_te_resp["scope"]) == set(_scope)

    @pytest.mark.parametrize(
        "token",
        [
            {"access_token": "urn:ietf:params:oauth:token-type:access_token"},
            {"refresh_token": "urn:ietf:params:oauth:token-type:refresh_token"},
        ],
    )
    def test_token_exchange_per_client(self, token):
        """
        Test that per-client token exchange configuration works correctly
        """
        self.context.cdb["client_1"]["token_exchange"] = {
            "subject_token_types_supported": [
                "urn:ietf:params:oauth:token-type:access_token",
                "urn:ietf:params:oauth:token-type:refresh_token",
            ],
            "requested_token_types_supported": [
                "urn:ietf:params:oauth:token-type:access_token",
                "urn:ietf:params:oauth:token-type:refresh_token",
            ],
            "policy": {
                "": {
                    "function":
                        "idpyoidc.server.oauth2.token_helper.validate_token_exchange_policy",
                    "kwargs": {"scope": ["openid", "offline_access"]},
                }
            },
        }

        resp, _state, _scope = self.process_setup(token)

        # ****** Token Exchange Request **********

        req_args = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "requested_token_type": token[list(token.keys())[0]],
            "subject_token": resp["access_token"],
            "subject_token_type": 'urn:ietf:params:oauth:token-type:access_token',
            "state": _state
        }

        _token_exchange_request, _te_resp = self.do_query("token_exchange", "token", req_args,
                                                          _state)

        assert set(_te_resp.keys()) == {
            "access_token",
            "token_type",
            "scope",
            "expires_in",
            "issued_token_type",
        }

        assert _te_resp["issued_token_type"] == token[list(token.keys())[0]]
        assert set(_te_resp["scope"]) == set(_scope)

    def test_additional_parameters(self):
        """
        Test that a token exchange with additional parameters including
        scope, audience and subject_token_type works.
        """
        endp = self.server.get_endpoint("token")
        conf = endp.grant_type_helper["urn:ietf:params:oauth:grant-type:token-exchange"].config
        conf["policy"][""]["kwargs"] = {}
        conf["policy"][""]["kwargs"]["audience"] = ["https://example.com"]
        conf["policy"][""]["kwargs"]["resource"] = ["https://example.com"]

        resp, _state, _scope = self.process_setup()

        # ****** Token Exchange Request **********

        req_args = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": resp["access_token"],
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": ["https://example.com"],
            "resource": ["https://example.com"],
        }

        _token_exchange_request, _te_resp = self.do_query("token_exchange", "token", req_args,
                                                          _state)

        assert set(_te_resp.keys()) == {
            "access_token",
            "token_type",
            "expires_in",
            "issued_token_type",
            "scope",
        }

    def test_token_exchange_fails_if_disabled(self):
        """
        Test that token exchange fails if it's not included in Token's
        grant_types_supported (that are set in its helper attribute).
        """
        endpoint = self.server.get_endpoint("token")
        del endpoint.grant_type_helper["urn:ietf:params:oauth:grant-type:token-exchange"]

        resp, _state, _scope = self.process_setup()

        # ****** Token Exchange Request **********

        req_args = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": resp["access_token"],
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "resource": ["https://example.com/api"]
        }

        _te_request, _te_resp = self.do_query("token_exchange", "token", req_args, _state)

        assert _te_resp["error"] == "invalid_request"
        assert _te_resp["error_description"] == "Do not know how to handle this type of request"

    def test_wrong_resource(self):
        """
        Test that requesting a token for an unknown resource fails.
        """
        endpoint = self.server.get_endpoint("token")

        conf = endpoint.grant_type_helper["urn:ietf:params:oauth:grant-type:token-exchange"].config
        conf["policy"][""]["kwargs"] = {}
        conf["policy"][""]["kwargs"]["resource"] = ["https://example.com"]

        resp, _state, _scope = self.process_setup()

        # ****** Token Exchange Request **********

        req_args = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": resp["access_token"],
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "resource": ["https://unknown-resource.com/api"],
        }

        _te_request, _te_resp = self.do_query("token_exchange", "token", req_args, _state)

        assert set(_te_resp.keys()) == {"error", "error_description"}
        assert _te_resp["error"] == "invalid_target"
        assert _te_resp["error_description"] == "Unknown resource"

    def test_refresh_token_audience(self):
        """
        Test that requesting a refresh token with audience fails.
        """

        resp, _state, _scope = self.process_setup(
            {"refresh_token": "urn:ietf:params:oauth:token-type:refresh_token"})

        # ****** Token Exchange Request **********

        req_args = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": resp["refresh_token"],
            "subject_token_type": "urn:ietf:params:oauth:token-type:refresh_token",
            "audience": ["https://example.com"],
        }

        _te_request, _te_resp = self.do_query("token_exchange", "token", req_args, _state)

        assert set(_te_resp.keys()) == {"error", "error_description"}
        assert _te_resp["error"] == "invalid_target"
        assert _te_resp["error_description"] == "Refresh token has single owner"

    def test_wrong_audience(self):
        """
        Test that requesting a token for an unknown audience fails.
        """
        endpoint = self.server.get_endpoint("token")
        conf = endpoint.grant_type_helper["urn:ietf:params:oauth:grant-type:token-exchange"].config
        conf["policy"][""]["kwargs"] = {}
        conf["policy"][""]["kwargs"]["audience"] = ["https://example.com"]

        resp, _state, _scope = self.process_setup()

        # ****** Token Exchange Request **********

        req_args = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": resp["access_token"],
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": ["https://unknown-audience.com/"],
        }

        _te_request, _te_resp = self.do_query("token_exchange", "token", req_args, _state)

        assert set(_te_resp.keys()) == {"error", "error_description"}
        assert _te_resp["error"] == "invalid_target"
        assert _te_resp["error_description"] == "Unknown audience"

    def test_exchange_refresh_token_to_refresh_token(self):
        """
        Test whether exchanging a refresh token to another refresh token works.
        """
        resp, _state, _scope = self.process_setup(
            {"refresh_token": "urn:ietf:params:oauth:token-type:refresh_token"})

        # ****** Token Exchange Request **********

        req_args = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": resp["refresh_token"],
            "subject_token_type": "urn:ietf:params:oauth:token-type:refresh_token",
            "requested_token_type": "urn:ietf:params:oauth:token-type:refresh_token",
        }

        _te_request, _te_resp = self.do_query("token_exchange", "token", req_args, _state)

        assert set(_te_resp.keys()) == {"error", "error_description"}

    @pytest.mark.parametrize(
        "scopes",
        [
            ["openid", "offline_access"],
            ["openid"],
        ],
    )
    def test_exchange_access_token_to_refresh_token(self, scopes):

        resp, _state, _scope = self.process_setup(scope=scopes)

        # ****** Token Exchange Request **********

        req_args = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": resp["access_token"],
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "requested_token_type": "urn:ietf:params:oauth:token-type:refresh_token",
        }

        _te_request, _te_resp = self.do_query("token_exchange", "token", req_args, _state)

        if "offline_access" in scopes:
            assert set(_te_resp.keys()) != {"error", "error_description"}
        else:
            assert _te_resp["error"] == "invalid_request"

    @pytest.mark.parametrize(
        "unsupported_type",
        [
            "unknown",
            "urn:ietf:params:oauth:token-type:id_token",
            "urn:ietf:params:oauth:token-type:saml2",
            "urn:ietf:params:oauth:token-type:saml1",
        ],
    )
    def test_unsupported_requested_token_type(self, unsupported_type):
        """
        Test that requesting a token type that is unknown or unsupported fails.
        """

        resp, _state, _scope = self.process_setup()

        # ****** Token Exchange Request **********

        req_args = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": resp["access_token"],
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "requested_token_type": unsupported_type,
            "audience": ["https://example.com"],
            "resource": ["https://example.com/api"],
        }

        _te_request, _te_resp = self.do_query("token_exchange", "token", req_args, _state)

        assert set(_te_resp.keys()) == {"error", "error_description"}
        assert _te_resp["error"] == "invalid_request"
        assert _te_resp["error_description"] == "Unsupported requested token type"

    @pytest.mark.parametrize(
        "unsupported_type",
        [
            "unknown",
            "urn:ietf:params:oauth:token-type:id_token",
            "urn:ietf:params:oauth:token-type:saml2",
            "urn:ietf:params:oauth:token-type:saml1",
        ],
    )
    def test_unsupported_subject_token_type(self, unsupported_type):
        """
        Test that providing an unsupported subject token type fails.
        """
        resp, _state, _scope = self.process_setup()

        # ****** Token Exchange Request **********

        req_args = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": resp["access_token"],
            "subject_token_type": unsupported_type,
            "audience": ["https://example.com"],
            "resource": ["https://example.com/api"],
        }

        _te_request, _te_resp = self.do_query("token_exchange", "token", req_args, _state)

        assert set(_te_resp.keys()) == {"error", "error_description"}
        assert _te_resp["error"] == "invalid_request"
        assert _te_resp["error_description"] == "Subject token invalid"

    def test_unsupported_actor_token(self):
        """
        Test that providing an actor token fails as it's unsupported.
        """
        resp, _state, _scope = self.process_setup()

        # ****** Token Exchange Request **********

        req_args = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": resp["access_token"],
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "actor_token": resp["access_token"],
        }

        _te_request, _te_resp = self.do_query("token_exchange", "token", req_args, _state)

        assert set(_te_resp.keys()) == {"error", "error_description"}
        assert _te_resp["error"] == "invalid_request"
        assert _te_resp["error_description"] == "Actor token not supported"

    def test_invalid_token(self):
        """
        Test that providing an invalid token fails.
        """
        resp, _state, _scope = self.process_setup()

        # ****** Token Exchange Request **********

        req_args = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": "invalid_token",
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        }

        _te_request, _te_resp = self.do_query("token_exchange", "token", req_args, _state)

        assert set(_te_resp.keys()) == {"error", "error_description"}
        assert _te_resp["error"] == "invalid_request"
        assert _te_resp["error_description"] == "Subject token invalid"
