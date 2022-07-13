import json
import os

import pytest
from cryptojwt import JWT
from cryptojwt.key_jar import build_keyjar

from idpyoidc.defaults import JWT_BEARER
from idpyoidc.message.oauth2 import CCAccessTokenRequest
from idpyoidc.message.oidc import AuthorizationRequest
from idpyoidc.message.oidc import RefreshAccessTokenRequest
from idpyoidc.message.oidc import TokenErrorResponse
from idpyoidc.server import Server
from idpyoidc.server.authn_event import create_authn_event
from idpyoidc.server.authz import AuthzHandling
from idpyoidc.server.client_authn import verify_client
from idpyoidc.server.configure import ASConfiguration
from idpyoidc.server.exception import InvalidToken
from idpyoidc.server.oauth2.authorization import Authorization
from idpyoidc.server.oauth2.introspection import Introspection
from idpyoidc.server.oauth2.token import Token
from idpyoidc.server.session import MintingNotAllowed
from idpyoidc.server.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from idpyoidc.server.user_info import UserInfo
from idpyoidc.time_util import utc_time_sans_frac
from tests import CRYPT_CONFIG
from tests import SESSION_PARAMS

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

CLIENT_KEYJAR = build_keyjar(KEYDEFS)

RESPONSE_TYPES_SUPPORTED = [
    ["code"],
    ["token"],
]

CAPABILITIES = {
    "grant_types_supported": [
        "authorization_code",
        "implicit",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "refresh_token",
        "client_credentials"
    ],
}

TOKEN_REQ = CCAccessTokenRequest(
    client_id="client_1",
    grant_type="client_credentials",
    client_secret="hemligt",
    scope=""
)

TOKEN_REQ_DICT = TOKEN_REQ.to_dict()

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


@pytest.fixture
def conf():
    return {
        "issuer": "https://example.com/",
        "httpc_params": {"verify": False},
        "capabilities": CAPABILITIES,
        "keys": {"uri_path": "jwks.json", "key_defs": KEYDEFS},
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
        "endpoint": {
            "authorization": {
                "path": "authorization",
                "class": Authorization,
                "kwargs": {},
            },
            "introspection": {
                    "path": "{}/intro",
                    "class": Introspection,
                    "kwargs": {
                        "client_authn_method": ["client_secret_post"],
                        "enable_claims_per_client": False,
                    },
                },
            "token": {
                "path": "token",
                "class": Token,
                "kwargs": {
                    "client_authn_method": [
                        "client_secret_basic",
                        "client_secret_post",
                        "client_secret_jwt",
                        "private_key_jwt",
                    ]
                },
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
        "claims_interface": {
            "class": "idpyoidc.server.session.claims.OAuth2ClaimsInterface",
            "kwargs": {},
        },
        "authz": {
            "class": AuthzHandling,
            "kwargs": {
                "grant_config": {
                    "usage_rules": {
                        "authorization_code": {
                            "expires_in": 300,
                            "supports_minting": ["access_token", "refresh_token"],
                            "max_usage": 1,
                        },
                        "access_token": {"expires_in": 600},
                        "refresh_token": {
                            "expires_in": 86400,
                            "supports_minting": ["access_token", "refresh_token"],
                        },
                    },
                    "expires_in": 43200,
                }
            },
        },
        "session_params": {"encrypter": SESSION_PARAMS},
    }


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self, conf):
        server = Server(ASConfiguration(conf=conf, base_path=BASEDIR), cwd=BASEDIR)
        endpoint_context = server.endpoint_context
        endpoint_context.cdb["client_1"] = {
            "client_secret": "hemligt",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token"],
        }
        endpoint_context.keyjar.import_jwks(CLIENT_KEYJAR.export_jwks(), "client_1")
        self.session_manager = endpoint_context.session_manager
        self.token_endpoint = server.server_get("endpoint", "token")
        self.introspection_endpoint = server.server_get("endpoint", "introspection")
        self.endpoint_context = endpoint_context

    def test_client_credentials(self):
        """
        Test client credentials
        """
        self.endpoint_context.cdb["client_1"] = {
            "client_secret": "hemligt",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token"],
        }

        _token_request = TOKEN_REQ_DICT.copy()

        _req = self.token_endpoint.parse_request(_token_request)
        _resp = self.token_endpoint.process_request(request=_req)

        assert "access_token" in _resp["response_args"]
        assert "token_type" in _resp["response_args"]
        assert "expires_in" in _resp["response_args"]

    def test_client_credentials_with_scopes(self):
        """
        Test client credentials grant with scopes requested.
        """
        self.endpoint_context.cdb["client_1"] = {
            "client_secret": "hemligt",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token"],
        }
    
        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["scope"] = "profile email"

        _req = self.token_endpoint.parse_request(_token_request)
        _resp = self.token_endpoint.process_request(request=_req)

        assert "access_token" in _resp["response_args"]
        assert "token_type" in _resp["response_args"]
        assert "expires_in" in _resp["response_args"]
        assert set(_resp["response_args"]["scope"]) == set(["profile", "email"])

    def test_client_credentials_offline_access(self):
        """
        Test client credentials grant with offline scope requested.
        """
        self.endpoint_context.cdb["client_1"] = {
            "client_secret": "hemligt",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token"],
        }
    
        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["scope"] = "offline_access"

        _req = self.token_endpoint.parse_request(_token_request)
        _resp = self.token_endpoint.process_request(request=_req)

        assert "access_token" in _resp["response_args"]
        assert "token_type" in _resp["response_args"]
        assert "expires_in" in _resp["response_args"]
        assert "refresh_token" not in _resp["response_args"]

    
    def test_client_credentials_fails_if_disabled(self):
        """
        Test that Client Credentials fails if it's not included in Token's
        grant_types_supported (that are set in its helper attribute).
        """
        del self.token_endpoint.helper["client_credentials"]

        self.endpoint_context.cdb["client_1"] = {
            "client_secret": "hemligt",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token", "code id_token", "id_token"],
        }

        _token_request = TOKEN_REQ_DICT.copy()

        _req = self.token_endpoint.parse_request(_token_request)
        _resp = self.token_endpoint.process_request(request=_req)

        assert _resp["error"] == "invalid_request"
        assert (
            _resp["error_description"]
            == "Unsupported grant_type: client_credentials"
        )

    def test_client_credentials_per_client(self):
        """
        Test that per-client client credentials configuration works correctly
        """
        self.token_endpoint.grant_types_supported.remove("client_credentials")
        self.endpoint_context.cdb["client_1"] = {
            "client_secret": "hemligt",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token", "code id_token"],
            "grant_types_supported": ["client_credentials"]
        }

        _token_request = TOKEN_REQ_DICT.copy()

        _req = self.token_endpoint.parse_request(_token_request)
        _resp = self.token_endpoint.process_request(request=_req)

        assert "access_token" in _resp["response_args"]
        assert "token_type" in _resp["response_args"]
        assert "expires_in" in _resp["response_args"]

    def test_introspection(self):
        self.token_endpoint.grant_types_supported.remove("client_credentials")
        self.endpoint_context.cdb["client_1"] = {
            "client_secret": "hemligt",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token", "code id_token"],
            "grant_types_supported": ["client_credentials"]
        }

        _token_request = TOKEN_REQ_DICT.copy()

        _req = self.token_endpoint.parse_request(_token_request)
        _resp = self.token_endpoint.process_request(request=_req)
        access_token = _resp["response_args"]["access_token"]

        self.introspection_endpoint.kwargs["enable_claims_per_client"] = True

        _context = self.introspection_endpoint.server_get("endpoint_context")
        _req = self.introspection_endpoint.parse_request(
            {
                "token": access_token,
                "client_id": "client_1",
                "client_secret": _context.cdb["client_1"]["client_secret"],
            }
        )
        _resp = self.introspection_endpoint.process_request(_req)
        _resp_args = _resp["response_args"]
        assert "active" in _resp_args
        assert _resp_args["active"] == True

