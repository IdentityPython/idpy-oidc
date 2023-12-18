import io
import json
import os
from http.cookies import SimpleCookie
from urllib.parse import parse_qs
from urllib.parse import urlparse

import pytest
import yaml
from cryptojwt import KeyJar
from cryptojwt.jwt import JWT
from cryptojwt.jwt import utc_time_sans_frac
from cryptojwt.key_jar import init_key_jar
from cryptojwt.utils import as_bytes
from cryptojwt.utils import b64e

from idpyoidc.exception import ParameterError
from idpyoidc.exception import URIError
from idpyoidc.message.oauth2 import AuthorizationErrorResponse
from idpyoidc.message.oauth2 import AuthorizationRequest
from idpyoidc.message.oauth2 import AuthorizationResponse
from idpyoidc.message.oauth2 import TokenErrorResponse
from idpyoidc.message.oidc import AccessTokenRequest
from idpyoidc.server import Server
from idpyoidc.server.authn_event import create_authn_event
from idpyoidc.server.authz import AuthzHandling
from idpyoidc.server.configure import ASConfiguration
from idpyoidc.server.cookie_handler import CookieHandler
from idpyoidc.server.exception import InvalidRequest
from idpyoidc.server.exception import NoSuchAuthentication
from idpyoidc.server.exception import RedirectURIError
from idpyoidc.server.exception import ToOld
from idpyoidc.server.exception import UnAuthorizedClientScope
from idpyoidc.server.exception import UnknownClient
from idpyoidc.server.oauth2.authorization import FORM_POST
from idpyoidc.server.oauth2.authorization import Authorization
from idpyoidc.server.oauth2.authorization import get_uri
from idpyoidc.server.oauth2.authorization import inputs
from idpyoidc.server.oauth2.authorization import join_query
from idpyoidc.server.oauth2.authorization import (
    validate_resource_indicators_policy as validate_authorization_resource_indicators_policy,
)
from idpyoidc.server.oauth2.authorization import verify_uri
from idpyoidc.server.oauth2.token import Token
from idpyoidc.server.oauth2.token_helper import (
    validate_resource_indicators_policy as validate_token_resource_indicators_policy,
)
from idpyoidc.server.user_info import UserInfo
from idpyoidc.time_util import in_a_while
from tests import CRYPT_CONFIG
from tests import SESSION_PARAMS

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

COOKIE_KEYDEFS = [
    {"type": "oct", "kid": "sig", "use": ["sig"]},
    {"type": "oct", "kid": "enc", "use": ["enc"]},
]

RESPONSE_TYPES_SUPPORTED = [["code"], ["token"], ["code", "token"], ["none"]]

CAPABILITIES = {
    "grant_types_supported": [
        "authorization_code",
        "implicit",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "refresh_token",
    ]
}

AUTH_REQ = AuthorizationRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    scope=["openid", "email", "profile"],
    state="STATE",
    response_type="code",
    resource=["client_2"],
)

AUTH_REQ_DICT = AUTH_REQ.to_dict()

TOKEN_REQ = AccessTokenRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    state="STATE",
    grant_type="authorization_code",
    client_secret="hemligt",
    resource=["client_3"],
)

TOKEN_REQ_DICT = TOKEN_REQ.to_dict()

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


USERINFO_db = json.loads(open(full_path("users.json")).read())


class SimpleCookieDealer(object):
    def __init__(self, name=""):
        self.name = name

    def create_cookie(self, value, typ, **kwargs):
        cookie = SimpleCookie()
        timestamp = str(utc_time_sans_frac())

        _payload = "::".join([value, timestamp, typ])

        bytes_load = _payload.encode("utf-8")
        bytes_timestamp = timestamp.encode("utf-8")

        cookie_payload = [bytes_load, bytes_timestamp]
        cookie[self.name] = (b"|".join(cookie_payload)).decode("utf-8")
        try:
            ttl = kwargs["ttl"]
        except KeyError:
            pass
        else:
            cookie[self.name]["expires"] = in_a_while(seconds=ttl)

        return cookie

    @staticmethod
    def get_cookie_value(cookie=None, name=None):
        if cookie is None or name is None:
            return None
        else:
            try:
                info, timestamp = cookie[name].split("|")
            except (TypeError, AssertionError):
                return None
            else:
                value = info.split("::")
                if timestamp == value[1]:
                    return value
        return None


client_yaml = """
clients:
  client_1:
    "client_secret": 'hemligt'
    "redirect_uris":
        - ['https://example.com/cb', '']
    "client_salt": "salted"
    'token_endpoint_auth_method': 'client_secret_post'
    'response_types':
        - 'code'
        - 'token'
    'scope':
        - 'test'
    'allowed_scopes':
        - 'openid'
        - 'profile'
  client_2:
    client_secret: "spraket"
    redirect_uris:
      - ['https://app1.example.net/foo', '']
      - ['https://app2.example.net/bar', '']
    response_types:
      - code
    'allowed_scopes':
      - 'openid'
      - 'email'
"""

RESOURCE_INDICATORS_DISABLED = {
    "issuer": "https://example.com/",
    "password": "mycket hemligt zebra",
    "verify_ssl": False,
    "capabilities": CAPABILITIES,
    "keys": {"uri_path": "static/jwks.json", "key_defs": KEYDEFS},
    "token_handler_args": {
        "jwks_def": {
            "private_path": "private/token_jwks.json",
            "read_only": False,
            "key_defs": [{"type": "oct", "bytes": "24", "use": ["enc"], "kid": "code"}],
        },
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
    "endpoint": {
        "authorization": {
            "path": "{}/authorization",
            "class": Authorization,
            "kwargs": {
                "response_types_supported": [" ".join(x) for x in RESPONSE_TYPES_SUPPORTED],
                "response_modes_supported": ["query", "fragment", "form_post"],
                "claims_parameter_supported": True,
                "request_parameter_supported": True,
                "request_uri_parameter_supported": True,
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
                ],
            },
        },
    },
    "authentication": {
        "anon": {
            "acr": "http://www.swamid.se/policy/assurance/al1",
            "class": "idpyoidc.server.user_authn.user.NoAuthn",
            "kwargs": {"user": "diana"},
        }
    },
    "userinfo": {"class": UserInfo, "kwargs": {"db": USERINFO_db}},
    "template_dir": "template",
    "cookie_handler": {
        "class": CookieHandler,
        "kwargs": {
            "keys": {"key_defs": COOKIE_KEYDEFS},
            "name": {
                "session": "oidc_op",
                "register": "oidc_op_reg",
                "session_management": "oidc_op_sman",
            },
        },
    },
    "authz": {
        "class": AuthzHandling,
        "kwargs": {
            "grant_config": {
                "usage_rules": {
                    "authorization_code": {
                        "supports_minting": [
                            "access_token",
                            "refresh_token",
                            "id_token",
                        ],
                        "max_usage": 1,
                    },
                    "access_token": {},
                    "refresh_token": {
                        "supports_minting": [
                            "access_token",
                            "refresh_token",
                            "id_token",
                        ],
                    },
                },
                "expires_in": 43200,
            }
        },
    },
    "session_params": SESSION_PARAMS,
}

RESOURCE_INDICATORS_ENABLED = {
    "issuer": "https://example.com/",
    "password": "mycket hemligt zebra",
    "verify_ssl": False,
    "capabilities": CAPABILITIES,
    "keys": {"uri_path": "static/jwks.json", "key_defs": KEYDEFS},
    "token_handler_args": {
        "jwks_def": {
            "private_path": "private/token_jwks.json",
            "read_only": False,
            "key_defs": [{"type": "oct", "bytes": "24", "use": ["enc"], "kid": "code"}],
        },
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
    "endpoint": {
        "authorization": {
            "path": "{}/authorization",
            "class": Authorization,
            "kwargs": {
                "response_types_supported": [" ".join(x) for x in RESPONSE_TYPES_SUPPORTED],
                "response_modes_supported": ["query", "fragment", "form_post"],
                "claims_parameter_supported": True,
                "request_parameter_supported": True,
                "request_uri_parameter_supported": True,
                "resource_indicators": {
                    "policy": {
                        "function": validate_authorization_resource_indicators_policy,
                        "kwargs": {
                            "resource_servers_per_client": {
                                "client_1": ["client_1", "client_2"],
                            },
                        },
                    }
                },
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
                ],
                "resource_indicators": {
                    "policy": {
                        "function": validate_token_resource_indicators_policy,
                        "kwargs": {
                            "resource_servers_per_client": {"client_1": ["client_2", "client_3"]},
                        },
                    }
                },
            },
        },
    },
    "authentication": {
        "anon": {
            "acr": "http://www.swamid.se/policy/assurance/al1",
            "class": "idpyoidc.server.user_authn.user.NoAuthn",
            "kwargs": {"user": "diana"},
        }
    },
    "userinfo": {"class": UserInfo, "kwargs": {"db": USERINFO_db}},
    "template_dir": "template",
    "cookie_handler": {
        "class": CookieHandler,
        "kwargs": {
            "keys": {"key_defs": COOKIE_KEYDEFS},
            "name": {
                "session": "oidc_op",
                "register": "oidc_op_reg",
                "session_management": "oidc_op_sman",
            },
        },
    },
    "authz": {
        "class": AuthzHandling,
        "kwargs": {
            "grant_config": {
                "usage_rules": {
                    "authorization_code": {
                        "supports_minting": [
                            "access_token",
                            "refresh_token",
                            "id_token",
                        ],
                        "max_usage": 1,
                    },
                    "access_token": {},
                    "refresh_token": {
                        "supports_minting": [
                            "access_token",
                            "refresh_token",
                            "id_token",
                        ],
                    },
                },
                "expires_in": 43200,
            }
        },
    },
    "session_params": SESSION_PARAMS,
}


class TestEndpoint(object):
    @pytest.fixture(autouse=False)
    def create_endpoint_ri_disabled(self):
        conf = RESOURCE_INDICATORS_DISABLED
        server = Server(ASConfiguration(conf=conf, base_path=BASEDIR), cwd=BASEDIR)

        endpoint_context = server.context
        _clients = yaml.safe_load(io.StringIO(client_yaml))
        endpoint_context.cdb = _clients["clients"]
        endpoint_context.keyjar.import_jwks(
            endpoint_context.keyjar.export_jwks(True, ""), conf["issuer"]
        )
        self.endpoint_context = endpoint_context
        self.endpoint = server.get_endpoint("authorization")
        self.token_endpoint = server.get_endpoint("token")
        self.session_manager = endpoint_context.session_manager
        self.user_id = "diana"

        self.rp_keyjar = KeyJar()
        self.rp_keyjar.add_symmetric("client_1", "hemligtkodord1234567890")
        self.endpoint.upstream_get("endpoint_context").keyjar.add_symmetric(
            "client_1", "hemligtkodord1234567890"
        )

    @pytest.fixture(autouse=False)
    def create_endpoint_ri_enabled(self):
        conf = RESOURCE_INDICATORS_ENABLED
        server = Server(ASConfiguration(conf=conf, base_path=BASEDIR), cwd=BASEDIR)

        endpoint_context = server.context
        _clients = yaml.safe_load(io.StringIO(client_yaml))
        endpoint_context.cdb = _clients["clients"]
        endpoint_context.keyjar.import_jwks(
            endpoint_context.keyjar.export_jwks(True, ""), conf["issuer"]
        )
        self.endpoint_context = endpoint_context
        self.endpoint = server.get_endpoint("authorization")
        self.token_endpoint = server.get_endpoint("token")
        self.session_manager = endpoint_context.session_manager
        self.user_id = "diana"

        self.rp_keyjar = KeyJar()
        self.rp_keyjar.add_symmetric("client_1", "hemligtkodord1234567890")
        self.endpoint.upstream_get("context").keyjar.add_symmetric(
            "client_1", "hemligtkodord1234567890"
        )

    def _create_session(self, auth_req, sub_type="public", sector_identifier=""):
        if sector_identifier:
            areq = auth_req.copy()
            areq["sector_identifier_uri"] = sector_identifier
        else:
            areq = auth_req

        client_id = areq["client_id"]
        ae = create_authn_event(self.user_id)
        return self.session_manager.create_session(
            ae, areq, self.user_id, client_id=client_id, sub_type=sub_type
        )

    def _mint_code(self, grant, client_id):
        session_id = self.session_manager.encrypted_session_id(self.user_id, client_id, grant.id)
        usage_rules = grant.usage_rules.get("authorization_code", {})
        _exp_in = usage_rules.get("expires_in")

        # Constructing an authorization code is now done
        _code = grant.mint_token(
            session_id=session_id,
            context=self.endpoint_context,
            token_class="authorization_code",
            token_handler=self.session_manager.token_handler["authorization_code"],
            usage_rules=usage_rules,
            resources=grant.resources,
        )

        if _exp_in:
            if isinstance(_exp_in, str):
                _exp_in = int(_exp_in)
            if _exp_in:
                _code.expires_at = utc_time_sans_frac() + _exp_in
        return _code

    def test_init(self, create_endpoint_ri_enabled):
        assert self.endpoint

    def test_parse(self, create_endpoint_ri_enabled):
        _req = self.endpoint.parse_request(AUTH_REQ_DICT)
        assert isinstance(_req, AuthorizationRequest)
        assert set(_req.keys()) == set(AUTH_REQ.keys())

    def test_authorization_code_req_no_resource(self, create_endpoint_ri_enabled):
        """
        Test that appropriate error message is returned when resource indicators is enabled
        for the authorization endpoint and resource parameter is missing from request.
        """
        endpoint_context = self.endpoint.upstream_get("context")
        msg = self.endpoint._post_parse_request({}, "client_1", endpoint_context)
        assert "error" in msg

        request = AuthorizationRequest(
            client_id="client_1",
            response_type=["code"],
            state="state",
            nonce="nonce",
            scope="openid",
        )

        msg = self.endpoint._post_parse_request(request, "client_1", endpoint_context)

        assert "error" not in msg
        assert isinstance(msg, AuthorizationRequest)
        for key, _ in request.items():
            assert msg[key] == request[key]

    def test_authorization_code_req_no_resource_indicators_disabled(
        self, create_endpoint_ri_disabled
    ):
        """
        Test successful authorization request when resource indicators is disabled.
        """
        endpoint_context = self.endpoint.upstream_get("context")
        request = AUTH_REQ.copy()
        del request["resource"]

        msg = self.endpoint._post_parse_request(request, "client_1", endpoint_context)
        assert "error" not in msg

    def test_authorization_code_req(self, create_endpoint_ri_enabled):
        """
        Test successful authorization request when resource indicators is enabled.
        """
        endpoint_context = self.endpoint.upstream_get("context")
        request = AUTH_REQ.copy()

        msg = self.endpoint._post_parse_request(request, "client_1", endpoint_context)
        assert "error" not in msg

    def test_authorization_code_req_per_client(self, create_endpoint_ri_disabled):
        """
        Test that appropriate error message is returned when resource indicators is enabled per client
        for the authorization endpoint and requested resource is not permitted for client.
        """
        endpoint_context = self.endpoint.upstream_get("context")
        endpoint_context.cdb["client_1"]["resource_indicators"] = {
            "authorization_code": {
                "policy": {
                    "function": validate_authorization_resource_indicators_policy,
                    "kwargs": {"resource_servers_per_client": ["client_3"]},
                },
            },
        }
        request = AUTH_REQ.copy()
        client_id = request["client_id"]

        msg = self.endpoint._post_parse_request(request, "client_1", endpoint_context)
        assert "error" in msg
        assert msg["error_description"] == f"Invalid resource requested by client {client_id}"

    def test_authorization_code_req_no_resource_client(self, create_endpoint_ri_enabled):
        """
        Test that appropriate error message is returned when resource indicators is enabled
        for the authorization endpoint and permitted resources are not configured for client.
        """
        request = AUTH_REQ.copy()
        client_id = request["client_id"]
        endpoint_context = self.endpoint.upstream_get("context")
        self.endpoint.kwargs["resource_indicators"]["policy"]["kwargs"][
            "resource_servers_per_client"
        ] = {"client_2": ["client_1"]}

        msg = self.endpoint._post_parse_request(request, client_id, endpoint_context)

        assert "error" in msg
        assert msg["error"] == "invalid_target"
        assert msg["error_description"] == f"Resources for client {client_id} not found"

    def test_authorization_code_req_invalid_resource_client(self, create_endpoint_ri_enabled):
        """
        Test that appropriate error message is returned when resource indicators is enabled
        for the authorization endpoint and requested resource is not permitted for client.
        """
        request = AUTH_REQ.copy()
        request["resource"] = "client_3"
        client_id = request["client_id"]
        endpoint_context = self.endpoint.upstream_get("context")

        msg = self.endpoint._post_parse_request(request, client_id, endpoint_context)

        assert "error" in msg
        assert msg["error"] == "invalid_target"
        assert msg["error_description"] == f"Invalid resource requested by client {client_id}"

    def test_access_token_req(self, create_endpoint_ri_enabled):
        """
        Test successful access_token request when resource indicators is enabled.
        """
        self.endpoint.upstream_get("context").cdb["client_3"] = {
            "client_id": "client_3",
            "redirect_uris": [("https://rp.example.com/cb", {})],
            "id_token_signed_response_alg": "ES256",
            "allowed_scopes": ["openid"],
        }
        session_id = self._create_session(AUTH_REQ)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant, AUTH_REQ["client_id"])

        assert code.resources != []

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
        _req = self.token_endpoint.parse_request(_token_request)

        _resp = self.token_endpoint.process_request(request=_req)

        access_token = TokenErrorResponse().from_jwt(
            _resp["response_args"]["access_token"],
            self.endpoint_context.keyjar,
            sender="",
        )

        assert set(access_token["aud"]) == set(["client_3", "client_1"])

    def test_access_token_req_invalid_resource_client(self, create_endpoint_ri_enabled):
        """
        Test that appropriate error message is returned when resource indicators is enabled
        for the token endpoint and requested resource is not permitted for client.
        """
        session_id = self._create_session(AUTH_REQ)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant, AUTH_REQ["client_id"])

        assert code.resources != []

        _token_request = TOKEN_REQ_DICT.copy()
        client_id = _token_request["client_id"]
        _token_request["resource"] = "client_2"
        _token_request["code"] = code.value
        _req = self.token_endpoint.parse_request(_token_request)

        _resp = self.token_endpoint.process_request(request=_req)

        assert "error" in _resp
        assert _resp["error"] == "invalid_target"
        assert _resp["error_description"] == f"Invalid resource requested by client {client_id}"

    def test_create_authn_response(self, create_endpoint_ri_enabled):
        """
        Test that the requested access_token has the correct scopes based on the allowed scopes of
        the requested resources
        """
        self.endpoint.upstream_get("context").cdb["client_3"] = {
            "client_id": "client_3",
            "redirect_uris": [("https://rp.example.com/cb", {})],
            "id_token_signed_response_alg": "ES256",
            "allowed_scopes": ["openid"],
        }

        session_id = self._create_session(AUTH_REQ)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant, AUTH_REQ["client_id"])

        assert code.resources != []

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["scope"] = ["openid", "profile"]
        _token_request["code"] = code.value
        _req = self.token_endpoint.parse_request(_token_request)

        _resp = self.token_endpoint.process_request(request=_req)
        assert "response_args" in _resp
        assert set(_resp["response_args"]["scope"]) == set(["openid", "profile"])
