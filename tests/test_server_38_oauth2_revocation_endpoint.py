import base64
import os

import pytest
from cryptojwt import as_unicode
from cryptojwt.utils import as_bytes

from idpyoidc.message.oauth2 import TokenRevocationRequest
from idpyoidc.message.oauth2 import TokenRevocationResponse
from idpyoidc.message.oidc import AccessTokenRequest
from idpyoidc.message.oidc import AuthorizationRequest
from idpyoidc.server import Server
from idpyoidc.server.authn_event import create_authn_event
from idpyoidc.server.authz import AuthzHandling
from idpyoidc.server.client_authn import verify_client
from idpyoidc.server.configure import ASConfiguration
from idpyoidc.server.exception import ClientAuthenticationError
from idpyoidc.server.oauth2.authorization import Authorization
from idpyoidc.server.oauth2.introspection import Introspection
from idpyoidc.server.oauth2.token_revocation import TokenRevocation
from idpyoidc.server.oauth2.token_revocation import validate_token_revocation_policy
from idpyoidc.server.oidc.token import Token
from idpyoidc.server.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from idpyoidc.server.user_info import UserInfo
from idpyoidc.time_util import utc_time_sans_frac
from tests import CRYPT_CONFIG
from tests import SESSION_PARAMS

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
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
        "refresh_token",
    ],
    "claim_types_supported": ["normal", "aggregated", "distributed"],
    "claims_parameter_supported": True,
    "request_parameter_supported": True,
    "request_uri_parameter_supported": True,
}

AUTH_REQ = AuthorizationRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    scope=["openid", "offline_access"],
    state="STATE",
    response_type="code id_token",
)

TOKEN_REQ = AccessTokenRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    state="STATE",
    grant_type="authorization_code",
    client_secret="hemligt",
)

TOKEN_REQ_DICT = TOKEN_REQ.to_dict()

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


@pytest.mark.parametrize("jwt_token", [True, False])
class TestEndpoint:

    @pytest.fixture(autouse=True)
    def create_endpoint(self, jwt_token):
        conf = {
            "issuer": "https://example.com/",
            "httpc_params": {"verify": False, "timeout": 1},
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
                "id_token": {
                    "class": "idpyoidc.server.token.id_token.IDToken",
                },
            },
            "endpoint": {
                "authorization": {
                    "path": "{}/authorization",
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
                "token_revocation": {
                    "path": "{}/revoke",
                    "class": TokenRevocation,
                    "kwargs": {
                        "client_authn_method": ["client_secret_post"],
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
            "userinfo": {
                "path": "{}/userinfo",
                "class": UserInfo,
                "kwargs": {"db_file": full_path("users.json")},
            },
            "client_authn": verify_client,
            "template_dir": "template",
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
                                "supports_minting": ["access_token", "refresh_token"],
                            },
                        },
                        "expires_in": 43200,
                    }
                },
            },
            "session_params": SESSION_PARAMS,
        }
        if jwt_token:
            conf["token_handler_args"]["token"] = {
                "class": "idpyoidc.server.token.jwt_token.JWTToken",
                "kwargs": {},
            }
        server = Server(ASConfiguration(conf=conf, base_path=BASEDIR), cwd=BASEDIR)
        endpoint_context = server.context
        endpoint_context.cdb["client_1"] = {
            "client_secret": "hemligt",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "token_endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token", "code id_token", "id_token"],
            "add_claims": {
                "always": {
                    "introspection": ["nickname", "eduperson_scoped_affiliation"],
                },
                "by_scope": {},
            },
            "allowed_scopes": ["openid", "profile", "email", "address", "phone", "offline_access",
                               "research_and_scholarship"]
        }
        endpoint_context.keyjar.import_jwks_as_json(
            endpoint_context.keyjar.export_jwks_as_json(private=True),
            endpoint_context.issuer,
        )
        self.revocation_endpoint = server.get_endpoint("token_revocation")
        self.token_endpoint = server.get_endpoint("token")
        self.session_manager = endpoint_context.session_manager
        self.user_id = "diana"

    def _create_session(self, auth_req, sub_type="public", sector_identifier=""):
        if sector_identifier:
            authz_req = auth_req.copy()
            authz_req["sector_identifier_uri"] = sector_identifier
        else:
            authz_req = auth_req
        client_id = authz_req["client_id"]
        ae = create_authn_event(self.user_id)
        return self.session_manager.create_session(
            ae, authz_req, self.user_id, client_id=client_id, sub_type=sub_type
        )

    def _mint_token(self, token_class, grant, session_id, based_on=None, **kwargs):
        # Constructing an authorization code is now done
        return grant.mint_token(
            session_id=session_id,
            context=self.token_endpoint.upstream_get("context"),
            token_class=token_class,
            token_handler=self.session_manager.token_handler.handler[token_class],
            expires_at=utc_time_sans_frac() + 300,  # 5 minutes from now
            based_on=based_on,
            **kwargs
        )

    def _get_access_token(self, areq):
        session_id = self._create_session(areq)
        # Consent handling
        grant = self.token_endpoint.upstream_get("endpoint_context").authz(session_id, areq)
        self.session_manager[session_id] = grant
        # grant = self.session_manager[session_id]
        code = self._mint_token("authorization_code", grant, session_id)
        return self._mint_token("access_token", grant, session_id, code)

    def _get_refresh_token(self, areq):
        session_id = self._create_session(areq)
        # Consent handling
        grant = self.token_endpoint.upstream_get("endpoint_context").authz(session_id, areq)
        self.session_manager[session_id] = grant
        # grant = self.session_manager[session_id]
        code = self._mint_token("authorization_code", grant, session_id)
        return self._mint_token("refresh_token", grant, session_id, code)

    def test_parse_no_authn(self):
        access_token = self._get_access_token(AUTH_REQ)
        with pytest.raises(ClientAuthenticationError):
            self.revocation_endpoint.parse_request({"token": access_token.value})

    def test_parse_with_client_auth_in_req(self):
        access_token = self._get_access_token(AUTH_REQ)

        _context = self.revocation_endpoint.upstream_get("endpoint_context")
        _req = self.revocation_endpoint.parse_request(
            {
                "token": access_token.value,
                "client_id": "client_1",
                "client_secret": _context.cdb["client_1"]["client_secret"],
            }
        )

        assert isinstance(_req, TokenRevocationRequest)
        assert set(_req.keys()) == {"token", "client_id", "client_secret", 'authenticated'}

    def test_parse_with_wrong_client_authn(self):
        access_token = self._get_access_token(AUTH_REQ)

        _basic_token = "{}:{}".format(
            "client_1",
            self.revocation_endpoint.upstream_get("endpoint_context").cdb["client_1"][
                "client_secret"
            ],
        )
        _basic_token = as_unicode(base64.b64encode(as_bytes(_basic_token)))
        _basic_authz = "Basic {}".format(_basic_token)
        http_info = {"headers": {"authorization": _basic_authz}}

        with pytest.raises(ClientAuthenticationError):
            self.revocation_endpoint.parse_request(
                {"token": access_token.value}, http_info=http_info
            )

    def test_process_request(self):
        access_token = self._get_access_token(AUTH_REQ)

        _req = self.revocation_endpoint.parse_request(
            {
                "token": access_token.value,
                "client_id": "client_1",
                "client_secret": self.revocation_endpoint.upstream_get("endpoint_context").cdb[
                    "client_1"
                ]["client_secret"],
            }
        )
        _resp = self.revocation_endpoint.process_request(_req)
        assert _resp
        assert set(_resp.keys()) == {"response_args"}

    def test_do_response(self):
        access_token = self._get_access_token(AUTH_REQ)

        _req = self.revocation_endpoint.parse_request(
            {
                "token": access_token.value,
                "client_id": "client_1",
                "client_secret": self.revocation_endpoint.upstream_get("endpoint_context").cdb[
                    "client_1"
                ]["client_secret"],
            }
        )
        _resp = self.revocation_endpoint.process_request(_req)
        msg_info = self.revocation_endpoint.do_response(request=_req, **_resp)
        assert isinstance(msg_info, dict)
        assert set(msg_info.keys()) == {"response", "http_headers"}
        assert msg_info["http_headers"] == [
            ("Content-type", "application/json; charset=utf-8"),
            ("Pragma", "no-cache"),
            ("Cache-Control", "no-store"),
        ]

    def test_do_response_no_token(self):
        # access_token = self._get_access_token(AUTH_REQ)
        _context = self.revocation_endpoint.upstream_get("endpoint_context")
        _req = self.revocation_endpoint.parse_request(
            {
                "client_id": "client_1",
                "client_secret": _context.cdb["client_1"]["client_secret"],
            }
        )
        _resp = self.revocation_endpoint.process_request(_req)
        assert "error" in _resp

    def test_access_token(self):
        access_token = self._get_access_token(AUTH_REQ)
        assert access_token.revoked is False
        _context = self.revocation_endpoint.upstream_get("endpoint_context")
        _req = self.revocation_endpoint.parse_request(
            {
                "token": access_token.value,
                "client_id": "client_1",
                "client_secret": _context.cdb["client_1"]["client_secret"],
            }
        )
        _resp = self.revocation_endpoint.process_request(_req)
        assert "response_args" in _resp
        assert access_token.revoked

    def test_access_token_per_client(self):

        def custom_token_revocation_policy(token, session_info, **kwargs):
            _token = token
            _token.revoke()
            response_args = {"response_args": {"type": "custom"}}
            return TokenRevocationResponse(**response_args)

        access_token = self._get_access_token(AUTH_REQ)
        assert access_token.revoked is False
        _context = self.revocation_endpoint.upstream_get("endpoint_context")
        _context.cdb["client_1"]["token_revocation"] = {
            "token_types_supported": [
                "access_token",
            ],
            "policy": {
                "": {
                    "callable": validate_token_revocation_policy,
                },
                "access_token": {
                    "callable": custom_token_revocation_policy,
                }
            },
        }
        _req = self.revocation_endpoint.parse_request(
            {
                "token": access_token.value,
                "client_id": "client_1",
                "client_secret": _context.cdb["client_1"]["client_secret"],
            }
        )
        _resp = self.revocation_endpoint.process_request(_req)
        assert "response_args" in _resp
        assert "type" in _resp["response_args"]
        assert _resp["response_args"]["type"] == "custom"
        assert access_token.revoked

    def test_missing_token_policy_per_client(self):

        def custom_token_revocation_policy(token, session_info, **kwargs):
            _token = token
            _token.revoke()
            response_args = {"response_args": {"type": "custom"}}
            return TokenRevocationResponse(**response_args)

        access_token = self._get_access_token(AUTH_REQ)
        assert access_token.revoked is False
        _context = self.revocation_endpoint.upstream_get("endpoint_context")
        _context.cdb["client_1"]["token_revocation"] = {
            "token_types_supported": [
                "access_token",
            ],
            "policy": {
                "": {
                    "callable": validate_token_revocation_policy,
                },
                "refresh_token": {
                    "callable": custom_token_revocation_policy,
                }
            },
        }
        _req = self.revocation_endpoint.parse_request(
            {
                "token": access_token.value,
                "client_id": "client_1",
                "client_secret": _context.cdb["client_1"]["client_secret"],
            }
        )
        _resp = self.revocation_endpoint.process_request(_req)
        assert "response_args" in _resp
        assert access_token.revoked

    def test_code(self):
        session_id = self._create_session(AUTH_REQ)

        # Apply consent
        grant = self.token_endpoint.upstream_get("endpoint_context").authz(session_id, AUTH_REQ)
        self.session_manager[session_id] = grant

        code = self._mint_token("authorization_code", grant, session_id)
        assert code.revoked is False
        _context = self.revocation_endpoint.upstream_get("endpoint_context")

        _req = self.revocation_endpoint.parse_request(
            {
                "token": code.value,
                "client_id": "client_1",
                "client_secret": _context.cdb["client_1"]["client_secret"],
            }
        )
        _resp = self.revocation_endpoint.process_request(_req)
        assert "response_args" in _resp
        assert code.revoked

    def test_refresh_token(self):
        refresh_token = self._get_refresh_token(AUTH_REQ)
        assert refresh_token.revoked is False
        _context = self.revocation_endpoint.upstream_get("endpoint_context")
        _req = self.revocation_endpoint.parse_request(
            {
                "token": refresh_token.value,
                "client_id": "client_1",
                "client_secret": _context.cdb["client_1"]["client_secret"],
            }
        )
        _resp = self.revocation_endpoint.process_request(_req)
        assert "response_args" in _resp
        assert refresh_token.revoked

    def test_expired_access_token(self):
        access_token = self._get_access_token(AUTH_REQ)
        access_token.expires_at = utc_time_sans_frac() - 1000

        _context = self.revocation_endpoint.upstream_get("endpoint_context")

        _req = self.revocation_endpoint.parse_request(
            {
                "token": access_token.value,
                "client_id": "client_1",
                "client_secret": _context.cdb["client_1"]["client_secret"],
            }
        )
        _resp = self.revocation_endpoint.process_request(_req)
        assert "response_args" in _resp

    def test_revoked_access_token(self):
        access_token = self._get_access_token(AUTH_REQ)
        access_token.revoked = True

        _context = self.revocation_endpoint.upstream_get("endpoint_context")

        _req = self.revocation_endpoint.parse_request(
            {
                "token": access_token.value,
                "client_id": "client_1",
                "client_secret": _context.cdb["client_1"]["client_secret"],
            }
        )
        _resp = self.revocation_endpoint.process_request(_req)
        assert "response_args" in _resp

    def test_unsupported_token_type(self):
        self.revocation_endpoint.token_types_supported = ["access_token"]
        session_id = self._create_session(AUTH_REQ)

        # Apply consent
        grant = self.token_endpoint.upstream_get("endpoint_context").authz(session_id, AUTH_REQ)
        self.session_manager[session_id] = grant

        code = self._mint_token("authorization_code", grant, session_id)
        assert code.revoked is False
        _context = self.revocation_endpoint.upstream_get("endpoint_context")

        _req = self.revocation_endpoint.parse_request(
            {
                "token": code.value,
                "client_id": "client_1",
                "client_secret": _context.cdb["client_1"]["client_secret"],
            }
        )
        _resp = self.revocation_endpoint.process_request(_req)
        err_dscr = (
            "The authorization server does not support the revocation of "
            "the presented token type. That is, the client tried to revoke an access "
            "token on a server not supporting this feature."
        )
        assert "error" in _resp
        assert _resp.to_dict() == {
            "error": "unsupported_token_type",
            "error_description": err_dscr,
        }
        assert code.revoked is False

    def test_unsupported_token_type_per_client(self):
        _context = self.revocation_endpoint.upstream_get("endpoint_context")
        _context.cdb["client_1"]["token_revocation"] = {
            "token_types_supported": [
                "refresh_token",
            ],
        }
        session_id = self._create_session(AUTH_REQ)

        # Apply consent
        grant = self.token_endpoint.upstream_get("endpoint_context").authz(session_id, AUTH_REQ)
        self.session_manager[session_id] = grant

        code = self._mint_token("authorization_code", grant, session_id)
        assert code.revoked is False
        _context = self.revocation_endpoint.upstream_get("endpoint_context")

        _req = self.revocation_endpoint.parse_request(
            {
                "token": code.value,
                "client_id": "client_1",
                "client_secret": _context.cdb["client_1"]["client_secret"],
            }
        )
        _resp = self.revocation_endpoint.process_request(_req)
        err_dscr = (
            "The authorization server does not support the revocation of "
            "the presented token type. That is, the client tried to revoke an access "
            "token on a server not supporting this feature."
        )
        assert "error" in _resp
        assert _resp.to_dict() == {
            "error": "unsupported_token_type",
            "error_description": err_dscr,
        }
        assert code.revoked is False
