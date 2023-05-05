import os

import pytest
from cryptojwt.jwt import JWT
from cryptojwt.key_jar import init_key_jar

from idpyoidc.message.oidc import AccessTokenRequest
from idpyoidc.message.oidc import AuthorizationRequest
from idpyoidc.server import Server
from idpyoidc.server import user_info
from idpyoidc.server.authn_event import create_authn_event
from idpyoidc.server.authz import AuthzHandling
from idpyoidc.server.client_authn import verify_client
from idpyoidc.server.oauth2.introspection import Introspection
from idpyoidc.server.oidc.authorization import Authorization
from idpyoidc.server.oidc.provider_config import ProviderConfiguration
from idpyoidc.server.oidc.registration import Registration
from idpyoidc.server.oidc.session import Session
from idpyoidc.server.oidc.token import Token
from idpyoidc.server.scopes import SCOPE2CLAIMS
from idpyoidc.server.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from idpyoidc.time_util import utc_time_sans_frac
from tests import CRYPT_CONFIG
from tests import SESSION_PARAMS

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

ISSUER = "https://example.com/"

KEYJAR = init_key_jar(key_defs=KEYDEFS, issuer_id=ISSUER)
KEYJAR.import_jwks(KEYJAR.export_jwks(True, ISSUER), "")

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

TOKEN_REQ_DICT = TOKEN_REQ.to_dict()

BASEDIR = os.path.abspath(os.path.dirname(__file__))

MAP = {
    "authorization_code": "authorization_code",
    "access_token": "access_token",
    "refresh_token": "refresh_token",
    "id_token": "id_token",
}


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        conf = {
            "issuer": ISSUER,
            "httpc_params": {"verify": False, "timeout": 1},
            "capabilities": CAPABILITIES,
            "keys": {"uri_path": "jwks.json", "key_defs": KEYDEFS},
            "token_handler_args": {
                # "jwks_file": "private/token_jwks.json",
                "code": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
                "token": {
                    "class": "idpyoidc.server.token.jwt_token.JWTToken",
                    "kwargs": {
                        "lifetime": 3600,
                        "base_claims": {"eduperson_scoped_affiliation": None},
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
                "provider_config": {
                    "path": "{}/.well-known/openid-configuration",
                    "class": ProviderConfiguration,
                    "kwargs": {},
                },
                "registration": {
                    "path": "{}/registration",
                    "class": Registration,
                    "kwargs": {},
                },
                "authorization": {
                    "path": "{}/authorization",
                    "class": Authorization,
                    "kwargs": {},
                },
                "token": {"path": "{}/token", "class": Token, "kwargs": {}},
                "session": {"path": "{}/end_session", "class": Session},
                "introspection": {"path": "{}/introspection", "class": Introspection},
            },
            "client_authn": verify_client,
            "authentication": {
                "anon": {
                    "acr": INTERNETPROTOCOLPASSWORD,
                    "class": "idpyoidc.server.user_authn.user.NoAuthn",
                    "kwargs": {"user": "diana"},
                }
            },
            "template_dir": "template",
            "userinfo": {
                "class": user_info.UserInfo,
                "kwargs": {"db_file": full_path("users.json")},
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
                                "supports_minting": ["access_token", "refresh_token"],
                            },
                        },
                        "expires_in": 43200,
                    }
                },
            },
            "claims_interface": {
                "class": "idpyoidc.server.session.claims.ClaimsInterface",
                "kwargs": {},
            },
            "session_params": {"encrypter": SESSION_PARAMS},
        }
        self.server = Server(conf, keyjar=KEYJAR)
        self.context = self.server.context
        self.context.cdb["client_1"] = {
            "client_secret": "hemligt",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "token_endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token", "code id_token", "id_token"],
            "add_claims": {
                "always": {},
                "by_scope": {},
            },
            "allowed_scopes": ["openid", "profile", "email", "address", "phone", "offline_access"]
        }
        self.session_manager = self.context.session_manager
        self.user_id = "diana"
        self.endpoint = self.server.get_endpoint("session")

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
            context=self.context,
            token_class=token_class,
            token_handler=self.session_manager.token_handler.handler[token_class],
            expires_at=utc_time_sans_frac() + 300,  # 5 minutes from now
            based_on=based_on,
            **kwargs
        )

    def test_parse(self):
        session_id = self._create_session(AUTH_REQ)
        # apply consent
        grant = self.context.authz(session_id=session_id, request=AUTH_REQ)
        # grant = self.session_manager[session_id]
        code = self._mint_token("authorization_code", grant, session_id)
        access_token = self._mint_token(
            "access_token", grant, session_id, code, resources=[AUTH_REQ["client_id"]]
        )

        _verifier = JWT(self.server.keyjar)
        _info = _verifier.unpack(access_token.value)

        assert _info["token_class"] == "access_token"
        # assert _info["eduperson_scoped_affiliation"] == ["staff@example.org"]
        assert set(_info["aud"]) == {"client_1"}

    def test_info(self):
        session_id = self._create_session(AUTH_REQ)
        # apply consent
        grant = self.context.authz(session_id=session_id, request=AUTH_REQ)
        #
        code = self._mint_token("authorization_code", grant, session_id)
        access_token = self._mint_token("access_token", grant, session_id, code)

        _info = self.session_manager.token_handler.info(access_token.value)
        assert _info["token_class"] == "access_token"
        assert _info["sid"] == session_id

    @pytest.mark.parametrize("enable_claims_per_client", [True, False])
    def test_enable_claims_per_client(self, enable_claims_per_client):
        # Set up configuration
        self.context.cdb["client_1"]["add_claims"]["always"]["access_token"] = {
            "address": None
        }
        self.context.session_manager.token_handler.handler["access_token"].kwargs[
            "enable_claims_per_client"
        ] = enable_claims_per_client

        session_id = self._create_session(AUTH_REQ)
        # apply consent
        grant = self.context.authz(session_id=session_id, request=AUTH_REQ)
        #
        code = self._mint_token("authorization_code", grant, session_id)
        access_token = self._mint_token("access_token", grant, session_id, code)

        _jwt = JWT(key_jar=KEYJAR, iss="client_1")
        res = _jwt.unpack(access_token.value)
        assert enable_claims_per_client is ("address" in res)

    def test_is_expired(self):
        session_id = self._create_session(AUTH_REQ)
        grant = self.session_manager[session_id]
        code = self._mint_token("authorization_code", grant, session_id)
        access_token = self._mint_token("access_token", grant, session_id, code)

        assert access_token.is_active()
        # 4000 seconds in the future. Passed the lifetime.
        assert access_token.is_active(now=utc_time_sans_frac() + 4000) is False


class TestEndpointWebID(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        _scope2claims = SCOPE2CLAIMS.copy()
        _scope2claims.update({"webid": ["webid"]})
        conf = {
            "issuer": ISSUER,
            "httpc_params": {"verify": False, "timeout": 1},
            "capabilities": CAPABILITIES,
            "keys": {"uri_path": "jwks.json", "key_defs": KEYDEFS},
            "token_handler_args": {
                # "jwks_file": "private/token_jwks.json",
                "code": {"lifetime": 600, "crypt_config": CRYPT_CONFIG},
                "token": {
                    "class": "idpyoidc.server.token.jwt_token.JWTToken",
                    "kwargs": {
                        "lifetime": 3600,
                        "base_claims": {"eduperson_scoped_affiliation": None},
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
                "provider_config": {
                    "path": "{}/.well-known/openid-configuration",
                    "class": ProviderConfiguration,
                    "kwargs": {},
                },
                "registration": {
                    "path": "{}/registration",
                    "class": Registration,
                    "kwargs": {},
                },
                "authorization": {
                    "path": "{}/authorization",
                    "class": Authorization,
                    "kwargs": {},
                },
                "token": {"path": "{}/token", "class": Token, "kwargs": {}},
                "session": {"path": "{}/end_session", "class": Session},
                "introspection": {"path": "{}/introspection", "class": Introspection},
            },
            "client_authn": verify_client,
            "authentication": {
                "anon": {
                    "acr": INTERNETPROTOCOLPASSWORD,
                    "class": "idpyoidc.server.user_authn.user.NoAuthn",
                    "kwargs": {"user": "diana"},
                }
            },
            "template_dir": "template",
            "userinfo": {
                "class": user_info.UserInfo,
                "kwargs": {"db_file": full_path("users.json")},
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
                                "supports_minting": ["access_token", "refresh_token"],
                            },
                        },
                        "expires_in": 43200,
                    }
                },
            },
            "claims_interface": {
                "class": "idpyoidc.server.session.claims.ClaimsInterface",
                "kwargs": {},
            },
            "scopes_to_claims": _scope2claims,
            "session_params": SESSION_PARAMS,
        }
        self.server = Server(conf, keyjar=KEYJAR)
        self.context = self.server.context
        self.context.cdb["client_1"] = {
            "client_secret": "hemligt",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "token_endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token", "code id_token", "id_token"],
            "add_claims": {
                "always": {},
                "by_scope": {},
            },
            "allowed_scopes": ["openid", "profile", "email", "address", "phone", "offline_access", "webid"]
        }
        self.session_manager = self.context.session_manager
        self.user_id = "diana"
        self.endpoint = self.server.get_endpoint("session")

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
            context=self.context,
            token_class=token_class,
            token_handler=self.session_manager.token_handler.handler[token_class],
            expires_at=utc_time_sans_frac() + 300,  # 5 minutes from now
            based_on=based_on,
            **kwargs
        )

    def test_parse(self):
        _auth_req = AuthorizationRequest(
            client_id="client_1",
            redirect_uri="https://example.com/cb",
            scope=["openid", "webid"],
            state="STATE",
            response_type="code",
        )

        session_id = self._create_session(_auth_req)
        # apply consent
        grant = self.context.authz(session_id=session_id, request=_auth_req)
        # grant = self.session_manager[session_id]
        code = self._mint_token("authorization_code", grant, session_id)
        access_token = self._mint_token(
            "access_token", grant, session_id, code, resources=[_auth_req["client_id"]]
        )

        _verifier = JWT(self.server.keyjar)
        _info = _verifier.unpack(access_token.value)

        assert _info["token_class"] == "access_token"
        # assert _info["eduperson_scoped_affiliation"] == ["staff@example.org"]
        assert set(_info["aud"]) == {"client_1"}
        assert "webid" in _info

    def test_mint_with_aud(self):
        _auth_req = AuthorizationRequest(
            client_id="client_1",
            redirect_uri="https://example.com/cb",
            scope=["openid", "webid"],
            state="STATE",
            response_type="code",
        )

        session_id = self._create_session(_auth_req)
        # apply consent
        grant = self.context.authz(session_id=session_id, request=_auth_req)
        # grant = self.session_manager[session_id]
        code = self._mint_token("authorization_code", grant, session_id)
        access_token = self._mint_token(
            "access_token",
            grant,
            session_id,
            code,
            resources=[_auth_req["client_id"]],
            aud=["https://audience.example.com"],
        )

        _verifier = JWT(self.server.keyjar)
        _info = _verifier.unpack(access_token.value)

        assert _info["token_class"] == "access_token"
        # assert _info["eduperson_scoped_affiliation"] == ["staff@example.org"]
        assert set(_info["aud"]) == {"client_1", "https://audience.example.com"}
        assert "webid" in _info

    def test_mint_with_scope(self):
        _auth_req = AuthorizationRequest(
            client_id="client_1",
            redirect_uri="https://example.com/cb",
            scope=["openid", "webid"],
            state="STATE",
            response_type="code",
        )

        session_id = self._create_session(_auth_req)
        # apply consent
        grant = self.context.authz(session_id=session_id, request=_auth_req)
        # grant = self.session_manager[session_id]
        code = self._mint_token("authorization_code", grant, session_id)
        access_token = self._mint_token(
            "access_token",
            grant,
            session_id,
            code,
            scope=["openid", 'foobar'],
            aud=["https://audience.example.com"],
        )

        _verifier = JWT(self.server.keyjar)
        _info = _verifier.unpack(access_token.value)

        assert _info["token_class"] == "access_token"
        # assert _info["eduperson_scoped_affiliation"] == ["staff@example.org"]
        assert set(_info["aud"]) == {"https://audience.example.com"}
        assert _info["scope"] == "openid foobar"

    def test_mint_with_extra(self):
        _auth_req = AuthorizationRequest(
            client_id="client_1",
            redirect_uri="https://example.com/cb",
            scope=["openid", "webid"],
            state="STATE",
            response_type="code",
        )

        session_id = self._create_session(_auth_req)
        # apply consent
        grant = self.context.authz(session_id=session_id, request=_auth_req)
        # grant = self.session_manager[session_id]
        code = self._mint_token("authorization_code", grant, session_id)
        access_token = self._mint_token(
            "access_token",
            grant,
            session_id,
            code,
            claims=["name", "family_name"],
        )

        _verifier = JWT(self.server.keyjar)
        _info = _verifier.unpack(access_token.value)
        assert "name" in _info
        assert "family_name" in _info

    def test_token_handler(self):
        master_handler = self.session_manager.token_handler
        _handler = master_handler["access_token"]
        assert _handler
        _jwt = _handler(aud="https://example.org")
        _verifier = JWT(self.server.keyjar)
        _info = _verifier.unpack(_jwt)
        assert _info
