import os

import pytest

from idpyoidc.message.oidc import AuthorizationRequest
from idpyoidc.server import Server
from idpyoidc.server.authn_event import create_authn_event
from tests import CRYPT_CONFIG

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

AREQ = AuthorizationRequest(
    response_type="code",
    client_id="client_1",
    redirect_uri="http://example.com/authz",
    scope=["openid"],
    state="state000",
    nonce="nonce",
)

AREQ_2 = AuthorizationRequest(
    response_type="code",
    client_id="client_1",
    redirect_uri="http://example.com/authz",
    scope=["openid", "address", "email"],
    state="state000",
    nonce="nonce",
    claims={"id_token": {"nickname": None}},
)

AREQ_3 = AuthorizationRequest(
    response_type="code",
    client_id="client_1",
    redirect_uri="http://example.com/authz",
    scope=["openid", "address", "email"],
    state="state000",
    nonce="nonce",
    claims={
        "id_token": {"nickname": None},
        "userinfo": {"name": None, "email": None, "email_verified": None},
    },
)

conf = {
    "issuer": "https://example.com/",
    "template_dir": "template",
    "keys": {"uri_path": "static/jwks.json", "key_defs": KEYDEFS, "read_only": True},
    "endpoint": {
        "authorization_endpoint": {
            "path": "authorization",
            "class": "idpyoidc.server.oidc.authorization.Authorization",
            "kwargs": {},
        },
        "token_endpoint": {
            "path": "token",
            "class": "idpyoidc.server.oidc.token.Token",
            "kwargs": {},
        },
        "userinfo_endpoint": {
            "path": "userinfo",
            "class": "idpyoidc.server.oidc.userinfo.UserInfo",
            "kwargs": {},
        },
        "introspection_endpoint": {
            "path": "introspection",
            "class": "idpyoidc.server.oauth2.introspection.Introspection",
            "kwargs": {},
        },
    },
    "token_handler_args": {
        "jwks_def": {
            "private_path": "private/token_jwks.json",
            "read_only": False,
            "key_defs": [{"type": "oct", "bytes": "24", "use": ["enc"], "kid": "code"}],
        },
        "code": {"kwargs": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}}},
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
        "id_token": {"class": "idpyoidc.server.token.id_token.IDToken", "kwargs": {}},
    },
    "userinfo": {
        "class": "idpyoidc.server.user_info.UserInfo",
        "kwargs": {"db_file": full_path("users.json")},
    },
    "claims_interface": {"class": "idpyoidc.server.session.claims.ClaimsInterface", "kwargs": {}},
    "session_params": {
        "encrypter": {
            "kwargs": {
                "keys": {
                    "key_defs": [
                        {"type": "OCT", "use": ["enc"], "kid": "password"},
                        {"type": "OCT", "use": ["enc"], "kid": "salt"},
                    ]
                },
                "iterations": 1,
            }
        }
    },
}

USER_ID = "diana"


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_idtoken(self):
        self.server = Server(conf)
        # self.endpoint_context = EndpointContext(conf=conf, upstream_get=self.upstream_get)
        self.endpoint_context = self.server.endpoint_context
        self.endpoint_context.cdb["client_1"] = {
            "client_secret": "hemligtochintekort",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "token_endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token", "code id_token", "id_token"],
            "add_claims": {
                "always": {},
            },
            "allowed_scopes": ["openid", "profile", "email", "address", "phone", "offline_access"]
        }
        self.server.get_attribute('keyjar').add_symmetric("client_1", "hemligtochintekort",
                                                          ["sig", "enc"])
        self.claims_interface = self.endpoint_context.claims_interface

        self.user_id = USER_ID

    def _create_session(self, auth_req, sub_type="public", sector_identifier=""):
        if sector_identifier:
            authz_req = auth_req.copy()
            authz_req["sector_identifier_uri"] = sector_identifier
        else:
            authz_req = auth_req

        client_id = authz_req["client_id"]
        ae = create_authn_event(self.user_id)
        return self.endpoint_context.session_manager.create_session(
            ae, authz_req, self.user_id, client_id=client_id, sub_type=sub_type
        )

    def test_authorization_request_id_token_claims(self):
        claims = self.claims_interface.authorization_request_claims(AREQ, "id_token")
        assert claims == {}

    def test_authorization_request_id_token_claims_2(self):
        claims = self.claims_interface.authorization_request_claims(AREQ_2, "id_token")
        assert claims
        assert set(claims.keys()) == {"nickname"}

    def test_authorization_request_userinfo_claims(self):
        claims = self.claims_interface.authorization_request_claims(AREQ, "userinfo")
        assert claims == {}

    def test_authorization_request_userinfo_claims_2(self):
        claims = self.claims_interface.authorization_request_claims(AREQ_2, "userinfo")
        assert claims == {}

    def test_authorization_request_userinfo_claims_3(self):
        claims = self.claims_interface.authorization_request_claims(AREQ_3, "userinfo")
        assert set(claims.keys()) == {"name", "email", "email_verified"}

    def test_get_claims_id_token_1(self):
        session_id = self._create_session(AREQ)
        self.endpoint_context.session_manager.token_handler["id_token"].kwargs = {
            "base_claims": {"email": None, "email_verified": None}
        }
        claims = self.claims_interface.get_claims(session_id, [], "id_token")
        assert set(claims.keys()) == {"email", "email_verified"}

    def test_get_claims_id_token_2(self):
        session_id = self._create_session(AREQ)
        self.endpoint_context.session_manager.token_handler["id_token"].kwargs = {
            "base_claims": {"email": None, "email_verified": None},
            "enable_claims_per_client": True,
        }
        self.endpoint_context.cdb["client_1"]["add_claims"]["always"]["id_token"] = [
            "name",
            "email",
        ]

        claims = self.claims_interface.get_claims(session_id, [], "id_token")
        assert set(claims.keys()) == {"name", "email", "email_verified"}

    def test_get_claims_id_token_3(self):
        session_id = self._create_session(AREQ)
        self.endpoint_context.session_manager.token_handler["id_token"].kwargs = {
            "base_claims": {"email": None, "email_verified": None},
            "enable_claims_per_client": True,
            "add_claims_by_scope": True,
        }
        self.endpoint_context.cdb["client_1"]["add_claims"]["always"]["id_token"] = [
            "name",
            "email",
        ]

        claims = self.claims_interface.get_claims(session_id, ["openid", "address"], "id_token")
        assert set(claims.keys()) == {
            "name",
            "email",
            "email_verified",
            "sub",
            "address",
        }

    def test_get_claims_id_token_and_userinfo(self):
        session_id = self._create_session(AREQ)
        self.endpoint_context.session_manager.token_handler["id_token"].kwargs = {
            "base_claims": {"email": None, "email_verified": None},
            "enable_claims_per_client": True,
            "add_claims_by_scope": True,
        }
        self.endpoint_context.cdb["client_1"]["add_claims"]["always"]["id_token"] = [
            "name",
            "email",
        ]
        self.endpoint_context.cdb["client_1"]["add_claims"]["always"]["userinfo"] = [
            "phone",
            "phone_verified",
        ]

        claims = self.claims_interface.get_claims(
            session_id, ["openid", "address"], "id_token", "userinfo"
        )
        assert set(claims.keys()) == {
            "name",
            "email",
            "email_verified",
            "sub",
            "address",
            "phone",
            "phone_verified",
        }

    def test_get_claims_access_token_3(self):
        _module = self.endpoint_context.session_manager.token_handler["access_token"]
        _module.kwargs = {
            "base_claims": {"email": None, "email_verified": None},
            "enable_claims_per_client": True,
            "add_claims_by_scope": True,
        }
        self.endpoint_context.cdb["client_1"]["add_claims"]["always"]["access_token"] = [
            "name",
            "email",
        ]

        session_id = self._create_session(AREQ)
        claims = self.claims_interface.get_claims(session_id, ["openid", "address"], "access_token")
        assert set(claims.keys()) == {
            "name",
            "email",
            "email_verified",
            "sub",
            "address",
        }
