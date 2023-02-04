import pytest

from idpyoidc.message.oidc import AuthorizationRequest
from idpyoidc.server import Server
from idpyoidc.server import do_endpoints
from idpyoidc.server.authn_event import create_authn_event
from idpyoidc.server.authz import Implicit
from idpyoidc.server.authz import factory
from idpyoidc.server.endpoint import Endpoint
from idpyoidc.server.session.grant import Grant
from tests import CRYPT_CONFIG
from tests import SESSION_PARAMS

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


class Endpoint_1(Endpoint):
    name = "userinfo"


conf = {
    "issuer": "https://example.com/",
    "template_dir": "template",
    "keys": {"uri_path": "static/jwks.json", "key_defs": KEYDEFS, "read_only": True},
    "endpoint": {
        "userinfo": {
            "path": "userinfo",
            "class": Endpoint_1,
            "kwargs": {
                "client_authn_method": [
                    "private_key_jwt",
                    "client_secret_jwt",
                    "client_secret_post",
                    "client_secret_basic",
                ]
            },
        }
    },
    "authz": {
        "class": "idpyoidc.server.authz.AuthzHandling",
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
                    "refresh_token": {"supports_minting": ["access_token", "refresh_token"]},
                },
                "expires_in": 43200,
            }
        },
    },
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
        "id_token": {"class": "idpyoidc.server.token.id_token.IDToken", "kwargs": {}},
    },
    "claims_interface": {"class": "idpyoidc.server.session.claims.ClaimsInterface", "kwargs": {}},
    "session_params": SESSION_PARAMS,
}

USER_ID = "diana"


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_idtoken(self):
        server = Server(conf)
        server.context.cdb["client_1"] = {
            "client_secret": "hemligtochintekort",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "token_endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token", "code id_token", "id_token"],
            "allowed_scopes": ["openid", "profile", "email", "address", "phone", "offline_access"]
        }
        server.get_attribute('keyjar').add_symmetric(
            "client_1", "hemligtochintekort", ["sig", "enc"]
        )
        server.endpoint = do_endpoints(conf, server.upstream_get)
        self.session_manager = server.context.session_manager
        self.user_id = USER_ID
        self.server = server
        self.authz = server.context.authz

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

    def test_usage_rules(self):
        _ = self._create_session(AREQ)
        _usage_rules = self.authz.usage_rules(AREQ["client_id"])
        assert set(_usage_rules.keys()) == {
            "authorization_code",
            "access_token",
            "refresh_token",
        }
        assert _usage_rules["authorization_code"]["supports_minting"] == [
            "access_token",
            "refresh_token",
            "id_token",
        ]
        assert _usage_rules["refresh_token"]["supports_minting"] == [
            "access_token",
            "refresh_token",
        ]

    def test_usage_rules_client(self):
        _ = self._create_session(AREQ)
        self.server.context.cdb["client_1"]["token_usage_rules"] = {
            "authorization_code": {"supports_minting": ["access_token", "id_token"]},
            "refresh_token": {},
        }
        _usage_rules = self.authz.usage_rules(AREQ["client_id"])
        assert set(_usage_rules.keys()) == {
            "authorization_code",
            "access_token",
            "refresh_token",
        }
        assert _usage_rules["authorization_code"]["supports_minting"] == [
            "access_token",
            "id_token",
        ]
        assert _usage_rules["refresh_token"] == {}

    def test_factory(self):
        _mod = factory("Implicit", upstream_get=self.server.upstream_get)
        assert isinstance(_mod, Implicit)

    def test_call(self):
        sid = self._create_session(AREQ)
        _grant = self.authz(sid, AREQ)
        assert isinstance(_grant, Grant)
