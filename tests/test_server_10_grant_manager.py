from cryptojwt.key_jar import build_keyjar
import pytest

from idpyoidc.server import EndpointContext
from idpyoidc.server.session.grant_manager import GrantManager
from idpyoidc.server.session.token import AccessToken
from idpyoidc.server.session.token import RefreshToken
from idpyoidc.server.token import handler
from idpyoidc.time_util import utc_time_sans_frac

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

CLI1 = "https://client1.example.com/"

KEYJAR = build_keyjar(KEYDEFS)


class TestGrantManager:
    @pytest.fixture(autouse=True)
    def create_grant_manager(self):
        conf = {
            "keys": {"key_defs": KEYDEFS, "uri_path": "static/jwks.json"},
            "claims_interface": {
                "class": "idpyoidc.server.session.claims.ClaimsInterface",
                "kwargs": {},
            },
            "session_params": {
                "function": "idpyoidc.server.session.grant_manager.create_grant_manager",
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
            "token_handler_args": {
                "jwks_def": {
                    "private_path": "private/token_jwks.json",
                    "read_only": False,
                    "key_defs": [{"type": "oct", "bytes": "24", "use": ["enc"], "kid": "code"}],
                },
                "code": {"kwargs": {"lifetime": 600}},
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
            }

        }

        self.endpoint_context = EndpointContext(
            conf=conf,
            server_get=self.server_get,
            keyjar=KEYJAR,

        )
        token_handler = handler.factory(server_get=self.server_get,
                                        **self.endpoint_context.th_args)

        self.endpoint_context.session_manager = GrantManager(handler=token_handler)
        self.grant_manager = self.endpoint_context.session_manager

    def server_get(self, *args):
        if args[0] == "endpoint_context":
            return self.endpoint_context


    def _create_grant(self, path, scope):
        return self.grant_manager.add_grant(path=path, scope=scope)


    def _mint_token(self, token_class, grant, grant_id, based_on=None):
        # Constructing an authorization code is now done
        return grant.mint_token(
            session_id=grant_id,
            endpoint_context=self.endpoint_context,
            token_class=token_class,
            token_handler=self.grant_manager.token_handler.handler[token_class],
            expires_at=utc_time_sans_frac() + 300,  # 5 minutes from now
            based_on=based_on,
        )

    def test_code_usage(self):
        grant_id = self._create_grant([CLI1], scope=["foo"])
        grant = self.grant_manager[grant_id]

        assert grant.issued_token == []
        assert grant.is_active() is True

        access_token = self._mint_token("access_token", grant, grant_id)
        assert isinstance(access_token, AccessToken)
        assert access_token.is_active()
        assert len(grant.issued_token) == 1

        refresh_token = self._mint_token("refresh_token", grant, grant_id)
        assert isinstance(refresh_token, RefreshToken)
        assert refresh_token.is_active()
        assert len(grant.issued_token) == 2

        grant.revoke_token(access_token.value)
        grant.revoke_token(refresh_token.value)

        assert access_token.revoked is True
        assert refresh_token.revoked is True

    def test_check_grant(self):
        grant_id = self.grant_manager.add_grant(
            path=["client_1"],
            scope=["openid", "phoe"],
        )

        _grant_info = self.grant_manager.branch_info(grant_id, "grant")
        grant = _grant_info["grant"]
        assert grant.scope == ["openid", "phoe"]

        _grant = self.grant_manager.get(["client_1", grant.id])
        assert _grant.scope == ["openid", "phoe"]

# def test_find_token(self):
#     grant_id = self.grant_manager.create_grant(
#         authn_event=self.authn_event,
#         auth_req=AUTH_REQ,
#         user_id="diana",
#         client_id="client_1",
#     )
#
#     _info = self.grant_manager.get_grant_info(grant_id=grant_id, grant=True)
#     grant = _info["grant"]
#
#     code = self._mint_token("authorization_code", grant, grant_id)
#     access_token = self._mint_token("access_token", grant, grant_id, code)
#
#     _grant_id = self.grant_manager.encrypted_grant_id("diana", "client_1", grant.id)
#     _token = self.grant_manager.find_token(_grant_id, access_token.value)
#
#     assert _token.token_class == "access_token"
#     assert _token.id == access_token.id
#
# def test_get_authentication_event(self):
#     grant_id = self.grant_manager.create_grant(
#         authn_event=self.authn_event,
#         auth_req=AUTH_REQ,
#         user_id="diana",
#         # test taking the client_id from the authn request
#         # client_id="client_1",
#     )
#
#     _info = self.grant_manager.get_grant_info(grant_id, authentication_event=True)
#     authn_event = _info["authentication_event"]
#
#     assert isinstance(authn_event, AuthnEvent)
#     assert authn_event["uid"] == "uid"
#     assert authn_event["authn_info"] == "authn_class_ref"
#
#     # cover the remaining one ...
#     _info = self.grant_manager.get_grant_info(grant_id, authorization_request=True)
#
# def test_get_client_grant_info(self):
#     _grant_id = self.grant_manager.create_grant(
#         authn_event=self.authn_event,
#         auth_req=AUTH_REQ,
#         user_id="diana",
#         client_id="client_1",
#     )
#
#     csi = self.grant_manager.get_client_grant_info(_grant_id)
#
#     assert isinstance(csi, ClientSessionInfo)
#
# def test_get_general_grant_info(self):
#     _grant_id = self.grant_manager.create_grant(
#         authn_event=self.authn_event,
#         auth_req=AUTH_REQ,
#         user_id="diana",
#         client_id="client_1",
#     )
#
#     _grant_info = self.grant_manager.get_grant_info(_grant_id)
#
#     assert set(_grant_info.keys()) == {
#         "client_id",
#         "grant_id",
#         "grant_id",
#         "user_id",
#     }
#     assert _grant_info["user_id"] == "diana"
#     assert _grant_info["client_id"] == "client_1"
#
# def test_get_grant_info_by_token(self):
#     _grant_id = self.grant_manager.create_grant(
#         authn_event=self.authn_event,
#         auth_req=AUTH_REQ,
#         user_id="diana",
#         client_id="client_1",
#     )
#
#     grant = self.grant_manager.get_grant(_grant_id)
#     code = self._mint_token("authorization_code", grant, _grant_id)
#     _grant_info = self.grant_manager.get_grant_info_by_token(
#         code.value, handler_key="authorization_code"
#     )
#
#     assert set(_grant_info.keys()) == {
#         "client_id",
#         "grant_id",
#         "grant_id",
#         "user_id",
#     }
#     assert _grant_info["user_id"] == "diana"
#     assert _grant_info["client_id"] == "client_1"
#
# def test_token_usage_default(self):
#     _grant_id = self.grant_manager.create_grant(
#         authn_event=self.authn_event,
#         auth_req=AUTH_REQ,
#         user_id="diana",
#         client_id="client_1",
#     )
#     grant = self.grant_manager[_grant_id]
#
#     code = self._mint_token("authorization_code", grant, _grant_id)
#
#     assert code.usage_rules == {
#         "max_usage": 1,
#         "supports_minting": ["access_token", "refresh_token", "id_token"],
#     }
#
#     token = self._mint_token("access_token", grant, _grant_id, code)
#
#     assert token.usage_rules == {}
#
#     refresh_token = self._mint_token("refresh_token", grant, _grant_id, code)
#
#     assert refresh_token.usage_rules == {"supports_minting": ["access_token",
#     "refresh_token"]}
#
# def test_token_usage_grant(self):
#     _grant_id = self.grant_manager.create_grant(
#         authn_event=self.authn_event,
#         auth_req=AUTH_REQ,
#         user_id="diana",
#         client_id="client_1",
#     )
#     grant = self.grant_manager[_grant_id]
#     grant.usage_rules = {
#         "authorization_code": {
#             "max_usage": 1,
#             "supports_minting": ["access_token", "refresh_token", "id_token"],
#             "expires_in": 300,
#         },
#         "access_token": {"expires_in": 3600},
#         "refresh_token": {"supports_minting": ["access_token", "refresh_token", "id_token"]},
#     }
#
#     code = self._mint_token("authorization_code", grant, _grant_id)
#     assert code.usage_rules == {
#         "max_usage": 1,
#         "supports_minting": ["access_token", "refresh_token", "id_token"],
#         "expires_in": 300,
#     }
#
#     token = self._mint_token("access_token", grant, _grant_id, code)
#     assert token.usage_rules == {"expires_in": 3600}
#
#     refresh_token = self._mint_token("refresh_token", grant, _grant_id, code)
#     assert refresh_token.usage_rules == {
#         "supports_minting": ["access_token", "refresh_token", "id_token"]
#     }
#
# def test_token_usage_authz(self):
#     grant_config = {
#         "usage_rules": {
#             "authorization_code": {
#                 "supports_minting": ["access_token"],
#                 "max_usage": 1,
#                 "expires_in": 120,
#             },
#             "access_token": {"expires_in": 600},
#         },
#         "expires_in": 43200,
#     }
#
#     self.endpoint_context.authz = AuthzHandling(
#         self.server.get_endpoint_context, grant_config=grant_config
#     )
#
#     self.endpoint_context.cdb["client_1"] = {}
#
#     token_usage_rules = self.endpoint_context.authz.usage_rules("client_1")
#
#     _grant_id = self.grant_manager.create_grant(
#         authn_event=self.authn_event,
#         auth_req=AUTH_REQ,
#         user_id="diana",
#         client_id="client_1",
#         token_usage_rules=token_usage_rules,
#     )
#     grant = self.grant_manager[_grant_id]
#
#     code = self._mint_token("authorization_code", grant, _grant_id)
#     assert code.usage_rules == {
#         "max_usage": 1,
#         "supports_minting": ["access_token"],
#         "expires_in": 120,
#     }
#
#     token = self._mint_token("access_token", grant, _grant_id, code)
#     assert token.usage_rules == {"expires_in": 600}
#
#     # Only allowed to mint access_tokens using the authorization_code
#     with pytest.raises(MintingNotAllowed):
#         self._mint_token("refresh_token", grant, _grant_id, code)
#
# def test_token_usage_client_config(self):
#     grant_config = {
#         "usage_rules": {
#             "authorization_code": {
#                 "supports_minting": ["access_token"],
#                 "max_usage": 1,
#                 "expires_in": 120,
#             },
#             "access_token": {"expires_in": 600},
#             "refresh_token": {},
#         },
#         "expires_in": 43200,
#     }
#
#     self.endpoint_context.authz = AuthzHandling(
#         self.server.get_endpoint_context, grant_config=grant_config
#     )
#
#     # Change expiration time for the code and allow refresh tokens for this
#     # specific client
#     self.endpoint_context.cdb["client_1"] = {
#         "token_usage_rules": {
#             "authorization_code": {
#                 "expires_in": 600,
#                 "supports_minting": ["access_token", "refresh_token"],
#             },
#             "refresh_token": {"supports_minting": ["access_token"]},
#         }
#     }
#
#     token_usage_rules = self.endpoint_context.authz.usage_rules("client_1")
#
#     _grant_id = self.grant_manager.create_grant(
#         authn_event=self.authn_event,
#         auth_req=AUTH_REQ,
#         user_id="diana",
#         client_id="client_1",
#         token_usage_rules=token_usage_rules,
#     )
#     grant = self.grant_manager[_grant_id]
#
#     code = self._mint_token("authorization_code", grant, _grant_id)
#     assert code.usage_rules == {
#         "max_usage": 1,
#         "supports_minting": ["access_token", "refresh_token"],
#         "expires_in": 600,
#     }
#
#     token = self._mint_token("access_token", grant, _grant_id, code)
#     assert token.usage_rules == {"expires_in": 600}
#
#     refresh_token = self._mint_token("refresh_token", grant, _grant_id, code)
#     assert refresh_token.usage_rules == {"supports_minting": ["access_token"]}
#
#     # Test with another client
#
#     self.endpoint_context.cdb["client_2"] = {}
#
#     token_usage_rules = self.endpoint_context.authz.usage_rules("client_2")
#
#     _grant_id = self.grant_manager.create_grant(
#         authn_event=self.authn_event,
#         auth_req=AUTH_REQ,
#         user_id="diana",
#         client_id="client_2",
#         token_usage_rules=token_usage_rules,
#     )
#     grant = self.grant_manager[_grant_id]
#     code = self._mint_token("authorization_code", grant, _grant_id)
#     # Not allowed to mint refresh token for this client
#     with pytest.raises(MintingNotAllowed):
#         self._mint_token("refresh_token", grant, _grant_id, code)
#
#     # test revoke token
#     self.grant_manager.revoke_token(_grant_id, code.value, recursive=1)
#
# def test_authentication_events(self):
#     token_usage_rules = self.endpoint_context.authz.usage_rules("client_1")
#     _grant_id = self.grant_manager.create_grant(
#         authn_event=self.authn_event,
#         auth_req=AUTH_REQ,
#         user_id="diana",
#         client_id="client_1",
#         token_usage_rules=token_usage_rules,
#     )
#     res = self.grant_manager.get_authentication_events(_grant_id)
#
#     assert isinstance(res[0], AuthnEvent)
#
#     res = self.grant_manager.get_authentication_events(user_id="diana", client_id="client_1")
#
#     assert isinstance(res[0], AuthnEvent)
#
#     try:
#         self.grant_manager.get_authentication_events(
#             user_id="diana",
#         )
#     except AttributeError:
#         pass
#     else:
#         raise Exception("get_authentication_events MUST return a list of AuthnEvent")
#
# def test_user_info(self):
#     token_usage_rules = self.endpoint_context.authz.usage_rules("client_1")
#     _grant_id = self.grant_manager.create_grant(
#         authn_event=self.authn_event,
#         auth_req=AUTH_REQ,
#         user_id="diana",
#         client_id="client_1",
#         token_usage_rules=token_usage_rules,
#     )
#     self.grant_manager.get_user_info("diana")
#
# def test_revoke_client_grant(self):
#     token_usage_rules = self.endpoint_context.authz.usage_rules("client_1")
#     _grant_id = self.grant_manager.create_grant(
#         authn_event=self.authn_event,
#         auth_req=AUTH_REQ,
#         user_id="diana",
#         client_id="client_1",
#         token_usage_rules=token_usage_rules,
#     )
#     self.grant_manager.revoke_client_grant(_grant_id)
#
# def test_revoke_grant(self):
#     token_usage_rules = self.endpoint_context.authz.usage_rules("client_1")
#     _grant_id = self.grant_manager.create_grant(
#         authn_event=self.authn_event,
#         auth_req=AUTH_REQ,
#         user_id="diana",
#         client_id="client_1",
#         token_usage_rules=token_usage_rules,
#     )
#     grant = self.grant_manager[_grant_id]
#     self.grant_manager.revoke_grant(_grant_id)
#
# def test_revoke_dependent(self):
#     token_usage_rules = self.endpoint_context.authz.usage_rules("client_1")
#     _grant_id = self.grant_manager.create_grant(
#         authn_event=self.authn_event,
#         auth_req=AUTH_REQ,
#         user_id="diana",
#         client_id="client_1",
#         token_usage_rules=token_usage_rules,
#     )
#     grant = self.grant_manager[_grant_id]
#
#     code = self._mint_token("authorization_code", grant, _grant_id)
#     token = self._mint_token("access_token", grant, _grant_id, code)
#
#     grant.remove_inactive_token = True
#     grant.revoke_token(value=token.value)
#     assert len(grant.issued_token) == 1
#     assert grant.issued_token[0].token_class == "authorization_code"
#
# def test_grants(self):
#     token_usage_rules = self.endpoint_context.authz.usage_rules("client_1")
#     _grant_id = self.grant_manager.create_grant(
#         authn_event=self.authn_event,
#         auth_req=AUTH_REQ,
#         user_id="diana",
#         client_id="client_1",
#         token_usage_rules=token_usage_rules,
#     )
#     res = self.grant_manager.grants(_grant_id)
#
#     assert isinstance(res, list)
#
#     res = self.grant_manager.grants(user_id="diana", client_id="client_1")
#
#     assert isinstance(res, list)
#
#     try:
#         self.grant_manager.grants(
#             user_id="diana",
#         )
#     except AttributeError:
#         pass
#     else:
#         raise Exception("get_authentication_events MUST return a list of AuthnEvent")
#
#     # and now cove add_grant
#     grant = self.grant_manager[_grant_id]
#     grant_kwargs = grant.parameter
#     for i in ("not_before", "used"):
#         grant_kwargs.pop(i)
#     self.grant_manager.add_grant("diana", "client_1", **grant_kwargs)
#
# def test_find_latest_idtoken(self):
#     token_usage_rules = self.endpoint_context.authz.usage_rules("client_1")
#     _grant_id = self.grant_manager.create_grant(
#         authn_event=self.authn_event,
#         auth_req=AUTH_REQ,
#         user_id="diana",
#         client_id="client_1",
#         token_usage_rules=token_usage_rules,
#     )
#     grant = self.grant_manager[_grant_id]
#
#     code = self._mint_token("authorization_code", grant, _grant_id)
#     id_token_1 = self._mint_token("id_token", grant, _grant_id)
#
#     refresh_token = self._mint_token("refresh_token", grant, _grant_id, code)
#     id_token_2 = self._mint_token("id_token", grant, _grant_id, code)
#
#     _jwt1 = factory(id_token_1.value)
#     _jwt2 = factory(id_token_2.value)
#     assert _jwt1.jwt.payload()["sid"] == _jwt2.jwt.payload()["sid"]
#
#     assert id_token_1.grant_id == id_token_2.grant_id
#
#     idt = grant.last_issued_token_of_type("id_token")
#
#     assert idt.grant_id == id_token_2.grant_id
#
#     id_token_3 = self._mint_token("id_token", grant, _grant_id, refresh_token)
#
#     idt = grant.last_issued_token_of_type("id_token")
#
#     assert idt.grant_id == id_token_3.grant_id
