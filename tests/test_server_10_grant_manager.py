from cryptojwt.key_jar import build_keyjar
import pytest
from idpyoidc.server.session.info import SessionInfo

from idpyoidc.server.session.info import ClientSessionInfo

from idpyoidc.server import EndpointContext
from idpyoidc.server.session.grant import Grant
from idpyoidc.server.session.grant_manager import GrantManager
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

    @pytest.mark.parametrize(
        "path, node_type, node_info_class",
        [([CLI1],
          ["client", "grant"],
          {"client": ClientSessionInfo, "grant": Grant}),
         (["foo", CLI1],
          ["subject", "client", "grant"],
          {"subject": SessionInfo, "client": ClientSessionInfo, "grant": Grant}),
         ([CLI1, "foo", "bar"],
          ["subject", "other", "client", "grant"],
          {"subject": SessionInfo,
           "other": SessionInfo,
           "client": ClientSessionInfo,
           "grant": Grant})
         ],
    )
    def test_grant(self, path, node_type, node_info_class):
        self.grant_manager.node_type = node_type
        self.grant_manager.node_info_class = node_info_class
        grant_id = self._create_grant(path, scope=["foo"])
        grant = self.grant_manager[grant_id]
        assert grant

    @pytest.mark.parametrize(
        "path, node_type, node_info_class",
        [([CLI1],
          ["client", "grant"],
          {"client": ClientSessionInfo, "grant": Grant}),
         (["foo", CLI1],
          ["high", "client", "grant"],
          {"high": SessionInfo, "client": ClientSessionInfo, "grant": Grant}),
         ([CLI1, "foo", "bar"],
          ["client", "high", "hat", "grant"],
          {"client": ClientSessionInfo, "high": SessionInfo, "hat": SessionInfo, "grant": Grant})
         ],
    )
    def test_check_leaf(self, path, node_type, node_info_class):
        self.grant_manager.node_type = node_type
        self.grant_manager.node_info_class = node_info_class
        grant_id = self.grant_manager.add_grant(
            path=path,
            scope=["openid", "phoe"],
        )

        _grant_info = self.grant_manager.branch_info(grant_id, "grant")
        grant = _grant_info["grant"]
        assert grant.scope == ["openid", "phoe"]

        _new_path = path[:]
        _new_path.append(grant.id)
        _grant = self.grant_manager.get(_new_path)
        assert _grant.scope == ["openid", "phoe"]

    @pytest.mark.parametrize(
        "path, node_type, node_info_class",
        [([CLI1],
          ["client", "grant"],
          {"client": ClientSessionInfo, "grant": Grant}),
         (["foo", CLI1],
          ["subject", "client", "grant"],
          {"subject": SessionInfo, "client": ClientSessionInfo, "grant": Grant}),
         ([CLI1, "foo", "bar"],
          ["client", "subject", "object", "grant"],
          {
              "subject": SessionInfo,
              "object": SessionInfo,
              "client": ClientSessionInfo,
              "grant": Grant
          })
         ],
    )
    def test_branch_info(self, path, node_type, node_info_class):
        self.grant_manager.node_type = node_type
        self.grant_manager.node_info_class = node_info_class
        grant_id = self.grant_manager.add_grant(
            path=path,
            scope=["openid", "phoe"],
        )

        _branch_info = self.grant_manager.branch_info(grant_id)
        _keys = node_type[:]
        _id_keys = [f"{k}_id" for k in _keys]
        _keys.extend(_id_keys)

        assert set(_branch_info.keys()) == set(_keys)

    def test_get_grant_argument(self):
        self.grant_manager.node_type = ["client", "grant"]
        self.grant_manager.node_info_class = {"client": ClientSessionInfo, "grant": Grant}
        grant_id = self.grant_manager.add_grant(
            path=["client_1"],
            scope=["openid", "phoe"],
            foo="bar"
        )

        _val = self.grant_manager.get_grant_argument(grant_id, "foo")
        assert _val == "bar"

    def test_get_node_info(self):
        self.grant_manager.node_type = ["client", "grant"]
        self.grant_manager.node_info_class = {"client": ClientSessionInfo, "grant": Grant}
        grant_id = self.grant_manager.add_grant(
            path=["client_1"],
            scope=["openid", "phoe"],
            foo="bar"
        )

        _info_a = self.grant_manager.get_node_info(grant_id, level=0)
        _info_b = self.grant_manager.get_node_info(grant_id, node_type='client')
        assert _info_a == _info_b

    def test_get_subordinates(self):
        self.grant_manager.node_type = ["client", "grant"]
        self.grant_manager.node_info_class = {"client": ClientSessionInfo, "grant": Grant}
        grant_id_1 = self.grant_manager.add_grant(
            path=["client_1"],
            scope=["openid", "phoe"],
            foo="bar"
        )
        grant_id_2 = self.grant_manager.add_grant(
            path=["client_1"],
            scope=["openid", "other"]
        )

        subs = self.grant_manager.get_subordinates(["client_1"])
        assert len(subs) == 2
        assert isinstance(subs[0], Grant)
        assert isinstance(subs[1], Grant)
        assert subs[0] != subs[1]

    def test_get_grants(self):
        self.grant_manager.node_type = ["client", "intermediate", "grant"]
        self.grant_manager.node_info_class = {"client": ClientSessionInfo,
                                              "intermediate": SessionInfo,
                                              "grant": Grant}
        grant_id_1 = self.grant_manager.add_grant(
            path=["client_1", "other"],
            scope=["openid", "phoe"],
            foo="bar"
        )
        grant_id_2 = self.grant_manager.add_grant(
            path=["client_1", "other"],
            scope=["openid", "other"]
        )

        subs = self.grant_manager.grants(path=["client_1", "other"])
        assert len(subs) == 2
        assert isinstance(subs[0], Grant)
        assert isinstance(subs[1], Grant)
        assert subs[0] != subs[1]

    def test_revoke_sub_tree(self):
        self.grant_manager.node_type = ["client", "intermediate", "grant"]
        self.grant_manager.node_info_class = {"client": ClientSessionInfo,
                                              "intermediate": SessionInfo,
                                              "grant": Grant}
        grant_id_1 = self.grant_manager.add_grant(
            path=["client_1", "other"],
            scope=["openid", "phoe"],
            foo="bar"
        )
        grant_id_2 = self.grant_manager.add_grant(
            path=["client_1", "other"],
            scope=["openid", "other"]
        )

        self.grant_manager.revoke_sub_tree(branch_id=grant_id_1)

        grant_1 = self.grant_manager[grant_id_1]
        assert grant_1.revoked is True
        grant_2 = self.grant_manager[grant_id_2]
        assert grant_2.revoked is False

        grant_1.revoked = False
        self.grant_manager.revoke_sub_tree(branch_id=grant_id_1, level=1)

        grant_1 = self.grant_manager[grant_id_1]
        assert grant_1.revoked is True
        grant_2 = self.grant_manager[grant_id_2]
        assert grant_2.revoked is True

        _id, _node = self.grant_manager.get_node_info(grant_id_2, node_type="intermediate")
        assert _node.revoked is True

    def test_remove_branch(self):
        self.grant_manager.node_type = ["client", "intermediate", "grant"]
        self.grant_manager.node_info_class = {"client": ClientSessionInfo,
                                              "intermediate": SessionInfo,
                                              "grant": Grant}
        grant_id_1 = self.grant_manager.add_grant(
            path=["client_1", "other"],
            scope=["openid", "phoe"],
            foo="bar"
        )
        grant_id_2 = self.grant_manager.add_grant(
            path=["client_1", "other"],
            scope=["openid", "other"]
        )

        self.grant_manager.remove_branch(grant_id_2)

        with pytest.raises(KeyError):
            _ = self.grant_manager[grant_id_2]

        grant_1 = self.grant_manager[grant_id_1]
        assert grant_1.revoked is False
