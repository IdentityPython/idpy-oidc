import pytest
from cryptojwt.key_jar import build_keyjar

from idpyoidc.message.oidc import AuthorizationRequest
from idpyoidc.server import Server
from idpyoidc.server.authn_event import create_authn_event
from idpyoidc.server.session.grant import Grant
from idpyoidc.server.session.grant import find_token
from idpyoidc.server.session.grant import get_usage_rules
from idpyoidc.server.session.grant import remember_token
from idpyoidc.server.session.token import TOKEN_MAP
from idpyoidc.server.session.token import AuthorizationCode
from idpyoidc.server.session.token import SessionToken
from idpyoidc.server.token import DefaultToken
from idpyoidc.server.user_authn.authn_context import INTERNETPROTOCOLPASSWORD

from . import CRYPT_CONFIG
from . import full_path

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

KEYJAR = build_keyjar(KEYDEFS)

conf = {
    "issuer": "https://example.com/",
    "template_dir": "template",
    "keys": {"uri_path": "static/jwks.json", "key_defs": KEYDEFS, "read_only": True},
    "authentication": {
        "anon": {
            "acr": INTERNETPROTOCOLPASSWORD,
            "class": "idpyoidc.server.user_authn.user.NoAuthn",
            "kwargs": {"user": "diana"},
        }
    },
    "claims_interface": {"class": "idpyoidc.server.session.claims.ClaimsInterface", "kwargs": {}},
    "userinfo": {
        "class": "idpyoidc.server.user_info.UserInfo",
        "kwargs": {"db_file": full_path("users.json")},
    },
    "session_params": {
        "encrypter": CRYPT_CONFIG,
        "remove_inactive_token": True,
        "remember_token": {
            "function": remember_token,
        },
    },
}

USER_ID = "diana"

AREQ = AuthorizationRequest(
    response_type="code",
    client_id="client_1",
    redirect_uri="http://example.com/authz",
    scope=["openid"],
    state="state000",
    nonce="nonce",
)


def test_access_code():
    token = AuthorizationCode("authorization_code", value="ABCD")
    assert token.issued_at
    assert token.token_class == "authorization_code"
    assert token.value == "ABCD"

    token.register_usage()
    #  max_usage == 1
    assert token.max_usage_reached() is True


def test_access_token():
    code = AuthorizationCode("authorization_code", value="ABCD")
    token = SessionToken(
        "access_token", value="1234", based_on=code.id, usage_rules={"max_usage": 2}
    )
    assert token.issued_at
    assert token.token_class == "access_token"
    assert token.value == "1234"

    token.register_usage()
    #  max_usage - undefined
    assert token.max_usage_reached() is False

    token.register_usage()
    assert token.max_usage_reached() is True

    t = find_token([code, token], token.based_on)
    assert t.value == "ABCD"

    token.revoked = True
    assert token.revoked is True


TOKEN_HANDLER = {
    "authorization_code": DefaultToken("authorization_code", typ="A"),
    "access_token": DefaultToken("access_token", typ="T"),
    "refresh_token": DefaultToken("refresh_token", typ="R"),
}


class MyToken(SessionToken):
    pass


class TestGrant:
    @pytest.fixture(autouse=True)
    def create_session_manager(self):
        self.server = Server(conf=conf)
        self.context = self.server.get_context()

    def _create_session(self, auth_req, sub_type="public", sector_identifier=""):
        if sector_identifier:
            authz_req = auth_req.copy()
            authz_req["sector_identifier_uri"] = sector_identifier
        else:
            authz_req = auth_req

        client_id = authz_req["client_id"]
        ae = create_authn_event(USER_ID)
        return self.server.context.session_manager.create_session(
            ae, authz_req, USER_ID, client_id=client_id, sub_type=sub_type
        )

    def test_mint_token(self):
        session_id = self._create_session(AREQ)
        session_info = self.context.session_manager.get_session_info(
            session_id=session_id, grant=True
        )
        grant = session_info["grant"]

        code = grant.mint_token(
            session_id,
            context=self.context,
            token_class="authorization_code",
            token_handler=TOKEN_HANDLER["authorization_code"],
        )

        access_token = grant.mint_token(
            session_id,
            context=self.context,
            token_class="access_token",
            token_handler=TOKEN_HANDLER["access_token"],
            based_on=code,
            scope=["openid", "foo", "bar"],
        )

        assert access_token.scope == ["openid", "foo", "bar"]

    def test_grant(self):
        session_id = self._create_session(AREQ)
        session_info = self.context.session_manager.get_session_info(
            session_id=session_id, grant=True
        )
        grant = session_info["grant"]
        code = grant.mint_token(
            session_id,
            context=self.context,
            token_class="authorization_code",
            token_handler=TOKEN_HANDLER["authorization_code"],
        )

        access_token = grant.mint_token(
            session_id,
            context=self.context,
            token_class="access_token",
            token_handler=TOKEN_HANDLER["access_token"],
            based_on=code,
        )

        refresh_token = grant.mint_token(
            session_id,
            context=self.context,
            token_class="refresh_token",
            token_handler=TOKEN_HANDLER["refresh_token"],
            based_on=code,
        )

        grant.revoke_token()
        assert grant.issued_token == []

    def test_get_token(self):
        session_id = self._create_session(AREQ)
        session_info = self.context.session_manager.get_session_info(
            session_id=session_id, grant=True
        )
        grant = session_info["grant"]
        code = grant.mint_token(
            session_id,
            context=self.context,
            token_class="authorization_code",
            token_handler=TOKEN_HANDLER["authorization_code"],
        )

        access_token = grant.mint_token(
            session_id,
            context=self.context,
            token_class="access_token",
            token_handler=TOKEN_HANDLER["access_token"],
            based_on=code,
            scope=["openid", "foo", "bar"],
        )

        _code = grant.get_token(code.value)
        assert _code.id == code.id

        _token = grant.get_token(access_token.value)
        assert _token.id == access_token.id
        assert set(_token.scope) == {"openid", "foo", "bar"}

    def test_grant_revoked_based_on(self):
        session_id = self._create_session(AREQ)
        session_info = self.context.session_manager.get_session_info(
            session_id=session_id, grant=True
        )
        grant = session_info["grant"]
        code = grant.mint_token(
            session_id,
            context=self.context,
            token_class="authorization_code",
            token_handler=TOKEN_HANDLER["authorization_code"],
        )

        access_token = grant.mint_token(
            session_id,
            context=self.context,
            token_class="access_token",
            token_handler=TOKEN_HANDLER["access_token"],
            based_on=code,
        )

        refresh_token = grant.mint_token(
            session_id,
            context=self.context,
            token_class="refresh_token",
            token_handler=TOKEN_HANDLER["refresh_token"],
            based_on=code,
        )

        code.register_usage()
        if code.max_usage_reached():
            grant.revoke_token(based_on=code.value)

        assert code.is_active() is False
        assert access_token.is_active() is False
        assert refresh_token.is_active() is False

    def test_revoke(self):
        session_id = self._create_session(AREQ)
        session_info = self.context.session_manager.get_session_info(
            session_id=session_id, grant=True
        )
        grant = session_info["grant"]
        code = grant.mint_token(
            session_id,
            context=self.context,
            token_class="authorization_code",
            token_handler=TOKEN_HANDLER["authorization_code"],
        )

        access_token = grant.mint_token(
            session_id,
            context=self.context,
            token_class="access_token",
            token_handler=TOKEN_HANDLER["access_token"],
            based_on=code,
        )

        grant.revoke_token(based_on=code.value)

        assert code.is_active() is True
        assert access_token.is_active() is False

        access_token_2 = grant.mint_token(
            session_id,
            context=self.context,
            token_class="access_token",
            token_handler=TOKEN_HANDLER["access_token"],
            based_on=code,
        )

        grant.revoke_token(value=code.value, recursive=True)

        assert code.is_active() is False
        assert access_token_2.is_active() is False

    def test_json_conversion(self):
        session_id = self._create_session(AREQ)
        session_info = self.context.session_manager.get_session_info(
            session_id=session_id, grant=True
        )
        grant = session_info["grant"]
        code = grant.mint_token(
            session_id,
            context=self.context,
            token_class="authorization_code",
            token_handler=TOKEN_HANDLER["authorization_code"],
        )

        grant.mint_token(
            session_id,
            context=self.context,
            token_class="access_token",
            token_handler=TOKEN_HANDLER["access_token"],
            based_on=code,
        )

        _item = grant.dump()

        _grant_copy = Grant().load(_item)

        assert len(_grant_copy.issued_token) == 2

        tt = {"code": 0, "access_token": 0}
        for token in _grant_copy.issued_token:
            if token.token_class == "authorization_code":
                tt["code"] += 1
            if token.token_class == "access_token":
                tt["access_token"] += 1

        assert tt == {"code": 1, "access_token": 1}

    def test_json_no_token_map(self):
        session_id = self._create_session(AREQ)
        session_info = self.context.session_manager.get_session_info(
            session_id=session_id, grant=True
        )
        grant = session_info["grant"]
        grant.token_map = {}
        with pytest.raises(ValueError):
            grant.mint_token(
                session_id,
                context=self.context,
                token_class="authorization_code",
                token_handler=TOKEN_HANDLER["authorization_code"],
            )

    def test_json_custom_token_map(self):
        session_id = self._create_session(AREQ)
        session_info = self.context.session_manager.get_session_info(
            session_id=session_id, grant=True
        )
        grant = session_info["grant"]

        token_map = TOKEN_MAP.copy()
        token_map["my_token"] = MyToken
        grant.token_map = token_map
        code = grant.mint_token(
            session_id,
            context=self.context,
            token_class="authorization_code",
            token_handler=TOKEN_HANDLER["authorization_code"],
        )

        grant.mint_token(
            session_id,
            context=self.context,
            token_class="access_token",
            token_handler=TOKEN_HANDLER["access_token"],
            based_on=code,
        )

        grant.mint_token(
            session_id,
            context=self.context,
            token_class="my_token",
            token_handler=DefaultToken("my_token", typ="M"),
        )

        _jstr = grant.dump()

        _grant_copy = Grant(token_map=token_map).load(_jstr)

        assert len(_grant_copy.issued_token) == 3

        tt = {k: 0 for k, v in grant.token_map.items()}

        for token in _grant_copy.issued_token:
            for _type in tt.keys():
                if token.token_class == _type:
                    tt[_type] += 1

        assert tt == {
            "access_token": 1,
            "authorization_code": 1,
            "my_token": 1,
            "refresh_token": 0,
            "id_token": 0,
        }

    def test_get_spec(self):
        session_id = self._create_session(AREQ)
        session_info = self.context.session_manager.get_session_info(
            session_id=session_id, grant=True
        )
        grant = session_info["grant"]

        grant.scope = ["openid", "email", "address"]
        grant.claims = {"userinfo": {"given_name": None, "email": None}}
        grant.resources = ["https://api.example.com"]

        code = grant.mint_token(
            session_id,
            context=self.context,
            token_class="authorization_code",
            token_handler=TOKEN_HANDLER["authorization_code"],
        )

        access_token = grant.mint_token(
            session_id,
            context=self.context,
            token_class="access_token",
            token_handler=TOKEN_HANDLER["access_token"],
            based_on=code,
            scope=["openid", "email", "eduperson"],
            claims=["given_name", "eduperson_affiliation"],
        )

        spec = grant.get_spec(access_token)
        assert set(spec.keys()) == {"scope", "claims", "resources"}
        assert spec["scope"] == ["openid", "email", "eduperson"]
        assert spec["claims"] == {"eduperson_affiliation": None, "given_name": None}
        assert spec["resources"] == ["https://api.example.com"]

    def test_get_usage_rules(self):
        session_id = self._create_session(AREQ)
        session_info = self.context.session_manager.get_session_info(
            session_id=session_id, grant=True
        )
        grant = session_info["grant"]

        grant.scope = ["openid", "email", "address"]
        grant.claims = {"userinfo": {"given_name": None, "email": None}}
        grant.resources = ["https://api.example.com"]

        # Default usage rules
        self.context.cdb["client_id"] = {}
        rules = get_usage_rules("access_token", self.context, grant, "client_id")
        assert rules == {"supports_minting": [], "expires_in": 3600}

        # client specific usage rules
        self.context.cdb["client_id"] = {"access_token": {"expires_in": 600}}

    def test_assigned_scope(self):
        session_id = self._create_session(AREQ)
        session_info = self.context.session_manager.get_session_info(
            session_id=session_id, grant=True
        )
        grant = session_info["grant"]
        code = grant.mint_token(
            session_id,
            context=self.context,
            token_class="authorization_code",
            token_handler=TOKEN_HANDLER["authorization_code"],
        )

        code.scope = ["openid", "email"]

        access_token = grant.mint_token(
            session_id,
            context=self.context,
            token_class="access_token",
            token_handler=TOKEN_HANDLER["access_token"],
            based_on=code,
        )

        assert access_token.scope == code.scope

    def test_assigned_scope_2nd(self):
        session_id = self._create_session(AREQ)
        session_info = self.context.session_manager.get_session_info(
            session_id=session_id, grant=True
        )
        grant = session_info["grant"]
        code = grant.mint_token(
            session_id,
            context=self.context,
            token_class="authorization_code",
            token_handler=TOKEN_HANDLER["authorization_code"],
        )

        code.scope = ["openid", "email"]

        refresh_token = grant.mint_token(
            session_id,
            context=self.context,
            token_class="refresh_token",
            token_handler=TOKEN_HANDLER["refresh_token"],
            based_on=code,
        )

        access_token = grant.mint_token(
            session_id,
            context=self.context,
            token_class="access_token",
            token_handler=TOKEN_HANDLER["access_token"],
            based_on=refresh_token,
        )

        assert access_token.scope == code.scope

        refresh_token.scope = ["openid", "xyz"]

        access_token = grant.mint_token(
            session_id,
            context=self.context,
            token_class="access_token",
            token_handler=TOKEN_HANDLER["access_token"],
            based_on=refresh_token,
        )

        assert access_token.scope == refresh_token.scope

    def test_grant_remove_based_on_code(self):
        session_id = self._create_session(AREQ)
        session_info = self.context.session_manager.get_session_info(
            session_id=session_id, grant=True
        )
        grant = session_info["grant"]
        code = grant.mint_token(
            session_id,
            context=self.context,
            token_class="authorization_code",
            token_handler=TOKEN_HANDLER["authorization_code"],
        )

        access_token = grant.mint_token(
            session_id,
            context=self.context,
            token_class="access_token",
            token_handler=TOKEN_HANDLER["access_token"],
            based_on=code,
        )

        refresh_token = grant.mint_token(
            session_id,
            context=self.context,
            token_class="refresh_token",
            token_handler=TOKEN_HANDLER["refresh_token"],
            based_on=code,
        )

        grant.revoke_token(based_on=code.value)
        assert len(grant.issued_token) == 1

    def test_grant_remove_one_by_one(self):
        session_id = self._create_session(AREQ)
        session_info = self.context.session_manager.get_session_info(
            session_id=session_id, grant=True
        )
        grant = session_info["grant"]
        code = grant.mint_token(
            session_id,
            context=self.context,
            token_class="authorization_code",
            token_handler=TOKEN_HANDLER["authorization_code"],
        )

        access_token = grant.mint_token(
            session_id,
            context=self.context,
            token_class="access_token",
            token_handler=TOKEN_HANDLER["access_token"],
            based_on=code,
        )

        refresh_token = grant.mint_token(
            session_id,
            context=self.context,
            token_class="refresh_token",
            token_handler=TOKEN_HANDLER["refresh_token"],
            based_on=code,
        )

        grant.revoke_token(value=refresh_token.value)
        assert len(grant.issued_token) == 2

        grant.revoke_token(value=access_token.value)
        assert len(grant.issued_token) == 1
