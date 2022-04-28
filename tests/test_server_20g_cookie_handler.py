import pytest
from cryptojwt.jwk.hmac import SYMKey

from idpyoidc.server.cookie_handler import CookieHandler
from idpyoidc.server.cookie_handler import compute_session_state
from tests import CRYPT_CONFIG

KEYDEFS = [
    {"type": "OCT", "kid": "sig", "use": ["sig"]},
    {"type": "OCT", "kid": "enc", "use": ["enc"]},
]


class TestCookieSign(object):
    @pytest.fixture(autouse=True)
    def make_cookie_content_handler(self):
        cookie_conf = {
            "sign_key": SYMKey(k="ghsNKDDLshZTPn974nOsIGhedULrsqnsGoBFBLwUKuJhE2ch"),
        }

        self.cookie_handler = CookieHandler(**cookie_conf)

    def test_init(self):
        assert self.cookie_handler

    def test_make_cookie_content(self):
        _cookie_info = self.cookie_handler.make_cookie_content("idpyoidc.server", "value", "sso")
        assert _cookie_info
        assert set(_cookie_info.keys()) == {"name", "value", "samesite", "httponly", "secure"}
        assert len(_cookie_info["value"].split("|")) == 3

    def test_make_cookie_content_max_age(self):
        _cookie_info = self.cookie_handler.make_cookie_content(
            "idpyoidc.server", "value", "sso", max_age=3600
        )
        assert _cookie_info
        assert set(_cookie_info.keys()) == {
            "name",
            "value",
            "max-age",
            "samesite",
            "httponly",
            "secure",
        }
        assert len(_cookie_info["value"].split("|")) == 3

    def test_read_cookie_info(self):
        _cookie_info = [self.cookie_handler.make_cookie_content("idpyoidc.server", "value", "sso")]
        returned = [{"name": c["name"], "value": c["value"]} for c in _cookie_info]
        _info = self.cookie_handler.parse_cookie("idpyoidc.server", returned)
        assert len(_info) == 1
        assert set(_info[0].keys()) == {"value", "type", "timestamp"}
        assert _info[0]["value"] == "value"
        assert _info[0]["type"] == "sso"

    def test_mult_cookie(self):
        _cookie = [
            self.cookie_handler.make_cookie_content("idpyoidc.server", "value", "sso"),
            self.cookie_handler.make_cookie_content("idpyoidc.server", "session_state", "session"),
        ]
        assert len(_cookie) == 2
        _c_info = self.cookie_handler.parse_cookie("idpyoidc.server", _cookie)
        assert len(_c_info) == 2
        assert _c_info[0]["value"] == "value"
        assert _c_info[0]["type"] == "sso"
        assert _c_info[1]["value"] == "session_state"
        assert _c_info[1]["type"] == "session"


class TestCookieHandlerSignEnc(object):
    @pytest.fixture(autouse=True)
    def make_cookie_handler(self):
        cookie_conf = {
            "sign_key": SYMKey(k="ghsNKDDLshZTPn974nOsIGhedULrsqnsGoBFBLwUKuJhE2ch"),
            "enc_key": SYMKey(k="NXi6HD473d_YS4exVRn7z9z23mGmvU641MuvKqH0o7Y"),
        }

        self.cookie_handler = CookieHandler(**cookie_conf)

    def test_make_cookie_content(self):
        _cookie_info = self.cookie_handler.make_cookie_content("idpyoidc.server", "value", "sso")
        assert _cookie_info
        assert set(_cookie_info.keys()) == {"name", "value", "samesite", "httponly", "secure"}
        assert len(_cookie_info["value"].split("|")) == 4

    def test_make_cookie_content_max_age(self):
        _cookie_info = self.cookie_handler.make_cookie_content(
            "idpyoidc.server", "value", "sso", max_age=3600
        )
        assert _cookie_info
        assert set(_cookie_info.keys()) == {
            "name",
            "value",
            "max-age",
            "samesite",
            "httponly",
            "secure",
        }
        assert len(_cookie_info["value"].split("|")) == 4

    def test_read_cookie_info(self):
        _cookie_info = [self.cookie_handler.make_cookie_content("idpyoidc.server", "value", "sso")]
        returned = [{"name": c["name"], "value": c["value"]} for c in _cookie_info]
        _info = self.cookie_handler.parse_cookie("idpyoidc.server", returned)
        assert len(_info) == 1
        assert set(_info[0].keys()) == {"value", "type", "timestamp"}
        assert _info[0]["value"] == "value"
        assert _info[0]["type"] == "sso"

    def test_mult_cookie(self):
        _cookie = [
            self.cookie_handler.make_cookie_content("idpyoidc.server", "value", "sso"),
            self.cookie_handler.make_cookie_content("idpyoidc.server", "session_state", "session"),
        ]
        assert len(_cookie) == 2
        _c_info = self.cookie_handler.parse_cookie("idpyoidc.server", _cookie)
        assert len(_c_info) == 2
        assert _c_info[0]["value"] == "value"
        assert _c_info[0]["type"] == "sso"
        assert _c_info[1]["value"] == "session_state"
        assert _c_info[1]["type"] == "session"


class TestCookieHandlerEnc(object):
    @pytest.fixture(autouse=True)
    def make_cookie_content_handler(self):
        cookie_conf = {
            "enc_key": SYMKey(k="NXi6HD473d_YS4exVRn7z9z23mGmvU641MuvKqH0o7Y"),
        }

        self.cookie_handler = CookieHandler(**cookie_conf)

    def test_make_cookie_content(self):
        _cookie_info = self.cookie_handler.make_cookie_content("idpyoidc.server", "value", "sso")
        assert _cookie_info
        assert set(_cookie_info.keys()) == {"name", "value", "samesite", "httponly", "secure"}
        assert len(_cookie_info["value"].split("|")) == 4

    def test_make_cookie_content_max_age(self):
        _cookie_info = self.cookie_handler.make_cookie_content(
            "idpyoidc.server", "value", "sso", max_age=3600
        )
        assert _cookie_info
        assert set(_cookie_info.keys()) == {
            "name",
            "value",
            "max-age",
            "samesite",
            "httponly",
            "secure",
        }
        assert len(_cookie_info["value"].split("|")) == 4

    def test_read_cookie_info(self):
        _cookie_info = [self.cookie_handler.make_cookie_content("idpyoidc.server", "value", "sso")]
        returned = [{"name": c["name"], "value": c["value"]} for c in _cookie_info]
        _info = self.cookie_handler.parse_cookie("idpyoidc.server", returned)
        assert len(_info) == 1
        assert set(_info[0].keys()) == {"value", "type", "timestamp"}
        assert _info[0]["value"] == "value"
        assert _info[0]["type"] == "sso"

    def test_mult_cookie(self):
        _cookie = [
            self.cookie_handler.make_cookie_content("idpyoidc.server", "value", "sso"),
            self.cookie_handler.make_cookie_content("idpyoidc.server", "session_state", "session"),
        ]
        assert len(_cookie) == 2
        _c_info = self.cookie_handler.parse_cookie("idpyoidc.server", _cookie)
        assert len(_c_info) == 2
        assert _c_info[0]["value"] == "value"
        assert _c_info[0]["type"] == "sso"
        assert _c_info[1]["value"] == "session_state"
        assert _c_info[1]["type"] == "session"


class TestCookieHandlerSignEncKeys(object):
    @pytest.fixture(autouse=True)
    def make_cookie_handler(self):
        cookie_conf = {
            "keys": {
                "private_path": "private/cookie_jwks.json",
                "key_defs": KEYDEFS,
                "read_only": False,
            }
        }

        self.cookie_handler = CookieHandler(**cookie_conf)

    def test_make_cookie_content(self):
        _cookie_info = self.cookie_handler.make_cookie_content("idpyoidc.server", "value", "sso")
        assert _cookie_info
        assert set(_cookie_info.keys()) == {"name", "value", "samesite", "httponly", "secure"}
        assert len(_cookie_info["value"].split("|")) == 4

    def test_make_cookie_content_max_age(self):
        _cookie_info = self.cookie_handler.make_cookie_content(
            "idpyoidc.server", "value", "sso", max_age=3600
        )
        assert _cookie_info
        assert set(_cookie_info.keys()) == {
            "name",
            "value",
            "max-age",
            "samesite",
            "httponly",
            "secure",
        }
        assert len(_cookie_info["value"].split("|")) == 4

    def test_read_cookie_info(self):
        _cookie_info = [self.cookie_handler.make_cookie_content("idpyoidc.server", "value", "sso")]
        returned = [{"name": c["name"], "value": c["value"]} for c in _cookie_info]
        _info = self.cookie_handler.parse_cookie("idpyoidc.server", returned)
        assert len(_info) == 1
        assert set(_info[0].keys()) == {"value", "type", "timestamp"}
        assert _info[0]["value"] == "value"
        assert _info[0]["type"] == "sso"

    def test_mult_cookie(self):
        _cookie = [
            self.cookie_handler.make_cookie_content("idpyoidc.server", "value", "sso"),
            self.cookie_handler.make_cookie_content("idpyoidc.server", "session_state", "session"),
        ]
        assert len(_cookie) == 2
        _c_info = self.cookie_handler.parse_cookie("idpyoidc.server", _cookie)
        assert len(_c_info) == 2
        assert _c_info[0]["value"] == "value"
        assert _c_info[0]["type"] == "sso"
        assert _c_info[1]["value"] == "session_state"
        assert _c_info[1]["type"] == "session"


def test_compute_session_state():
    hv = compute_session_state("state", "salt", "client_id", "https://example.com/redirect")
    assert hv == "d21113fbe4b54661ae45f3a3233b0f865ccc646af248274b6fa5664267540e29.salt"


class TestCookieHandlerFernetEnc(object):
    @pytest.fixture(autouse=True)
    def make_cookie_content_handler(self):
        cookie_conf = {
            "crypt_config": CRYPT_CONFIG,
        }

        self.cookie_handler = CookieHandler(**cookie_conf)

    def test_make_cookie_content(self):
        _cookie_info = self.cookie_handler.make_cookie_content("idpyoidc.server", "value", "sso")
        assert _cookie_info
        assert set(_cookie_info.keys()) == {"name", "value", "samesite", "httponly", "secure"}
        assert len(_cookie_info["value"].split("|")) == 2

    def test_make_cookie_content_max_age(self):
        _cookie_info = self.cookie_handler.make_cookie_content(
            "idpyoidc.server", "value", "sso", max_age=3600
        )
        assert _cookie_info
        assert set(_cookie_info.keys()) == {
            "name",
            "value",
            "max-age",
            "samesite",
            "httponly",
            "secure",
        }
        assert len(_cookie_info["value"].split("|")) == 2

    def test_read_cookie_info(self):
        _cookie_info = [self.cookie_handler.make_cookie_content("idpyoidc.server", "value", "sso")]
        returned = [{"name": c["name"], "value": c["value"]} for c in _cookie_info]
        _info = self.cookie_handler.parse_cookie("idpyoidc.server", returned)
        assert len(_info) == 1
        assert set(_info[0].keys()) == {"value", "type", "timestamp"}
        assert _info[0]["value"] == "value"
        assert _info[0]["type"] == "sso"

    def test_mult_cookie(self):
        _cookie = [
            self.cookie_handler.make_cookie_content("idpyoidc.server", "value", "sso"),
            self.cookie_handler.make_cookie_content("idpyoidc.server", "session_state", "session"),
        ]
        assert len(_cookie) == 2
        _c_info = self.cookie_handler.parse_cookie("idpyoidc.server", _cookie)
        assert len(_c_info) == 2
        assert _c_info[0]["value"] == "value"
        assert _c_info[0]["type"] == "sso"
        assert _c_info[1]["value"] == "session_state"
        assert _c_info[1]["type"] == "session"
