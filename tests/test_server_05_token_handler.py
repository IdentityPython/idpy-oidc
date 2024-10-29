import os

import pytest

from idpyoidc.encrypter import default_crypt_config
from idpyoidc.server import Server
from idpyoidc.server.configure import OPConfiguration
from idpyoidc.server.endpoint import Endpoint
from idpyoidc.server.token import is_expired
from idpyoidc.server.token.handler import DefaultToken
from idpyoidc.server.token.handler import TokenHandler
from idpyoidc.server.token.id_token import IDToken
from idpyoidc.server.token.jwt_token import JWTToken
from idpyoidc.time_util import utc_time_sans_frac
from tests import CRYPT_CONFIG
from tests import SESSION_PARAMS

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


def test_is_expired():
    assert is_expired(-1) is False
    assert is_expired(1, 2)
    assert is_expired(1, 1) is False
    assert is_expired(2, 1) is False

    now = utc_time_sans_frac()
    assert is_expired(now - 1)
    assert is_expired(now + 1) is False


class TestDefaultToken(object):

    @pytest.fixture(autouse=True)
    def setup_token_handler(self):
        password = "The longer the better. Is this close to enough ?"
        grant_expires_in = 600
        crypt_config = default_crypt_config()
        crypt_config["kwargs"]["iterations"] = 10
        self.th = DefaultToken(
            crypt_conf=crypt_config, token_class="authorization_code", lifetime=grant_expires_in
        )

    def test_default_token_split_token(self):
        _token = self.th("session_id")
        p = self.th.split_token(_token)
        assert p[1] == "authorization_code"
        assert p[2] == "session_id"

    def test_default_token_info(self):
        _token = self.th("another_id")
        _info = self.th.info(_token)

        assert set(_info.keys()) == {
            "_id",
            "token_class",
            "sid",
            "exp",
            "handler",
        }
        assert _info["handler"] == self.th

    def test_is_expired(self):
        _token = self.th("another_id")
        assert self.th.is_expired(_token) is False

        when = utc_time_sans_frac()
        # has it expired 24 hours from now ?
        assert self.th.is_expired(_token, int(when) + 86400)


class TestTokenHandler(object):

    @pytest.fixture(autouse=True)
    def setup_token_handler(self):
        grant_expires_in = 600
        token_expires_in = 900
        refresh_token_expires_in = 86400

        crypt_config = default_crypt_config()
        crypt_config["kwargs"]["iterations"] = 10

        authorization_code = DefaultToken(
            crypt_conf=crypt_config, token_class="authorization_code", lifetime=grant_expires_in
        )
        access_token = DefaultToken(
            crypt_conf=crypt_config, token_class="access_token", lifetime=token_expires_in
        )
        refresh_token = DefaultToken(
            crypt_conf=crypt_config, token_class="refresh_token", lifetime=refresh_token_expires_in
        )

        self.handler = TokenHandler(
            authorization_code=authorization_code,
            access_token=access_token,
            refresh_token=refresh_token,
        )

    def test_getitem(self):
        th = self.handler["authorization_code"]
        assert th.token_class == "authorization_code"
        th = self.handler["access_token"]
        assert th.token_class == "access_token"
        th = self.handler["refresh_token"]
        assert th.token_class == "refresh_token"

    def test_contains(self):
        assert "authorization_code" in self.handler
        assert "access_token" in self.handler
        assert "refresh_token" in self.handler

        assert "foobar" not in self.handler

    def test_info(self):
        _token = self.handler["authorization_code"]("another_id")
        _info = self.handler.info(_token)
        assert _info["token_class"] == "authorization_code"

    def test_sid(self):
        _token = self.handler["authorization_code"]("another_id")
        sid = self.handler.sid(_token)
        assert sid == "another_id"

    def test_token_class(self):
        _token = self.handler["authorization_code"]("another_id")
        assert self.handler.token_class(_token) == "authorization_code"

    def test_get_handler(self):
        _token = self.handler["authorization_code"]("another_id")
        th, _ = self.handler.get_handler(_token)
        assert th.token_class == "authorization_code"

    def test_keys(self):
        assert set(self.handler.keys()) == {"access_token", "authorization_code", "refresh_token"}


KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]


def test_token_handler_from_config():
    conf = {
        "issuer": "https://example.com/op",
        "keys": {"uri_path": "static/jwks.json", "key_defs": KEYDEFS},
        "endpoint": {
            "endpoint": {"path": "endpoint", "class": Endpoint, "kwargs": {}},
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
        },
        "session_params": SESSION_PARAMS,
    }

    server = Server(OPConfiguration(conf=conf, base_path=BASEDIR), cwd=BASEDIR)
    token_handler = server.context.session_manager.token_handler
    assert token_handler
    assert len(token_handler.handler) == 4
    assert set(token_handler.handler.keys()) == {
        "authorization_code",
        "access_token",
        "refresh_token",
        "id_token",
    }
    assert isinstance(token_handler.handler["authorization_code"], DefaultToken)
    assert isinstance(token_handler.handler["access_token"], JWTToken)
    assert isinstance(token_handler.handler["refresh_token"], JWTToken)
    assert isinstance(token_handler.handler["id_token"], IDToken)

    assert token_handler.handler["authorization_code"].lifetime == 600

    assert token_handler.handler["access_token"].alg == "ES256"
    assert token_handler.handler["access_token"].kwargs == {"add_claims_by_scope": True}
    assert token_handler.handler["access_token"].lifetime == 3600
    assert token_handler.handler["access_token"].def_aud == ["https://example.org/appl"]

    assert token_handler.handler["refresh_token"].alg == "ES256"
    assert token_handler.handler["refresh_token"].kwargs == {}
    assert token_handler.handler["refresh_token"].lifetime == 3600
    assert token_handler.handler["refresh_token"].def_aud == ["https://example.org/appl"]

    assert token_handler.handler["id_token"].lifetime == 300
    assert "base_claims" in token_handler.handler["id_token"].kwargs


@pytest.mark.parametrize(
    "jwks",
    [
        {"jwks_file": "private/token_jwks_1.json"},
        {
            "jwks_def": {
                "private_path": "private/token_jwks_2.json",
                "read_only": False,
                "key_defs": [{"type": "oct", "bytes": "24", "use": ["enc"], "kid": "code"}],
            }
        },
        {
            "jwks_file": "private/token_jwks_1.json",
            "jwks_def": {
                "private_path": "private/token_jwks_2.json",
                "read_only": False,
                "key_defs": [{"type": "oct", "bytes": "24", "use": ["enc"], "kid": "code"}],
            },
        },
        None,
    ],
)
def test_file(jwks):
    conf = {
        "issuer": "https://example.com/op",
        "keys": {"uri_path": "static/jwks.json", "key_defs": KEYDEFS},
        "endpoint": {
            "endpoint": {"path": "endpoint", "class": Endpoint, "kwargs": {}},
        },
        "token_handler_args": {
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
        "session_params": SESSION_PARAMS,
    }

    server = Server(OPConfiguration(conf=conf, base_path=BASEDIR), cwd=BASEDIR)
    token_handler = server.context.session_manager.token_handler
    assert token_handler

def test_token_handler_from_config_2():
    conf = {
        "issuer": "https://example.com/op",
        "keys": {"uri_path": "static/jwks.json", "key_defs": KEYDEFS},
        "endpoint": {
            "endpoint": {"path": "endpoint", "class": Endpoint, "kwargs": {}},
        },
        "token_handler_args": {
            "jwks_def": {
                "private_path": "private/token_jwks.json",
                "read_only": False,
                "key_defs": [{"type": "oct", "bytes": "24", "use": ["enc"], "kid": "code"}],
            },
            "code": {
                "kwargs": {
                    "lifetime": 600,
                    "crypt_conf": {
                        "kwargs": {
                            "key": "0987654321abcdefghijklmnop...---",
                            "salt": "abcdefghijklmnop",
                            "iterations": 1
                        }
                    }
                }
            },
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
        "session_params": SESSION_PARAMS,
    }

    server = Server(OPConfiguration(conf=conf, base_path=BASEDIR), cwd=BASEDIR)
    token_handler = server.context.session_manager.token_handler
    assert token_handler
    assert len(token_handler.handler) == 4
    assert set(token_handler.handler.keys()) == {
        "authorization_code",
        "access_token",
        "refresh_token",
        "id_token",
    }
    assert isinstance(token_handler.handler["authorization_code"], DefaultToken)
    assert isinstance(token_handler.handler["access_token"], JWTToken)
    assert isinstance(token_handler.handler["refresh_token"], JWTToken)
    assert isinstance(token_handler.handler["id_token"], IDToken)

    assert token_handler.handler["authorization_code"].lifetime == 600

    assert token_handler.handler["access_token"].alg == "ES256"
    assert token_handler.handler["access_token"].kwargs == {"add_claims_by_scope": True}
    assert token_handler.handler["access_token"].lifetime == 3600
    assert token_handler.handler["access_token"].def_aud == ["https://example.org/appl"]

    assert token_handler.handler["refresh_token"].alg == "ES256"
    assert token_handler.handler["refresh_token"].kwargs == {}
    assert token_handler.handler["refresh_token"].lifetime == 3600
    assert token_handler.handler["refresh_token"].def_aud == ["https://example.org/appl"]

    assert token_handler.handler["id_token"].lifetime == 300
    assert "base_claims" in token_handler.handler["id_token"].kwargs

