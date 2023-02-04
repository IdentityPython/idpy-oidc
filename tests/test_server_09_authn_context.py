import json
import os

import pytest
from cryptojwt.jwk.hmac import SYMKey

from idpyoidc.server import Server
from idpyoidc.server.authn_event import AuthnEvent
from idpyoidc.server.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from idpyoidc.server.user_authn.authn_context import TIMESYNCTOKEN
from idpyoidc.server.user_authn.authn_context import init_method
from idpyoidc.server.user_authn.authn_context import pick_auth
from idpyoidc.server.user_authn.authn_context import populate_authn_broker
from idpyoidc.server.user_authn.user import NoAuthn
from idpyoidc.server.user_info import UserInfo
from idpyoidc.time_util import utc_time_sans_frac
from tests import CRYPT_CONFIG
from tests import SESSION_PARAMS

METHOD = {
    "diana": {
        "acr": INTERNETPROTOCOLPASSWORD,
        "kwargs": {"user": "diana"},
        "class": "idpyoidc.server.user_authn.user.NoAuthn",
    },
    "krall": {
        "acr": INTERNETPROTOCOLPASSWORD,
        "kwargs": {"user": "krall"},
        "class": NoAuthn,
    },
}

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]}
    # {"type": "EC", "crv": "P-256", "use": ["sig"]}
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

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


USERINFO_db = json.loads(open(full_path("users.json")).read())


class TestAuthnBroker:
    @pytest.fixture(autouse=True)
    def create_authn_broker(self):
        self.authn_broker = populate_authn_broker(METHOD, None)

    def test_2(self):
        method = list(self.authn_broker.get_method("NoAuthn"))
        assert len(method) == 2

    def test_3(self):
        method = self.authn_broker.get_method_by_id("diana")
        assert method.user == "diana"
        method = self.authn_broker.get_method_by_id("krall")
        assert method.user == "krall"

    def test_add_method(self):
        method_spec = {
            "acr": INTERNETPROTOCOLPASSWORD,
            "kwargs": {"user": "knoll"},
            "class": NoAuthn,
        }
        self.authn_broker["foo"] = init_method(method_spec, None)
        method = self.authn_broker.get_method_by_id("foo")
        assert method.user == "knoll"

    def test_del_method(self):
        del self.authn_broker["diana"]
        with pytest.raises(KeyError):
            self.authn_broker.get_method_by_id("diana")

    def test_pick(self):
        res = self.authn_broker.pick(INTERNETPROTOCOLPASSWORD)
        assert len(res) == 2

    def test_pick_unknown_acr(self):
        res = self.authn_broker.pick(TIMESYNCTOKEN)
        assert res == []


class TestAuthnBrokerEC:
    @pytest.fixture(autouse=True)
    def create_authn_broker(self):
        conf = {
            "issuer": "https://example.com/",
            "token_handler_args": {
                "code": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
                "token": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
                "refresh": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
            },
            "verify_ssl": False,
            "capabilities": CAPABILITIES,
            "keys": {"uri_path": "static/jwks.json", "key_defs": KEYDEFS},
            "authentication": METHOD,
            "userinfo": {"class": UserInfo, "kwargs": {"db": USERINFO_db}},
            "template_dir": "template",
            "claims_interface": {
                "class": "idpyoidc.server.session.claims.ClaimsInterface",
                "kwargs": {},
            },
            "session_params": SESSION_PARAMS,
        }
        cookie_conf = {
            "sign_key": SYMKey(k="ghsNKDDLshZTPn974nOsIGhedULrsqnsGoBFBLwUKuJhE2ch"),
            "name": {
                "session": "oidc_op",
                "register": "oidc_op_reg",
                "session_management": "oidc_op_sman",
            },
        }
        # cookie_handler = CookieHandler(**cookie_conf)
        # server = Server(conf, cookie_handler=cookie_handler)
        server = Server(conf)
        context = server.context
        context.cdb["client_1"] = {
            "client_secret": "hemligt",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "token_endpoint_auth_method": "client_secret_post",
            "response_types": [
                "code",
                "token",
                "code id_token",
                "id_token",
                "code id_token token",
            ],
        }
        server.keyjar.import_jwks(server.keyjar.export_jwks(True, ""), conf["issuer"])

        self.server = server

    def test_pick_authn_one(self):
        request = {"acr_values": INTERNETPROTOCOLPASSWORD}
        res = pick_auth(self.server.get_context(), request)
        assert res["acr"] == INTERNETPROTOCOLPASSWORD

    def test_pick_authn_all(self):
        request = {"acr_values": INTERNETPROTOCOLPASSWORD}
        res = pick_auth(self.server.get_context(), request, pick_all=True)
        assert len(res) == 2


def test_authn_event():
    an = AuthnEvent(
        uid="uid",
        valid_until=utc_time_sans_frac() + 1,
        authn_info="authn_class_ref",
    )

    assert an.is_valid()

    n = utc_time_sans_frac() + 3
    assert an.is_valid(n) is False

    n = an.expires_in()
    assert n == 1  # could possibly be 0
