import base64
import os

import pytest

from idpyoidc.server import Server
from idpyoidc.server.authn_event import create_authn_event
from idpyoidc.server.configure import OPConfiguration
from idpyoidc.server.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from idpyoidc.server.user_authn.authn_context import UNSPECIFIED
from idpyoidc.server.user_authn.user import BasicAuthn
from idpyoidc.server.user_authn.user import NoAuthn
from idpyoidc.server.user_authn.user import SymKeyAuthn
from idpyoidc.server.user_authn.user import UserPassJinja2
from idpyoidc.server.util import JSONDictDB
from tests import CRYPT_CONFIG
from tests import SESSION_PARAMS

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


class TestUserAuthn(object):
    @pytest.fixture(autouse=True)
    def create_endpoint_context(self):
        conf = {
            "issuer": "https://example.com/",
            "httpc_params": {"verify": False, "timeout": 1},
            "grant_expires_in": 300,
            "keys": {"uri_path": "static/jwks.json", "key_defs": KEYDEFS},
            "authentication": {
                "user": {
                    "acr": INTERNETPROTOCOLPASSWORD,
                    "class": UserPassJinja2,
                    "verify_endpoint": "verify/user",
                    "kwargs": {
                        "template": "user_pass.jinja2",
                        "sym_key": "24AA/LR6HighEnergy",
                        "db": {
                            "class": JSONDictDB,
                            "kwargs": {"filename": full_path("passwd.json")},
                        },
                        "page_header": "Testing log in",
                        "submit_btn": "Get me in!",
                        "user_label": "Nickname",
                        "passwd_label": "Secret sauce",
                    },
                },
                "anon": {
                    "acr": UNSPECIFIED,
                    "class": NoAuthn,
                    "kwargs": {"user": "diana"},
                },
            },
            "template_dir": "templates",
            "cookie_handler": {
                "class": "idpyoidc.server.cookie_handler.CookieHandler",
                "kwargs": {
                    "sign_key": "ghsNKDDLshZTPn974nOsIGhedULrsqnsGoBFBLwUKuJhE2ch",
                    "name": {
                        "session": "oidc_op",
                        "register": "oidc_op_reg",
                        "session_management": "oidc_op_sman",
                    },
                },
            },
            "session_params": SESSION_PARAMS,
            "token_handler_args": {
                "code": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
                "token": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
                "refresh": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
            },
        }
        self.server = Server(OPConfiguration(conf=conf, base_path=BASEDIR), cwd=BASEDIR)
        self.context = self.server.context
        self.session_manager = self.context.session_manager
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

    def test_authenticated_as_without_cookie(self):
        authn_item = self.context.authn_broker.pick(INTERNETPROTOCOLPASSWORD)
        method = authn_item[0]["method"]

        _info, _time_stamp = method.authenticated_as(None)
        assert _info is None

    def test_authenticated_as_with_cookie(self):
        authn_item = self.context.authn_broker.pick(INTERNETPROTOCOLPASSWORD)
        method = authn_item[0]["method"]

        authn_req = {"state": "state_identifier", "client_id": "client 12345"}
        _sid = self._create_session(authn_req)
        _cookie = self.context.new_cookie(
            name=self.context.cookie_handler.name["session"],
            sub="diana",
            sid=_sid,
            state=authn_req["state"],
            client_id=authn_req["client_id"],
        )

        # Parsed once before authenticated_as
        kakor = self.context.cookie_handler.parse_cookie(
            cookies=[_cookie], name=self.context.cookie_handler.name["session"]
        )

        _info, _time_stamp = method.authenticated_as("client 12345", kakor)
        assert set(_info.keys()) == {
            "sub",
            "uid",
            "state",
            "grant_id",
            "timestamp",
            "sid",
            "client_id",
        }
        assert _info["sub"] == "diana"

    def test_userpassjinja2(self):
        db = {
            "class": JSONDictDB,
            "kwargs": {"filename": full_path("passwd.json")},
        }
        template_handler = self.context.template_handler
        res = UserPassJinja2(db, template_handler, upstream_get=self.server.unit_get)
        res()
        assert "page_header" in res.kwargs

    def test_basic_auth(self):
        basic_auth = base64.b64encode(b"diana:krall").decode()
        ba = BasicAuthn(pwd={"diana": "krall"}, upstream_get=self.server.unit_get)
        ba.authenticated_as(client_id="", authorization=f"Basic {basic_auth}")

    def test_no_auth(self):
        basic_auth = base64.b64encode(
            b"D\xfd\x8a\x85\xa6\xd1\x16\xe4\\6\x1e\x9ds~\xc3\t\x95\x99\x83\x91\x1f\xfb:iviviviv"
        )
        ba = SymKeyAuthn(symkey=b"0" * 32, ttl=600, upstream_get=self.server.unit_get)
        ba.authenticated_as(client_id="", authorization=basic_auth)
