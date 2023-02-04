import json
import os

from idpyoidc.server import Server
from idpyoidc.server.configure import OPConfiguration
from idpyoidc.server.endpoint_context import init_service
from idpyoidc.server.endpoint_context import init_user_info
from idpyoidc.server.login_hint import LoginHint2Acrs

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


def test_login_hint():
    userinfo = init_user_info(
        {
            "class": "idpyoidc.server.user_info.UserInfo",
            "kwargs": {"db_file": full_path("users.json")},
        },
        "",
    )
    login_hint_lookup = init_service({"class": "idpyoidc.server.login_hint.LoginHintLookup"}, None)
    login_hint_lookup.userinfo = userinfo

    assert login_hint_lookup("tel:0907865000") == "diana"


def test_login_hint2acrs():
    l2a = LoginHint2Acrs({"tel": ["http://www.swamid.se/policy/assurance/al1"]})

    assert l2a("tel:+467865000") == ["http://www.swamid.se/policy/assurance/al1"]


def test_login_hint2acrs_unmatched_schema():
    l2a = LoginHint2Acrs({"tel": ["http://www.swamid.se/policy/assurance/al1"]})

    assert l2a("mail:foobar@exaample.com") == []


def test_server_login_hint_lookup():
    _str = open(full_path("op_config.json")).read()
    _conf = json.loads(_str)
    configuration = OPConfiguration(conf=_conf, base_path=BASEDIR, domain="127.0.0.1", port=443)

    server = Server(configuration)
    assert server.context.login_hint_lookup("tel:0907865000") == "diana"
