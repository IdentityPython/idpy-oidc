import json
import os

from idpyoidc.server import OPConfiguration
from idpyoidc.server import Server
from tests import full_path

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def test_op_configure_oidc_clients_simple():
    _str = open(full_path(full_path("op_config.json"))).read()
    _conf = json.loads(_str)
    _conf["oidc_clients"] = {
        "client1": {
            "client_id": "client1",
            "client_secret": "Namnam",
            "redirect_uris": ["https://openidconnect.net/callback"],
            "response_types": ["code"],
        },
        "client2": {
            "client_id": "client2",
            "client_secret": "spraket",
            "redirect_uris": ["https://app1.example.net/foo", "https://app2.example.net/bar"],
            "response_types": ["code"],
        },
        "client3": {
            "client_id": "client3",
            "client_secret": "2222222222222222222222222222222222222222",
            "redirect_uris": ["https://127.0.0.1:8090/authz_cb/bobcat"],
            "post_logout_redirect_uri": "https://openidconnect.net/",
            "response_types": ["code"],
        },
    }

    server = Server(OPConfiguration(conf=_conf, base_path=BASEDIR), cwd=BASEDIR)
    assert server.context.cdb
    assert len(server.context.cdb) == 3
    assert set(server.context.cdb.keys()) == {'client1', 'client2', 'client3'}

def test_op_configuration_cdb():
    _str = open(full_path(full_path("op_config.json"))).read()
    _conf = json.loads(_str)
    _conf["client_db"] = {
        "class": "idpyoidc.storage.abfile.AbstractFileSystem",
        "kwargs": {
            "fdir": "client_db",
            "key_conv": "idpyoidc.util.Base64",
            "value_conv": "idpyoidc.util.JSON"
        }
    }

    server = Server(OPConfiguration(conf=_conf, base_path=BASEDIR), cwd=BASEDIR)
    assert server.context.cdb
    assert len(server.context.cdb) == 3
    assert set(server.context.cdb.keys()) == {'client1', 'client2', 'client3'}
    assert server.context.cdb["client2"]["client_secret"] == "spraket"

