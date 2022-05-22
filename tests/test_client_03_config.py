import os

from idpyoidc.client.configure import RPHConfiguration
from idpyoidc.configure import create_from_config_file

_dirname = os.path.dirname(os.path.abspath(__file__))


def test_json_1():
    configuration = create_from_config_file(
        RPHConfiguration, filename=os.path.join(_dirname, "rp_conf.json"), base_path=_dirname
    )
    assert configuration

    assert configuration.base_url == "https://127.0.0.1:8090"
    assert configuration.httpc_params == {"verify": False}
    assert set(configuration.default["services"].keys()) == {
        "discovery",
        "registration",
        "authorization",
        "accesstoken",
        "userinfo",
        "end_session",
    }
    assert set(configuration.clients.keys()) == {"", "bobcat", "flop"}


def test_json_2():
    configuration = create_from_config_file(
        RPHConfiguration, filename=os.path.join(_dirname, "rp_conf_2.json"), base_path=_dirname
    )
    assert configuration

    assert configuration.base_url == "https://127.0.0.1:8090"
    assert configuration.httpc_params == {"verify": False}
    assert set(configuration.default["services"].keys()) == {
        "discovery",
        "registration",
        "authorization",
        "accesstoken",
        "userinfo",
        "end_session",
    }
    assert set(configuration.clients.keys()) == {"", "bobcat", "flop"}
    assert set(configuration.clients["bobcat"]["services"]) == {
        "discovery",
        "registration",
        "authorization",
        "accesstoken",
        "userinfo",
        "end_session",
    }
