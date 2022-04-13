from idpyoidc.util import add_path
from idpyoidc.util import get_http_params
from idpyoidc.util import load_yaml_config
from idpyoidc.util import split_uri

from . import full_path


def test_get_http_params_1():
    conf = {
        "httpc_params": {"verify": False},
        "verify": True,
    }
    _params = get_http_params(conf)
    assert _params == {"verify": False}


def test_get_http_params_2():
    conf = {"verify": False}
    _params = get_http_params(conf)
    assert _params == {"verify": False}


def test_get_http_params_3():
    conf = {"verify_ssl": False}
    _params = get_http_params(conf)
    assert _params == {"verify": False}


def test_add_path():
    assert add_path("https://example.com/", "/usr") == "https://example.com/usr"
    assert add_path("https://example.com/", "usr") == "https://example.com/usr"
    assert add_path("https://example.com", "/usr") == "https://example.com/usr"
    assert add_path("https://example.com", "usr") == "https://example.com/usr"


def test_load_yaml():
    _cnf = load_yaml_config(full_path("logging.yaml"))


def test_split_uri():
    a, b = split_uri("https://example.com")
    assert a == "https://example.com"
    assert b is None

    a, b = split_uri("https://example.com?foo=bar&cue=ball")
    assert a == "https://example.com"
    assert b == {"foo": ["bar"], "cue": ["ball"]}

    a, b = split_uri("https://example.com#foobar")
    assert a == "https://example.com"
    assert b is None
