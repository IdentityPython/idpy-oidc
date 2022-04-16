import json
import os

from idpyoidc.configure import Configuration
from idpyoidc.configure import create_from_config_file
from idpyoidc.logging import configure_logging
from idpyoidc.server.configure import OPConfiguration
import pytest

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


def test_op_configure():
    _str = open(full_path("op_config.json")).read()
    _conf = json.loads(_str)

    configuration = OPConfiguration(conf=_conf, base_path=BASEDIR, domain="127.0.0.1", port=443)
    assert configuration
    authz_conf = configuration["authz"]
    assert set(authz_conf.keys()) == {"kwargs", "class"}
    id_token_conf = configuration.get("id_token")
    assert set(id_token_conf.keys()) == {"kwargs", "class"}

    with pytest.raises(KeyError):
        _ = configuration["foobar"]

    assert configuration.get("foobar", {}) == {}
    userinfo_conf = configuration.get("userinfo")
    assert userinfo_conf["kwargs"]["db_file"].startswith(BASEDIR)

    assert "session_params" in configuration


def test_op_configure_from_file():
    configuration = create_from_config_file(
        OPConfiguration,
        filename=full_path("op_config.json"),
        base_path=BASEDIR,
        domain="127.0.0.1",
        port=443,
    )

    assert configuration
    assert "key_conf" in configuration
    assert "userinfo" in configuration
    authz_conf = configuration["authz"]
    assert set(authz_conf.keys()) == {"kwargs", "class"}
    id_token_conf = configuration.get("id_token")
    assert set(id_token_conf.keys()) == {"kwargs", "class"}

    with pytest.raises(KeyError):
        _ = configuration["foobar"]

    assert configuration.get("foobar", {}) == {}
    userinfo_conf = configuration.get("userinfo")
    assert userinfo_conf["kwargs"]["db_file"].startswith(BASEDIR)


def test_op_configure_default():
    _str = open(full_path("op_config.json")).read()
    _conf = json.loads(_str)

    configuration = OPConfiguration(conf=_conf, base_path=BASEDIR, domain="127.0.0.1", port=443)
    assert configuration
    assert "userinfo" in configuration
    authz = configuration["authz"]
    assert set(authz.keys()) == {"kwargs", "class"}
    id_token_conf = configuration.get("id_token", {})
    assert set(id_token_conf.keys()) == {"kwargs", "class"}
    assert id_token_conf["kwargs"] == {
        "base_claims": {
            "email": {"essential": True},
            "email_verified": {"essential": True},
        }
    }


def test_op_configure_default_from_file():
    configuration = create_from_config_file(
        OPConfiguration,
        filename=full_path("op_config.json"),
        base_path=BASEDIR,
        domain="127.0.0.1",
        port=443,
    )
    assert configuration
    assert "userinfo" in configuration
    authz = configuration["authz"]
    assert set(authz.keys()) == {"kwargs", "class"}
    id_token_conf = configuration.get("id_token", {})
    assert set(id_token_conf.keys()) == {"kwargs", "class"}
    assert id_token_conf["kwargs"] == {
        "base_claims": {
            "email": {"essential": True},
            "email_verified": {"essential": True},
        }
    }


def test_server_configure():
    configuration = create_from_config_file(
        Configuration,
        entity_conf=[{"class": OPConfiguration, "attr": "op", "path": ["op", "server_info"]}],
        filename=full_path("srv_config.json"),
        base_path=BASEDIR,
    )
    assert configuration
    assert "logger" in configuration
    assert "op" in configuration
    op_conf = configuration["op"]
    assert "key_conf" in op_conf
    authz = op_conf["authz"]
    assert set(authz.keys()) == {"kwargs", "class"}
    id_token_conf = op_conf.get("id_token", {})
    assert set(id_token_conf.keys()) == {"kwargs", "class"}

    with pytest.raises(KeyError):
        _ = configuration["add_on"]

    assert configuration.get("add_on", {}) == {}

    userinfo_conf = op_conf.get("userinfo")
    assert userinfo_conf["kwargs"]["db_file"].startswith(BASEDIR)


def test_loggin_conf_file():
    logger = configure_logging(filename=full_path("logging.yaml"))
    assert logger


def test_loggin_conf_default():
    logger = configure_logging()
    assert logger


CONF = {
    "version": 1,
    "root": {"handlers": ["default"], "level": "DEBUG"},
    "loggers": {"bobcat": {"level": "DEBUG"}},
    "handlers": {
        "default": {
            "class": "logging.FileHandler",
            "filename": "debug.log",
            "formatter": "default",
        },
    },
    "formatters": {"default": {"format": "%(asctime)s %(name)s %(levelname)s %(message)s"}},
}


def test_loggin_conf_dict():
    logger = configure_logging(config=CONF)
    assert logger


extra = {
    "token_usage_rules": {
        "authorization_code": {
            "expires_in": 600,
            "supports_minting": ["access_token", "refresh_token"],
        },
        "refresh_token": {"supports_minting": ["access_token"]},
    },
    "pkce_essential": True,
    "auth_method": {
        "AccessTokenRequest": "client_secret_basic",
    },
    "dpop_jkt": "thumbprint",
    "revoke_refresh_on_issue": True,
    "token_exchange": {
        "urn:ietf:params:oauth:grant-type:token-exchange": {
            "class": "idpyoidc.server.oidc.token.TokenExchangeHelper",
            "kwargs": {
                "subject_token_types_supported": [
                    "urn:ietf:params:oauth:token-type:access_token",
                    "urn:ietf:params:oauth:token-type:refresh_token",
                    "urn:ietf:params:oauth:token-type:id_token"
                ],
                "requested_token_types_supported": [
                    "urn:ietf:params:oauth:token-type:access_token",
                    "urn:ietf:params:oauth:token-type:refresh_token",
                    "urn:ietf:params:oauth:token-type:id_token"
                ],
                "policy": {
                    "urn:ietf:params:oauth:token-type:access_token": {
                        "callable": "/path/to/callable",
                        "kwargs": {
                            "audience": ["https://example.com"],
                            "scopes": ["openid"]
                        }
                    },
                    "urn:ietf:params:oauth:token-type:refresh_token": {
                        "callable": "/path/to/callable",
                        "kwargs": {
                            "resource": ["https://example.com"],
                            "scopes": ["openid"]
                        }
                    },
                    "": {
                        "callable": "/path/to/callable",
                        "kwargs": {
                            "scopes": ["openid"]
                        }
                    }
                }
            }
        },
        # "backchannel_logout_uri": None,
        # frontchannel_logout_uri: None,
        "allowed_scopes": ["scope"],
        "scopes_to_claims": {
            "scope_a": ["claim1", "claim2"],
            "scope_b": []
        },
        "add_claims": {
            "always": {
              "userinfo": ["email", "phone"], # Always add "email" and "phone" in the userinfo response if such claims exists
              "id_token": {"email": None}, # Always add "email" in the id_token if such a claim exists
              "introspection": {"email": {"value": "a@a.com"}}, # Add "email" in the introspection response only if its value is "a@a.com"
            },
            "by_scope": {
                "id_token": False,
            },
        }
    }
}

def test_op_configure_oidc_clients():
    _str = open(full_path("op_config.json")).read()
    _conf = json.loads(_str)
    _conf["oidc_clients"] = {
        "client1": {
            # client secret is "password"
            "client_secret": "Namnam",
            "redirect_uris": ['https://openidconnect.net/callback', ''],
            "response_types": ["code"]
        },
        "client2": {
            "client_secret": "spraket",
            "redirect_uris": ['https://app1.example.net/foo', 'https://app2.example.net/bar'],
            "response_types": ["code"]
        },
        "client3": {
            "client_secret": '2222222222222222222222222222222222222222',
            "redirect_uris": ['https://127.0.0.1:8090/authz_cb/bobcat'],
            "post_logout_redirect_uri": 'https://openidconnect.net/',
            "response_types": ["code"]
        }
    }

    op_conf = OPConfiguration(conf=_conf)
    assert op_conf
