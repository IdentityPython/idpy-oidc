import os
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

import pytest
from cryptojwt.jwe.fernet import FernetEncrypter

from idpyoidc.configure import Base
from idpyoidc.configure import Configuration
from idpyoidc.configure import create_from_config_file
from idpyoidc.configure import lower_or_upper
from idpyoidc.encrypter import DEFAULT_CRYPTO
from idpyoidc.encrypter import init_encrypter
from idpyoidc.util import rndstr

_dirname = os.path.dirname(os.path.abspath(__file__))

URIS = ["base_url"]


class EntityConfiguration(Base):
    def __init__(
        self,
        conf: Dict,
        entity_conf: Optional[Any] = None,
        base_path: Optional[str] = "",
        domain: Optional[str] = "",
        port: Optional[int] = 0,
        file_attributes: Optional[List[str]] = None,
        uris: Optional[List[str]] = None,
        dir_attributes: Optional[List[str]] = None,
    ):
        Base.__init__(
            self,
            conf,
            base_path=base_path,
            file_attributes=file_attributes,
            dir_attributes=dir_attributes,
        )

        self.keys = lower_or_upper(conf, "keys")

        self.hash_seed = lower_or_upper(conf, "hash_seed", rndstr(32))
        self.base_url = conf.get("base_url")
        self.httpc_params = conf.get("httpc_params", {"verify": False})


def test_server_config():
    configuration = create_from_config_file(
        Configuration,
        entity_conf=[{"class": EntityConfiguration, "attr": "entity"}],
        filename=os.path.join(_dirname, "server_conf.json"),
        base_path=_dirname,
    )
    assert configuration
    assert set(configuration.web_conf.keys()) == {
        "port",
        "domain",
        "server_cert",
        "server_key",
        "debug",
    }

    entity_config = configuration.entity
    assert entity_config.base_url == "https://127.0.0.1:8090"
    assert entity_config.httpc_params == {"verify": False}


@pytest.mark.parametrize("filename", ["entity_conf.json", "entity_conf.py"])
def test_entity_config(filename):
    configuration = create_from_config_file(
        EntityConfiguration, filename=os.path.join(_dirname, filename), base_path=_dirname
    )
    assert configuration

    assert configuration.base_url == "https://127.0.0.1:8090"
    assert configuration.httpc_params == {"verify": False}
    assert configuration["keys"]
    ni = dict(configuration.items())
    assert len(ni) == 9
    assert set(ni.keys()) == {
        "base_url",
        "_dir_attributes",
        "_file_attributes",
        "hash_seed",
        "httpc_params",
        "keys",
        "conf",
        "port",
        "domain",
    }


def test_init_crypto_None():
    _res = init_encrypter()
    assert _res["conf"]["class"] == DEFAULT_CRYPTO
    assert set(_res["conf"]["kwargs"].keys()) == {"password", "salt"}
    assert isinstance(_res["encrypter"], FernetEncrypter)


def test_init_crypto_old():
    _res = init_encrypter({"password": "long sentence WITH number 64", "salt": "potassium_chloride"})
    assert _res["conf"]["class"] == DEFAULT_CRYPTO
    assert set(_res["conf"]["kwargs"].keys()) == {"password", "salt"}
    assert _res["conf"]["kwargs"]["password"] == "long sentence WITH number 64"
    assert _res["conf"]["kwargs"]["salt"] == "potassium_chloride"

    assert isinstance(_res["encrypter"], FernetEncrypter)


def test_init_crypto_default_alg():
    _conf = {
        "kwargs": {
            "keys": {
                "key_defs": [
                    {"type": "OCT", "use": ["enc"], "kid": "password"},
                    {"type": "OCT", "use": ["enc"], "kid": "salt"},
                ]
            }
        }
    }
    _res = init_encrypter(_conf)
    assert _res["conf"]["class"] == DEFAULT_CRYPTO
    assert set(_res["conf"]["kwargs"].keys()) == {"password", "salt"}
    assert "password" in _res["conf"]["kwargs"]
    assert "salt" in _res["conf"]["kwargs"]

    assert isinstance(_res["encrypter"], FernetEncrypter)


def test_init_crypto():
    _conf = {
        "kwargs": {
            "keys": {
                "key_defs": [
                    {"type": "OCT", "use": ["enc"], "kid": "password"},
                    {"type": "OCT", "use": ["enc"], "kid": "salt"},
                ]
            },
            "hash_alg": "SHA512",
            "iterations": 10,
        }
    }

    _res = init_encrypter(_conf)
    assert _res["conf"]["class"] == DEFAULT_CRYPTO
    assert set(_res["conf"]["kwargs"].keys()) == {"password", "salt", "hash_alg", "iterations"}
    assert "password" in _res["conf"]["kwargs"]
    assert "salt" in _res["conf"]["kwargs"]

    assert isinstance(_res["encrypter"], FernetEncrypter)


def test_init_crypto_password():
    _conf = {"kwargs": {"password": "long sentence WITH number 64"}}

    _res = init_encrypter(_conf)
    assert _res["conf"]["class"] == DEFAULT_CRYPTO
    assert set(_res["conf"]["kwargs"].keys()) == {"password", "salt"}
    assert _res["conf"]["kwargs"]["password"] == "long sentence WITH number 64"
    assert len(_res["conf"]["kwargs"]["salt"]) == 16

    assert isinstance(_res["encrypter"], FernetEncrypter)


def test_init_crypto_keys():
    _conf = {
        "keys": {
            "private_path": "private/cookie_jwks.json",
            "key_defs": [
                {"type": "OCT", "use": ["enc"], "kid": "enc"},
                {"type": "OCT", "use": ["sig"], "kid": "sig"},
            ],
            "read_only": False,
        }
    }
    _res = init_encrypter(_conf)
    assert _res["conf"]["class"] == DEFAULT_CRYPTO
    assert set(_res["conf"]["kwargs"].keys()) == {"password", "salt"}
    assert "password" in _res["conf"]["kwargs"]
    assert "salt" in _res["conf"]["kwargs"]
