import os
from typing import Optional

from cryptojwt.key_jar import init_key_jar

from idpyoidc.util import instantiate

DEFAULT_CRYPTO = "cryptojwt.jwe.fernet.FernetEncrypter"


def default_crypt_config():
    return {
        "class": DEFAULT_CRYPTO,
        "kwargs": {
            "key": os.urandom(32),
            # "password": os.urandom(16),
            "salt": os.urandom(16)
            # "keys": {
            #     "key_defs": [
            #         {"type": "OCT", "use": ["enc"], "kid": "password"},
            #         {"type": "OCT", "use": ["enc"], "kid": "salt"},
            #     ]
            # },
            # "hash_alg": "SHA256",
            # "digest_size": 0,
            # "iterations": DEFAULT_ITERATIONS,
        },
    }


def get_crypt_config(conf):
    # Try the new version first.
    _crypt_config = conf.get("encrypter")
    if _crypt_config is None:
        # try old variant
        _pwd = conf.get("password")
        if not _pwd:
            _crypt_config = default_crypt_config()
        else:
            _args = {"password": _pwd}
            _args["salt"] = conf.get("salt", os.urandom(16))
            _crypt_config = {"class": "cryptojwt.jwe.fernet.FernetEncrypter", "kwargs": _args}
    return _crypt_config


# This is pretty complex because it must be able to cope with many variants.
def init_encrypter(conf: Optional[dict] = None):
    if conf is None:
        conf = default_crypt_config()
        _kwargs = conf.get("kwargs")
        _class = conf.get("class")
    else:
        _class = conf.get("class", DEFAULT_CRYPTO)
        # either keys or password/salt
        _cargs = conf.get("kwargs")
        if _cargs is None:
            if conf.get("password"):
                _kwargs = {
                    "password": conf.get("password"),
                    "salt": conf.get("salt", os.urandom(16)),
                }
                for attr, val in conf.items():
                    if attr in ["password", "salt"]:
                        continue
                    _kwargs[attr] = val
            elif conf.get("keys"):
                _kj = init_key_jar(**conf["keys"])
                _kwargs = {}
                for usage in ["password", "salt"]:
                    _key = _kj.get_encrypt_key(kid=usage)
                    if _key:
                        _kwargs[usage] = _key[0].key
                    else:
                        _kwargs[usage] = os.urandom(16)
                for attr, val in conf.items():
                    if attr == "keys":
                        continue
                    _kwargs[attr] = val
            else:
                _kwargs = default_crypt_config().get("kwargs")
        else:
            if "keys" in _cargs:
                _kj = init_key_jar(**_cargs["keys"])
                _kwargs = {}
                for usage in ["password", "salt"]:
                    _key = _kj.get_encrypt_key(kid=usage)
                    if _key:
                        _kwargs[usage] = _key[0].key
                    else:
                        _kwargs[usage] = os.urandom(16)
            else:
                _kwargs = {
                    usage: _cargs.get(usage, os.urandom(16)) for usage in ["password", "salt"]
                }
            for attr, val in _cargs.items():
                if attr == "keys":
                    continue
                _kwargs[attr] = val
    return {
        "encrypter": instantiate(_class, **_kwargs),
        "conf": {"class": _class, "kwargs": _kwargs},
    }
