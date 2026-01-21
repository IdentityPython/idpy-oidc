import base64
import importlib
import json
import logging
import os
import secrets
import sys
from typing import List
from typing import Optional
from typing import Union
from urllib.parse import parse_qs
from urllib.parse import quote_plus
from urllib.parse import unquote_plus
from urllib.parse import urlsplit
from urllib.parse import urlunsplit

import yaml
from cryptojwt import KeyJar
from cryptojwt.jwk.asym import AsymmetricKey
from cryptojwt.utils import importer

logger = logging.getLogger(__name__)


def rndstr(size=16):
    """
    Returns a string of random url safe characters

    :param size: The length of the string
    :return: string
    """
    return secrets.token_urlsafe(size)


def instantiate(cls, **kwargs):
    if isinstance(cls, str):
        return importer(cls)(**kwargs)
    else:
        return cls(**kwargs)


def sanitize(str):
    return str


def load_yaml_config(filename):
    """Load a YAML configuration file."""
    with open(filename, "rt", encoding="utf-8") as file:
        config_dict = yaml.safe_load(file)
    return config_dict


def load_config_file(filename):
    if filename.endswith(".yaml"):
        """Load configuration as YAML"""
        _cnf = load_yaml_config(filename)
    elif filename.endswith(".json"):
        _str = open(filename).read()
        _cnf = json.loads(_str)
    elif filename.endswith(".py"):
        head, tail = os.path.split(filename)
        tail = tail[:-3]
        sys.path.append(head)
        module = importlib.import_module(tail)
        _cnf = getattr(module, "CONFIG")
    else:
        raise ValueError("Unknown file type")

    return _cnf


def split_uri(uri: str) -> [str, Union[dict, None]]:
    """Removes fragment and separates the query part from the rest."""
    p = urlsplit(uri)

    if p.fragment:
        p = p._replace(fragment="")

    if p.query:
        o = p._replace(query="")
        base = urlunsplit(o)
        return [base, parse_qs(p.query)]
    else:
        base = urlunsplit(p)
        return [base, None]


# Converters


class QPKey:

    def serialize(self, str):
        return quote_plus(str)

    def deserialize(self, str):
        return unquote_plus(str)


class JSON:

    def serialize(self, str):
        return json.dumps(str)

    def deserialize(self, str):
        return json.loads(str)


class PassThru:

    def serialize(self, str):
        return str

    def deserialize(self, str):
        return str


class Base64(object):

    @staticmethod
    def serialize(str):
        return base64.b64encode(str.encode("utf-8")).decode("utf-8")

    @staticmethod
    def deserialize(str):
        return base64.b64decode(str.encode("utf-8")).decode("utf-8")


def get_http_params(config):
    params = config.get("httpc_params", {})

    if "verify" not in params:
        _ver = config.get("verify")
        if _ver is None:
            _ver = config.get("verify_ssl", True)
        params["verify"] = _ver

    _cert = config.get("client_cert")
    _key = config.get("client_key")
    if _cert:
        if _key:
            params["cert"] = (_cert, _key)
        else:
            params["cert"] = _cert

    return params


def add_path(url, path):
    if url.endswith("/"):
        if path.startswith("/"):
            return "{}{}".format(url, path[1:])
        else:
            return "{}{}".format(url, path)
    else:
        if path.startswith("/"):
            return "{}{}".format(url, path)
        else:
            return "{}/{}".format(url, path)


def qualified_name(cls):
    """Does both classes and class instances

    :param cls: The item, class or class instance
    :return: fully qualified class name
    """

    try:
        return cls.__module__ + "." + cls.name
    except AttributeError:
        return cls.__module__ + "." + cls.__name__


def conf_get(config, attr, default=None):
    _res = config.get(attr, None)
    if _res is None:
        _conf = getattr(config, "conf", None)
        if _conf:
            _res = _conf.get(attr, None)
            if _res:
                return _res

        return default
    else:
        return _res


def get_keyjar_chain(item) -> list:
    """
    Returns a list of Key Jars.

    :param item: An item, can be a service, a context, a client or ...
    """
    res = []
    if item.upstream_get:
        _thing = item.upstream_get('unit')
        if _thing:
            _partial_res = get_keyjar_chain(_thing)
            if _partial_res:
                res.extend(_partial_res)

    _keyjar = getattr(item, "keyjar", None)
    if _keyjar:
        res.append(_keyjar)
    return res


def get_asymetric_keys_from_keyjar_chain(keyjar_chain: List[KeyJar],
                                         key_usages: List[str],
                                         owner: Optional[str] = '',
                                         key_type: Optional[str] = '',
                                         kid: Optional[str] = None) -> list:
    keys = []
    for keyjar in keyjar_chain:
        for usage in key_usages:
            _keys = keyjar.get(key_use=usage, key_type=key_type, issuer_id=owner, kid=kid)
            if _keys:
                _async_keys = [k for k in _keys if isinstance(k, AsymmetricKey)]
                if _async_keys:  # May have to check if the key is already in the list of keys
                    keys.extend(_async_keys)

    return keys


def keyjar_from_keyjar_chain(keyjar_chain: List[KeyJar]):
    keyjar = KeyJar()

    for kj in keyjar_chain:
        for iss in kj.owners():
            if iss == '':
                continue
            keyjar.import_jwks(kj.export_jwks(issuer_id=iss), issuer_id=iss)
    return keyjar


def jwks_from_keys(keys) -> dict:
    keyser = [k.serialize() for k in keys]
    return {"keys": keyser}


def use_default_keys(keyjar, key_conf, config):
    if keyjar or key_conf:
        return False

    if config:
        for attr in ['key_conf', 'keys', 'jwks']:
            if config.get(attr):
                return False

    return True


def get_jwks(item) -> dict:
    key_chain = get_keyjar_chain(item)
    if key_chain:
        keys = get_asymetric_keys_from_keyjar_chain(key_chain, key_usages=['sig'])
        if keys:
            return jwks_from_keys(keys)
    return {}


def _eval(item, server_entity_id=""):
    context = getattr(item, 'context', None)
    if context:
        if isinstance(context, dict):
            if server_entity_id in context:
                _keyjar = getattr(context[server_entity_id], 'keyjar', None)
                if _keyjar is not None:
                    return {"keyjar": _keyjar}
        else:
            _keyjar = getattr(context, 'keyjar', None)
            if _keyjar is not None:
                return {"keyjar": _keyjar}
    if item.upstream_get:
        return {"superior": item.upstream_get('unit')}
    else:
        return None


def get_keyjar(item, server_entity_id=""):
    res = _eval(item, server_entity_id)
    if res is None:
        return None
    if "keyjar" in res:
        return res["keyjar"]

    _superior = res["superior"]
    while True:
        res = _eval(_superior, server_entity_id)
        if 'keyjar' in res:
            return res["keyjar"]
        elif 'superior' in res:
            _superior = res["superior"]
        else:
            break
    return None


def keyjar_join(kj1, kj2, issuer_id='', private=False):
    _keyjar = KeyJar()
    _keyjar.import_jwks(kj1.export_jwks(issuer_id=issuer_id, private=private), issuer_id=issuer_id)
    _keyjar.import_jwks(kj2.export_jwks(issuer_id=issuer_id, private=private), issuer_id=issuer_id)
    return _keyjar


def wrapped_keyjar_join(entity=None, context=None, issuer_id='', private=False):
    if entity:
        _ent_keyjar = getattr(entity, 'keyjar', None)
        if _ent_keyjar is None:
            return None
        if context:
            _context_keyjar = getattr(context, 'keyjar', None)
            if _context_keyjar is None:
                return None
            return keyjar_join(_ent_keyjar, _context_keyjar, issuer_id, private)
        else:
            context = getattr(entity, 'context', None)
            if context:
                _context_keyjar = getattr(context, 'keyjar', None)
                if _context_keyjar is not None:
                    return keyjar_join(_ent_keyjar, _context_keyjar, issuer_id, private)
    elif context:
        entity = context.upstream_get('unit')
        if entity:
            _ent_keyjar = getattr(entity, 'keyjar', None)
            if _ent_keyjar is None:
                return None
            _context_keyjar = getattr(context, 'keyjar', None)
            if _context_keyjar is None:
                return None
            return keyjar_join(_ent_keyjar, _context_keyjar, issuer_id, private)
    return None


def full_keyjar_join(kj1, kj2, private=False):
    issuers = kj1.owners()
    issuers.extend(kj2.owners())
    issuers = list(set(issuers))
    _keyjar = KeyJar()
    for issuer_id in issuers:
        _keyjar.import_jwks(kj1.export_jwks(issuer_id=issuer_id, private=private), issuer_id=issuer_id)
        _keyjar.import_jwks(kj2.export_jwks(issuer_id=issuer_id, private=private), issuer_id=issuer_id)
    return _keyjar


def keyjar_combination(item,
                       private: Optional[bool] = True,
                       server_entity_id: Optional[str] = '') -> Optional[KeyJar]:
    keyjars = []
    kj = getattr(item, 'keyjar', None)
    if kj:
        keyjars.append(kj)

    _context = getattr(item, 'context', None)
    if _context:
        if isinstance(_context, dict):
            kj = getattr(_context[server_entity_id], 'keyjar', None)
        else:
            kj = getattr(_context, 'keyjar', None)
        if kj:
            keyjars.append(kj)

    if getattr(item, 'upstream_get', None):
        superior = item.upstream_get('unit')
        kj = keyjar_combination(superior, server_entity_id)
        if kj:
            keyjars.append(kj)


    if len(keyjars) == 0:
        return None
    elif len(keyjars) == 1:
        _keyjar = keyjars[0]

    elif len(keyjars) == 2:
        issuers = keyjars[0].owners()
        issuers.extend(keyjars[1].owners())
        issuers = list(set(issuers))
        _keyjar = KeyJar()
        for issuer_id in issuers:
            _keyjar.import_jwks(keyjars[0].export_jwks(issuer_id=issuer_id, private=private), issuer_id=issuer_id)
            _keyjar.import_jwks(keyjars[1].export_jwks(issuer_id=issuer_id, private=private), issuer_id=issuer_id)

    else:  # more than 2 keyjars
        issuers = keyjars[0].owners()
        for nr in range(1, len(keyjars)):
            issuers.extend(keyjars[nr].owners())
        issuers = list(set(issuers))

        _keyjar = KeyJar()
        for iss in issuers:
            for nr in range(1, len(keyjars)):
                _keyjar.import_jwks(keyjars[nr].export_jwks(issuer_id=iss, private=private), issuer_id=iss)

    return _keyjar
