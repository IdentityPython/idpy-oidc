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

from cryptojwt import KeyBundle
from cryptojwt import KeyJar
from cryptojwt import as_unicode
from cryptojwt.jwk.asym import AsymmetricKey
from cryptojwt.jwk.hmac import SYMKey
from cryptojwt.key_issuer import KeyIssuer
from cryptojwt.utils import as_bytes
from cryptojwt.utils import importer
import yaml

from idpyoidc import init_args_from_source

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

    _module = cls.__module__
    try:
        return _module + "." + cls.name
    except AttributeError:
        try:
            return _module + "." + cls.__name__
        except AttributeError:
            try:
                return _module + "." + cls.__qualname__
            except AttributeError:
                return _module + "." + cls.__class__.__name__


# def conf_get(config, attr, default=None):
#     _res = config.get(attr, None)
#     if _res is None:
#         _conf = getattr(config, "conf", None)
#         if _conf:
#             _res = _conf.get(attr, None)
#             if _res:
#                 return _res
#
#         return default
#     else:
#         return _res


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
        _keyjar.import_jwks(kj1.export_jwks(issuer_id=issuer_id, private=private),
                            issuer_id=issuer_id)
        _keyjar.import_jwks(kj2.export_jwks(issuer_id=issuer_id, private=private),
                            issuer_id=issuer_id)
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
            _keyjar.import_jwks(keyjars[0].export_jwks(issuer_id=issuer_id, private=private),
                                issuer_id=issuer_id)
            _keyjar.import_jwks(keyjars[1].export_jwks(issuer_id=issuer_id, private=private),
                                issuer_id=issuer_id)

    else:  # more than 2 keyjars
        issuers = keyjars[0].owners()
        for nr in range(1, len(keyjars)):
            issuers.extend(keyjars[nr].owners())
        issuers = list(set(issuers))

        _keyjar = KeyJar()
        for iss in issuers:
            for nr in range(1, len(keyjars)):
                _keyjar.import_jwks(keyjars[nr].export_jwks(issuer_id=iss, private=private),
                                    issuer_id=iss)

    return _keyjar


def load_key(info):
    typ, spec = info.split('::')
    _key = importer(typ)
    _dict = json.loads(spec)
    if typ == 'cryptojwt.jwk.hmac.SYMKey':
        __key = _key(k=as_bytes(_dict['k']))
        for k, v in _dict.items():
            if k in ['k', 'key']:
                continue
            setattr(_key, k, v)
    else:
        __key = _key(**_dict)
    # special case
    _ia = getattr(__key, 'inactive_since', None)
    if _ia is None:
        setattr(__key, 'inactive_since', 0)

    return __key


def key_bundle_load(info):
    key_bundle = KeyBundle()
    for k, v in info.items():
        if k == '_keys':
            setattr(key_bundle, '_keys', [load_key(a) for a in v])
        else:
            setattr(key_bundle, k, v)
    return key_bundle


def key_issuer_load(info):
    key_issuer = KeyIssuer()
    for k, v in info.items():
        if k == "keybundle_cls":
            setattr(key_issuer, k, importer(v))
        elif k == '_bundles':
            setattr(key_issuer, k, [key_bundle_load(val) for val in v])
        else:
            setattr(key_issuer, k, v)
    return key_issuer


def keyjar_load(item: dict, init_args: Optional[dict] = None, load_args: Optional[dict] = None):
    keyjar = KeyJar()
    for key, val in item.items():
        if key == "issuers":
            for k, v in val.items():
                iss = key_issuer_load(v)
                keyjar._issuers[k] = iss
        else:
            setattr(keyjar, key, val)
    return keyjar


def keys_dump(key_bundle):
    _keys = []
    for k_val in key_bundle._keys:
        # one key
        params, has_kwargs = init_args_from_source(k_val)
        init_args = {k: getattr(k_val, k, None) for k in params}
        if isinstance(k_val, SYMKey):
            # 'k' is the base64 encoded version of 'key'. Only need one of them.
            if 'k' in init_args:
                init_args['k'] = as_unicode(init_args['k'])
            if 'key' in init_args:
                del init_args['key']
        _keys.append(f'{qualified_name(k_val)}::{json.dumps(init_args)}')
    return _keys


def key_bundle_dump(key_issuer):
    _bundles = []
    for key_bundle in key_issuer._bundles:
        # A key bundle
        _bundle = {}
        for b_key in key_bundle.params:
            val = getattr(key_bundle, b_key, None)
            if val:
                _bundle[b_key] = val
        # bundle keys
        _bundle['_keys'] = keys_dump(key_bundle)
        _bundles.append(_bundle)
    return _bundles


def key_issuer_dump(item):
    issuers = {}
    # issuers
    for issuer, key_issuer in item.items():
        # About a key issuer
        _iss = {}
        # issuer parameters
        for i_key in key_issuer.params:
            val = getattr(key_issuer, i_key, None)
            if val:
                if i_key == "keybundle_cls":
                    _iss[i_key] = qualified_name(val)
                else:
                    _iss[i_key] = val
        # issuer bundles
        _iss['_bundles'] = key_bundle_dump(key_issuer)
        issuers[issuer] = _iss
    return issuers


def keyjar_dump(item, exclude_attributes):
    res = {}
    for key in ["httpc_params", "remove_after"]:
        val = getattr(item, key, None)
        if val:
            res[key] = val
    res['issuers'] = key_issuer_dump(item._issuers)
    return res
