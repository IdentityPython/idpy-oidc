from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt import KeyJar
from cryptojwt.key_jar import init_key_jar

from idpyoidc.configure import Configuration
from idpyoidc.impexp import ImpExp
from idpyoidc.util import instantiate


def create_keyjar(
    keyjar: Optional[KeyJar] = None,
    conf: Optional[Union[dict, Configuration]] = None,
    key_conf: Optional[dict] = None,
    id: Optional[str] = "",
):
    if keyjar is None:
        if key_conf:
            keys_args = {k: v for k, v in key_conf.items() if k != "uri_path"}
            _keyjar = init_key_jar(**keys_args)
        elif conf:
            if "keys" in conf:
                keys_args = {k: v for k, v in conf["keys"].items() if k != "uri_path"}
                _keyjar = init_key_jar(**keys_args)
            elif "key_conf" in conf:
                keys_args = {k: v for k, v in conf["key_conf"].items() if k != "uri_path"}
                _keyjar = init_key_jar(**keys_args)
            else:
                _keyjar = KeyJar()
                if "jwks" in conf:
                    _keyjar.import_jwks(conf["jwks"], "")
        else:
            _keyjar = None

        if _keyjar and "" in _keyjar and id:
            # make sure I have the keys under my own name too (if I know it)
            _keyjar.import_jwks_as_json(_keyjar.export_jwks_as_json(True, ""), id)

        return _keyjar
    else:
        return keyjar


def make_keyjar(
        keyjar: Optional[Union[KeyJar, bool]] = None,
        config: Optional[Union[Configuration, dict]] = None,
        key_conf: Optional[dict] = None,
        issuer_id: Optional[str] = "",
        client_id: Optional[str] = "",
):
    if keyjar is False:
        return None

    keyjar = keyjar or config.get("keyjar")
    key_conf = key_conf or config.get("key_conf", config.get("keys"))

    if not keyjar and not key_conf:
        keyjar = KeyJar()
        _jwks = config.get("jwks")
        if _jwks:
            keyjar.import_jwks_as_json(_jwks, client_id)

    if keyjar or key_conf:
        # Should be either one
        id = issuer_id or client_id
        keyjar = create_keyjar(keyjar, conf=config, key_conf=key_conf, id=id)
        if client_id:
            _key = config.get("client_secret")
            if _key:
                keyjar.add_symmetric(client_id, _key)
                keyjar.add_symmetric("", _key)
    else:
        if client_id:
            _key = config.get("client_secret")
            if _key:
                keyjar = KeyJar()
                keyjar.add_symmetric(client_id, _key)
                keyjar.add_symmetric("", _key)
        # else:
        #     keyjar = build_keyjar(DEFAULT_KEY_DEFS)
        #     if issuer_id:
        #         keyjar.import_jwks(keyjar.export_jwks(private=True), issuer_id)

    return keyjar


class Node:
    def __init__(self, upstream_get: Callable = None):
        self.upstream_get = upstream_get

    def unit_get(self, what, *arg):
        _func = getattr(self, f"get_{what}", None)
        if _func:
            return _func(*arg)
        return None

    def get_attribute(self, attr, *args):
        try:
            val = getattr(self, attr)
        except AttributeError:
            if self.upstream_get:
                return self.upstream_get("attribute", attr)
            else:
                return None
        else:
            if val is None and self.upstream_get:
                return self.upstream_get("attribute", attr)
            else:
                return val

    def set_attribute(self, attr, val):
        setattr(self, attr, val)

    def get_unit(self, *args):
        return self


class Unit(ImpExp):
    name = ""

    init_args = ["upstream_get"]

    def __init__(
        self,
        upstream_get: Callable = None,
        keyjar: Optional[Union[KeyJar, bool]] = None,
        httpc: Optional[object] = None,
        httpc_params: Optional[dict] = None,
        config: Optional[Union[Configuration, dict]] = None,
        key_conf: Optional[dict] = None,
        issuer_id: Optional[str] = "",
        client_id: Optional[str] = "",
    ):
        ImpExp.__init__(self)
        self.upstream_get = upstream_get
        self.httpc = httpc

        if config is None:
            config = {}

        self.keyjar = make_keyjar(keyjar, config, key_conf, issuer_id, client_id)

        self.httpc_params = httpc_params or config.get("httpc_params", {})

        if self.keyjar:
            self.keyjar.httpc = self.httpc
            self.keyjar.httpc_params = self.httpc_params

    def unit_get(self, what, *arg):
        _func = getattr(self, f"get_{what}", None)
        if _func:
            return _func(*arg)
        return None

    def get_attribute(self, attr, *args):
        val = getattr(self, attr, None)
        if val:
            return val

        cntx = getattr(self, "context", None)
        if cntx:
            val = getattr(cntx, attr, None)
            if val:
                return val

        # Go upstairs if possible
        if self.upstream_get:
            return self.upstream_get("attribute", attr)
        else:
            return val

    def set_attribute(self, attr, val):
        setattr(self, attr, val)

    def get_unit(self, *args):
        return self


def topmost_unit(unit):
    if hasattr(unit, "upstream_get"):
        if unit.upstream_get:
            superior = unit.upstream_get("unit")
            if superior:
                unit = topmost_unit(superior)

    return unit


class ClientUnit(Unit):
    name = ""

    def __init__(
        self,
        upstream_get: Callable = None,
        httpc: Optional[object] = None,
        httpc_params: Optional[dict] = None,
        keyjar: Optional[KeyJar] = None,
        context: Optional[ImpExp] = None,
        config: Optional[Union[Configuration, dict]] = None,
        # jwks_uri: Optional[str] = "",
        entity_id: Optional[str] = "",
        key_conf: Optional[dict] = None,
    ):
        if config is None:
            config = {}

        self.entity_id = entity_id or config.get("entity_id")
        self.client_id = config.get("client_id", entity_id)

        Unit.__init__(
            self,
            upstream_get=upstream_get,
            keyjar=keyjar,
            httpc=httpc,
            httpc_params=httpc_params,
            config=config,
            client_id=self.client_id,
            key_conf=key_conf,
        )

        self.context = context or None

    def get_context_attribute(self, attr, *args):
        _val = getattr(self.context, attr)
        if not _val and self.upstream_get:
            return self.upstream_get("context_attribute", attr)
        else:
            return _val


# Neither client nor Server
class Collection(Unit):
    def __init__(
        self,
        upstream_get: Callable = None,
        keyjar: Optional[KeyJar] = None,
        httpc: Optional[object] = None,
        httpc_params: Optional[dict] = None,
        config: Optional[Union[Configuration, dict]] = None,
        entity_id: Optional[str] = "",
        key_conf: Optional[dict] = None,
        functions: Optional[dict] = None,
        claims: Optional[dict] = None,
    ):
        if config is None:
            config = {}

        self.entity_id = entity_id or config.get("entity_id")

        Unit.__init__(
            self,
            upstream_get,
            keyjar,
            httpc,
            httpc_params,
            config,
            issuer_id=self.entity_id,
            key_conf=key_conf,
        )

        _args = {"upstream_get": self.unit_get}

        self.claims = claims or {}
        self.upstream_get = upstream_get
        # self.context = {}

        if functions:
            for key, val in functions.items():
                _kwargs = val["kwargs"].copy()
                _kwargs.update(_args)
                setattr(self, key, instantiate(val["class"], **_kwargs))

    def get_context_attribute(self, attr, *args):
        _cntx = getattr(self, "context", None)
        if _cntx:
            _val = getattr(_cntx, attr, None)
            if _val:
                return _val

        if self.upstream_get:
            return self.upstream_get("context_attribute", attr)
        else:
            return None

    def get_attribute(self, attr, *args):
        val = getattr(self, attr, None)
        if val:
            return val

        if self.upstream_get:
            return self.upstream_get("attribute", attr)
        else:
            return None
