from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt import KeyJar
from cryptojwt.key_jar import init_key_jar
from idpyoidc.configure import Configuration
from idpyoidc.impexp import ImpExp
from idpyoidc.util import instantiate


class Unit(ImpExp):
    name = ''

    def __init__(self,
                 upstream_get: Callable = None,
                 keyjar: Optional[KeyJar] = None,
                 httpc: Optional[object] = None,
                 httpc_params: Optional[dict] = None,
                 config: Optional[Union[Configuration, dict]] = None,
                 entity_id: Optional[str] = "",
                 key_conf: Optional[dict] = None
                 ):
        ImpExp.__init__(self)
        self.upstream_get = upstream_get
        self.httpc = httpc

        if config is None:
            config = {}

        self.entity_id = entity_id or config.get('entity_id', "")
        if not self.entity_id:
            self.entity_id = config.get('issuer', "")

        if keyjar or key_conf or config.get('key_conf') or config.get('jwks') or config.get('keys'):
            self.keyjar = self._keyjar(keyjar, conf=config, entity_id=self.entity_id,
                                       key_conf=key_conf)
        else:
            self.keyjar = KeyJar()

        self.httpc_params = httpc_params or config.get("httpc_params", {})

        if self.keyjar:
            self.keyjar.httpc = self.httpc
            self.keyjar.httpc_params = self.httpc_params

    def unit_get(self, what, *arg):
        _func = getattr(self, "get_{}".format(what), None)
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

    def _keyjar(self,
                keyjar: Optional[KeyJar] = None,
                conf: Optional[Union[dict, Configuration]] = None,
                entity_id: Optional[str] = "",
                key_conf: Optional[dict] = None):
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

            if _keyjar and "" in _keyjar and entity_id:
                # make sure I have the keys under my own name too (if I know it)
                _keyjar.import_jwks_as_json(_keyjar.export_jwks_as_json(True, ""), entity_id)

            return _keyjar
        else:
            return keyjar


def find_topmost_unit(unit):
    while hasattr(unit, 'upstream_get'):
        unit = unit.upstream_get('unit')

    return unit


class ClientUnit(Unit):
    name = ''

    def __init__(self,
                 upstream_get: Callable = None,
                 httpc: Optional[object] = None,
                 httpc_params: Optional[dict] = None,
                 keyjar: Optional[KeyJar] = None,
                 context: Optional[ImpExp] = None,
                 config: Optional[Union[Configuration, dict]] = None,
                 jwks_uri: Optional[str] = "",
                 entity_id: Optional[str] = "",
                 key_conf: Optional[dict] = None
                 ):
        Unit.__init__(self, upstream_get=upstream_get, keyjar=keyjar, httpc=httpc,
                      httpc_params=httpc_params, config=config, entity_id=entity_id,
                      key_conf=key_conf)

        self.context = context or None


class Collection(Unit):

    def __init__(self,
                 upstream_get: Callable = None,
                 keyjar: Optional[KeyJar] = None,
                 httpc: Optional[object] = None,
                 httpc_params: Optional[dict] = None,
                 config: Optional[Union[Configuration, dict]] = None,
                 entity_id: Optional[str] = "",
                 key_conf: Optional[dict] = None,
                 functions: Optional[dict] = None,
                 metadata: Optional[dict] = None
                 ):

        Unit.__init__(self, upstream_get, keyjar, httpc, httpc_params, config, entity_id, key_conf)

        _args = {
            'upstream_get': self.unit_get
        }

        self.metadata = metadata or {}

        if functions:
            for key, val in functions.items():
                _kwargs = val["kwargs"].copy()
                _kwargs.update(_args)
                setattr(self, key, instantiate(val["class"], **_kwargs))
