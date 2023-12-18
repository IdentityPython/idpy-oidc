from typing import Callable
from typing import Optional

from cryptojwt import KeyJar
from cryptojwt.key_jar import init_key_jar
from cryptojwt.utils import importer

from idpyoidc.client.util import get_uri
from idpyoidc.impexp import ImpExp
from idpyoidc.util import add_path
from idpyoidc.util import qualified_name


def claims_dump(info, exclude_attributes):
    return {qualified_name(info.__class__): info.dump(exclude_attributes=exclude_attributes)}


def claims_load(item: dict, **kwargs):
    _class_name = list(item.keys())[0]  # there is only one
    _cls = importer(_class_name)
    _cls = _cls().load(item[_class_name])
    return _cls


class Claims(ImpExp):
    parameter = {"prefer": None, "use": None, "callback_path": None, "_local": None}

    _supports = {}

    def __init__(self, prefer: Optional[dict] = None, callback_path: Optional[dict] = None):

        ImpExp.__init__(self)
        if isinstance(prefer, dict):
            self.prefer = {k: v for k, v in prefer.items() if k in self._supports}
        else:
            self.prefer = {}

        self.callback_path = callback_path or {}
        self.use = {}
        self._local = {}

    def get_use(self):
        return self.use

    def set_usage(self, key, value):
        self.use[key] = value

    def get_usage(self, key, default=None):
        return self.use.get(key, default)

    def get_preference(self, key, default=None):
        return self.prefer.get(key, default)

    def set_preference(self, key, value):
        self.prefer[key] = value

    def remove_preference(self, key):
        if key in self.prefer:
            del self.prefer[key]

    def _callback_uris(self, base_url, hex):
        _uri = []
        for type in self.get_usage("response_types", self._supports["response_types"]):
            if "code" in type:
                _uri.append("code")
            elif type in ["id_token"]:
                _uri.append("implicit")

        if "form_post" in self._supports:
            _uri.append("form_post")

        callback_uri = {}
        for key in _uri:
            callback_uri[key] = get_uri(base_url, self.callback_path[key], hex)
        return callback_uri

    def construct_redirect_uris(self, base_url: str, hex: str, callbacks: Optional[dict] = None):
        if not callbacks:
            callbacks = self._callback_uris(base_url, hex)

        if callbacks:
            self.set_preference("callbacks", callbacks)
            self.set_preference("redirect_uris", [v for k, v in callbacks.items()])

        self.callback = callbacks

    def verify_rules(self, supports):
        return True

    def locals(self, info):
        pass

    def _keyjar(self, keyjar=None, conf=None, entity_id=""):
        _uri_path = ""
        if keyjar is None:
            if "keys" in conf:
                keys_args = {k: v for k, v in conf["keys"].items() if k != "uri_path"}
                _keyjar = init_key_jar(**keys_args)
                _uri_path = conf["keys"].get("uri_path")
            elif "key_conf" in conf and conf["key_conf"]:
                keys_args = {k: v for k, v in conf["key_conf"].items() if k != "uri_path"}
                _keyjar = init_key_jar(**keys_args)
                _uri_path = conf["key_conf"].get("uri_path")
            else:
                _keyjar = KeyJar()
                if "jwks" in conf:
                    _keyjar.import_jwks(conf["jwks"], "")

            if "" in _keyjar and entity_id:
                # make sure I have the keys under my own name too (if I know it)
                _keyjar.import_jwks_as_json(_keyjar.export_jwks_as_json(True, ""), entity_id)

            _httpc_params = conf.get("httpc_params")
            if _httpc_params:
                _keyjar.httpc_params = _httpc_params
            return _keyjar, _uri_path
        else:
            if "keys" in conf:
                _uri_path = conf["keys"].get("uri_path")
            elif "key_conf" in conf and conf["key_conf"]:
                _uri_path = conf["key_conf"].get("uri_path")

        return keyjar, _uri_path

    def get_base_url(self, configuration: dict, entity_id: Optional[str]=""):
        raise NotImplementedError()

    def get_id(self, configuration: dict):
        raise NotImplementedError()

    def add_extra_keys(self, keyjar, id):
        return None

    def get_jwks(self, keyjar):
        return keyjar.export_jwks()

    def handle_keys(self,
                    configuration: dict,
                    keyjar: Optional[KeyJar] = None,
                    entity_id: Optional[str] = ""):
        _jwks = _jwks_uri = None
        _id = self.get_id(configuration)
        keyjar, uri_path = self._keyjar(keyjar, configuration, entity_id=_id)

        _kj = self.add_extra_keys(keyjar, _id)
        if keyjar is None and _kj:
            keyjar = _kj

        # now that keys are in the Key Jar, now for how to publish it
        if "jwks_uri" in configuration:  # simple
            _jwks_uri = configuration.get("jwks_uri")
        elif uri_path:
            _base_url = self.get_base_url(configuration, entity_id=entity_id)
            _jwks_uri = add_path(_base_url, uri_path)
        else:  # jwks or nothing
            _jwks = self.get_jwks(keyjar)

        return {"keyjar": keyjar, "jwks": _jwks, "jwks_uri": _jwks_uri}

    def load_conf(
            self,
            configuration: dict,
            supports: dict,
            keyjar: Optional[KeyJar] = None,
            entity_id: Optional[str] = ""
    ) -> KeyJar:
        for attr, val in configuration.items():
            if attr in ["preference", "capabilities"]:
                for k, v in val.items():
                    if k in supports:
                        self.set_preference(k, v)
            elif attr in supports:
                self.set_preference(attr, val)

        self.locals(configuration)

        for key, val in self.handle_keys(configuration, keyjar=keyjar, entity_id=entity_id).items():
            if key == "keyjar":
                keyjar = val
            elif val:
                self.set_preference(key, val)

        self.verify_rules(supports)
        return keyjar

    def get(self, key, default=None):
        if key in self._local:
            return self._local[key]
        else:
            return default

    def set(self, key, val):
        self._local[key] = val

    def construct_uris(self, *args):
        pass

    def supports(self):
        res = {}
        for key, val in self._supports.items():
            if isinstance(val, Callable):
                res[key] = val()
            else:
                res[key] = val
        return res

    def supported(self, claim):
        return claim in self._supports

    def prefers(self):
        return self.prefer

    def get_claim(self, key, default=None):
        _val = self.get_usage(key)
        if _val is None:
            _val = self.get_preference(key)

        if _val is None:
            return default
        else:
            return _val
