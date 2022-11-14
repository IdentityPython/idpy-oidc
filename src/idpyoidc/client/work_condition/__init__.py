from typing import Callable
from typing import Optional

from cryptojwt.jwe import SUPPORTED
from cryptojwt.jws.jws import SIGNER_ALGS
from cryptojwt.utils import importer

from idpyoidc.client.service import Service
from idpyoidc.impexp import ImpExp
from idpyoidc.util import qualified_name


def work_condition_dump(info, exclude_attributes):
    return {qualified_name(info.__class__): info.dump(exclude_attributes=exclude_attributes)}


def work_condition_load(item: dict, **kwargs):
    _class_name = list(item.keys())[0]  # there is only one
    _cls = importer(_class_name)
    _cls = _cls().load(item[_class_name])
    return _cls


class WorkCondition(ImpExp):
    parameter = {
        "prefer": None,
        "use": None,
        "callback_path": None,
        "_local": None
    }

    _supports = {}

    def __init__(self,
                 prefer: Optional[dict] = None,
                 callback_path: Optional[dict] = None):

        ImpExp.__init__(self)
        if isinstance(prefer, dict):
            self.prefer = {k: v for k, v in prefer.items() if k in self.supports}
        else:
            self.prefer = {}

        self.callback_path = callback_path or {}
        self.use = {}
        self._local = {}
        self.callback = {}

    def get_usage(self):
        return self.use

    def set_usage_claim(self, key, value):
        self.use[key] = value

    def get_usage_claim(self, key, default=None):
        return self.use.get(key, default)

    def get_preference(self, key, default=None):
        return self.prefer.get(key, default)

    def set_preference(self, key, value):
        self.prefer[key] = value

    def _callback_uris(self, base_url, hex):
        _uri = []
        for type in self.get_usage_claim("response_types",
                                         self._supports['response_types']):
            if "code" in type:
                _uri.append('code')
            elif type in ["id_token", "id_token token"]:
                _uri.append('implicit')

        if "form_post" in self.supports:
            _uri.append("form_post")

        callback_uri = {}
        for key in _uri:
            callback_uri[key] = Service.get_uri(base_url, self.callback_path[key], hex)
        return callback_uri

    def construct_redirect_uris(self,
                                base_url: str,
                                hex: str,
                                callbacks: Optional[dict] = None):
        if not callbacks:
            callbacks = self._callback_uris(base_url, hex)

        if callbacks:
            self.set_preference("redirect_uris", [v for k, v in callbacks.items()])

        self.callback = callbacks

    def verify_rules(self):
        return True

    def locals(self, info):
        pass

    def load_conf(self, info):
        for attr, val in info.items():
            if attr == "preference":
                for k, v in val.items():
                    if k in self._supports:
                        self.set_preference(k, v)
            elif attr in self._supports:
                self.set_preference(attr, val)

        # # defaults if nothing else is given
        # for key, default in self._supports.items():
        #     if default and key not in self.prefer:
        #         self.set_preference(key, default)

        self.locals(info)
        self.verify_rules()
        return self

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


def get_signing_algs():
    # Assumes Cryptojwt
    return list(SIGNER_ALGS.keys())


def get_encryption_algs():
    return SUPPORTED['alg']


def get_encryption_encs():
    return SUPPORTED['enc']
