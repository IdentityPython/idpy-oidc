from functools import cmp_to_key
from typing import Callable
from typing import Optional

from cryptojwt.jwe import SUPPORTED
from cryptojwt.jws.jws import SIGNER_ALGS
from cryptojwt.utils import importer

from idpyoidc.client.client_auth import CLIENT_AUTHN_METHOD
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
        for type in self.get_usage("response_types", self._supports['response_types']):
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
            self.set_preference('callbacks', callbacks)
            self.set_preference("redirect_uris", [v for k, v in callbacks.items()])

        self.callback = callbacks

    def verify_rules(self):
        return True

    def locals(self, info):
        pass

    def load_conf(self, info, supports):
        for attr, val in info.items():
            if attr == "preference":
                for k, v in val.items():
                    if k in supports:
                        self.set_preference(k, v)
            elif attr in supports:
                self.set_preference(attr, val)

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

    def supported(self, claim):
        return claim in self._supports

    def prefers(self):
        return self.prefer


SIGNING_ALGORITHM_SORT_ORDER = ['RS', 'ES', 'PS', 'HS']


def cmp(a, b):
    return (a > b) - (a < b)


def alg_cmp(a, b):
    if a == 'none':
        return 1
    elif b == 'none':
        return -1

    _pos1 = SIGNING_ALGORITHM_SORT_ORDER.index(a[0:2])
    _pos2 = SIGNING_ALGORITHM_SORT_ORDER.index(b[0:2])
    if _pos1 == _pos2:
        return (a > b) - (a < b)
    elif _pos1 > _pos2:
        return 1
    else:
        return -1


def get_signing_algs():
    # Assumes Cryptojwt
    return sorted(list(SIGNER_ALGS.keys()), key=cmp_to_key(alg_cmp))


def get_encryption_algs():
    return SUPPORTED['alg']


def get_encryption_encs():
    return SUPPORTED['enc']


def get_client_authn_methods():
    return list(CLIENT_AUTHN_METHOD.keys())
