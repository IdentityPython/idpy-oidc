from typing import Optional

from cryptojwt.utils import importer

from idpyoidc.client.service import Service
from idpyoidc.impexp import ImpExp
from idpyoidc.util import qualified_name


def specification_dump(info, exclude_attributes):
    return {qualified_name(info.__class__): info.dump(exclude_attributes=exclude_attributes)}


def specification_load(item: dict, **kwargs):
    _class_name = list(item.keys())[0]  # there is only one
    _cls = importer(_class_name)
    _cls = _cls().load(item[_class_name])
    return _cls


class Specification(ImpExp):
    parameter = {
        "metadata": None,
        "usage": None,
        "behaviour": None,
        "callback": None,
        "_local": None
    }

    attributes = {
        "redirect_uris": None,
        "grant_types": ["authorization_code", "implicit", "refresh_token"],
        "response_types": ["code"],
        "client_name": None,
        "client_uri": None,
        "logo_uri": None,
        "contacts": None,
        "scope": None,
        "tos_uri": None,
        "policy_uri": None,
        "jwks_uri": None,
        "jwks": None,
    }

    rules = {
        "jwks": None,
        "jwks_uri": None,
        "scope": ["openid"],
        "verify_args": None,
    }

    callback_path = {
        "requests": "req",
        "code": "authz_cb",
        "implicit": "authz_im_cb",
    }

    callback_uris = ["redirect_uris"]

    def __init__(self,
                 metadata: Optional[dict] = None,
                 usage: Optional[dict] = None,
                 behaviour: Optional[dict] = None
                 ):

        ImpExp.__init__(self)
        if isinstance(metadata, dict):
            self.metadata = {k: v for k, v in metadata.items() if k in self.attributes}
        else:
            self.metadata = {}

        if isinstance(usage, dict):
            self.usage = {k: v for k, v in usage.items() if k in self.rules}
        else:
            self.usage = {}

        if isinstance(behaviour, dict):
            self.behaviour = {k: v for k, v in behaviour.items() if k in self.attributes}
        else:
            self.behaviour = {}

        self.callback = {}
        self._local = {}

    def get_all(self):
        return self.metadata

    def get_metadata(self, key, default=None):
        if key in self.metadata:
            return self.metadata[key]
        else:
            return default

    def get_usage(self, key, default=None):
        if key in self.usage:
            return self.usage[key]
        else:
            return default

    def set_metadata(self, key, value):
        self.metadata[key] = value

    def set_usage(self, key, value):
        self.usage[key] = value

    def _callback_uris(self, base_url, hex):
        _red = {}
        for type in self.get_metadata("response_types", ["code"]):
            if "code" in type:
                _red['code'] = True
            elif type in ["id_token", "id_token token"]:
                _red['implicit'] = True

        if "form_post" in self.usage:
            _red["form_post"] = True

        callback_uri = {}
        for key in _red.keys():
            _uri = Service.get_uri(base_url, self.callback_path[key], hex)
            callback_uri[key] = _uri
        return callback_uri

    def construct_redirect_uris(self, base_url, hex, callbacks):
        if not callbacks:
            callbacks = self._callback_uris(base_url, hex)

        if callbacks:
            self.set_metadata("redirect_uris", [v for k, v in callbacks.items()])

        self.callback = callbacks

    def verify_rules(self):
        return True

    def locals(self, info):
        pass

    def load_conf(self, info):
        for attr, val in info.items():
            if attr == "usage":
                for k, v in val.items():
                    if k in self.rules:
                        self.set_usage(k, v)
            elif attr == "metadata":
                for k, v in val.items():
                    if k in self.attributes:
                        self.set_metadata(k, v)
            elif attr == "behaviour":
                self.behaviour = val
            elif attr in self.attributes:
                self.set_metadata(attr, val)
            elif attr in self.rules:
                self.set_usage(attr, val)

        # defaults is nothing else is given
        for key, val in self.attributes.items():
            if val and key not in self.metadata:
                self.set_metadata(key, val)

        for key, val in self.rules.items():
            if val and key not in self.usage:
                self.set_usage(key, val)

        self.locals(info)
        self.verify_rules()

    def bm_get(self, key, default=None):
        if key in self.behaviour:
            return self.behaviour[key]
        elif key in self.metadata:
            return self.metadata[key]

        return default

    def get(self, key, default=None):
        if key in self._local:
            return self._local[key]
        else:
            return default

    def set(self, key, val):
        self._local[key] = val

    def construct_uris(self, *args):
        pass