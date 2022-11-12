from typing import Optional

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
        "metadata": None,
        "support": None,
        "behaviour": None,
        "callback": None,
        "_local": None
    }

    metadata_claims = {
        "redirect_uris": None,
        "response_types": ["code"],
        "grant_types": ["authorization_code", "implicit", "refresh_token"],
        "application_type": "web",
        "contacts": None,
        "client_name": None,
        "logo_uri": None,
        "client_uri": None,
        "policy_uri": None,
        "tos_uri": None,
        "jwks_uri": None,
        "jwks": None,
    }

    can_support = {
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
                 support: Optional[dict] = None,
                 behaviour: Optional[dict] = None
                 ):

        ImpExp.__init__(self)
        if isinstance(metadata, dict):
            self.metadata = {k: v for k, v in metadata.items() if k in self.metadata_claims}
        else:
            self.metadata = {}

        if isinstance(support, dict):
            self.support = {k: v for k, v in support.items() if k in self.can_support}
        else:
            self.support = {}

        if isinstance(behaviour, dict):
            self.behaviour = {k: v for k, v in behaviour.items() if k in self.metadata_claims}
        else:
            self.behaviour = {}

        self.callback = {}
        self._local = {}

    def get_metadata(self):
        return self.metadata

    def get_metadata_claim(self, key, default=None):
        if key in self.metadata:
            return self.metadata[key]
        else:
            return default

    def get_support(self, key, default=None):
        if key in self.support:
            return self.support[key]
        else:
            return default

    def set_metadata_claim(self, key, value):
        self.metadata[key] = value

    def set_support(self, key, value):
        self.support[key] = value

    def _callback_uris(self, base_url, hex):
        _red = {}
        for type in self.get_metadata_claim("response_types", ["code"]):
            if "code" in type:
                _red['code'] = True
            elif type in ["id_token", "id_token token"]:
                _red['implicit'] = True

        if "form_post" in self.support:
            _red["form_post"] = True

        callback_uri = {}
        for key in _red.keys():
            _uri = Service.get_uri(base_url, self.callback_path[key], hex)
            callback_uri[key] = _uri
        return callback_uri

    def construct_redirect_uris(self,
                                base_url: str,
                                hex: str,
                                callbacks: Optional[dict] = None):
        if not callbacks:
            callbacks = self._callback_uris(base_url, hex)

        if callbacks:
            self.set_metadata_claim("redirect_uris", [v for k, v in callbacks.items()])

        self.callback = callbacks

    def verify_rules(self):
        return True

    def locals(self, info):
        pass

    def load_conf(self, info):
        for attr, val in info.items():
            if attr == "support":
                for k, v in val.items():
                    if k in self.can_support:
                        self.set_support(k, v)
            elif attr == "metadata":
                for k, v in val.items():
                    if k in self.metadata_claims:
                        self.set_metadata_claim(k, v)
            elif attr == "behaviour":
                self.behaviour = val
            elif attr in self.metadata_claims:
                self.set_metadata_claim(attr, val)
            elif attr in self.can_support:
                self.set_support(attr, val)

        # defaults if nothing else is given
        for key, default in self.metadata_claims.items():
            if default and key not in self.metadata:
                self.set_metadata_claim(key, default)

        for key, default in self.can_support.items():
            if default and key not in self.support:
                self.set_support(key, default)

        self.locals(info)
        self.verify_rules()
        return self

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
