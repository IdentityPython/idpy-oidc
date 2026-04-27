import copy
from typing import Callable
from typing import Optional
from urllib.parse import quote_plus

from idpyoidc.impexp import ImpExp
from idpyoidc.util import keyjar_dump
from idpyoidc.util import keyjar_load


def add_issuer(conf, issuer):
    res = {}
    for key, val in conf.items():
        if key == "abstract_storage_cls":
            res[key] = val
        else:
            _val = copy.copy(val)
            _val["issuer"] = quote_plus(issuer)
            res[key] = _val
    return res


class Context(ImpExp):
    parameter = {"entity_id": None}

    special_load_dump = {
        "keyjar": {"load": keyjar_load, 'dump': keyjar_dump}
    }

    def __init__(self, config=None, entity_id="", upstream_get: Optional[Callable] = None):
        ImpExp.__init__(self)
        self.entity_id = entity_id
        self.keyjar = None
        self.upstream_get = upstream_get


class OidcContext(Context):

    def __init__(self, config=None, entity_id: Optional[str] = "", upstream_get: Optional[Callable] = None):
        Context.__init__(self, config, entity_id, upstream_get)
        if not self.entity_id and config:
            val = ""
            for alt in ["client_id", "issuer", "entity_id"]:
                val = config.get(alt)
                if val:
                    break
            self.entity_id = val
        else:
            self.entity_id = ""

