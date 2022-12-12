import copy
from urllib.parse import quote_plus

from idpyoidc.impexp import ImpExp


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


class OidcContext(ImpExp):
    parameter = {"entity_id": None}

    def __init__(self, config=None, entity_id=""):
        ImpExp.__init__(self)
        if entity_id:
            self.entity_id = entity_id
        else:
            if config:
                val = ''
                for alt in ['client_id', 'issuer', 'entity_id']:
                    val = config.get(alt)
                    if val:
                        break
                self.entity_id = val
            else:
                self.entity_id = ''
