import copy
from urllib.parse import quote_plus

from cryptojwt import KeyJar
from cryptojwt.key_jar import init_key_jar

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
    parameter = {"keyjar": KeyJar, "issuer": None}

    def __init__(self, config=None, keyjar=None, entity_id=""):
        ImpExp.__init__(self)
        if config is None:
            config = {}
        self.issuer = entity_id
        self.keyjar = self._keyjar(keyjar, conf=config, entity_id=entity_id)

    def _keyjar(self, keyjar=None, conf=None, entity_id=""):
        if keyjar is None:
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

            if "" in _keyjar and entity_id:
                # make sure I have the keys under my own name too (if I know it)
                _keyjar.import_jwks_as_json(_keyjar.export_jwks_as_json(True, ""), entity_id)

            _httpc_params = conf.get("httpc_params")
            if _httpc_params:
                _keyjar.httpc_params = _httpc_params

            return _keyjar
        else:
            return keyjar
