from typing import Optional
from typing import Union

from cryptojwt import KeyJar

from idpyoidc.configure import Configuration
from idpyoidc.node import Unit
from idpyoidc.server.util import execute


class Combo(Unit):
    name = 'root'

    def __init__(self,
                 config: Union[dict, Configuration],
                 httpc: Optional[object] = None,
                 entity_id: Optional[str] = '',
                 keyjar: Optional[Union[KeyJar, bool]] = None,
                 httpc_params: Optional[dict] = None
                 ):
        self.entity_id = entity_id or config.get('entity_id')
        if not httpc_params:
            httpc_params = self._get_httpc_params(config)

        Unit.__init__(self, config=config, httpc=httpc, issuer_id=self.entity_id, keyjar=keyjar)
        self._part = {}
        for key, spec in config.items():
            if isinstance(spec, dict) and 'class' in spec:
                if httpc_params:
                    self._add_httpc_params(spec, httpc_params)
                self._part[key] = execute(spec, upstream_get=self.unit_get,
                                          entity_id=self.entity_id, httpc=httpc)

    def _get_httpc_params(self, config):
        return config.get("httpc_params")

    def _add_httpc_params(self, spec, httpc_params):
        spec_kwargs = spec.get("kwargs", {})
        if "config" in spec_kwargs:
            if httpc_params and "httpc_params" not in spec_kwargs["config"]:
                spec_kwargs["config"]["httpc_params"] = httpc_params
        else:
            if "httpc_params" not in spec_kwargs:
                spec_kwargs["httpc_params"] = httpc_params

    def __getitem__(self, item):
        if item in self._part:
            return self._part[item]
        else:
            return None

    def __setitem__(self, key, value):
        self._part[key] = value

    def get_entity_types(self):
        return list(self._part.keys())

    def keys(self):
        return self._part.keys()

    def items(self):
        return self._part.items()
