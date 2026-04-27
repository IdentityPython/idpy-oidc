from typing import Callable
from typing import Optional

from cryptojwt import KeyJar

from idpyoidc.context import Context
from idpyoidc.defaults import KEYDEFS
from idpyoidc.message import Message
from idpyoidc.message.oauth2 import OAuthProtectedResourceRequest
from idpyoidc.resource.claims import ResourceClaims
from idpyoidc.server.util import init_keyjar


class ResourceContext(Context):
    claims_class = ResourceClaims
    def __init__(self,
                 config=None,
                 entity_id: Optional[str] = '',
                 upstream_get: Optional[Callable] = None,
                 keyjar: Optional[KeyJar] = None,
                 key_conf: Optional[dict] = None,
                 metadata_schema: Optional[type] = None,
                 claims_class: Optional[type] = None,
                 **kwargs
                 ):
        Context.__init__(self, config, entity_id, upstream_get)

        self.metadata_class = metadata_schema or OAuthProtectedResourceRequest
        if not claims_class:
            claims_class = config.getarg("claims_class", None)
        if not claims_class:
            claims_class = self.claims_class
        self.claims = claims_class()

        key_conf = key_conf or config.getarg("key_conf", config.getarg("keys", None))
        if keyjar is None and key_conf is None:
            key_conf = {"key_defs": KEYDEFS}

        self.keyjar = init_keyjar(config, keyjar=keyjar, key_config=key_conf, issuer_id=self.entity_id, **kwargs)

        _supports = self.claims.supports()
        self.claims.load_conf(config, supports=_supports, keyjar=keyjar, metadata_class=self.metadata_class)

    def get_endpoint_info(self):
        _res = {}
        _endpoints = self.upstream_get("endpoints")
        if not _endpoints:
            return _res

        for name, endp in _endpoints.items():
            if endp.endpoint_name:
                _res[endp.endpoint_name] = endp.full_path
        return _res

    def get_metadata(self, supports: Optional[dict] = None, schema: Optional[Message] = None):
        if supports is None:
            supports = self.supports()
        _metadata = self.claims.metadata(supports, schema)
        _metadata.update(self.get_endpoint_info())
        return _metadata

    def supports(self):
        res = {}
        _services = getattr(self, "service", {})
        if _services:
            for service in self.service.values():
                res.update(service.supports())
                res = service.extends(res)
        res.update(self.claims.supports())
        return res
