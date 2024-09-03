from typing import Callable
from typing import List
from typing import Optional

from idpyoidc.message import Message

from idpyoidc.transform import preferred_to_registered


class XMetadata():
    def __int__(self, upstream_get: Callable):
        self.upstream_get = upstream_get

    def get_endpoint_claims(self, entity):
        _info = {}
        for endp in entity.server.endpoint.values():
            if endp.endpoint_name:
                _info[endp.endpoint_name] = endp.full_path
                for arg, claim in [("client_authn_method", "auth_methods"),
                                   ("auth_signing_alg_values", "auth_signing_alg_values")]:
                    _val = getattr(endp, arg, None)
                    if _val:
                        # trust_mark_status_endpoint_auth_methods_supported
                        md_param = f"{endp.endpoint_name}_{claim}"
                        _info[md_param] = _val
        return _info

    def __call__(self,
                 entity_type: str,
                 metadata_schema: Optional[Message] = None,
                 extra_claims: Optional[List[str]] = None,
                 **kwargs):
        _claims = self.upstream_get("context").claims
        entity = self.upstream_get("unit")
        if not _claims.use:
            _claims.use = preferred_to_registered(_claims.prefer, supported=entity.supports())

        metadata = _claims.use
        # the claims that can appear in the metadata
        if metadata_schema:
            attr = list(metadata_schema.c_param.keys())
        else:
            attr = []

        if extra_claims:
            attr.extend(extra_claims)

        if attr:
            metadata = {k:v for k,v in metadata.items() if k in attr}

        # collect endpoints
        metadata.update(self.get_endpoint_claims(entity))
        # _issuer = getattr(self.server.context, "trust_mark_server", None)
        return {entity_type: metadata}
