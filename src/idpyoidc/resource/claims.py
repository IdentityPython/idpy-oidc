from typing import Optional

from idpyoidc import claims
from idpyoidc.message import Message
from idpyoidc.message.oauth2 import OAuthProtectedResourceRequest


class ResourceClaims(claims.Claims):
    schema = OAuthProtectedResourceRequest
    _supports = {
        "scopes_supported": [],
    }

    callback_path = {}
    callback_uris = []

    def __init__(self,
                 prefer: Optional[dict] = None,
                 callback_path: Optional[dict] = None):
        claims.Claims.__init__(self, prefer=prefer, callback_path=callback_path)

    def metadata(self, supports, schema: Optional[Message] = None):
        _info = {}
        if schema is None:
            schema = OAuthProtectedResourceRequest

        for key in schema.c_param.keys():
            _val = self.get_preference(key, supports.get(key, None))
            if _val and _val != []:
                _info[key] = _val
        return _info
