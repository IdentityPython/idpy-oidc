from typing import Optional

from idpyoidc.client import claims
from idpyoidc.message.oauth2 import OAuthProtectedResourceRequest
from idpyoidc.client.claims.transform import array_or_singleton

class Claims(claims.Claims):
    _supports = {
        "resource": None,
        "grant_types_supported": ["authorization_code", "implicit", "refresh_token"],
        "scopes_supported": [],
        "authorization_servers": [],
        "bearer_methods_supported": [],
        "resource_documentation": None,
        "resource_signing_alg_values_supported": [],
        "resource_encryption_alg_values_supported": [],
        "resource_encryption_enc_values_supported": [],
        "client_registration_types": [],
        "organization_name": None,
        "resource_policy_uri": None,
        "resource_tos_uri": None
    }

    callback_path = {}

    callback_uris = ["redirect_uris"]

    def __init__(self, prefer: Optional[dict] = None, callback_path: Optional[dict] = None):
        claims.Claims.__init__(self, prefer=prefer, callback_path=callback_path)

    def create_registration_request(self):
        _request = {}
        for key, spec in OAuthProtectedResourceRequest.c_param.items():
            _pref_key = key
            if _pref_key in self.prefer:
                value = self.prefer[_pref_key]
            elif _pref_key in self.supports():
                value = self.supports()[_pref_key]
            else:
                continue

            if not value:
                continue

            _request[key] = array_or_singleton(spec, value)
        return _request
