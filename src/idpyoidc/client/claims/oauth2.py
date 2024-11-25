from typing import Optional

from idpyoidc.client import claims
from idpyoidc.transform import create_registration_request
from idpyoidc.transform import create_registration_request

REGISTER2PREFERRED = {
    "scope": "scopes_supported",
    "token_endpoint_auth_signing_alg": "token_endpoint_auth_signing_alg_values_supported",
    "response_types": "response_types_supported",
    # "response_modes": "response_modes_supported",
    "grant_types": "grant_types_supported",
    "token_endpoint_auth_method": "token_endpoint_auth_methods_supported",
    "token_auth_signing_algs": "token_auth_signing_algs_supported",
    # 'ui_locales': 'ui_locales_supported',
}

class Claims(claims.Claims):
    register2preferred = REGISTER2PREFERRED

    _supports = {
        "redirect_uris": None,
        "grant_types_supported": ["authorization_code", "implicit", "refresh_token"],
        "response_types_supported": ["code"],
        "client_id": None,
        "client_name": None,
        "client_secret": None,
        "client_uri": None,
        "logo_uri": None,
        "scope": None,
        "contacts": None,
        # "scopes_supported": [],
        "tos_uri": None,
        "policy_uri": None,
        "jwks_uri": None,
        "jwks": None,
        "software_id": None,
        "software_version": None,
    }

    callback_path = {}

    callback_uris = ["redirect_uris"]

    def __init__(self, prefer: Optional[dict] = None, callback_path: Optional[dict] = None):
        claims.Claims.__init__(self, prefer=prefer, callback_path=callback_path)

    def create_registration_request(self):
        return create_registration_request(self.prefer, self.supports())
