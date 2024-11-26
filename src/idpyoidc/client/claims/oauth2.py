from typing import Optional

from idpyoidc.client import claims
from idpyoidc.transform import create_registration_request


class Claims(claims.Claims):
    _supports = {
        "redirect_uris": None,
        "grant_types_supported": ["authorization_code", "implicit", "refresh_token"],
        "response_types_supported": ["code"],
        "client_id": None,
        "client_secret": None,
        "client_name": None,
        "client_uri": None,
        "logo_uri": None,
        "contacts": None,
        "scopes_supported": [],
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
