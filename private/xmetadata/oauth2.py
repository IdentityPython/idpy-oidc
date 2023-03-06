from typing import Optional

from idpyoidc.client import metadata
from idpyoidc.message.oauth2 import OauthClientInformationResponse
from idpyoidc.message.oauth2 import OauthClientMetadata

REGISTER2PREFERRED = {
    # "require_signed_request_object": "request_object_algs_supported",
    "token_endpoint_auth_method": "token_endpoint_auth_methods_supported",
    "response_types": "response_types_supported",
    "grant_types": "grant_types_supported",
    # In OAuth2 but not in OIDC
    "scope": "scopes_supported",
    "token_endpoint_auth_signing_alg": "token_endpoint_auth_signing_alg_values_supported",
}


class Metadata(metadata.Metadata):
    _supports = {
        # "client_authn_methods": get_client_authn_methods,
        "redirect_uris": None,
        "grant_types": ["authorization_code", "implicit", "refresh_token"],
        'token_endpoint_auth_method'
        "response_types": ["code"],
        "client_id": None,
        'client_secret': None,
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
        "deny_unknown_scopes": None
    }

    callback_path = {}

    callback_uris = ["redirect_uris"]

    register2preferred = REGISTER2PREFERRED
    registration_response = OauthClientInformationResponse
    registration_request = OauthClientMetadata

    def __init__(self,
                 prefer: Optional[dict] = None,
                 callback_path: Optional[dict] = None):
        metadata.Metadata.__init__(self, prefer=prefer, callback_path=callback_path)
