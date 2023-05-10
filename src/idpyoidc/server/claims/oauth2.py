from typing import Optional

from idpyoidc.message.oauth2 import ASConfigurationResponse
from idpyoidc.server import claims

REGISTER2PREFERRED = {
    # "require_signed_request_object": "request_object_algs_supported",
    "token_endpoint_auth_method": "token_endpoint_auth_methods_supported",
    "response_types": "response_types_supported",
    "grant_types": "grant_types_supported",
    # In OAuth2 but not in OIDC
    "scope": "scopes_supported",
    "token_endpoint_auth_signing_alg": "token_endpoint_auth_signing_alg_values_supported",
}


class Claims(claims.Claims):
    register2preferred = REGISTER2PREFERRED

    _supports = {
        "deny_unknown_scopes": False,
        "scopes_handler": None,
        "response_types_supported": ["code"],
        "response_modes_supported": ["code"],
        "jwks_uri": None,
        "jwks": None,
        "scopes_supported": [],
        "service_documentation": None,
        "ui_locales_supported": [],
        "op_tos_uri": None,
        "op_policy_uri": None,
    }

    callback_path = {}

    callback_uris = ["redirect_uris"]

    def __init__(self, prefer: Optional[dict] = None, callback_path: Optional[dict] = None):
        claims.Claims.__init__(self, prefer=prefer, callback_path=callback_path)

    def provider_info(self, supports):
        _info = {}
        for key in ASConfigurationResponse.c_param.keys():
            _val = self.get_preference(key, supports.get(key, None))
            if _val and _val != []:
                _info[key] = _val
        return _info
