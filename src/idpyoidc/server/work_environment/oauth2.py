from typing import Optional

from idpyoidc.message.oauth2 import ASConfigurationResponse
from idpyoidc.server import work_environment
# from idpyoidc.server.client_authn import get_client_authn_methods


class WorkEnvironment(work_environment.WorkEnvironment):
    # 'issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri', 'registration_endpoint',
    # 'scopes_supported', 'response_types_supported', 'response_modes_supported',
    # 'grant_types_supported', 'token_endpoint_auth_methods_supported',
    # 'token_endpoint_auth_signing_alg_values_supported', 'service_documentation',
    # 'ui_locales_supported', 'op_policy_uri', 'op_tos_uri', 'revocation_endpoint',
    # 'introspection_endpoint'
    _supports = {
        # "client_authn_methods": get_client_authn_methods,
        "grant_types_supported": ["authorization_code", "implicit", "refresh_token"],
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

    def __init__(self,
                 prefer: Optional[dict] = None,
                 callback_path: Optional[dict] = None):
        work_environment.WorkEnvironment.__init__(self, prefer=prefer, callback_path=callback_path)

    def provider_info(self, supports):
        _info = {}
        for key in ASConfigurationResponse.c_param.keys():
            _val = self.get_preference(key, supports.get(key, None))
            if _val:
                _info[key] = _val
        return _info
