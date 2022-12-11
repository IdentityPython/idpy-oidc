from typing import Optional

from idpyoidc import work_environment as WE
from idpyoidc.message.oidc import ProviderConfigurationResponse
from idpyoidc.server import work_environment


class WorkEnvironment(work_environment.WorkEnvironment):
    parameter = work_environment.WorkEnvironment.parameter.copy()

    _supports = {
        "acr_values_supported": None,
        "claim_types_supported": None,
        "claims_locales_supported": None,
        "claims_supported": None,
        # "client_authn_methods": get_client_authn_methods,
        "contacts": None,
        "default_max_age": 86400,
        "display_values_supported": None,
        "encrypt_id_token_supported": None,
        "grant_types_supported": ["authorization_code", "implicit", "refresh_token"],
        "id_token_signing_alg_values_supported": WE.get_signing_algs,
        "id_token_encryption_alg_values_supported": WE.get_encryption_algs,
        "id_token_encryption_enc_values_supported": WE.get_encryption_encs,
        "initiate_login_uri": None,
        "jwks": None,
        "jwks_uri": None,
        "op_policy_uri": None,
        "require_auth_time": None,
        "scopes_supported": ["openid"],
        "service_documentation": None,
        "op_tos_uri": None,
        "ui_locales_supported": None,
        # "version": '3.0'
        #  "verify_args": None,
    }

    def __init__(self,
                 prefer: Optional[dict] = None,
                 callback_path: Optional[dict] = None
                 ):
        work_environment.WorkEnvironment.__init__(self, prefer=prefer, callback_path=callback_path)

    def verify_rules(self):
        if self.get_preference("request_parameter_supported") and self.get_preference(
                "request_uri_parameter_supported"):
            raise ValueError(
                "You have to chose one of 'request_parameter_supported' and "
                "'request_uri_parameter_supported'. You can't have both.")

        if not self.get_preference('encrypt_userinfo_supported'):
            self.set_preference('userinfo_encryption_alg_values_supported', [])
            self.set_preference('userinfo_encryption_enc_values_supported', [])

        if not self.get_preference('encrypt_request_object_supported'):
            self.set_preference('request_object_encryption_alg_values_supported', [])
            self.set_preference('request_object_encryption_enc_values_supported', [])

        if not self.get_preference('encrypt_id_token_supported'):
            self.set_preference('id_token_encryption_alg_values_supported', [])
            self.set_preference('id_token_encryption_enc_values_supported', [])

    def provider_info(self, supports):
        _info = {}
        for key in ProviderConfigurationResponse.c_param.keys():
            _val = self.get_preference(key, supports.get(key, None))
            if _val is not None:
                _info[key] = _val
        return _info
