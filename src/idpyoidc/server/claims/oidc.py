from typing import Optional

from idpyoidc import claims
from idpyoidc.message.oidc import ProviderConfigurationResponse
from idpyoidc.message.oidc import RegistrationRequest
from idpyoidc.message.oidc import RegistrationResponse
from idpyoidc.server import claims as server_claims

REGISTER2PREFERRED = {
    # "require_signed_request_object": "request_object_algs_supported",
    "request_object_signing_alg": "request_object_signing_alg_values_supported",
    "request_object_encryption_alg": "request_object_encryption_alg_values_supported",
    "request_object_encryption_enc": "request_object_encryption_enc_values_supported",
    "userinfo_signed_response_alg": "userinfo_signing_alg_values_supported",
    "userinfo_encrypted_response_alg": "userinfo_encryption_alg_values_supported",
    "userinfo_encrypted_response_enc": "userinfo_encryption_enc_values_supported",
    "id_token_signed_response_alg": "id_token_signing_alg_values_supported",
    "id_token_encrypted_response_alg": "id_token_encryption_alg_values_supported",
    "id_token_encrypted_response_enc": "id_token_encryption_enc_values_supported",
    "default_acr_values": "acr_values_supported",
    "subject_type": "subject_types_supported",
    "token_endpoint_auth_method": "token_endpoint_auth_methods_supported",
    "response_types": "response_types_supported",
    "grant_types": "grant_types_supported",
    # In OAuth2 but not in OIDC
    "scope": "scopes_supported",
    "token_endpoint_auth_signing_alg": "token_endpoint_auth_signing_alg_values_supported",
}


class Claims(server_claims.Claims):
    parameter = server_claims.Claims.parameter.copy()

    registration_response = RegistrationResponse
    registration_request = RegistrationRequest

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
        # "grant_types_supported": ["authorization_code", "implicit", "refresh_token"],
        "id_token_signing_alg_values_supported": claims.get_signing_algs,
        "id_token_encryption_alg_values_supported": claims.get_encryption_algs,
        "id_token_encryption_enc_values_supported": claims.get_encryption_encs,
        "initiate_login_uri": None,
        "jwks": None,
        "jwks_uri": None,
        "op_policy_uri": None,
        "require_auth_time": None,
        "scopes_supported": ["openid"],
        "service_documentation": None,
        'subject_types_supported': ['public', 'pairwise', 'ephemeral'],
        "op_tos_uri": None,
        "ui_locales_supported": None,
        # "version": '3.0'
        #  "verify_args": None,
    }

    register2preferred = REGISTER2PREFERRED

    def __init__(self,
                 prefer: Optional[dict] = None,
                 callback_path: Optional[dict] = None
                 ):
        server_claims.Claims.__init__(self, prefer=prefer, callback_path=callback_path)

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
            if _val not in [None, []]:
                _info[key] = _val

        return _info
