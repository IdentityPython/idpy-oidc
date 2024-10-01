import logging
import os
from typing import Optional

from idpyoidc import metadata
from idpyoidc.client import claims as client_claims
from idpyoidc.client.claims.transform import create_registration_request
from idpyoidc.message.oidc import APPLICATION_TYPE_WEB
from idpyoidc.message.oidc import RegistrationRequest
from idpyoidc.message.oidc import RegistrationResponse

logger = logging.getLogger(__name__)

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
    # "display": "display_values_supported",
    # "claims": "claims_supported",
    # "request": "request_parameter_supported",
    # "request_uri": "request_uri_parameter_supported",
    # 'claims_locales': 'claims_locales_supported',
    # 'ui_locales': 'ui_locales_supported',
}

PREFERRED2REGISTER = dict([(v, k) for k, v in REGISTER2PREFERRED.items()])

REQUEST2REGISTER = {
    "client_id": "client_id",
    "client_secret": "client_secret",
    #    'acr_values': "default_acr_values" ,
    #    'max_age': "default_max_age",
    "redirect_uri": "redirect_uris",
    "response_type": "response_types",
    "request_uri": "request_uris",
    "grant_type": "grant_types",
    "scope": "scopes_supported",
    "post_logout_redirect_uri": "post_logout_redirect_uris",
}


class Claims(client_claims.Claims):
    parameter = client_claims.Claims.parameter.copy()
    parameter.update({"requests_dir": None})

    register2preferred = REGISTER2PREFERRED
    registration_response = RegistrationResponse
    registration_request = RegistrationRequest

    _supports = {
        "acr_values_supported": None,
        "application_type": APPLICATION_TYPE_WEB,
        "callback_uris": None,
        # "client_authn_methods": get_client_authn_methods,
        "client_id": None,
        "client_name": None,
        "client_secret": None,
        "client_uri": None,
        "contacts": None,
        "default_max_age": 86400,
        "encrypt_id_token_supported": None,
        # "grant_types_supported": ["authorization_code", "refresh_token"],
        "logo_uri": None,
        "id_token_signing_alg_values_supported": metadata.get_signing_algs(),
        "id_token_encryption_alg_values_supported": metadata.get_encryption_algs(),
        "id_token_encryption_enc_values_supported": metadata.get_encryption_encs(),
        "initiate_login_uri": None,
        "jwks": None,
        "jwks_uri": None,
        "policy_uri": None,
        "requests_dir": None,
        "require_auth_time": None,
        "sector_identifier_uri": None,
        "scopes_supported": ["openid"],
        "subject_types_supported": ["public", "pairwise", "ephemeral"],
        "tos_uri": None,
    }

    def __init__(self, prefer: Optional[dict] = None, callback_path: Optional[dict] = None):
        client_claims.Claims.__init__(self, prefer=prefer, callback_path=callback_path)

    def verify_rules(self, supports):
        if self.get_preference("request_parameter_supported") and self.get_preference(
            "request_uri_parameter_supported"
        ):
            raise ValueError(
                "You have to chose one of 'request_parameter_supported' and "
                "'request_uri_parameter_supported'. You can't have both."
            )

        if self.get_preference("request_parameter_supported") or self.get_preference(
            "request_uri_parameter_supported"
        ):
            if not self.get_preference("request_object_signing_alg_values_supported"):
                self.set_preference(
                    "request_object_signing_alg_values_supported",
                    supports["request_object_signing_alg_values_supported"],
                )

        if not self.get_preference("encrypt_userinfo_supported"):
            self.set_preference("userinfo_encryption_alg_values_supported", [])
            self.set_preference("userinfo_encryption_enc_values_supported", [])

        if not self.get_preference("encrypt_request_object_supported"):
            self.set_preference("request_object_encryption_alg_values_supported", [])
            self.set_preference("request_object_encryption_enc_values_supported", [])

        if not self.get_preference("encrypt_id_token_supported"):
            self.set_preference("id_token_encryption_alg_values_supported", [])
            self.set_preference("id_token_encryption_enc_values_supported", [])

    def locals(self, info):
        requests_dir = info.get("requests_dir")
        if requests_dir:
            # make sure the path exists. If not, then create it.
            if not os.path.isdir(requests_dir):
                os.makedirs(requests_dir)

            self.set("requests_dir", requests_dir)

    def create_registration_request(self):
        return create_registration_request(self.prefer, self.supports())
