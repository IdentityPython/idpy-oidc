import os
from typing import Optional

from idpyoidc import work_environment
from idpyoidc.client import work_environment as client_work_environment
# from idpyoidc.client.client_auth import get_client_authn_methods


class WorkEnvironment(client_work_environment.WorkEnvironment):
    parameter = client_work_environment.WorkEnvironment.parameter.copy()
    parameter.update({
        "requests_dir": None
    })

    _supports = {
        "acr_values_supported": None,
        "application_type": "web",
        "callback_uris": None,
        # "client_authn_methods": get_client_authn_methods,
        "client_id": None,
        "client_name": None,
        "client_secret": None,
        "client_uri": None,
        "contacts": None,
        "default_max_age": 86400,
        "encrypt_id_token_supported": None,
        "grant_types_supported": ["authorization_code", "implicit", "refresh_token"],
        "logo_uri": None,
        "id_token_signing_alg_values_supported": work_environment.get_signing_algs,
        "id_token_encryption_alg_values_supported": work_environment.get_encryption_algs,
        "id_token_encryption_enc_values_supported": work_environment.get_encryption_encs,
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

    def locals(self, info):
        requests_dir = info.get("requests_dir")
        if requests_dir:
            # make sure the path exists. If not, then create it.
            if not os.path.isdir(requests_dir):
                os.makedirs(requests_dir)

            self.set("requests_dir", requests_dir)
