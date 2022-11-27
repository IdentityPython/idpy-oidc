import os
from typing import Optional

from idpyoidc.client import work_condition


class WorkCondition(work_condition.WorkCondition):
    parameter = work_condition.WorkCondition.parameter.copy()
    parameter.update({
        "requests_dir": None
    })

    _supports = {
        "grant_types_supported": ["authorization_code", "implicit", "refresh_token"],
        "id_token_signing_alg_values_supported": work_condition.get_signing_algs,
        "id_token_encryption_alg_values_supported": work_condition.get_encryption_algs,
        "id_token_encryption_enc_values_supported": work_condition.get_encryption_encs,
        "acr_values_supported": None,
        "subject_types_supported": ["public", "pairwise", "ephemeral"],
        "application_type": "web",
        "contacts": None,
        "client_name": None,
        "logo_uri": None,
        "client_uri": None,
        "policy_uri": None,
        "tos_uri": None,
        "jwks": None,
        "jwks_uri": None,
        "sector_identifier_uri": None,
        "default_max_age": 86400,
        "require_auth_time": None,
        "initiate_login_uri": None,
        "client_id": None,
        "client_secret": None,
        "scopes_supported": ["openid"],
        #  "verify_args": None,
        "requests_dir": None,
        "encrypt_id_token_supported": None,
        "callback_uris": None
    }

    def __init__(self,
                 prefer: Optional[dict] = None,
                 callback_path: Optional[dict] = None
                 ):
        work_condition.WorkCondition.__init__(self, prefer=prefer, callback_path=callback_path)

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
