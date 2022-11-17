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
        "subject_type": None,
        "default_max_age": None,
        "require_auth_time": None,
        "initiate_login_uri": None,
        "client_id": None,
        "client_secret": None,
        "scope": ["openid"],
        #  "verify_args": None,
        "requests_dir": None,
        "encrypt_id_token": None
    }

    def __init__(self,
                 prefer: Optional[dict] = None,
                 callback_path: Optional[dict] = None
                 ):
        work_condition.WorkCondition.__init__(self, prefer=prefer, callback_path=callback_path)

    def verify_rules(self):
        if self.get_preference("request_parameter") and self.get_preference("request_uri"):
            raise ValueError("You have to chose one of 'request_parameter' and 'request_uri'."
                             " you can't have both.")

    def locals(self, info):
        requests_dir = info.get("requests_dir")
        if requests_dir:
            # make sure the path exists. If not, then create it.
            if not os.path.isdir(requests_dir):
                os.makedirs(requests_dir)

            self.set("requests_dir", requests_dir)

