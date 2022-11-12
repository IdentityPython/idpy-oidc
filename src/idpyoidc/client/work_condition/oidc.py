import os
from typing import Optional

from idpyoidc.client import work_condition


class WorkCondition(work_condition.WorkCondition):
    parameter = work_condition.WorkCondition.parameter.copy()
    parameter.update({
        "requests_dir": None
    })

    metadata_claims = {
        "redirect_uris": None,
        "response_types": ["code"],
        "grant_types": ["authorization_code", "implicit", "refresh_token"],
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
        "id_token_signed_response_alg": "RS256",
        "id_token_encrypted_response_alg": None,
        "id_token_encrypted_response_enc": None,
        "request_object_signing_alg": None,
        "request_object_encryption_alg": None,
        "request_object_encryption_enc": None,
        "default_max_age": None,
        "require_auth_time": None,
        "initiate_login_uri": None,
        "default_acr_values": None,
        "request_uris": None,
        "client_id": None,
    }

    can_support = {
        "form_post": None,
        "jwks": None,
        "jwks_uri": None,
        "request_parameter": None,
        "request_uri": None,
        "scope": ["openid"],
        "verify_args": None,
    }

    callback_path = {
        "requests": "req",
        "code": "authz_cb",
        "implicit": "authz_im_cb",
        "form_post": "form"
    }

    callback_uris = ["redirect_uris"]

    def __init__(self,
                 metadata: Optional[dict] = None,
                 support: Optional[dict] = None,
                 behaviour: Optional[dict] = None,
                 ):
        work_condition.WorkCondition.__init__(self, metadata=metadata, support=support,
                                              behaviour=behaviour)

    def verify_rules(self):
        if self.get_support("request_parameter") and self.get_support("request_uri"):
            raise ValueError("You have to chose one of 'request_parameter' and 'request_uri'.")
        # default is jwks_uri
        if not self.get_support("jwks") and not self.get_support('jwks_uri'):
            self.set_support('jwks_uri', True)

    def locals(self, info):
        requests_dir = info.get("requests_dir")
        if requests_dir:
            # make sure the path exists. If not, then create it.
            if not os.path.isdir(requests_dir):
                os.makedirs(requests_dir)

            self.set("requests_dir", requests_dir)
