import os
from typing import Optional

from idpyoidc.client import specification as sp
from idpyoidc.client.service import Service


class Specification(sp.Specification):
    parameter = sp.Specification.parameter.copy()
    parameter.update({
        "requests_dir": None
    })

    attributes = {
        "application_type": "web",
        "contacts": None,
        "client_name": None,
        "client_id": None,
        "logo_uri": None,
        "client_uri": None,
        "policy_uri": None,
        "tos_uri": None,
        "jwks_uri": None,
        "jwks": None,
        "sector_identifier_uri": None,
        "grant_types": ["authorization_code", "implicit", "refresh_token"],
        "default_max_age": None,
        "id_token_signed_response_alg": "RS256",
        "id_token_encrypted_response_alg": None,
        "id_token_encrypted_response_enc": None,
        "initiate_login_uri": None,
        "subject_type": None,
        "default_acr_values": None,
        "require_auth_time": None,
        "redirect_uris": None,
        "request_object_signing_alg": None,
        "request_object_encryption_alg": None,
        "request_object_encryption_enc": None,
        "request_uris": None,
        "response_types": ["code"]
    }

    rules = {
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
                 usage: Optional[dict] = None,
                 behaviour: Optional[dict] = None,
                 ):
        sp.Specification.__init__(self, metadata=metadata, usage=usage, behaviour=behaviour)

    def construct_uris(self, base_url, hex):
        if "request_uri" in self.usage:
            if self.usage["request_uri"]:
                _dir = self.get("requests_dir")
                if _dir:
                    self.set_metadata("request_uris", Service.get_uri(base_url, _dir, hex))
                else:
                    self.set_metadata("request_uris",
                                      Service.get_uri(base_url, self.callback_path["requests"], hex))

    def verify_rules(self):
        if self.get_usage("request_parameter") and self.get_usage("request_uri"):
            raise ValueError("You have to chose one of 'request_parameter' and 'request_uri'.")
        # default is jwks_uri
        if not self.get_usage("jwks") and not self.get_usage('jwks_uri'):
            self.set_usage('jwks_uri', True)

    def locals(self, info):
        requests_dir = info.get("requests_dir")
        if requests_dir:
            # make sure the path exists. If not, then create it.
            if not os.path.isdir(requests_dir):
                os.makedirs(requests_dir)

            self.set("requests_dir", requests_dir)

