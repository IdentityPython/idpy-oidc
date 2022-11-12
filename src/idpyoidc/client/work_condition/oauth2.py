from typing import Optional

from idpyoidc.client import work_condition


class WorkCondition(work_condition.WorkCondition):
    metadata_claims = {
        "redirect_uris": None,
        "grant_types": ["authorization_code", "implicit", "refresh_token"],
        "response_types": ["code"],
        "client_id": None,
        "client_name": None,
        "client_uri": None,
        "logo_uri": None,
        "contacts": None,
        "scope": None,
        "tos_uri": None,
        "policy_uri": None,
        "jwks_uri": None,
        "jwks": None,
        "software_id": None,
        "software_version": None
    }

    rules = {
        "jwks": None,
        "jwks_uri": None,
        "scope": ["openid"],
        "verify_args": None,
    }

    callback_path = {
        "requests": "req",
        "code": "authz_cb",
        "implicit": "authz_im_cb",
    }

    callback_uris = ["redirect_uris"]

    def __init__(self,
                 metadata: Optional[dict] = None,
                 support: Optional[dict] = None,
                 behaviour: Optional[dict] = None
                 ):
        work_condition.WorkCondition.__init__(self, metadata=metadata, support=support,
                                              behaviour=behaviour)
