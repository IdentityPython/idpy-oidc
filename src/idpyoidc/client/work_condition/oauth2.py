from typing import Optional

from idpyoidc.client import work_condition


class WorkCondition(work_condition.WorkCondition):
    _supports = {
        "redirect_uris": None,
        "grant_types": ["authorization_code", "implicit", "refresh_token"],
        "response_types": ["code"],
        "client_id": None,
        'client_secret': None,
        "client_name": None,
        "client_uri": None,
        "logo_uri": None,
        "contacts": None,
        "scopes_supported": [],
        "tos_uri": None,
        "policy_uri": None,
        "jwks_uri": None,
        "jwks": None,
        "software_id": None,
        "software_version": None
    }


    callback_path = {}

    callback_uris = ["redirect_uris"]

    def __init__(self,
                 prefer: Optional[dict] = None,
                 callback_path: Optional[dict] = None):
        work_condition.WorkCondition.__init__(self, prefer=prefer, callback_path=callback_path)
