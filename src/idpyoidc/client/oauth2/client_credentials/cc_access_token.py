from typing import Optional

from idpyoidc.client.service import Service
from idpyoidc.message import oauth2
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.time_util import time_sans_frac


class CCAccessToken(Service):
    msg_type = oauth2.CCAccessTokenRequest
    response_cls = oauth2.AccessTokenResponse
    error_msg = ResponseMessage
    endpoint_name = "token_endpoint"
    synchronous = True
    service_name = "accesstoken"
    default_authn_method = "client_secret_basic"
    http_method = "POST"
    request_body_type = "urlencoded"
    response_body_type = "json"

    def __init__(self, upstream_get, conf=None):
        Service.__init__(self, upstream_get, conf=conf)

    def update_service_context(self, resp, key: Optional[str] = "cc", **kwargs):
        if "expires_in" in resp:
            resp["__expires_at"] = time_sans_frac() + int(resp["expires_in"])
        self.upstream_get("context").cstate.update(key, resp)
