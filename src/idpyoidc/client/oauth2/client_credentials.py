import logging
from typing import Optional
from typing import Union

from idpyoidc.client.service import Service
from idpyoidc.message import Message
from idpyoidc.message import oauth2
from idpyoidc.time_util import time_sans_frac


class CCAccessTokenRequest(Service):
    """The service that talks to the OAuth2 client credentials endpoint."""

    msg_type = oauth2.CCAccessTokenRequest
    response_cls = oauth2.AccessTokenResponse
    error_msg = oauth2.ResponseMessage
    endpoint_name = "token_endpoint"
    synchronous = True
    service_name = "client_credentials"
    default_authn_method = ""
    http_method = "POST"

    def __init__(self, upstream_get, conf=None):
        Service.__init__(self, upstream_get, conf=conf)
        self.pre_construct.append(self.cc_pre_construct)

    def cc_pre_construct(self,
                         request: Union[Message, dict],
                         service: Service,
                         post_args: Optional[dict],
                         **_args):
        _grant_type = request.get('grant_type')
        if not _grant_type:
            request['grant_type'] = 'client_credentials'
        elif _grant_type != 'client_credentials':
            logging.error('Wrong grant_type')

        return request, post_args

    def update_service_context(self, resp, key: Optional[str] = "", **kwargs):
        if "expires_in" in resp:
            resp["__expires_at"] = time_sans_frac() + int(resp["expires_in"])
        self.upstream_get("context").cstate.update(key, resp)
