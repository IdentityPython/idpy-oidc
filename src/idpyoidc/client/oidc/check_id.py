import logging

from idpyoidc.client.service import Service
from idpyoidc.message.oauth2 import Message
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.message.oidc import session

__author__ = "Roland Hedberg"

logger = logging.getLogger(__name__)


class CheckID(Service):
    msg_type = session.CheckIDRequest
    response_cls = Message
    error_msg = ResponseMessage
    endpoint_name = ""
    synchronous = True
    service_name = "check_id"

    def __init__(self, superior_get, conf=None):
        Service.__init__(self, superior_get, conf=conf)
        self.pre_construct = [self.oidc_pre_construct]

    def oidc_pre_construct(self, request_args=None, **kwargs):
        request_args = self.superior_get("context").state.multiple_extend_request_args(
            request_args,
            kwargs["state"],
            ["id_token"],
            ["auth_response", "token_response", "refresh_token_response"],
        )
        return request_args, {}
