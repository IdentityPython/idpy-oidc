import logging

from idpyoidc.client.service import Service
from idpyoidc.message.oauth2 import Message
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.message.oidc import session

__author__ = "Roland Hedberg"

logger = logging.getLogger(__name__)


class CheckSession(Service):
    msg_type = session.CheckSessionRequest
    response_cls = Message
    error_msg = ResponseMessage
    endpoint_name = ""
    synchronous = True
    service_name = "check_session"

    def __init__(self, upstream_get, conf=None):
        Service.__init__(self, upstream_get, conf=conf)
        self.pre_construct = [self.oidc_pre_construct]

    def oidc_pre_construct(self, request_args=None, **kwargs):
        _args = self.upstream_get("context").cstate.get_set(kwargs["state"], claim=["id_token"])
        if request_args:
            request_args.update(_args)
        else:
            request_args = _args

        return request_args, {}
