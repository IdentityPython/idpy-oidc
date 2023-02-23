import logging
from typing import Optional

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

    def __init__(self, upstream_get, conf=None):
        Service.__init__(self, upstream_get, conf=conf)
        self.pre_construct = [self.oidc_pre_construct]

    def oidc_pre_construct(self, request_args: Optional[dict] = None, **kwargs):
        _args = self.upstream_get("context").cstate.get_set(
            kwargs["state"],
            claim=["id_token"]
        )
        if request_args:
            request_args.update()
        else:
            request_args = _args

        return request_args, {}
