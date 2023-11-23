import logging

from idpyoidc.client.service import Service
from idpyoidc.message import Message
from idpyoidc.message import oauth2

logger = logging.getLogger(__name__)


class Resource(Service):
    msg_type = Message
    response_cls = Message
    error_msg = oauth2.ResponseMessage
    endpoint_name = ""
    service_name = "resource"
    default_authn_method = "bearer_header"

    def __init__(self, upstream_get, conf=None):
        Service.__init__(self, upstream_get, conf=conf)
