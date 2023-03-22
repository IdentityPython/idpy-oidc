import logging
from typing import Optional
from typing import Union

from idpyoidc import verified_claim_name
from idpyoidc.client.oauth2.utils import get_state_parameter
from idpyoidc.client.service import Service
from idpyoidc.claims import get_encryption_algs
from idpyoidc.claims import get_encryption_encs
from idpyoidc.claims import get_signing_algs
from idpyoidc.exception import MissingSigningKey
from idpyoidc.message import Message
from idpyoidc.message import oauth2
from idpyoidc.message import oidc

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
