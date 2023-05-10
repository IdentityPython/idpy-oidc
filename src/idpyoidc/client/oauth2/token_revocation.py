"""The service that talks to the OAuth2 refresh access token endpoint."""
import logging
from typing import Optional

from idpyoidc.client.oauth2.utils import get_state_parameter
from idpyoidc.client.service import Service
from idpyoidc.message import oauth2
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.time_util import time_sans_frac

LOGGER = logging.getLogger(__name__)


class TokenRevocation(Service):
    """The service that talks to the OAuth2 refresh access token endpoint."""

    msg_type = oauth2.TokenRevocationRequest
    response_cls = oauth2.TokenRevocationResponse
    error_msg = oauth2.TokenRevocationErrorResponse
    endpoint_name = "revocation_endpoint"
    response_body_type = "text"
    synchronous = True
    service_name = "token_revocation"
    default_authn_method = "client_secret_basic"
    http_method = "POST"

    def __init__(self, upstream_get, conf=None):
        Service.__init__(self, upstream_get, conf=conf)
