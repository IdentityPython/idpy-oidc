"""Implements the service that talks to the Access Token endpoint."""
import logging
from typing import Optional

from idpyoidc.client.client_auth import get_client_authn_methods
from idpyoidc.client.oauth2.utils import get_state_parameter
from idpyoidc.client.service import Service
from idpyoidc.message import oauth2
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.time_util import time_sans_frac
from idpyoidc.claims import get_signing_algs

LOGGER = logging.getLogger(__name__)


class AccessToken(Service):
    """The access token service."""

    msg_type = oauth2.AccessTokenRequest
    response_cls = oauth2.AccessTokenResponse
    error_msg = ResponseMessage
    endpoint_name = "token_endpoint"
    synchronous = True
    service_name = "accesstoken"
    default_authn_method = "client_secret_basic"
    http_method = "POST"
    request_body_type = "urlencoded"
    response_body_type = "json"

    _include = {"grant_types_supported": ["authorization_code"]}

    _supports = {
        "token_endpoint_auth_methods_supported": get_client_authn_methods,
        "token_endpoint_auth_signing_alg": get_signing_algs,
    }

    def __init__(self, upstream_get, conf=None):
        Service.__init__(self, upstream_get, conf=conf)
        self.pre_construct.append(self.oauth_pre_construct)

    def update_service_context(self, resp, key: Optional[str] = "", **kwargs):
        if "expires_in" in resp:
            resp["__expires_at"] = time_sans_frac() + int(resp["expires_in"])
        if key:
            self.upstream_get("context").cstate.update(key, resp)

    def oauth_pre_construct(self, request_args=None, post_args=None, **kwargs):
        """

        :param request_args: Initial set of request arguments
        :param kwargs: Extra keyword arguments
        :return: Request arguments
        """
        _state = get_state_parameter(request_args, kwargs)
        parameters = list(self.msg_type.c_param.keys())

        _context = self.upstream_get("context")
        _args = _context.cstate.get_set(_state, claim=parameters)

        if "grant_type" not in _args:
            _args["grant_type"] = "authorization_code"

        if request_args is None:
            request_args = _args
        else:
            _args.update(request_args)
            request_args = _args

        return request_args, post_args
