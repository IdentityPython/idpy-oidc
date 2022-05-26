"""Implements the service that can exchange one token for another."""
import logging

from idpyoidc.client.oauth2.utils import get_state_parameter
from idpyoidc.client.service import Service
from idpyoidc.exception import MissingParameter
from idpyoidc.exception import MissingRequiredAttribute
from idpyoidc.message import oauth2
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.time_util import time_sans_frac

LOGGER = logging.getLogger(__name__)


class TokenExchange(Service):
    """The token exchange service."""

    msg_type = oauth2.TokenExchangeRequest
    response_cls = oauth2.TokenExchangeResponse
    error_msg = ResponseMessage
    endpoint_name = "token_endpoint"
    synchronous = True
    service_name = "token_exchange"
    default_authn_method = "client_secret_basic"
    http_method = "POST"
    request_body_type = "urlencoded"
    response_body_type = "json"


    def __init__(self, client_get, conf=None):
        Service.__init__(self, client_get, conf=conf)
        self.pre_construct.append(self.oauth_pre_construct)

    def update_service_context(self, resp, key="", **kwargs):
        if "expires_in" in resp:
            resp["__expires_at"] = time_sans_frac() + int(resp["expires_in"])
        self.client_get("service_context").state.store_item(resp, "token_response", key)

    def oauth_pre_construct(self, request_args=None, post_args=None, **kwargs):
        """

        :param request_args: Initial set of request arguments
        :param kwargs: Extra keyword arguments
        :return: Request arguments
        """
        if request_args is None:
            request_args = {}

        if 'subject_token' not in request_args:
            try:
                _key = get_state_parameter(request_args, kwargs)
            except MissingParameter:
                raise MissingRequiredAttribute("subject_token")

            parameters = {'access_token', 'scope'}

            _state = self.client_get("service_context").state

            _args = _state.extend_request_args(
                {}, oauth2.AuthorizationResponse, "auth_response", _key, parameters
            )
            _args = _state.extend_request_args(
                _args, oauth2.AccessTokenResponse, "token_response", _key, parameters
            )
            _args = _state.extend_request_args(
                _args, oauth2.AccessTokenResponse, "refresh_token_response", _key, parameters
            )

            request_args["subject_token"] = _args["access_token"]
            request_args["subject_token_type"] = 'urn:ietf:params:oauth:token-type:access_token'
            if 'scope' not in request_args and "scope" in _args:
                request_args["scope"] = _args["scope"]

        return request_args, post_args
