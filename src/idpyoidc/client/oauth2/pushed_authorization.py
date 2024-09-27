"""The service that talks to the OAuth2 Authorization endpoint."""
import logging

from idpyoidc.client.oauth2.utils import get_state_parameter
from idpyoidc.client.oauth2.utils import pre_construct_pick_redirect_uri
from idpyoidc.client.oauth2.utils import set_request_object
from idpyoidc.client.oauth2.utils import set_state_parameter
from idpyoidc.client.service import Service
from idpyoidc.exception import MissingParameter
from idpyoidc.message import oauth2
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.time_util import time_sans_frac

LOGGER = logging.getLogger(__name__)


class PushedAuthorization(Service):
    """The service that talks to the OAuth2 Pushed Authorization endpoint."""

    msg_type = oauth2.PushedAuthorizationRequest
    response_cls = oauth2.PushedAuthorizationResponse
    error_msg = ResponseMessage
    endpoint_name = "pushed_authorization_request_endpoint"
    service_name = "pushed_authorization"
    response_body_type = "json"
    http_method = "POST"

    _supports = {
        "response_types_supported": ["code"],
        "grant_types": None
    }

    def __init__(self, upstream_get, conf=None):
        Service.__init__(self, upstream_get, conf=conf)
        self.pre_construct.extend([pre_construct_pick_redirect_uri, set_state_parameter])
        self.post_construct.append(self.store_auth_request)

    def add_(self, request_args=None, **kwargs):
        _add_request_object = kwargs.get("add_request_object", False)
        if _add_request_object:
            request_args["request"] = set_request_object(self, request_args)

    def update_service_context(self, resp, key="", **kwargs):
        if "expires_in" in resp:
            resp["__expires_at"] = time_sans_frac() + int(resp["expires_in"])
        self.upstream_get("context").cstate.update(key, resp)

    def store_auth_request(self, request_args=None, **kwargs):
        """Store the authorization request in the state DB."""
        _key = get_state_parameter(request_args, kwargs)
        self.upstream_get("context").cstate.update(_key, request_args)
        return request_args

    def gather_request_args(self, **kwargs):
        ar_args = Service.gather_request_args(self, **kwargs)

        if "redirect_uri" not in ar_args:
            try:
                ar_args["redirect_uri"] = self.upstream_get("context").get_usage("redirect_uris")[0]
            except (KeyError, AttributeError):
                raise MissingParameter("redirect_uri")

        return ar_args

    def post_parse_response(self, response, **kwargs):
        """
        Add scope claim to response, from the request, if not present in the
        response

        :param response: The response
        :param kwargs: Extra Keyword arguments
        :return: A possibly augmented response
        """

        if "scope" not in response:
            try:
                _key = kwargs["state"]
            except KeyError:
                pass
            else:
                if _key:
                    item = self.upstream_get("context").cstate.get_set(
                        _key, message=oauth2.AuthorizationRequest
                    )
                    try:
                        response["scope"] = item["scope"]
                    except KeyError:
                        pass
        return response
