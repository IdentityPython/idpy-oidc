"""The service that talks to the OAuth2 Authorization endpoint."""
import logging
from typing import List
from typing import Optional

from idpyoidc import claims
from idpyoidc.client.oauth2.utils import get_state_parameter
from idpyoidc.client.oauth2.utils import pre_construct_pick_redirect_uri
from idpyoidc.client.oauth2.utils import set_state_parameter
from idpyoidc.client.service import Service
from idpyoidc.client.service_context import ServiceContext
from idpyoidc.client.util import implicit_response_types
from idpyoidc.exception import MissingParameter
from idpyoidc.message import oauth2
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.time_util import time_sans_frac

LOGGER = logging.getLogger(__name__)


class Authorization(Service):
    """The service that talks to the OAuth2 Authorization endpoint."""

    msg_type = oauth2.AuthorizationRequest
    response_cls = oauth2.AuthorizationResponse
    error_msg = ResponseMessage
    endpoint_name = "authorization_endpoint"
    synchronous = False
    service_name = "authorization"
    response_body_type = "urlencoded"

    _supports = {
        "response_types_supported": ["code", 'token'],
        "response_modes_supported": ['query', 'fragment'],
        "request_object_signing_alg_values_supported": claims.get_signing_algs,
        "request_object_encryption_alg_values_supported": claims.get_encryption_algs,
        "request_object_encryption_enc_values_supported": claims.get_encryption_encs,
    }

    _callback_path = {
        "redirect_uris": {  # based on response_types
            "code": "authz_cb",
            "implicit": "authz_im_cb",
            # "form_post": "form"
        }
    }

    def __init__(self, upstream_get, conf=None):
        Service.__init__(self, upstream_get, conf=conf)
        self.pre_construct.extend([pre_construct_pick_redirect_uri, set_state_parameter])
        self.post_construct.append(self.store_auth_request)

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
                ar_args["redirect_uri"] = self.upstream_get("context").get_usage(
                    "redirect_uris")[0]
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
                        _key, message=oauth2.AuthorizationRequest)
                    try:
                        response["scope"] = item["scope"]
                    except KeyError:
                        pass
        return response

    def _do_flow(self, flow_type, response_types):
        if flow_type == 'code' and 'code' in response_types:
            return True
        elif flow_type == 'implicit':
            if implicit_response_types(response_types):
                return True
        return False

    def _do_redirect_uris(self, base_url, hex, context, callback_uris, response_types):
        _redirect_uris = context.get_preference('redirect_uris', [])
        if _redirect_uris:
            if not callback_uris or 'redirect_uris' not in callback_uris:
                # the same redirect_uris for all flow types
                callback_uris['redirect_uris'] = {}
                for flow_type in self._callback_path['redirect_uris'].keys():
                    if self._do_flow(flow_type, response_types):
                        callback_uris['redirect_uris'][flow_type] = _redirect_uris
        elif callback_uris:
            if 'redirect_uris' in callback_uris:
                pass
            else:
                callback_uris['redirect_uris'] = {}
                for flow_type, path in self._callback_path['redirect_uris'].items():
                    if self._do_flow(flow_type, response_types):
                        callback_uris['redirect_uris'][flow_type] = [
                            self.get_uri(base_url, path, hex)]
        else:
            callback_uris['redirect_uris'] = {}
            for flow_type, path in self._callback_path['redirect_uris'].items():
                if self._do_flow(flow_type, response_types):
                    callback_uris['redirect_uris'][flow_type] = [self.get_uri(base_url, path, hex)]
        return callback_uris

    def construct_uris(self,
                       base_url: str,
                       hex: bytes,
                       context: ServiceContext,
                       targets: Optional[List[str]] = None,
                       response_types: Optional[List[str]] = None):
        _callback_uris = context.get_preference('callback_uris', {})

        for uri_name in self._callback_path.keys():
            if uri_name == 'redirect_uris':
                _callback_uris = self._do_redirect_uris(base_url, hex, context, _callback_uris,
                                                        response_types)
                _redirect_uris = set()
                for flow, _uris in _callback_uris['redirect_uris'].items():
                    _redirect_uris.update(set(_uris))
                context.set_preference('redirect_uris', list(_redirect_uris))
            else:
                _callback_uris[uri_name] = self.get_uri(base_url, self._callback_path[uri_name],
                                                        hex)

        return _callback_uris
