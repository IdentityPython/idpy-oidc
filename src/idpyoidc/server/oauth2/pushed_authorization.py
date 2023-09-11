from typing import Optional
from typing import Union
import uuid

from idpyoidc.message import Message
from idpyoidc.message import oauth2
from idpyoidc.message.oauth2 import AuthorizationRequest
from idpyoidc.server.oauth2.authorization import Authorization


class PushedAuthorization(Authorization):
    request_cls = oauth2.PushedAuthorizationRequest
    response_cls = oauth2.Message
    endpoint_name = "pushed_authorization_request_endpoint"
    request_placement = "body"
    request_format = "urlencoded"
    response_placement = "body"
    response_format = "json"
    name = "pushed_authorization"
    endpoint_type = "oauth2"

    def __init__(self, upstream_get, **kwargs):
        Authorization.__init__(self, upstream_get, **kwargs)
        # self.pre_construct.append(self._pre_construct)
        self.post_parse_request.append(self._post_parse_request)
        self.ttl = kwargs.get("ttl", 3600)

    def process_request(self, request: Optional[Union[Message, str]] = None, **kwargs):
        """
        Store the request and return a URI.

        :param request:
        """
        # create URN

        if isinstance(request, str):
            _request = AuthorizationRequest().from_urlencoded(request)
        else:
            _request = AuthorizationRequest(**request)

        _request.verify(keyjar=self.upstream_get("attribute", "keyjar"))

        _urn = "urn:uuid:{}".format(uuid.uuid4())
        # Store the parsed and verified request
        self.upstream_get("context").par_db[_urn] = _request

        return {
            "http_response": {"request_uri": _urn, "expires_in": self.ttl},
            "return_uri": _request["redirect_uri"],
        }
