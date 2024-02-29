import json
import logging
from typing import Callable
from typing import Optional
from typing import Union
from urllib.parse import urlparse

from cryptojwt.exception import IssuerNotFound

from idpyoidc.exception import MissingRequiredAttribute
from idpyoidc.exception import MissingRequiredValue
from idpyoidc.exception import ParameterError
from idpyoidc.message import Message
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.message.oidc import RegistrationRequest
from idpyoidc.node import Node
from idpyoidc.server.client_authn import verify_client
from idpyoidc.server.exception import UnAuthorizedClient
from idpyoidc.server.util import OAUTH2_NOCACHE_HEADERS
from idpyoidc.util import sanitize

__author__ = "Roland Hedberg"

LOGGER = logging.getLogger(__name__)

"""
method call structure for Endpoints:

parse_request
    - client_authentication (*)
    - post_parse_request (*)

process_request

do_response
    - response_info
        - construct
            - pre_construct (*)
            - _parse_args
            - post_construct (*)
    - update_http_args

do_response returns a dictionary that can look like this::

    {
      'response':
        _response as a string or as a Message instance_
      'http_headers': [
        ('Content-type', 'application/json'),
        ('Pragma', 'no-cache'),
        ('Cache-Control', 'no-store')
      ],
      'cookie': _list of cookies_,
      'response_placement': 'body'
    }

"response" MUST be present
"http_headers" MAY be present
"cookie": MAY be present
"response_placement": If absent defaults to the endpoints response_placement
parameter value or if that is also missing 'url'
"""


def set_content_type(headers, content_type):
    if ("Content-type", content_type) in headers:
        return headers

    _headers = [h for h in headers if h[0] != "Content-type"]
    _headers.append(("Content-type", content_type))
    return _headers


def fragment_encoding(return_type):
    if return_type == ["code"]:
        return False
    else:
        return True


class Endpoint(Node):
    request_cls = Message
    response_cls = Message
    error_cls = ResponseMessage
    endpoint_name = ""
    endpoint_path = ""
    endpoint_type = ""
    name = ""
    request_format = "urlencoded"
    request_placement = "query"
    response_format = "json"
    response_placement = "body"
    response_content_type = ""
    client_authn_method = ""
    auth_method_attribute = ""

    _supports = {}

    def __init__(self, upstream_get: Callable, **kwargs):
        self.upstream_get = upstream_get
        self.pre_construct = []
        self.post_construct = []
        self.post_parse_request = []
        self.kwargs = kwargs
        self.full_path = ""

        Node.__init__(self, upstream_get=upstream_get)

        for param in [
            "request_cls",
            "response_cls",
            "request_format",
            "request_placement",
            "response_format",
            "response_placement",
        ]:
            _val = kwargs.get(param)
            if _val:
                setattr(self, param, _val)

        self.kwargs = self.set_client_authn_methods(**kwargs)
        # This is for matching against aud in JWTs
        # By default the endpoint's endpoint URL is an allowed target
        self.allowed_targets = [self.name]
        self.client_verification_method = []

    def set_client_authn_methods(self, **kwargs):
        self.client_authn_method = []
        _ama = kwargs.get(self.auth_method_attribute)
        if _ama:
            _methods = _ama
        else:
            _methods = kwargs.get("client_authn_method")

        if _methods:
            self.client_authn_method = _methods
            if self.auth_method_attribute:
                kwargs[self.auth_method_attribute] = _methods
        elif _methods is not None:  # [] or '' or something not None but regarded as nothing.
            self.client_authn_method = ["none"]  # Ignore default value
        # self.endpoint_info = construct_provider_info(self.default_capabilities, **kwargs)
        return kwargs

    def process_verify_error(self, exception):
        _error = "invalid_request"
        return self.error_cls(error=_error, error_description="%s" % exception)

    def find_client_keys(self, iss):
        return False

    def verify_request(self, request, keyjar, client_id, verify_args, lap=0):
        # verify that the request message is correct, may have to do it twice
        try:
            if verify_args is None:
                request.verify(keyjar=keyjar, opponent_id=client_id)
            else:
                request.verify(keyjar=keyjar, opponent_id=client_id, **verify_args)
        except (MissingRequiredAttribute, ValueError, MissingRequiredValue, ParameterError) as err:
            _error = "invalid_request"
            if isinstance(err, ValueError) and self.request_cls == RegistrationRequest:
                if len(err.args) > 1:
                    if err.args[1] == "initiate_login_uri":
                        _error = "invalid_client_metadata"

            return self.error_cls(error=_error, error_description="%s" % err)
        except IssuerNotFound as err:
            if lap:
                return self.error_cls(error=err)
            # Find a client ID I believe will work
            client_id = self.find_client_keys(err.args[0])
            if not client_id:
                return self.error_cls(error=err)
            else:
                self.verify_request(
                    request=request,
                    keyjar=keyjar,
                    client_id=client_id,
                    verify_args=verify_args,
                    lap=1,
                )
        return None

    def parse_request(
        self,
        request: Union[Message, dict, str],
        http_info: Optional[dict] = None,
        verify_args: Optional[dict] = None,
        **kwargs
    ):
        """

        :param request: The request the server got
        :param http_info: HTTP information in connection with the request.
            This is a dictionary with keys: headers, url, cookies.
        :param kwargs: extra keyword arguments
        :return:
        """
        LOGGER.debug("- {} -".format(self.endpoint_name))
        LOGGER.info("Request: %s" % sanitize(request))

        _context = self.upstream_get("context")
        _keyjar = self.upstream_get("attribute", "keyjar")

        if http_info is None:
            http_info = {}

        if request:
            if isinstance(request, (dict, Message)):
                req = self.request_cls(**request)
            else:
                _cls_inst = self.request_cls()
                if self.request_format == "jwt":
                    req = _cls_inst.deserialize(
                        request,
                        "jwt",
                        keyjar=_keyjar,
                        verify=_context.httpc_params["verify"],
                        **kwargs
                    )
                elif self.request_format == "url":  # A whole URL not just the query part
                    parts = urlparse(request)
                    scheme, netloc, path, params, query, fragment = parts[:6]
                    req = _cls_inst.deserialize(query, "urlencoded")
                else:
                    req = _cls_inst.deserialize(request, self.request_format)
        else:
            req = self.request_cls()

        # Verify that the client is allowed to do this
        auth_info = self.client_authentication(req, http_info, endpoint=self, **kwargs)
        LOGGER.debug(f"parse_request:auth_info:{auth_info}")

        _client_id = auth_info.get("client_id", "")
        if _client_id:
            req["client_id"] = _client_id

            _auth_method = auth_info.get("method")
            if _auth_method and _auth_method not in ["public", "none"]:
                req["authenticated"] = True
        else:
            _client_id = req.get("client_id", None)

        LOGGER.debug(f"parse_request:auth_info:{auth_info}")

        # verify that the request message is correct, may have to do it twice
        err_response = self.verify_request(
            request=req, keyjar=_keyjar, client_id=_client_id, verify_args=verify_args
        )
        if err_response:
            return err_response

        LOGGER.info("Parsed and verified request: %s" % sanitize(req))

        # Do any endpoint specific parsing
        return self.do_post_parse_request(
            request=req, client_id=_client_id, http_info=http_info, auth_info=auth_info, **kwargs
        )

    def client_authentication(self, request: Message, http_info: Optional[dict] = None, **kwargs):
        """
        Do client authentication

        :param request: Parsed request, a self.request_cls class instance
        :param http_info: HTTP headers, URL used and cookies.
        :return: client_id or raise an exception
        """

        if "endpoint" not in kwargs:
            kwargs["endpoint"] = self

        get_client_id_from_token = kwargs.get("get_client_id_from_token")
        if not get_client_id_from_token:
            kwargs["get_client_id_from_token"] = getattr(self, "get_client_id_from_token", None)

        authn_info = verify_client(request=request, http_info=http_info, **kwargs)

        LOGGER.debug("authn_info: %s", authn_info)
        if authn_info == {}:
            if self.client_authn_method and len(self.client_authn_method):
                LOGGER.debug("client_authn_method: %s", self.client_authn_method)
                raise UnAuthorizedClient("Authorization failed")
        elif "client_id" not in authn_info and authn_info.get("method") != "none":
            raise UnAuthorizedClient("Authorization failed")
        return authn_info

    def do_post_parse_request(
        self, request: Message, client_id: Optional[str] = "", **kwargs
    ) -> Message:
        _context = self.upstream_get("context")
        for meth in self.post_parse_request:
            if isinstance(request, self.error_cls):
                break
            request = meth(request, client_id, context=_context, **kwargs)
        return request

    def do_pre_construct(
        self, response_args: dict, request: Optional[Union[Message, dict]] = None, **kwargs
    ) -> dict:
        _context = self.upstream_get("context")
        for meth in self.pre_construct:
            response_args = meth(response_args, request, context=_context, **kwargs)

        return response_args

    def do_post_construct(
        self,
        response_args: Union[Message, dict],
        request: Optional[Union[Message, dict]] = None,
        **kwargs
    ) -> dict:
        _context = self.upstream_get("context")
        for meth in self.post_construct:
            response_args = meth(response_args, request, context=_context, **kwargs)

        return response_args

    def process_request(
        self,
        request: Optional[Union[Message, dict]] = None,
        http_info: Optional[dict] = None,
        **kwargs
    ) -> Union[Message, dict]:
        """

        :param http_info: Information on the HTTP request
        :param request: The request, can be in a number of formats
        :return: Arguments for the do_response method
        """
        return {}

    def construct(
        self,
        response_args: Optional[dict] = None,
        request: Optional[Union[Message, dict]] = None,
        **kwargs
    ):
        """
        Construct the response

        :param response_args: response arguments
        :param request: The parsed request, a self.request_cls class instance
        :param kwargs: Extra keyword arguments
        :return: An instance of the self.response_cls class
        """
        response_args = self.do_pre_construct(response_args, request, **kwargs)

        # LOGGER.debug("kwargs: %s" % sanitize(kwargs))
        response = self.response_cls(**response_args)

        return self.do_post_construct(response, request, **kwargs)

    def response_info(
        self,
        response_args: Optional[dict] = None,
        request: Optional[Union[Message, dict]] = None,
        **kwargs
    ) -> dict:
        return self.construct(response_args, request, **kwargs)

    def do_response(
        self,
        response_args: Optional[dict] = None,
        request: Optional[Union[Message, dict]] = None,
        error: Optional[str] = "",
        **kwargs
    ) -> dict:
        """
        :param response_args: Information to use when constructing the response
        :param request: The original request
        :param error: Possible error encountered while processing the request
        """
        do_placement = True
        content_type = "text/html"
        _resp = {}
        _response_placement = None
        if response_args is None:
            response_args = {}

        LOGGER.debug("do_response kwargs: %s", kwargs)

        resp = None
        if error:
            _response = ResponseMessage(error=error)
            for attr in ["error_description", "error_uri", "state"]:
                if attr in kwargs:
                    _response[attr] = kwargs[attr]
        elif "response_msg" in kwargs:
            resp = kwargs["response_msg"]
            _response_placement = kwargs.get("response_placement")
            do_placement = False
            _response = ""
            content_type = kwargs.get("content_type")
            if content_type is None:
                if self.response_content_type:
                    content_type = self.response_content_type
                elif self.response_format == "json":
                    content_type = "application/json"
                elif self.response_format in ["jws", "jwe", "jose"]:
                    content_type = "application/jose"
                elif self.response_format == "text":
                    content_type = "text/plain"
                else:
                    content_type = "application/x-www-form-urlencoded"
        else:
            _response = self.response_info(response_args, request, **kwargs)

        if do_placement:
            content_type = kwargs.get("content_type")
            if content_type is None:
                if self.response_placement == "body":
                    if self.response_format == "json":
                        content_type = "application/json; charset=utf-8"
                        if isinstance(_response, Message):
                            resp = _response.to_json()
                        else:
                            resp = json.dumps(_response)
                    elif self.response_format in ["jws", "jwe", "jose"]:
                        if self.response_content_type:
                            content_type = self.response_content_type
                        else:
                            content_type = "application/jose; charset=utf-8"
                        resp = _response
                    else:
                        content_type = "application/x-www-form-urlencoded"
                        resp = _response.to_urlencoded()
                elif self.response_placement == "url":
                    content_type = "application/x-www-form-urlencoded"
                    fragment_enc = kwargs.get("fragment_enc")
                    if not fragment_enc:
                        _ret_type = kwargs.get("return_type")
                        if _ret_type:
                            fragment_enc = fragment_encoding(_ret_type)
                        else:
                            fragment_enc = False

                    if fragment_enc:
                        resp = _response.request(kwargs["return_uri"], True)
                    else:
                        resp = _response.request(kwargs["return_uri"])
                else:
                    raise ValueError(
                        "Don't know where that is: '{}".format(self.response_placement)
                    )

        if content_type:
            try:
                http_headers = set_content_type(kwargs["http_headers"], content_type)
            except KeyError:
                http_headers = [("Content-type", content_type)]
        else:
            try:
                http_headers = kwargs["http_headers"]
            except KeyError:
                http_headers = []

        if _response_placement:
            _resp["response_placement"] = _response_placement

        http_headers.extend(OAUTH2_NOCACHE_HEADERS)

        _resp.update({"response": resp, "http_headers": http_headers})

        try:
            _resp["cookie"] = kwargs["cookie"]
        except KeyError:
            pass

        try:
            _resp["response_code"] = kwargs["response_code"]
        except KeyError:
            pass

        return _resp

    def allowed_target_uris(self):
        res = []
        _context = self.upstream_get("context")
        for t in self.allowed_targets:
            if t == "":
                res.append(_context.issuer)
            else:
                res.append(self.upstream_get("endpoint", t).full_path)
        return set(res)

    def supports(self):
        res = {}
        for key, val in self._supports.items():
            if isinstance(val, Callable):
                res[key] = val()
            else:
                res[key] = val
        return res
