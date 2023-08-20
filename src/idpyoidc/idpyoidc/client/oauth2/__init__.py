import logging
from json import JSONDecodeError
from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt.key_jar import KeyJar
from requests import request

from idpyoidc.client.entity import Entity
from idpyoidc.client.exception import ConfigurationError
from idpyoidc.client.exception import OidcServiceError
from idpyoidc.client.exception import ParseError
from idpyoidc.client.service import REQUEST_INFO
from idpyoidc.client.service import Service
from idpyoidc.client.service import SUCCESSFUL
from idpyoidc.client.util import do_add_ons
from idpyoidc.client.util import get_deserialization_method
from idpyoidc.configure import Configuration
from idpyoidc.context import OidcContext
from idpyoidc.exception import FormatError
from idpyoidc.message import Message
from idpyoidc.message.oauth2 import is_error_message

__author__ = "Roland Hedberg"

logger = logging.getLogger(__name__)


class ExpiredToken(Exception):
    pass


# =============================================================================


class Client(Entity):
    client_type = "oauth2"

    def __init__(
            self,
            keyjar: Optional[KeyJar] = None,
            config: Optional[Union[dict, Configuration]] = None,
            services: Optional[dict] = None,
            httpc: Optional[Callable] = None,
            httpc_params: Optional[dict] = None,
            context: Optional[OidcContext] = None,
            upstream_get: Optional[Callable] = None,
            key_conf: Optional[dict] = None,
            entity_id: Optional[str] = "",
            verify_ssl: Optional[bool] = True,
            jwks_uri: Optional[str] = "",
            client_type: Optional[str] = "",
            **kwargs
    ):
        """

        :type client_type: str
        :param client_type: What kind of client this is. Presently 'oauth2' or 'oidc'
        :param keyjar: A py:class:`idpyoidc.key_jar.KeyJar` instance
        :param config: Configuration information passed on to the
            :py:class:`idpyoidc.client.service_context.ServiceContext`
            initialization
        :param httpc: A HTTP client to use
        :param httpc_params: HTTP request arguments
        :param services: A list of service definitions
        :param jwks_uri: A jwks_uri
        :return: Client instance
        """

        if client_type:
            self.client_type = client_type
        elif config and 'client_type' in config:
            client_type = self.client_type = config["client_type"]
        else:
            client_type = self.client_type

        if verify_ssl is False:
            # just ignore verify_ssl until it goes away
            if httpc_params:
                httpc_params["verify"] = False
            else:
                httpc_params = {"verify": False}

        jwks_uri = jwks_uri or config.get('jwks_uri', '')

        Entity.__init__(
            self,
            keyjar=keyjar,
            config=config,
            services=services,
            jwks_uri=jwks_uri,
            httpc=httpc,
            httpc_params=httpc_params,
            client_type=client_type,
            context=context,
            upstream_get=upstream_get,
            key_conf=key_conf,
            entity_id=entity_id,
        )

        self.httpc = httpc or request

        if isinstance(config, Configuration):
            _add_ons = config.conf.get("add_ons")
        else:
            _add_ons = config.get("add_ons")

        if _add_ons:
            do_add_ons(_add_ons, self._service)

    def do_request(
            self,
            request_type: str,
            response_body_type: Optional[str] = "",
            request_args: Optional[dict] = None,
            behaviour_args: Optional[dict] = None,
            **kwargs
    ):
        _srv = self._service[request_type]

        _info = _srv.get_request_parameters(request_args=request_args, **kwargs)

        if not response_body_type:
            response_body_type = _srv.response_body_type

        logger.debug("do_request info: {}".format(_info))

        try:
            _state = kwargs["state"]
        except Exception:
            _state = ""
        return self.service_request(
            _srv, response_body_type=response_body_type, state=_state, **_info
        )

    def set_client_id(self, client_id):
        self.get_context().set("client_id", client_id)

    def get_response(
            self,
            service: Service,
            url: str,
            method: Optional[str] = "GET",
            body: Optional[dict] = None,
            response_body_type: Optional[str] = "",
            headers: Optional[dict] = None,
            **kwargs
    ):
        """

        :param url:
        :param method:
        :param body:
        :param response_body_type:
        :param headers:
        :param kwargs:
        :return:
        """
        try:
            resp = self.httpc(method, url, data=body, headers=headers, **self.httpc_params)
        except Exception as err:
            logger.error("Exception on request: {}".format(err))
            raise

        if 300 <= resp.status_code < 400:
            return {"http_response": resp}

        if resp.status_code < 300:
            if "keyjar" not in kwargs:
                kwargs["keyjar"] = self.get_attribute("keyjar")
            if not response_body_type:
                response_body_type = service.response_body_type

            if response_body_type == "html":
                return resp.text

            if body:
                kwargs["request_body"] = body

        return self.parse_request_response(service, resp, response_body_type, **kwargs)

    def service_request(
            self,
            service: Service,
            url: str,
            method: Optional[str] = "GET",
            body: Optional[dict] = None,
            response_body_type: Optional[str] = "",
            headers: Optional[dict] = None,
            **kwargs
    ) -> Message:
        """
        The method that sends the request and handles the response returned.
        This assumes that the response arrives in the HTTP response.

        :param service: The Service instance
        :param url: The URL to which the request should be sent
        :param method: Which HTTP method to use
        :param body: A message body if any
        :param response_body_type: The expected format of the body of the
            return message
        :param httpc_params: Arguments for the HTTP client
        :return: A cls or ResponseMessage instance or the HTTP response
            instance if no response body was expected.
        """

        if headers is None:
            headers = {}

        logger.debug(REQUEST_INFO.format(url, method, body, headers))

        try:
            response = service.get_response_ext(
                url, method, body, response_body_type, headers, **kwargs
            )
        except AttributeError:
            response = self.get_response(
                service, url, method, body, response_body_type, headers, **kwargs
            )

        if "error" in response:
            pass
        else:
            service.update_service_context(response, key=kwargs.get("state"), **kwargs)
        return response

    def parse_request_response(self, service, reqresp, response_body_type="", state="", **kwargs):
        """
        Deal with a self.httpc response. The response are expected to
        follow a special pattern, having the attributes:

            - headers (list of tuples with headers attributes and their values)
            - status_code (integer)
            - text (The text version of the response)
            - url (The calling URL)

        :param service: A :py:class:`idpyoidc.client.service.Service` instance
        :param reqresp: The HTTP request response
        :param response_body_type: If response in body one of 'json', 'jwt' or
            'urlencoded'
        :param state: Session identifier
        :param kwargs: Extra keyword arguments
        :return:
        """

        # if not response_body_type:
        #     response_body_type = self.response_body_type

        if reqresp.status_code in SUCCESSFUL:
            logger.debug('response_body_type: "{}"'.format(response_body_type))
            _deser_method = get_deserialization_method(reqresp)

            if _deser_method != response_body_type:
                logger.warning(
                    "Not the body type I expected: {} != {}".format(
                        _deser_method, response_body_type
                    )
                )
            if _deser_method in ["json", "jwt", "urlencoded"]:
                value_type = _deser_method
            else:
                value_type = response_body_type

            logger.debug("Successful response: {}".format(reqresp.text))

            try:
                return service.parse_response(reqresp.text, value_type, state, **kwargs)
            except Exception as err:
                logger.error(err)
                raise
        elif reqresp.status_code in [302, 303]:  # redirect
            return reqresp
        elif reqresp.status_code == 500:
            logger.error("(%d) %s" % (reqresp.status_code, reqresp.text))
            raise ParseError("ERROR: Something went wrong: %s" % reqresp.text)
        elif 400 <= reqresp.status_code < 500:
            logger.error("Error response ({}): {}".format(reqresp.status_code, reqresp.text))
            # expecting an error response
            _deser_method = get_deserialization_method(reqresp)
            if not _deser_method:
                _deser_method = "json"

            try:
                err_resp = service.parse_response(reqresp.text, _deser_method)
            except (FormatError, ValueError):
                if _deser_method != response_body_type:
                    try:
                        err_resp = service.parse_response(reqresp.text, response_body_type)
                    except (OidcServiceError, FormatError, ValueError):
                        raise OidcServiceError(
                            "HTTP ERROR: %s [%s] on %s"
                            % (reqresp.text, reqresp.status_code, reqresp.url)
                        )
                else:
                    raise OidcServiceError(
                        "HTTP ERROR: %s [%s] on %s"
                        % (reqresp.text, reqresp.status_code, reqresp.url)
                    )
            except JSONDecodeError:  # So it's not JSON assume text then
                err_resp = {"error": reqresp.text}

            err_resp["status_code"] = reqresp.status_code
            return err_resp
        else:
            logger.error("Error response ({}): {}".format(reqresp.status_code, reqresp.text))
            raise OidcServiceError(
                "HTTP ERROR: %s [%s] on %s" % (reqresp.text, reqresp.status_code, reqresp.url)
            )


def dynamic_provider_info_discovery(client: Client, behaviour_args: Optional[dict] = None):
    """
    This is about performing dynamic Provider Info discovery

    :param behaviour_args:
    :param client: A :py:class:`idpyoidc.client.oidc.Client` instance
    """

    if client.client_type == 'oidc' and client.get_service("provider_info"):
        service = 'provider_info'
    elif client.client_type == 'oauth2' and client.get_service('server_metadata'):
        service = 'server_metadata'
    else:
        raise ConfigurationError("Can not do dynamic provider info discovery")

    _context = client.get_context()
    try:
        _context.set("issuer", _context.config["srv_discovery_url"])
    except KeyError:
        pass

    response = client.do_request(service, behaviour_args=behaviour_args)
    if is_error_message(response):
        raise OidcServiceError(response["error"])
