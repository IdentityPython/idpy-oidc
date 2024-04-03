import logging

from cryptojwt.utils import importer

from idpyoidc.client.client_auth import CLIENT_AUTHN_METHOD
from idpyoidc.message import Message
from idpyoidc.message.oauth2 import JWTSecuredAuthorizationRequest
from idpyoidc.server.util import execute
from idpyoidc.util import instantiate

logger = logging.getLogger(__name__)

HTTP_METHOD = "POST"


def push_authorization(request_args, service, **kwargs):
    """
    :param request_args: All the request arguments as a AuthorizationRequest instance
    :param service: The service to which this post construct method is applied.
    :param kwargs: Extra keyword arguments.
    """

    _context = service.upstream_get("context")
    method_args = _context.add_on["pushed_authorization"]
    logger.debug(f"PAR method args: {method_args}")
    logger.debug(f"PAR kwargs: {kwargs}")

    # Add client authentication if needed
    _headers = {}
    authn_method = method_args["authn_method"]
    if authn_method:
        if isinstance(authn_method, str):
            if authn_method not in _context.client_authn_methods:
                _context.client_authn_methods[authn_method] = CLIENT_AUTHN_METHOD[authn_method]()
        else:
            _name = ""
            for _name, spec in authn_method.items():
                if _name not in _context.client_authn_methods:
                    _context.client_authn_methods[_name] = execute(spec)
            authn_method = _name

        _args = kwargs.copy()
        if _context.issuer:
            _args["iss"] = _context.issuer

        _headers = service.get_headers(
            request_args, http_method=HTTP_METHOD, authn_method=authn_method, **_args
        )
        _headers["Content-Type"] = "application/x-www-form-urlencoded"

    # construct the message body
    _body = request_args.to_urlencoded()

    _http_client = method_args.get("http_client", None)
    if not _http_client:
        _http_client = service.upstream_get("unit").httpc

    _httpc_params = service.upstream_get("unit").httpc_params

    # Send it to the Pushed Authorization Request Endpoint using POST
    resp = _http_client(
        method=HTTP_METHOD,
        url=_context.provider_info["pushed_authorization_request_endpoint"],
        data=_body,
        headers=_headers,
        **_httpc_params
    )

    if resp.status_code == 200:
        _resp = Message().from_json(resp.text)
        _req = JWTSecuredAuthorizationRequest(request_uri=_resp["request_uri"])
        for param in request_args.required_parameters():
            _req[param] = request_args.get(param)
        request_args = _req
    else:
        raise ConnectionError(
            f"Could not connect to "
            f'{_context.provider_info["pushed_authorization_request_endpoint"]}'
        )

    return request_args


def add_support(
        services,
        http_client=None,
        authn_method="",
):
    """
    Add the necessary pieces to support Pushed authorization.

    :param http_client: Specification for a HTTP client to use different from the default
    :param authn_method: The client authentication method to use
    :param services: A dictionary with all the services the client has access to.
    """

    if http_client is not None:
        if isinstance(http_client, dict):
            if "class" in http_client:
                http_client = instantiate(http_client["class"], **http_client.get("kwargs", {}))
            else:
                http_client = importer(http_client["function"])
        else:
            http_client = importer(http_client)

    _service = services["authorization"]  # There must be such a service
    _service.upstream_get("context").add_on["pushed_authorization"] = {
        "http_client": http_client,
        "authn_method": authn_method,
    }

    _service.post_construct.append(push_authorization)
