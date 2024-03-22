import logging

from cryptojwt import JWT
from cryptojwt.utils import importer

from idpyoidc.client.client_auth import CLIENT_AUTHN_METHOD
from idpyoidc.message import Message
from idpyoidc.message.oauth2 import JWTSecuredAuthorizationRequest
from idpyoidc.server.util import execute
from idpyoidc.util import instantiate
from requests import request

logger = logging.getLogger(__name__)


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

    if method_args["apply"] is False:
        return request_args

    _http_method = method_args["http_client"]
    _httpc_params = service.upstream_get("unit").httpc_params

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
            request_args, http_method=_http_method, authn_method=authn_method, **_args
        )
        _headers["Content-Type"] = "application/x-www-form-urlencoded"

    # construct the message body
    if method_args["body_format"] == "urlencoded":
        _body = request_args.to_urlencoded()
    else:
        _jwt = JWT(
            key_jar=service.upstream_get("attribute", "keyjar"),
            iss=_context.claims.prefer["client_id"],
        )
        _jws = _jwt.pack(request_args.to_dict())

        _msg = Message(request=_jws)
        for param in request_args.required_parameters():
            _msg[param] = request_args.get(param)

        _body = _msg.to_urlencoded()

    # Send it to the Pushed Authorization Request Endpoint using POST
    resp = _http_method(
        method="POST",
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
    body_format="jws",
    signing_algorithm="RS256",
    http_client=None,
    merge_rule="strict",
    authn_method="",
):
    """
    Add the necessary pieces to support Pushed authorization.

    :param merge_rule:
    :param http_client:
    :param signing_algorithm:
    :param services: A dictionary with all the services the client has access to.
    :param body_format: jws or urlencoded
    """

    if http_client is None:
        _http_client = request
    else:
        if isinstance(http_client, dict):
            if "class" in http_client:
                _http_client = instantiate(http_client["class"], **http_client.get("kwargs", {}))
            else:
                _http_client = importer(http_client["function"])
        else:
            _http_client = importer(http_client)

    _service = services["authorization"]
    _service.upstream_get("context").add_on["pushed_authorization"] = {
        "body_format": body_format,
        "signing_algorithm": signing_algorithm,
        "http_client": _http_client,
        "merge_rule": merge_rule,
        "apply": True,
        "authn_method": authn_method,
    }

    _service.post_construct.append(push_authorization)
