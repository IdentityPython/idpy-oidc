import logging
from typing import Optional

from idpyoidc import alg_info
from idpyoidc.client.request_object import construct_request_parameter
from idpyoidc.client.request_object import construct_request_uri

logger = logging.getLogger(__name__)

DEFAULT_EXPIRES_IN = 3600


def store_request_on_file(service, req, **kwargs):
    """
    Stores the request parameter in a file.
    :param req: The request
    :param kwargs: Extra keyword arguments
    :return: The URL the OP should use to access the file
    """
    _context = service.upstream_get("context")
    _webname = _context.get_usage("request_uris")
    if _webname is None:
        filename, _webname = construct_request_uri(**kwargs)
    else:
        # webname should be a list
        _webname = _webname[0]
        filename = _context.filename_from_webname(_webname)

    fid = open(filename, mode="w")
    fid.write(req)
    fid.close()
    return _webname


def jar_post_construct(request_args, service, **kwargs):
    """
    Modify the request arguments.

    :param request_args: The request
    :param service: The service that uses this post_constructor
    :param kwargs: Extra keyword arguments
    :return: A possibly modified request.
    """
    _context = service.upstream_get("context")

    # Overrides what's in the configuration
    _request_param = kwargs.get("request_param")
    _local_dir = ""
    if _request_param:
        del kwargs["request_param"]
    else:
        _jar_config = _context.add_on["jar"]
        if "request_uri" in _context.add_on["jar"]:
            _request_param = "request_uri"
            _local_dir = _jar_config.get("requests_dir", "./requests")
        elif "request_parameter" in _jar_config:
            _request_param = "request"

    _req = None  # just a flag
    _state = request_args["state"]
    if _request_param == "request_uri":
        kwargs["base_path"] = _context.get("base_url") + "/" + "requests"
        if _local_dir:
            kwargs["local_dir"] = _local_dir
        else:
            kwargs["local_dir"] = kwargs.get("requests_dir", "./requests")

        _req = construct_request_parameter(service, request_args, _request_param, **kwargs)
        request_args["request_uri"] = store_request_on_file(service, _req, **kwargs)
    elif _request_param == "request":
        _req = construct_request_parameter(service, request_args, **kwargs)
        request_args["request"] = _req

    if _req:
        _leave = ["request", "request_uri"]
        _leave.extend(request_args.required_parameters())
        _keys = [k for k in request_args.keys() if k not in _leave]
        for k in _keys:
            del request_args[k]

    _context.cstate.update(_state, request_args)

    return request_args


def add_support(
        service,
        request_type: Optional[str] = "request_parameter",
        request_dir: Optional[str] = "",
        request_object_signing_alg: Optional[str] = "RS256",
        expires_in: Optional[int] = DEFAULT_EXPIRES_IN,
        with_jti: Optional[bool] = False,
        request_object_encryption_alg: Optional[str] = "",
        request_object_encryption_enc: Optional[str] = "",
):
    """
    JAR support can only be considered if this client can access an authorization service.

    :param service: Dictionary of services
    :return:
    """
    if "authorization" in service:
        _service = service["authorization"]
        _context = _service.upstream_get("context")

        _service.post_construct.append(jar_post_construct)
        args = {
            "request_object_signing_alg": request_object_signing_alg,
            "expires_in": expires_in,
            "with_jti": with_jti,
        }
        if request_type == "request_parameter":
            args["request_parameter"] = True
        elif request_type == "request_uri":
            args["request_uri"] = True
            if request_dir:
                args["request_dir"] = request_dir

        if request_object_encryption_enc and request_object_encryption_alg:
            if request_object_encryption_enc in alg_info.get_encryption_encs():
                if request_object_encryption_alg in alg_info.get_encryption_algs():
                    args["request_object_encryption_enc"] = request_object_encryption_enc
                    args["request_object_encryption_alg"] = request_object_encryption_alg
                else:
                    AttributeError(
                        f"An encryption alg {request_object_encryption_alg} there is no support "
                        f"for"
                    )
            else:
                AttributeError(
                    f"An encryption enc {request_object_encryption_enc} there is no support for"
                )

        _context.add_on["jar"] = args
    else:
        logger.warning("JAR support could NOT be added")
