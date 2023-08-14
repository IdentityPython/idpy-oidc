import logging
from typing import Optional

from idpyoidc import metadata

from idpyoidc import claims
from idpyoidc.client.oidc.utils import construct_request_uri
from idpyoidc.client.oidc.utils import request_object_encryption
from idpyoidc.message.oidc import make_openid_request
from idpyoidc.time_util import utc_time_sans_frac

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


def get_request_object_signing_alg(service, **kwargs):
    alg = ""
    for arg in ["request_object_signing_alg", "algorithm"]:
        try:  # Trumps everything
            alg = kwargs[arg]
        except KeyError:
            pass
        else:
            break

    if not alg:
        _context = service.upstream_get("context")
        alg = _context.add_on["jar"].get("request_object_signing_alg")
        if alg is None:
            alg = "RS256"
    return alg


def construct_request_parameter(service, req, audience=None, **kwargs):
    """Construct a request parameter"""
    alg = get_request_object_signing_alg(service, **kwargs)
    kwargs["request_object_signing_alg"] = alg

    _context = service.upstream_get("context")
    if "keys" not in kwargs and alg and alg != "none":
        kwargs["keys"] = service.upstream_get("attribute", "keyjar")

    if alg == "none":
        kwargs["keys"] = []

    # This is the issuer of the JWT, that is me !
    _issuer = kwargs.get("issuer")
    if _issuer is None:
        kwargs["issuer"] = _context.get_client_id()

    if kwargs.get("recv") is None:
        try:
            kwargs["recv"] = _context.provider_info["issuer"]
        except KeyError:
            kwargs["recv"] = _context.issuer

    try:
        del kwargs["service"]
    except KeyError:
        pass

    _jar_conf = _context.add_on["jar"]
    expires_in = _jar_conf.get("expires_in", DEFAULT_EXPIRES_IN)
    if expires_in:
        req["exp"] = utc_time_sans_frac() + int(expires_in)

    if _jar_conf.get("with_jti", False):
        kwargs["with_jti"] = True

    _enc_enc = _jar_conf.get("request_object_encryption_enc", "")
    if _enc_enc:
        kwargs["request_object_encryption_enc"] = _enc_enc
        kwargs["request_object_encryption_alg"] = _jar_conf.get("request_object_encryption_alg")

    # Filter out only the arguments I want
    _mor_args = {
        k: kwargs[k]
        for k in [
            "keys",
            "issuer",
            "request_object_signing_alg",
            "recv",
            "with_jti",
            "lifetime",
        ]
        if k in kwargs
    }

    if audience:
        _mor_args["aud"] = audience

    _req_jwt = make_openid_request(req, **_mor_args)

    if "target" not in kwargs:
        kwargs["target"] = _context.provider_info.get("issuer", _context.issuer)

    # Should the request be encrypted
    _req_jwte = request_object_encryption(
        _req_jwt, _context, service.upstream_get("attribute", "keyjar"), **kwargs
    )
    return _req_jwte


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
            if request_object_encryption_enc in metadata.get_encryption_encs():
                if request_object_encryption_alg in metadata.get_encryption_algs():
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
