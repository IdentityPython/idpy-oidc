import os

from cryptojwt.jwe.jwe import JWE
from cryptojwt.jwe.utils import alg2keytype
from cryptojwt.jwt import utc_time_sans_frac

from idpyoidc.exception import MissingRequiredAttribute
from idpyoidc.message.oidc import make_openid_request
from idpyoidc.util import rndstr

DEFAULT_EXPIRES_IN = 3600


def request_object_encryption(msg, service_context, keyjar, **kwargs):
    """
    Created an encrypted JSON Web token with *msg* as body.

    :param msg: The message
    :param service_context:
    :param kwargs:
    :return:
    """
    try:
        encalg = kwargs["request_object_encryption_alg"]
    except KeyError:
        try:
            encalg = service_context.get_usage("request_object_encryption_alg")
        except KeyError:
            return msg

    if not encalg:
        return msg

    try:
        encenc = kwargs["request_object_encryption_enc"]
    except KeyError:
        try:
            encenc = service_context.get_usage("request_object_encryption_enc")
        except KeyError:
            raise MissingRequiredAttribute("No request_object_encryption_enc specified")

    if not encenc:
        raise MissingRequiredAttribute("No request_object_encryption_enc specified")

    _jwe = JWE(msg, alg=encalg, enc=encenc)
    _kty = alg2keytype(encalg)

    try:
        _kid = kwargs["enc_kid"]
    except KeyError:
        _kid = ""

    _target = kwargs.get("target", kwargs.get("recv", None))
    if _target is None:
        raise MissingRequiredAttribute("No target specified")

    if _kid:
        _keys = keyjar.get_encrypt_key(_kty, issuer_id=_target, kid=_kid)
        _jwe["kid"] = _kid
    else:
        _keys = keyjar.get_encrypt_key(_kty, issuer_id=_target)

    return _jwe.encrypt(_keys)


def construct_request_uri(local_dir, base_path, **kwargs):
    """
    Constructs a special redirect_uri to be used when communicating with
    one OP. Each OP should get their own redirect_uris.

    :param local_dir: Local directory in which to place the file
    :param base_path: Base URL to start with
    :param kwargs:
    :return: 2-tuple with (filename, url)
    """
    _filedir = local_dir
    if not os.path.isdir(_filedir):
        os.makedirs(_filedir)
    _webpath = base_path
    _name = rndstr(10) + ".jwt"
    filename = os.path.join(_filedir, _name)
    while os.path.exists(filename):
        _name = rndstr(10)
        filename = os.path.join(_filedir, _name)
    if _webpath.endswith("/"):
        _webname = f"{_webpath}{_name}"
    else:
        _webname = f"{_webpath}/{_name}"
    return filename, _webname


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
        alg = _context.claims.get_usage("request_object_signing_alg", None)
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

    # The receiver
    if audience:
        kwargs["recv"] = audience
    elif kwargs.get("recv") is None:
        try:
            kwargs["recv"] = _context.provider_info["issuer"]
        except KeyError:
            kwargs["recv"] = _context.issuer

    try:
        del kwargs["service"]
    except KeyError:
        pass

    _expires_in = kwargs.get("expires_in", DEFAULT_EXPIRES_IN)
    req["exp"] = utc_time_sans_frac() + int(_expires_in)

    kwargs["with_jti"] = kwargs.get("with_jti",True)

    _enc_enc = kwargs.get("request_object_encryption_enc", "")
    if not _enc_enc:
        _enc_enc = _context.get_usage("request_object_encryption_enc")
        if _enc_enc:
            kwargs["request_object_encryption_enc"] = _enc_enc
            kwargs["request_object_encryption_alg"] = _context.get_usage("request_object_encryption_alg")

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

    _req_jwt = make_openid_request(req, **_mor_args)

    if "target" not in kwargs:
        kwargs["target"] = _context.provider_info.get("issuer", _context.issuer)

    # Should the request be encrypted
    _req_jwte = request_object_encryption(
        _req_jwt, _context, service.upstream_get("attribute", "keyjar"), **kwargs
    )
    return _req_jwte
