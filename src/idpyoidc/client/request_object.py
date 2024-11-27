from typing import Optional
from typing import Union

from cryptojwt.jwe.jwe import JWE
from cryptojwt.jwe.utils import alg2keytype
from cryptojwt.jwt import utc_time_sans_frac

from idpyoidc.defaults import DEF_SIGN_ALG
from idpyoidc.exception import MissingRequiredAttribute
from idpyoidc.message import Message
from idpyoidc.message.oidc import make_openid_request


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


def get_request_object_signing_alg(self, **kwargs):
    alg = ""
    for arg in ["request_object_signing_alg", "algorithm"]:
        try:  # Trumps everything
            alg = kwargs[arg]
        except KeyError:
            pass
        else:
            break

    if not alg:
        _context = self.upstream_get("context")
        try:
            alg = _context.claims.get_usage("request_object_signing_alg")
        except KeyError:  # Use default
            pass

        if not alg:
            alg = DEF_SIGN_ALG["request_object"]

    return alg


def construct_request_parameter(
        service,
        req: Union[Message, dict],
        expires_in: Optional[int] = 0,
        **kwargs):
    """Construct a request parameter"""
    alg = get_request_object_signing_alg(service, **kwargs)
    kwargs["request_object_signing_alg"] = alg

    _context = service.upstream_get("context")
    if "keys" not in kwargs:
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

    if expires_in:
        req["exp"] = utc_time_sans_frac() + int(expires_in)

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
