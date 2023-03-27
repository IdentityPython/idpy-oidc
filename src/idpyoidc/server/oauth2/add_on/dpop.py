from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt import JWS
from cryptojwt import as_unicode
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jws.jws import factory

from idpyoidc.claims import get_signing_algs
from idpyoidc.message import Message
from idpyoidc.message import SINGLE_REQUIRED_INT
from idpyoidc.message import SINGLE_REQUIRED_JSON
from idpyoidc.message import SINGLE_REQUIRED_STRING
from idpyoidc.server.client_authn import BearerHeader
from idpyoidc.server.client_authn import ClientAuthnMethod
from idpyoidc.server.client_authn import basic_authn
from idpyoidc.server.exception import ClientAuthenticationError


class DPoPProof(Message):
    c_param = {
        # header
        "typ": SINGLE_REQUIRED_STRING,
        "alg": SINGLE_REQUIRED_STRING,
        "jwk": SINGLE_REQUIRED_JSON,
        # body
        "jti": SINGLE_REQUIRED_STRING,
        "htm": SINGLE_REQUIRED_STRING,
        "htu": SINGLE_REQUIRED_STRING,
        "iat": SINGLE_REQUIRED_INT,
    }
    header_params = {"typ", "alg", "jwk"}
    body_params = {"jti", "htm", "htu", "iat"}

    def __init__(self, set_defaults=True, **kwargs):
        self.key = None
        Message.__init__(self, set_defaults=set_defaults, **kwargs)

        if self.key:
            pass
        elif "jwk" in self:
            self.key = key_from_jwk_dict(self["jwk"])
            self.key.deserialize()

    def from_dict(self, dictionary, **kwargs):
        Message.from_dict(self, dictionary, **kwargs)

        if "jwk" in self:
            self.key = key_from_jwk_dict(self["jwk"])
            self.key.deserialize()

        return self

    def verify(self, **kwargs):
        Message.verify(self, **kwargs)
        if self["typ"] != "dpop+jwt":
            raise ValueError("Wrong type")
        if self["alg"] == "none":
            raise ValueError("'none' is not allowed as signing algorithm")

    def create_header(self) -> str:
        payload = {k: self[k] for k in self.body_params}
        _jws = JWS(payload, alg=self["alg"])
        _headers = {k: self[k] for k in self.header_params}
        self.key.kid = ""
        _sjwt = _jws.sign_compact(keys=[self.key], **_headers)
        return _sjwt

    def verify_header(self, dpop_header) -> Optional["DPoPProof"]:
        _jws = factory(dpop_header)
        if _jws:
            _jwt = _jws.jwt
            if "jwk" in _jwt.headers:
                _pub_key = key_from_jwk_dict(_jwt.headers["jwk"])
                _pub_key.deserialize()
                _info = _jws.verify_compact(keys=[_pub_key], sigalg=_jwt.headers["alg"])
                for k, v in _jwt.headers.items():
                    self[k] = v

                for k, v in _info.items():
                    self[k] = v
            else:
                raise Exception()

            return self
        else:
            return None


def post_parse_request(request, client_id, context, **kwargs):
    """
    Expect http_info attribute in kwargs. http_info should be a dictionary
    containing HTTP information.

    :param request:
    :param client_id:
    :param context:
    :param kwargs:
    :return:
    """

    _http_info = kwargs.get("http_info")
    if not _http_info:
        return request

    _dpop = DPoPProof().verify_header(_http_info["headers"]["dpop"])

    # The signature of the JWS is verified, now for checking the
    # content

    if _dpop["htu"] != _http_info["url"]:
        raise ValueError("htu in DPoP does not match the HTTP URI")

    if _dpop["htm"] != _http_info["method"]:
        raise ValueError("htm in DPoP does not match the HTTP method")

    if not _dpop.key:
        _dpop.key = key_from_jwk_dict(_dpop["jwk"])

    # Need something I can add as a reference when minting tokens
    request["dpop_jkt"] = as_unicode(_dpop.key.thumbprint("SHA-256"))
    return request


def token_args(context, client_id, token_args: Optional[dict] = None):
    dpop_jkt = context.cdb[client_id]["dpop_jkt"]
    _jkt = list(dpop_jkt.keys())[0]
    if "dpop_jkt" in context.cdb[client_id]:
        if token_args is None:
            token_args = {"cnf": {"jkt": _jkt}}
        else:
            token_args.update({"cnf": {"jkt": context.cdb[client_id]["dpop_jkt"]}})

    return token_args


def add_support(endpoint: dict, **kwargs):
    #
    _token_endp = endpoint["token"]
    _token_endp.post_parse_request.append(post_parse_request)

    _algs_supported = kwargs.get("dpop_signing_alg_values_supported")
    if not _algs_supported:
        _algs_supported = ["RS256"]
    else:
        _algs_supported = [alg for alg in _algs_supported if alg in get_signing_algs()]

    _token_endp.upstream_get("context").provider_info[
        "dpop_signing_alg_values_supported"
    ] = _algs_supported

    _context = _token_endp.upstream_get("context")
    _context.add_on['dpop'] = {'algs_supported': _algs_supported}
    _context.client_authn_methods['dpop'] = DPoPClientAuth

# DPoP-bound access token in the "Authorization" header and the DPoP proof in the "DPoP" header


class DPoPClientAuth(BearerHeader):
    tag = "dpop_client_auth"

    def is_usable(self, request=None, authorization_info=None, http_headers=None):
        if authorization_info is not None and authorization_info.startswith("DPoP "):
            return True
        return False

    def verify(self,
               request: Optional[Union[dict, Message]] = None,
               authorization_token: Optional[str] = None,
               endpoint=None,  # Optional[Endpoint]
               get_client_id_from_token: Optional[Callable] = None,
               **kwargs,
               ):
        # info contains token and client_id
        info = BearerHeader._verify(self, request, authorization_token, endpoint,
                                    get_client_id_from_token, **kwargs)
        _context = self.upstream_get("context")
        return {"client_id": ''}
        # if _context.cdb[client_info["id"]]["client_secret"] == client_info["secret"]:
        #     return {"client_id": client_info["id"]}
        # else:
        #     raise ClientAuthenticationError()
