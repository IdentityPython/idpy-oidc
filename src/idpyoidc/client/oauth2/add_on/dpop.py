import logging
import uuid
from hashlib import sha256
from typing import Optional

from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jws.jws import factory
from cryptojwt.jws.jws import JWS
from cryptojwt.key_bundle import key_by_alg

from idpyoidc.client.client_auth import BearerHeader
from idpyoidc.client.client_auth import find_token_info
from idpyoidc.client.service_context import ServiceContext
from idpyoidc.message import Message
from idpyoidc.message import SINGLE_OPTIONAL_STRING
from idpyoidc.message import SINGLE_REQUIRED_INT
from idpyoidc.message import SINGLE_REQUIRED_JSON
from idpyoidc.message import SINGLE_REQUIRED_STRING
from idpyoidc.metadata import get_signing_algs
from idpyoidc.time_util import utc_time_sans_frac

logger = logging.getLogger(__name__)


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
        "ath": SINGLE_OPTIONAL_STRING,
    }
    header_params = {"typ", "alg", "jwk"}
    body_params = {"jti", "htm", "htu", "iat", "ath"}

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
        payload = {k: self[k] for k in self.body_params if k in self}
        _jws = JWS(payload, alg=self["alg"])
        _jws_headers = {k: self[k] for k in self.header_params}
        _signed_jwt = _jws.sign_compact(keys=[self.key], **_jws_headers)
        return _signed_jwt

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


def dpop_header(
        service_context: ServiceContext,
        service_endpoint: str,
        http_method: str,
        headers: Optional[dict] = None,
        token: Optional[str] = "",
        nonce: Optional[str] = "",
        **kwargs
) -> dict:
    """

    :param service_context:
    :param service_endpoint:
    :param http_method:
    :param headers: The HTTP headers to which the DPoP header should be added.
    :param token: If the DPoP Proof is sent together with an access token this should lead to
        the addition of the ath claim (hash of the token as value)
    :param nonce: AS or RS provided nonce.
    :param kwargs:
    :return:
    """

    provider_info = service_context.provider_info
    _dpop_conf = service_context.add_on.get("dpop")
    if not _dpop_conf:
        logger.warning("Asked to do dpop when I do not support it")
        return headers

    dpop_key = _dpop_conf.get("key")

    if not dpop_key:
        chosen_alg = _dpop_conf.get("algs_supported", [])[0]

        if not chosen_alg:
            return headers

        # Mint a new key
        dpop_key = key_by_alg(chosen_alg)
        _dpop_conf["key"] = dpop_key
        _dpop_conf["alg"] = chosen_alg

    header_dict = {
        "typ": "dpop+jwt",
        "alg": _dpop_conf["alg"],
        "jwk": dpop_key.serialize(),
        "jti": uuid.uuid4().hex,
        "htm": http_method,
        "htu": provider_info[service_endpoint],
        "iat": utc_time_sans_frac(),
    }

    if token:
        header_dict["ath"] = sha256(token.encode("utf8")).hexdigest()

    if nonce:
        header_dict["nonce"] = nonce

    _dpop = DPoPProof(**header_dict)
    _dpop.key = dpop_key
    jws = _dpop.create_header()

    if headers is None:
        headers = {"dpop": jws}
    else:
        headers["dpop"] = jws

    return headers


def add_support(services, dpop_signing_alg_values_supported, with_dpop_header=None):
    """
    Add the necessary pieces to make pushed authorization happen.

    :param services: A dictionary with all the services the client has access to.
    :param signing_algorithms: Allowed signing algorithms, there is no default algorithms
    """

    # Access token request should use DPoP header
    _service = services["accesstoken"]
    _context = _service.upstream_get("context")
    _algs_supported = [
        alg for alg in dpop_signing_alg_values_supported if alg in get_signing_algs()
    ]
    _context.add_on["dpop"] = {
        # "key": key_by_alg(signing_algorithm),
        "algs_supported": _algs_supported
    }
    _context.set_preference("dpop_signing_alg_values_supported", _algs_supported)

    _service.construct_extra_headers.append(dpop_header)

    # The same for userinfo requests
    _userinfo_service = services.get("userinfo")
    if _userinfo_service:
        _userinfo_service.construct_extra_headers.append(dpop_header)
    # To be backward compatible
    if with_dpop_header is None:
        with_dpop_header = ["userinfo"]

    # Add dpop HTTP header to these
    for _srv in with_dpop_header:
        if _srv == "accesstoken":
            continue
        _service = services.get(_srv)
        if _service:
            _service.construct_extra_headers.append(dpop_header)


class DPoPClientAuth(BearerHeader):
    tag = "dpop_client_auth"

    def construct(self, request=None, service=None, http_args=None, **kwargs):
        """
        Constructing the Authorization header. The value of
        the Authorization header is "Bearer <access_token>".

        :param request: Request class instance
        :param service: The service this authentication method applies to.
        :param http_args: HTTP header arguments
        :param kwargs: extra keyword arguments
        :return:
        """

        _token_type = "access_token"

        _token_info = find_token_info(request, _token_type, service, **kwargs)

        if not _token_info:
            raise KeyError("No bearer token available")

        # The authorization value starts with the token_type
        # if _token_info["token_type"].to_lower() != "bearer":
        _bearer = f"DPoP {_token_info[_token_type]}"

        # Add 'Authorization' to the headers
        if http_args is None:
            http_args = {"headers": {}}
            http_args["headers"]["Authorization"] = _bearer
        else:
            try:
                http_args["headers"]["Authorization"] = _bearer
            except KeyError:
                http_args["headers"] = {"Authorization": _bearer}

        return http_args
