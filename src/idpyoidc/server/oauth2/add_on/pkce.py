import hashlib
import logging
from typing import Dict
from typing import Optional

from cryptojwt.utils import b64e

from idpyoidc.message.oauth2 import AuthorizationErrorResponse
from idpyoidc.message.oauth2 import CCAccessTokenRequest
from idpyoidc.message.oauth2 import RefreshAccessTokenRequest
from idpyoidc.message.oauth2 import TokenExchangeRequest
from idpyoidc.message.oidc import TokenErrorResponse
from idpyoidc.server.endpoint import Endpoint

LOGGER = logging.getLogger(__name__)


def hash_fun(f):
    def wrapper(code_verifier):
        _h = f(code_verifier.encode("ascii")).digest()
        _cc = b64e(_h)
        return _cc.decode("ascii")

    return wrapper


CC_METHOD = {
    "plain": lambda x: x,
    "S256": hash_fun(hashlib.sha256),
    "S384": hash_fun(hashlib.sha384),
    "S512": hash_fun(hashlib.sha512),
}


def post_authn_parse(request, client_id, context, **kwargs):
    """

    :param request:
    :param client_id:
    :param context:
    :param kwargs:
    :return:
    """
    client = context.cdb[client_id]
    if "pkce_essential" in client:
        essential = client["pkce_essential"]
    else:
        essential = context.add_on["pkce"].get("essential", False)
    if essential and "code_challenge" not in request:
        return AuthorizationErrorResponse(
            error="invalid_request",
            error_description="Missing required code_challenge",
        )

    if "code_challenge_method" not in request:
        request["code_challenge_method"] = "plain"

    if "code_challenge" in request and (
        request["code_challenge_method"] not in context.add_on["pkce"]["code_challenge_methods"]
    ):
        return AuthorizationErrorResponse(
            error="invalid_request",
            error_description="Unsupported code_challenge_method={}".format(
                request["code_challenge_method"]
            ),
        )

    return request


def verify_code_challenge(code_verifier, code_challenge, code_challenge_method="S256"):
    """
    Verify a PKCE (RFC7636) code challenge.


    :param code_verifier: The origin
    :param code_challenge: The transformed verifier used as challenge
    :return:
    """
    if CC_METHOD[code_challenge_method](code_verifier) != code_challenge:
        LOGGER.error("PKCE Code Challenge check failed")
        return False

    LOGGER.debug("PKCE Code Challenge check succeeded")
    return True


def post_token_parse(request, client_id, context, **kwargs):
    """
    To be used as a post_parse_request function.

    :param token_request:
    :return:
    """
    if isinstance(
        request,
        (
            AuthorizationErrorResponse,
            RefreshAccessTokenRequest,
            TokenExchangeRequest,
            CCAccessTokenRequest,
        ),
    ):
        return request

    try:
        _session_info = context.session_manager.get_session_info_by_token(
            request["code"], grant=True, handler_key="authorization_code"
        )
    except KeyError:
        return TokenErrorResponse(error="invalid_grant", error_description="Unknown access grant")

    _authn_req = _session_info["grant"].authorization_request

    if "code_challenge" in _authn_req:
        if "code_verifier" not in request:
            return TokenErrorResponse(
                error="invalid_grant",
                error_description="Missing code_verifier",
            )

        _method = _authn_req["code_challenge_method"]

        if not verify_code_challenge(
            request["code_verifier"],
            _authn_req["code_challenge"],
            _method,
        ):
            return TokenErrorResponse(error="invalid_grant", error_description="PKCE check failed")

    return request


def add_support(
    endpoint: Dict[str, Endpoint],
    code_challenge_methods: Optional[dict] = None,
    essential: Optional[bool] = False,
    **kwargs
):
    authn_endpoint = endpoint.get("authorization")
    if authn_endpoint is None:
        LOGGER.warning("No authorization endpoint found, skipping PKCE configuration")
        return

    token_endpoint = endpoint.get("token")
    if token_endpoint is None:
        LOGGER.warning("No token endpoint found, skipping PKCE configuration")
        return

    authn_endpoint.post_parse_request.append(post_authn_parse)
    token_endpoint.post_parse_request.append(post_token_parse)

    if code_challenge_methods is None:
        code_challenge_methods = CC_METHOD
    else:
        for method in code_challenge_methods:
            if method not in CC_METHOD:
                raise ValueError("Unsupported method: {}".format(method))

    _context = authn_endpoint.upstream_get("context")
    _context.add_on["pkce"] = {
        "code_challenge_methods": code_challenge_methods,
        "essential": essential,
    }
    _context.set_preference("code_challenge_methods_supported", list(code_challenge_methods.keys()))
