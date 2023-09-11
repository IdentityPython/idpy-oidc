import logging
from typing import Callable
from urllib.parse import urlsplit

from idpyoidc import metadata
from idpyoidc.message import oidc
from idpyoidc.message.oidc import Claims
from idpyoidc.message.oidc import verified_claim_name
from idpyoidc.server.oauth2 import authorization

logger = logging.getLogger(__name__)


def proposed_user(request):
    cn = verified_claim_name("it_token_hint")
    if request.get(cn):
        return request[cn].get("sub", "")
    return ""


def acr_claims(request):
    acrdef = None

    _claims = request.get("claims")
    if isinstance(_claims, str):
        _claims = Claims().from_json(_claims)

    if _claims:
        _id_token_claim = _claims.get("id_token")
        if _id_token_claim:
            acrdef = _id_token_claim.get("acr")

    if isinstance(acrdef, dict):
        if acrdef.get("value"):
            return [acrdef["value"]]
        elif acrdef.get("values"):
            return acrdef["values"]


def host_component(url):
    res = urlsplit(url)
    return "{}://{}".format(res.scheme, res.netloc)


ALG_PARAMS = {
    "sign": [
        "request_object_signing_alg",
        "request_object_signing_alg_values_supported",
    ],
    "enc_alg": [
        "request_object_encryption_alg",
        "request_object_encryption_alg_values_supported",
    ],
    "enc_enc": [
        "request_object_encryption_enc",
        "request_object_encryption_enc_values_supported",
    ],
}


def re_authenticate(request, authn):
    if "prompt" in request and "login" in request["prompt"]:
        if authn.done(request):
            return True

    return False


class Authorization(authorization.Authorization):
    request_cls = oidc.AuthorizationRequest
    response_cls = oidc.AuthorizationResponse
    error_cls = oidc.AuthorizationErrorResponse
    request_format = "urlencoded"
    response_format = "urlencoded"
    response_placement = "url"
    endpoint_name = "authorization_endpoint"
    name = "authorization"
    endpoint_type = "oidc"

    _supports = {
        **authorization.Authorization._supports,
        **{
            "claims_parameter_supported": True,
            "encrypt_request_object_supported": False,
            "request_object_signing_alg_values_supported": metadata.get_signing_algs(),
            "request_object_encryption_alg_values_supported": metadata.get_encryption_algs(),
            "request_object_encryption_enc_values_supported": metadata.get_encryption_encs(),
            "request_parameter_supported": True,
            "request_uri_parameter_supported": True,
            "require_request_uri_registration": False,
            "response_types_supported": ["code", "id_token", "code id_token"],
            "response_modes_supported": ["query", "fragment", "form_post"],
            "subject_types_supported": ["public", "pairwise", "ephemeral"],
        },
    }

    def __init__(self, upstream_get: Callable, **kwargs):
        authorization.Authorization.__init__(self, upstream_get, **kwargs)
        self.post_parse_request.append(self._do_request_uri)
        self.post_parse_request.append(self._post_parse_request)

    def do_request_user(self, request_info, **kwargs):
        if proposed_user(request_info):
            kwargs["req_user"] = proposed_user(request_info)
        else:
            _login_hint = request_info.get("login_hint")
            if _login_hint:
                _context = self.upstream_get("context")
                if _context.login_hint_lookup:
                    kwargs["req_user"] = _context.login_hint_lookup(_login_hint)
        return kwargs
