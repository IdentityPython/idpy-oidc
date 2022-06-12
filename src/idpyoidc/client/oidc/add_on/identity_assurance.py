import logging
from typing import Optional

from idpyoidc.message.oidc import AuthorizationRequest
from idpyoidc.message.oidc.identity_assurance import EndUser
from idpyoidc.message.oidc.identity_assurance import VerifiedClaim

logger = logging.getLogger(__name__)


def identity_assurance_process(response, state_interface, state):
    auth_request = state_interface.get_item(AuthorizationRequest, "auth_request", state)
    claims_request = auth_request.get("claims")
    if "userinfo" in claims_request:
        if isinstance(response["verified_claims"], list):
            _vc = [VerifiedClaim(**v) for v in response["verified_claims"]]
        else:
            _vc = [VerifiedClaim(**response["verified_claims"])]

        if _vc:
            response.set("verified_claims", _vc)

    return response


def add_support(
        services,
        trust_frameworks_supported: list,
        evidence_supported: list,
        documents_supported: Optional[list] = None,
        documents_verification_methods_supported: Optional[list] = None,
        claims_in_verified_claims_supported: Optional[list] = None,
        verified_claims_request: Optional[dict] = None,
):
    """
    Add the necessary pieces to support identity assurance.

    :param services: A dictionary with all the services the client has access to.
    :param trust_frameworks_supported:
    :param evidence_supported:
    :param documents_supported:
    :param documents_verification_methods_supported:
    :param claims_in_verified_claims_supported:
    :param verified_claims_request:
    """

    _service = services["userinfo"]
    _context = _service.client_get("service_context")
    _context.add_on["identity_assurance"] = {
        "verified_claims_supported": True,
        "trust_frameworks_supported": trust_frameworks_supported,
        "evidence_supported": evidence_supported,
        "documents_supported": documents_supported,
        "documents_verification_methods_supported": documents_verification_methods_supported,
        "claims_in_verified_claims_supported": claims_in_verified_claims_supported,
        "verified_claims_request": verified_claims_request,
    }

    _service.response_cls = EndUser
    _service.post_parse_process.append(identity_assurance_process)


def map_request(claims_request, response, where):
    """
    Map claims request against a response
    """
    _ver = response["verification"].match_request(
        claims_request[where]["verified_claims"]["verification"])
    if _ver:
        _claims = response["claims"].match_request(
            claims_request[where]["verified_claims"]["claims"])
        if _claims:
            return {"verification": _ver, "claims": _claims}
    return None
