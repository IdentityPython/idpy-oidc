import json
from typing import Optional

from idpyoidc.message.oidc import AuthorizationRequest
from idpyoidc.message.oidc.identity_assurance import VerifiedClaims
from idpyoidc.message.oidc.identity_assurance import match_verified_claims
from idpyoidc.message.oidc.identity_assurance import verification_per_claim


def format_response(format, response, verified_response):
    _base_claims = _resp = {k: v for k, v in response.items() if
                            k not in ["_claim_names", "_claim_sources", "verified_claims"]}
    if format == "claims":
        _resp = _base_claims
        for vr in verified_response:
            if vr["verification"] is False:
                continue
            else:
                _resp.update(vr["claims"])
    elif format == "per_claim":
        verified_response[""] = _base_claims
        _resp = verification_per_claim(verified_response)
    else:  # format == "per_verification"
        _resp = {"": _base_claims}
        for vr in verified_response:
            if vr["verification"] is False:
                continue
            else:
                _resp[json.dumps(vr["verification"])] = vr["claims"]

    return _resp


def identity_assurance_process(response, service_context, state):
    auth_request = service_context.state.get_item(AuthorizationRequest, 'auth_request', state)
    claims_request = auth_request.get("claims")
    if 'userinfo' in claims_request:
        vc = VerifiedClaims(**response["verified_claims"])

        # find the claims request in the authorization request
        verified_response = match_verified_claims(vc, claims_request["userinfo"]["verified_claims"])
        _response_format = service_context.add_on['identity_assurance']['response_format']
        response = format_response(_response_format, response, verified_response)
    return response


def add_support(services, trust_frameworks_supported: list,
                evidence_supported: list,
                id_documents_supported: Optional[list] = None,
                id_documents_verification_methods_supported: Optional[list] = None,
                claims_in_verified_claims_supported: Optional[list] = None,
                verified_claims_request: Optional[dict] = None,
                response_format: Optional[str] = "claims"
                ):
    """
    Add the necessary pieces to support identity assurance.

    :param services: A dictionary with all the services the client has access to.
    :param trust_frameworks_supported:
    :param evidence_supported:
    :param id_documents_supported:
    :param id_documents_verification_methods_supported:
    :param claims_in_verified_claims_supported:
    :param verified_claims_request:
    :param response_format: One of 'claims', 'per_claim', 'per_verification'
    """

    # Access token request should use DPoP header
    _service = services["userinfo"]
    _context = _service.client_get("service_context")
    _context.add_on['identity_assurance'] = {
        "verified_claims_supported": True,
        "trust_frameworks_supported": trust_frameworks_supported,
        "evidence_supported": evidence_supported,
        "id_documents_supported": id_documents_supported,
        "id_documents_verification_methods_supported": id_documents_verification_methods_supported,
        "claims_in_verified_claims_supported": claims_in_verified_claims_supported,
        "verified_claims_request": verified_claims_request,
        "response_format": response_format
    }

    _service.post_parse_process.append(identity_assurance_process)
