import json
import logging
from typing import Callable
from typing import Optional
from typing import Type

from idpyoidc.client.client_auth import BearerHeader
from idpyoidc.client.oidc import FetchException
from idpyoidc.client.service import Service
from idpyoidc.exception import MissingSigningKey
from idpyoidc.message import Message
from idpyoidc.message.oidc import AuthorizationRequest
from idpyoidc.message.oidc.identity_assurance import VerifiedClaim

logger = logging.getLogger(__name__)


def match_verified_claims(verified_claims, claims_request):
    pass


def _collect_claims_by_url(spec: Message, httpc: type, service: Service,
                           callback: Optional[Callable] = None):
    if "access_token" in spec:
        cauth = BearerHeader()
        httpc_params = cauth.construct(
            service=service,
            access_token=spec["access_token"],
        )
        _resp = httpc.send(spec["endpoint"], "GET", **httpc_params)
    else:
        if callback:
            token = callback(spec["endpoint"])
            cauth = BearerHeader()
            httpc_params = cauth.construct(
                service=service, access_token=token
            )
            _resp = httpc.send(spec["endpoint"], "GET", **httpc_params)
        else:
            _resp = httpc.send(spec["endpoint"], "GET")

    if _resp.status_code == 200:
        _uinfo = json.loads(_resp.text)
    else:  # There shouldn't be any redirect
        raise FetchException(
            "HTTP error {}: {}".format(_resp.status_code, _resp.reason)
        )

    return _uinfo

    # claims = [
    #     value for value, src in userinfo["_claim_names"].items() if src == csrc
    # ]
    #
    # if set(claims) != set(_uinfo.keys()):
    #     logger.warning(
    #         "Claims from claim source doesn't match what's in " "the userinfo"
    #     )
    #
    # # only add those I expected
    # for key in claims:
    #     userinfo[key] = _uinfo[key]


def collect_claim_sources(item, keyjar, httpc, service):
    _aggregate = {}
    _csrc = item.get("_claim_sources")
    if _csrc:
        for csrc, spec in _csrc.items():
            if "JWT" in spec:
                try:
                    _ava = Message().from_jwt(spec["JWT"].encode("utf-8"), keyjar=keyjar)
                except MissingSigningKey as err:
                    logger.warning(
                        "Error encountered while unpacking aggregated " "claims".format(err)
                    )
                else:
                    claims = [
                        value for value, src in item["_claim_names"].items() if src == csrc
                    ]

                    for key in claims:
                        _aggregate[key] = _ava[key]
            elif "endpoint" in spec:
                _ava = _collect_claims_by_url(spec, httpc, service)
                claims = [value for value, src in item["_claim_names"].items() if src == csrc]
                for key in claims:
                    _aggregate[key] = _ava[key]
    return _aggregate

def identity_assurance_process(response, state_interface, state):
    auth_request = state_interface.get_item(AuthorizationRequest, "auth_request", state)
    claims_request = auth_request.get("claims")
    if "userinfo" in claims_request:
        _vc = VerifiedClaim(**response["verified_claims"])
        if _vc:
            response["verified_claims"] = _vc
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

    _service.post_parse_process.append(identity_assurance_process)
