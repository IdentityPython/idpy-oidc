import json
import os
import sys
import time

from cryptojwt.jwk.rsa import import_private_rsa_key_from_file
from cryptojwt.key_bundle import KeyBundle
import pytest
import responses

from idpyoidc.client.oidc import RP
from idpyoidc.message.oauth2 import AuthorizationRequest
from idpyoidc.message.oauth2 import AuthorizationResponse
from idpyoidc.message.oidc import IdToken
from idpyoidc.message.oidc import OpenIDSchema
from idpyoidc.message.oidc.identity_assurance import EndUser
from idpyoidc.time_util import utc_time_sans_frac

sys.path.insert(0, ".")

_dirname = os.path.dirname(os.path.abspath(__file__))
BASE_PATH = os.path.join(_dirname, "data", "keys")

_key = import_private_rsa_key_from_file(os.path.join(BASE_PATH, "rsa.key"))
KC_RSA = KeyBundle({"priv_key": _key, "kty": "RSA", "use": "sig"})

CLIENT_ID = "client_1"
IDTOKEN = IdToken(
    iss="http://oidc.example.org/",
    sub="sub",
    aud=CLIENT_ID,
    exp=utc_time_sans_frac() + 86400,
    nonce="N0nce",
    iat=time.time(),
)


def access_token_callback(endpoint):
    if endpoint:
        return "access_token"


class TestClient(object):
    @pytest.fixture(autouse=True)
    def create_client(self):
        self.redirect_uri = "http://example.com/redirect"
        conf = {
            "redirect_uris": ["https://example.com/cli/authz_cb"],
            "client_id": "client_1",
            "client_secret": "abcdefghijklmnop",
            "add_ons": {
                "identity_assurance": {
                    "function": "idpyoidc.client.oidc.add_on.identity_assurance.add_support",
                    "kwargs": {
                        "trust_frameworks_supported": ["eidas", "de_aml"],
                        "evidence_supported": ["document"]
                    },
                }
            },
        }
        self.client = RP(config=conf)

    def _init_sequence(self):
        req_args = {
            "state": "ABCDE",
            "redirect_uri": "https://example.com/auth_cb",
            "response_type": ["code"],
            "nonce": "nonce",
            "claims": {
                "userinfo": {
                    "verified_claims": {
                        "verification": {
                            "trust_framework": None,
                            "time": None,
                            "evidence": [
                                {
                                    "type": {
                                        "value": "document"
                                    },
                                    "method": None,
                                    "document_details": {
                                        "type": None
                                    }
                                }
                            ]
                        },
                        "claims": {
                            "given_name": None,
                            "family_name": None,
                            "birthdate": None
                        }
                    }
                }
            }
        }
        _context = self.client.client_get("service_context")
        _context.state.create_state("issuer", "ABCDE")

        auth_request = AuthorizationRequest(**req_args)
        _context.state.store_item(auth_request, "auth_request", "ABCDE")

        auth_response = AuthorizationResponse(code="access_code")
        _context.state.store_item(auth_response, "auth_response", "ABCDE")

        # token_response = AccessTokenResponse(refresh_token="refresh_with_me",
        # access_token="access")
        # _context.state.store_item(token_response, "token_response", "ABCDE")

    def test_1(self):
        self._init_sequence()
        _url = "https://example.com/claims.json"
        # split the example in 5.6.2.2 into two
        uinfo = EndUser(
            **{
                "sub": "1b2fc9341a16ae4e30082965d537",
                "verified_claims": {
                    "verification": {
                        "trust_framework": "de_aml",
                        "time": "2012-04-23T18:25Z",
                        "verification_process": "f24c6f-6d3f-4ec5-973e-b0d8506f3bc7",
                        "evidence": [
                            {
                                "type": "document",
                                "method": "pipp",
                                "verifier": {
                                    "organization": "Deutsche Post",
                                    "txn": "1aa05779-0775-470f-a5c4-9f1f5e56cf06"
                                },
                                "time": "2012-04-22T11:30Z",
                                "document_details": {
                                    "type": "idcard",
                                    "issuer": {
                                        "name": "Stadt Augsburg",
                                        "country": "DE"
                                    },
                                    "document_number": "53554554",
                                    "date_of_issuance": "2010-03-23",
                                    "date_of_expiry": "2020-03-22"
                                }
                            }
                        ]
                    },
                    "claims": {
                        "given_name": "Max",
                        "family_name": "Meier",
                        "birthdate": "1956-01-28",
                        "place_of_birth": {
                            "country": "DE",
                            "locality": "Musterstadt"
                        },
                        "nationalities": [
                            "DE"
                        ],
                        "address": {
                            "locality": "Maxstadt",
                            "postal_code": "12344",
                            "country": "DE",
                            "street_address": "An der Weide 22"
                        }
                    }
                }
            }
        )

        userinfo_service = self.client.client_get("service", "userinfo")
        _resp = userinfo_service.parse_response(uinfo.to_json(), state="ABCDE")

        assert _resp
        assert "verified_claims" in _resp

