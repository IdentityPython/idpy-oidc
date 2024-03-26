import json
import os
import sys
import time

import pytest
import responses
from cryptojwt.jwk.rsa import import_private_rsa_key_from_file
from cryptojwt.key_bundle import KeyBundle

from idpyoidc.client.oidc import RP
from idpyoidc.message.oauth2 import AccessTokenRequest
from idpyoidc.message.oauth2 import AccessTokenResponse
from idpyoidc.message.oauth2 import AuthorizationRequest
from idpyoidc.message.oauth2 import AuthorizationResponse
from idpyoidc.message.oauth2 import RefreshAccessTokenRequest
from idpyoidc.message.oidc import IdToken
from idpyoidc.message.oidc import OpenIDSchema
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
            "client_authn_methods": ["bearer_header"],
        }
        self.client = RP(config=conf)

    def test_construct_authorization_request(self):
        req_args = {
            "state": "ABCDE",
            "redirect_uri": "https://example.com/auth_cb",
            "response_type": ["code"],
            "nonce": "nonce",
        }

        self.client.get_context().cstate.set("ABCDE", {"iss": "issuer"})

        msg = self.client.get_service("authorization").construct(request_args=req_args)
        assert isinstance(msg, AuthorizationRequest)
        assert msg["redirect_uri"] == "https://example.com/auth_cb"

    def test_construct_accesstoken_request(self):
        _context = self.client.get_context()
        auth_request = AuthorizationRequest(redirect_uri="https://example.com/cli/authz_cb")

        _state = _context.cstate.create_key()
        _context.cstate.set(_state, {"iss": "issuer"})
        auth_request["state"] = _state

        _context.cstate.update(_state, auth_request)

        auth_response = AuthorizationResponse(code="access_code")

        _context.cstate.update(_state, auth_response)

        # Bind access code to state
        req_args = {}
        msg = self.client.get_service("accesstoken").construct(request_args=req_args, state=_state)
        assert isinstance(msg, AccessTokenRequest)
        assert msg.to_dict() == {
            "client_id": "client_1",
            "client_secret": "abcdefghijklmnop",
            "grant_type": "authorization_code",
            "state": _state,
            "code": "access_code",
            "redirect_uri": "https://example.com/cli/authz_cb",
        }

    def test_construct_refresh_token_request(self):
        _context = self.client.get_context()
        _context.cstate.set("ABCDE", {"iss": "issuer"})

        auth_request = AuthorizationRequest(
            redirect_uri="https://example.com/cli/authz_cb", state="state"
        )

        _context.cstate.update("ABCDE", auth_request)

        auth_response = AuthorizationResponse(code="access_code")
        _context.cstate.set("ABCDE", auth_response)

        token_response = AccessTokenResponse(refresh_token="refresh_with_me", access_token="access")
        _context.cstate.update("ABCDE", token_response)

        req_args = {}
        msg = self.client.get_service("refresh_token").construct(
            request_args=req_args, state="ABCDE"
        )
        assert isinstance(msg, RefreshAccessTokenRequest)
        assert msg.to_dict() == {
            "client_id": "client_1",
            "client_secret": "abcdefghijklmnop",
            "grant_type": "refresh_token",
            "refresh_token": "refresh_with_me",
            'scope': 'openid'
        }

    def test_do_userinfo_request_init(self):
        _context = self.client.get_context()
        _state = _context.cstate.create_key()
        _context.cstate.set(_state, {"iss": "issuer"})

        auth_request = AuthorizationRequest(
            redirect_uri="https://example.com/cli/authz_cb", state="state"
        )

        _context.cstate.update(_state, auth_request)

        auth_response = AuthorizationResponse(code="access_code")
        _context.cstate.update(_state, auth_response)

        token_response = AccessTokenResponse(refresh_token="refresh_with_me", access_token="access")
        _context.cstate.update(_state, token_response)

        _srv = self.client.get_service("userinfo")
        _srv.endpoint = "https://example.com/userinfo"
        _info = _srv.get_request_parameters(state=_state)
        assert _info
        assert _info["headers"] == {"Authorization": "Bearer access"}
        assert _info["url"] == "https://example.com/userinfo"

    def test_fetch_distributed_claims_1(self):
        _url = "https://example.com/claims.json"
        # split the example in 5.6.2.2 into two
        uinfo = OpenIDSchema(
            **{
                "sub": "jane_doe",
                "name": "Jane Doe",
                "given_name": "Jane",
                "family_name": "Doe",
                "email": "janedoe@example.com",
                "birthdate": "0000-03-22",
                "eye_color": "blue",
                "_claim_names": {
                    "payment_info": "src1",
                    "shipping_address": "src1",
                },
                "_claim_sources": {"src1": {"endpoint": _url}},
            }
        )

        # Wrong set of claims. Actually extra claim
        _info = {
            "shipping_address": {
                "street_address": "1234 Hollywood Blvd.",
                "locality": "Los Angeles",
                "region": "CA",
                "postal_code": "90210",
                "country": "US",
            },
            "payment_info": "Some_Card 1234 5678 9012 3456",
            "phone_number": "+1 (310) 123-4567",
        }

        with responses.RequestsMock() as rsps:
            rsps.add(
                "GET",
                _url,
                body=json.dumps(_info),
                adding_headers={"Content-Type": "application/json"},
                status=200,
            )

            res = self.client.fetch_distributed_claims(uinfo)

        assert "payment_info" in res
        assert "shipping_address" in res
        assert "phone_number" not in res

    def test_fetch_distributed_claims_2(self):
        _url = "https://example.com/claims.json"

        uinfo = OpenIDSchema(
            **{
                "sub": "jane_doe",
                "name": "Jane Doe",
                "given_name": "Jane",
                "family_name": "Doe",
                "email": "janedoe@example.com",
                "birthdate": "0000-03-22",
                "eye_color": "blue",
                "_claim_names": {"credit_score": "src2"},
                "_claim_sources": {"src2": {"endpoint": _url, "access_token": "ksj3n283dke"}},
            }
        )

        _claims = {"credit_score": 650}

        with responses.RequestsMock() as rsps:
            rsps.add(
                "GET",
                _url,
                body=json.dumps(_claims),
                adding_headers={"Content-Type": "application/json"},
                status=200,
            )

            res = self.client.fetch_distributed_claims(uinfo)

        assert "credit_score" in res

    def test_fetch_distributed_claims_3(self, httpserver):
        _url = "https://example.com/claims.json"

        uinfo = OpenIDSchema(
            **{
                "sub": "jane_doe",
                "name": "Jane Doe",
                "given_name": "Jane",
                "family_name": "Doe",
                "email": "janedoe@example.com",
                "birthdate": "0000-03-22",
                "eye_color": "blue",
                "_claim_names": {"credit_score": "src2"},
                "_claim_sources": {
                    "src2": {
                        "endpoint": _url,
                    }
                },
            }
        )

        _claims = {"credit_score": 650}

        with responses.RequestsMock() as rsps:
            rsps.add(
                "GET",
                _url,
                body=json.dumps(_claims),
                adding_headers={"Content-Type": "application/json"},
                status=200,
            )

            res = self.client.fetch_distributed_claims(uinfo, callback=access_token_callback)

        assert "credit_score" in res
