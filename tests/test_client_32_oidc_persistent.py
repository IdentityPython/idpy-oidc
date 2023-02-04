import os
import sys
import time

from cryptojwt.jwk.rsa import import_private_rsa_key_from_file
from cryptojwt.key_bundle import KeyBundle

from idpyoidc.client.oidc import RP
from idpyoidc.message.oauth2 import AccessTokenRequest
from idpyoidc.message.oauth2 import AccessTokenResponse
from idpyoidc.message.oauth2 import AuthorizationRequest
from idpyoidc.message.oauth2 import AuthorizationResponse
from idpyoidc.message.oauth2 import RefreshAccessTokenRequest
from idpyoidc.message.oidc import IdToken
from idpyoidc.time_util import utc_time_sans_frac

sys.path.insert(0, ".")

_dirname = os.path.dirname(os.path.abspath(__file__))
BASE_PATH = os.path.join(_dirname, "data", "keys")

_key = import_private_rsa_key_from_file(os.path.join(BASE_PATH, "rsa.key"))
KC_RSA = KeyBundle({"priv_key": _key, "kty": "RSA", "use": "sig"})

CLIENT_ID = "client_1"
ISSUER = "http://op.example.com"

IDTOKEN = IdToken(
    iss=ISSUER,
    sub="sub",
    aud=CLIENT_ID,
    exp=utc_time_sans_frac() + 86400,
    nonce="N0nce",
    iat=time.time(),
)

CONF = {
    "issuer": ISSUER,
    "redirect_uris": ["https://example.com/cli/authz_cb"],
    "client_id": CLIENT_ID,
    "client_secret": "abcdefghijklmnop",
}


def access_token_callback(endpoint):
    if endpoint:
        return "access_token"


class TestClient(object):
    def test_construct_accesstoken_request(self):
        # Client 1 starts
        client_1 = RP(config=CONF)
        _state = client_1.get_context().cstate.create_state(iss=ISSUER)
        auth_request = AuthorizationRequest(
            redirect_uri="https://example.com/cli/authz_cb", state=_state
        )
        client_1.get_context().cstate.update(_state, auth_request)

        # Client 2 carries on
        client_2 = RP(config=CONF)
        _state_dump = client_1.get_context().dump()
        client_2.get_context().load(_state_dump)

        auth_response = AuthorizationResponse(code="access_code")
        client_2.get_context().cstate.update(_state, auth_response)

        # Bind access code to state
        req_args = {}
        msg = client_2.get_service("accesstoken").construct(
            request_args=req_args, state=_state
        )
        assert isinstance(msg, AccessTokenRequest)
        assert msg.to_dict() == {
            "client_id": "client_1",
            "code": "access_code",
            "client_secret": "abcdefghijklmnop",
            "grant_type": "authorization_code",
            "redirect_uri": "https://example.com/cli/authz_cb",
            "state": _state,
        }

    def test_construct_refresh_token_request(self):
        # Client 1 starts
        client_1 = RP(config=CONF)
        _state = client_1.get_context().cstate.create_state(iss=ISSUER)

        auth_request = AuthorizationRequest(
            redirect_uri="https://example.com/cli/authz_cb", state=_state
        )

        client_1.get_context().cstate.update(_state,auth_request)

        # Client 2 carries on
        client_2 = RP(config=CONF)
        _state_dump = client_1.get_context().dump()
        client_2.get_context().load(_state_dump)

        auth_response = AuthorizationResponse(code="access_code")
        client_2.get_context().cstate.update(_state, auth_response)

        token_response = AccessTokenResponse(refresh_token="refresh_with_me", access_token="access")
        client_2.get_context().cstate.update(_state,token_response )

        # Back to Client 1
        _state_dump = client_2.get_context().dump()
        client_1.get_context().load(_state_dump)

        req_args = {}
        msg = client_1.get_service("refresh_token").construct(
            request_args=req_args, state=_state
        )
        assert isinstance(msg, RefreshAccessTokenRequest)
        assert msg.to_dict() == {
            "client_id": "client_1",
            "client_secret": "abcdefghijklmnop",
            "grant_type": "refresh_token",
            "refresh_token": "refresh_with_me",
        }

    def test_do_userinfo_request_init(self):
        # Client 1 starts
        client_1 = RP(config=CONF)
        _state = client_1.get_context().cstate.create_state(iss=ISSUER)

        auth_request = AuthorizationRequest(
            redirect_uri="https://example.com/cli/authz_cb", state="state"
        )

        # Client 2 carries on
        client_2 = RP(config=CONF)
        _state_dump = client_1.get_context().dump()
        client_2.get_context().load(_state_dump)

        auth_response = AuthorizationResponse(code="access_code")
        client_2.get_context().cstate.update(_state,auth_response)

        token_response = AccessTokenResponse(refresh_token="refresh_with_me", access_token="access")
        client_2.get_context().cstate.update(_state,token_response)

        # Back to Client 1
        _state_dump = client_2.get_context().dump()
        client_1.get_context().load(_state_dump)

        _srv = client_1.get_service("userinfo")
        _srv.endpoint = "https://example.com/userinfo"
        _info = _srv.get_request_parameters(state=_state)
        assert _info
        assert _info["headers"] == {"Authorization": "Bearer access"}
        assert _info["url"] == "https://example.com/userinfo"
