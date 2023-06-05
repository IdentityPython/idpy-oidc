import os

import pytest
from cryptojwt.key_jar import init_key_jar

from idpyoidc.client.entity import Entity
from idpyoidc.message import Message
from idpyoidc.message.oauth2 import AccessTokenResponse
from idpyoidc.message.oauth2 import AuthorizationResponse
from idpyoidc.message.oidc import IdToken
from tests.test_client_21_oidc_service import make_keyjar

KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

_dirname = os.path.dirname(os.path.abspath(__file__))

ISS = "https://example.com"

ISS_KEY = init_key_jar(
    public_path="{}/pub_iss.jwks".format(_dirname),
    private_path="{}/priv_iss.jwks".format(_dirname),
    key_defs=KEYSPEC,
    issuer_id=ISS,
    read_only=False,
)

ISS_KEY.import_jwks_as_json(open("{}/pub_client.jwks".format(_dirname)).read(), "client_id")


def create_jws(val):
    lifetime = 3600

    idts = IdToken(**val)

    return idts.to_jwt(
        key=ISS_KEY.get_signing_key("ec", issuer_id=ISS), algorithm="ES256", lifetime=lifetime
    )


class TestUserInfo(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self._iss = ISS
        client_config = {
            "client_id": "client_id",
            "client_secret": "a longesh password",
            "redirect_uris": ["https://example.com/cli/authz_cb"],
            "issuer": self._iss,
            "requests_dir": "requests",
            "base_url": "https://example.com/cli/",
        }
        entity = Entity(keyjar=make_keyjar(), config=client_config,
                        services={
                            "discovery": {
                                "class":
                                    "idpyoidc.client.oauth2.server_metadata.ServerMetadata"},
                            "authorization": {
                                "class": "idpyoidc.client.oauth2.authorization.Authorization"},
                            "access_token": {
                                "class": "idpyoidc.client.oauth2.access_token.AccessToken"},
                            "token_exchange": {
                                "class":
                                    "idpyoidc.client.oauth2.token_exchange.TokenExchange"
                            },
                        }
                        )
        entity.get_context().issuer = "https://example.com"
        self.service = entity.get_service("token_exchange")
        _cstate = self.service.upstream_get("context").cstate
        # Add history
        auth_response = AuthorizationResponse(code="access_code")
        _cstate.update("abcde", auth_response)

        idtval = {"nonce": "KUEYfRM2VzKDaaKD", "sub": "diana", "iss": ISS, "aud": "client_id"}
        idt = create_jws(idtval)

        ver_idt = IdToken().from_jwt(idt, make_keyjar())

        token_response = AccessTokenResponse(access_token="access_token", id_token=idt,
                                             __verified_id_token=ver_idt)
        _cstate.update("abcde", token_response)

    def test_construct(self):
        _req = self.service.construct(state="abcde")
        assert isinstance(_req, Message)
        assert len(_req) == 2
        assert "subject_token" in _req
