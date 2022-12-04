import os

import pytest
from cryptojwt.key_jar import init_key_jar

from idpyoidc.client.defaults import DEFAULT_OAUTH2_SERVICES
from idpyoidc.client.entity import Entity
from idpyoidc.client.oauth2.add_on import do_add_ons
from idpyoidc.client.oauth2.add_on.pkce import add_code_challenge
from idpyoidc.client.oauth2.add_on.pkce import add_code_verifier
from idpyoidc.client.service import Service
from idpyoidc.message import SINGLE_REQUIRED_STRING
from idpyoidc.message import Message
from idpyoidc.message.oauth2 import AuthorizationResponse


class DummyMessage(Message):
    c_param = {
        "req_str": SINGLE_REQUIRED_STRING,
    }


class DummyService(Service):
    msg_type = DummyMessage


_dirname = os.path.dirname(os.path.abspath(__file__))

ISS = "https://example.com"

KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

CLI_KEY = init_key_jar(
    public_path="{}/pub_client.jwks".format(_dirname),
    private_path="{}/priv_client.jwks".format(_dirname),
    key_defs=KEYSPEC,
    issuer_id="client_id",
)


class TestPKCE256:
    @pytest.fixture(autouse=True)
    def create_client(self):
        config = {
            "client_id": "client_id",
            "client_secret": "a longesh password",
            "redirect_uris": ["https://example.com/cli/authz_cb"],
            "preference": {
                "response_types": ["code"]
            },
            "add_ons": {
                "pkce": {
                    "function": "idpyoidc.client.oauth2.add_on.pkce.add_support",
                    "kwargs": {
                        "code_challenge_length": 64,
                        "code_challenge_method": "S256"
                    },
                }
            },
        }
        self.entity = Entity(keyjar=CLI_KEY,
                             config=config,
                             services=DEFAULT_OAUTH2_SERVICES,
                             client_type='oauth2')

        if "add_ons" in config:
            do_add_ons(config["add_ons"], self.entity.client_get("services"))
        _context = self.entity.get_service_context()
        _context.map_supported_to_preferred()
        _context.map_preferred_to_register()

    def test_add_code_challenge_default_values(self):
        auth_serv = self.entity.client_get("service", "authorization")
        _state_key = self.entity.client_get("service_context").state.create_state(iss="Issuer")
        request_args, _ = add_code_challenge({"state": _state_key}, auth_serv)

        # default values are length:64 method:S256
        assert set(request_args.keys()) == {"code_challenge", "code_challenge_method", "state"}
        assert request_args["code_challenge_method"] == "S256"

        request_args = add_code_verifier({}, auth_serv, state=_state_key)
        assert len(request_args["code_verifier"]) == 64

    def test_authorization_and_pkce(self):
        auth_serv = self.entity.client_get("service", "authorization")
        _state = self.entity.client_get("service_context").state.create_state(iss="Issuer")

        request = auth_serv.construct_request({"state": _state, "response_type": "code"})
        assert set(request.keys()) == {
            "client_id",
            "code_challenge",
            "code_challenge_method",
            "state",
            "redirect_uri",
            "response_type",
        }

    def test_access_token_and_pkce(self):
        authz_service = self.entity.client_get("service", "authorization")
        request = authz_service.construct_request({"state": "state", "response_type": "code"})
        _state = request["state"]
        auth_response = AuthorizationResponse(code="access code")
        self.entity.client_get("service_context").state.store_item(
            auth_response, "auth_response", _state
        )

        token_service = self.entity.client_get("service", "accesstoken")
        request = token_service.construct_request(state=_state)
        assert set(request.keys()) == {
            "client_id",
            "redirect_uri",
            "grant_type",
            "client_secret",
            "code_verifier",
            "code",
            "state",
        }


class TestPKCE384:
    @pytest.fixture(autouse=True)
    def create_client(self):
        config = {
            "client_id": "client_id",
            "client_secret": "a longesh password",
            "redirect_uris": ["https://example.com/cli/authz_cb"],
            "add_ons": {
                "pkce": {
                    "function": "idpyoidc.client.oauth2.add_on.pkce.add_support",
                    "kwargs": {"code_challenge_length": 128, "code_challenge_method": "S384"},
                }
            },
        }
        self.entity = Entity(keyjar=CLI_KEY, config=config, services=DEFAULT_OAUTH2_SERVICES)
        if "add_ons" in config:
            do_add_ons(config["add_ons"], self.entity.client_get("services"))

    def test_add_code_challenge_spec_values(self):
        auth_serv = self.entity.client_get("service", "authorization")
        request_args, _ = add_code_challenge({"state": "state"}, auth_serv)
        assert set(request_args.keys()) == {"code_challenge", "code_challenge_method", "state"}
        assert request_args["code_challenge_method"] == "S384"

        request_args = add_code_verifier({}, auth_serv, state="state")
        assert len(request_args["code_verifier"]) == 128
