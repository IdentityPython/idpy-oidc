import pytest

from idpyoidc.client.entity import Entity
from idpyoidc.client.oauth2 import Client
from idpyoidc.message.oauth2 import AccessTokenResponse
from idpyoidc.util import rndstr

KEYDEF = [{"type": "EC", "crv": "P-256", "use": ["sig"]}]

BASE_URL = "https://example.com"


class TestCC:
    @pytest.fixture(autouse=True)
    def create_service(self):
        client_config = {
            "client_id": "client_id",
            "client_secret": "another password",
            "base_url": BASE_URL,
        }
        services = {
            "client_credentials": {
                "class": "idpyoidc.client.oauth2.client_credentials.CCAccessTokenRequest"
            }
        }

        self.entity = Client(config=client_config, services=services)

        self.entity.get_service("client_credentials").endpoint = "https://example.com/token"

    def test_token_get_request(self):
        _srv = self.entity.get_service("client_credentials")
        _info = _srv.get_request_parameters()
        assert _info["method"] == "POST"
        assert _info["url"] == "https://example.com/token"
        assert (
            _info["body"]
            == "grant_type=client_credentials&client_id=client_id&client_secret=another+password"
        )

        assert _info["headers"] == {
            "Content-Type": "application/x-www-form-urlencoded",
        }

    def test_token_parse_response(self):
        _srv = self.entity.get_service("client_credentials")
        _request_info = _srv.get_request_parameters()

        response = AccessTokenResponse(
            **{
                "access_token": "2YotnFZFEjr1zCsicMWpAA",
                "token_type": "access_token",
                "expires_in": 3600,
                "example_parameter": "example_value",
            }
        )

        _response = _srv.parse_response(response.to_json(), sformat="json")
        # since no state attribute is involved, a key is minted
        _key = rndstr(16)
        _srv.update_service_context(_response, key=_key)
        info = _srv.upstream_get("context").cstate.get(_key)
        assert "__expires_at" in info


class TestROPC:
    @pytest.fixture(autouse=True)
    def create_service(self):
        client_config = {
            "client_id": "client_id",
            "client_secret": "another password",
            "base_url": BASE_URL,
        }
        services = {
            "resource_owner_password_credentials": {
                "class": "idpyoidc.client.oauth2.resource_owner_password_credentials"
                ".ROPCAccessTokenRequest"
            }
        }

        self.entity = Entity(config=client_config, services=services)

        self.entity.get_service(
            "resource_owner_password_credentials"
        ).endpoint = "https://example.com/token"

    def test_token_get_request(self):
        _srv = self.entity.get_service("resource_owner_password_credentials")
        _info = _srv.get_request_parameters({"username": "diana", "password": "krall"})
        assert _info["method"] == "POST"
        assert _info["url"] == "https://example.com/token"
        assert _info["body"] == (
            "username=diana&"
            "password=krall&"
            "grant_type=password&"
            "client_id=client_id&"
            "client_secret=another+password"
        )

        assert _info["headers"] == {
            "Content-Type": "application/x-www-form-urlencoded",
        }

    def test_token_parse_response(self):
        _srv = self.entity.get_service("resource_owner_password_credentials")
        _request_info = _srv.get_request_parameters()

        response = AccessTokenResponse(
            **{
                "access_token": "2YotnFZFEjr1zCsicMWpAA",
                "token_type": "access_token",
                "expires_in": 3600,
                "example_parameter": "example_value",
            }
        )

        _response = _srv.parse_response(response.to_json(), sformat="json")
        # since no state attribute is involved, a key is minted
        _key = rndstr(16)
        _srv.update_service_context(_response, key=_key)
        info = _srv.upstream_get("context").cstate.get(_key)
        assert "__expires_at" in info
