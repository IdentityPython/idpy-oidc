import pytest

from idpyoidc.client.entity import Entity
from idpyoidc.message.oauth2 import AccessTokenResponse
from idpyoidc.util import rndstr

KEYDEF = [{"type": "EC", "crv": "P-256", "use": ["sig"]}]


BASE_URL = "https://example.com"

class TestRP:
    @pytest.fixture(autouse=True)
    def create_service(self):
        client_config = {
            "client_id": "client_id",
            "client_secret": "another password",
            "base_url": BASE_URL,
            "client_authn_methods": ['client_secret_basic', 'bearer_header']
        }
        services = {
            "token": {
                "class": "idpyoidc.client.oauth2.client_credentials.cc_access_token.CCAccessToken"
            },
            "refresh_token": {
                "class": "idpyoidc.client.oauth2.client_credentials.cc_refresh_access_token"
                ".CCRefreshAccessToken"
            },
        }

        self.entity = Entity(config=client_config, services=services)

        self.entity.get_service("accesstoken").endpoint = "https://example.com/token"
        self.entity.get_service("refresh_token").endpoint = "https://example.com/token"

    def test_token_get_request(self):
        request_args = {"grant_type": "client_credentials"}
        _srv = self.entity.get_service("accesstoken")
        _info = _srv.get_request_parameters(request_args=request_args)
        assert _info["method"] == "POST"
        assert _info["url"] == "https://example.com/token"
        assert _info["body"] == "grant_type=client_credentials"
        assert _info["headers"] == {
            "Authorization": "Basic Y2xpZW50X2lkOmFub3RoZXIgcGFzc3dvcmQ=",
            "Content-Type": "application/x-www-form-urlencoded",
        }

    def test_token_parse_response(self):
        request_args = {"grant_type": "client_credentials"}
        _srv = self.entity.get_service("accesstoken")
        _request_info = _srv.get_request_parameters(request_args=request_args)

        response = AccessTokenResponse(
            **{
                "access_token": "2YotnFZFEjr1zCsicMWpAA",
                "token_type": "example",
                "expires_in": 3600,
                "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
                "example_parameter": "example_value",
            }
        )

        _response = _srv.parse_response(response.to_json(), sformat="json")
        # since no state attribute is involved, a key is minted
        _key = rndstr(16)
        _srv.update_service_context(_response, key=_key)
        info = _srv.upstream_get("context").cstate.get(_key)
        assert "__expires_at" in info

    def test_refresh_token_get_request(self):
        _srv = self.entity.get_service("accesstoken")
        _srv.update_service_context(
            {
                "access_token": "2YotnFZFEjr1zCsicMWpAA",
                "token_type": "example",
                "expires_in": 3600,
                "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
                "example_parameter": "example_value",
            }
        )
        _srv = self.entity.get_service("refresh_token")
        _info = _srv.get_request_parameters(state='cc')
        assert _info["method"] == "POST"
        assert _info["url"] == "https://example.com/token"
        assert _info["body"] == "grant_type=refresh_token"
        assert _info["headers"] == {
            "Authorization": "Bearer tGzv3JOkF0XG5Qx2TlKWIA",
            "Content-Type": "application/x-www-form-urlencoded",
        }

    def test_refresh_token_parse_response(self):
        request_args = {"grant_type": "client_credentials"}
        _srv = self.entity.get_service("accesstoken")
        _request_info = _srv.get_request_parameters(request_args=request_args)

        response = AccessTokenResponse(
            **{
                "access_token": "2YotnFZFEjr1zCsicMWpAA",
                "token_type": "example",
                "expires_in": 3600,
                "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
                "example_parameter": "example_value",
            }
        )

        _response = _srv.parse_response(response.to_json(), sformat="json")
        # since no state attribute is involved, a key is minted
        _key = rndstr(16)
        _srv.update_service_context(_response, key=_key)
        info = _srv.upstream_get("context").cstate.get(_key)
        assert "__expires_at" in info

        # Move from token to refresh token service

        _srv = self.entity.get_service("refresh_token")
        _request_info = _srv.get_request_parameters(request_args=request_args, state=_key)

        refresh_response = AccessTokenResponse(
            **{
                "access_token": "wy4R01DmMoB5xkI65nNkVv1l",
                "token_type": "example",
                "expires_in": 3600,
                "refresh_token": "lhNX9LSG8w1QuD6tSgc6CPfJ",
            }
        )

        _response = _srv.parse_response(refresh_response.to_json(), sformat="json")
        _srv.update_service_context(_response, key=_key)
        info = _srv.upstream_get("context").cstate.get(_key)
        assert "__expires_at" in info

    def test_2nd_refresh_token_parse_response(self):
        request_args = {"grant_type": "client_credentials"}
        _srv = self.entity.get_service("accesstoken")
        _request_info = _srv.get_request_parameters(request_args=request_args)

        response = AccessTokenResponse(
            **{
                "access_token": "2YotnFZFEjr1zCsicMWpAA",
                "token_type": "example",
                "expires_in": 3600,
                "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
                "example_parameter": "example_value",
            }
        )

        _response = _srv.parse_response(response.to_json(), sformat="json")
        # since no state attribute is involved, a key is minted
        _key = rndstr(16)
        _srv.update_service_context(_response, key=_key)
        info = _srv.upstream_get("context").cstate.get(_key)
        assert "__expires_at" in info

        # Move from token to refresh token service

        _srv = self.entity.get_service("refresh_token")
        _request_info = _srv.get_request_parameters(request_args=request_args, state=_key)

        refresh_response = AccessTokenResponse(
            **{
                "access_token": "wy4R01DmMoB5xkI65nNkVv1l",
                "token_type": "example",
                "expires_in": 3600,
                "refresh_token": "lhNX9LSG8w1QuD6tSgc6CPfJ",
            }
        )

        _response = _srv.parse_response(refresh_response.to_json(), sformat="json")
        _srv.update_service_context(_response, key=_key)
        info = _srv.upstream_get("context").cstate.get(_key)
        assert "__expires_at" in info

        _request_info = _srv.get_request_parameters(request_args=request_args, state=_key)
        assert _request_info["headers"] == {
            "Authorization": "Bearer {}".format(refresh_response["refresh_token"]),
            "Content-Type": "application/x-www-form-urlencoded",
        }
