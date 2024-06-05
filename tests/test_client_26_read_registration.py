import json
import time

import pytest
import responses
from cryptojwt.utils import as_bytes

import requests
from idpyoidc.client.entity import Entity
from idpyoidc.message.oidc import APPLICATION_TYPE_WEB
from idpyoidc.message.oidc import RegistrationResponse

ISS = "https://example.com"
RP_BASEURL = "https://example.com/rp"


class TestRegistrationRead(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self._iss = ISS
        client_config = {
            "issuer": self._iss,
            "requests_dir": "requests",
            "base_url": "https://example.com/cli/",
            "application_type": APPLICATION_TYPE_WEB,
            "response_types_supported": ["code"],
            "contacts": ["ops@example.org"],
            "jwks_uri": "https://example.com/rp/static/jwks.json",
            "redirect_uris": ["{}/authz_cb".format(RP_BASEURL)],
            "token_endpoint_auth_methods_supported": ["client_secret_basic"],
            "grant_types_supported": ["authorization_code"],
        }
        services = {
            "registration": {"class": "idpyoidc.client.oidc.registration.Registration"},
            "read_registration": {
                "class": "idpyoidc.client.oidc.read_registration.RegistrationRead"
            },
            "authorization": {"class": "idpyoidc.client.oidc.authorization.Authorization"},
            "accesstoken": {"class": "idpyoidc.client.oidc.access_token.AccessToken"},
        }

        self.entity = Entity(config=client_config, services=services)
        _context = self.entity.get_service_context()
        _context.map_supported_to_preferred()
        _context.map_preferred_to_registered()

        self.reg_service = self.entity.get_service("registration")
        self.read_service = self.entity.get_service("registration_read")

    def test_construct(self):
        self.reg_service.endpoint = "{}/registration".format(ISS)

        _param = self.reg_service.get_request_parameters()

        now = int(time.time())

        _client_registration_response = json.dumps(
            {
                "client_id": "zls2qhN1jO6A",
                "client_secret": "c8434f28cf9375d9a7",
                "registration_access_token": "NdGrGR7LCuzNtixvBFnDphGXv7wRcONn",
                "registration_client_uri": "{}/registration_api?client_id=zls2qhN1jO6A".format(ISS),
                "client_secret_expires_at": now + 3600,
                "client_id_issued_at": now,
                "application_type": APPLICATION_TYPE_WEB,
                "response_types": ["code"],
                "contacts": ["ops@example.com"],
                "redirect_uris": ["{}/authz_cb".format(RP_BASEURL)],
                "token_endpoint_auth_method": "client_secret_basic",
                "grant_types": ["authorization_code"],
            }
        )

        with responses.RequestsMock() as rsps:
            rsps.add(
                _param["method"], _param["url"], body=_client_registration_response, status=200
            )
            _resp = requests.request(
                _param["method"],
                _param["url"],
                data=as_bytes(_param["body"]),
                headers=_param["headers"],
                verify=False,
            )

        resp = self.reg_service.parse_response(_resp.text)
        self.reg_service.update_service_context(resp)

        assert resp

        _read_param = self.read_service.get_request_parameters()
        with responses.RequestsMock() as rsps:
            rsps.add(
                _param["method"],
                _param["url"],
                body=_client_registration_response,
                adding_headers={"Content-Type": "application/json"},
                status=200,
            )
            _resp = requests.request(
                _param["method"], _param["url"], headers=_param["headers"], verify=False
            )

        read_resp = self.reg_service.parse_response(_resp.text)
        assert isinstance(read_resp, RegistrationResponse)
