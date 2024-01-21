import os

import pytest
from cryptojwt.key_jar import build_keyjar

from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.client.oauth2 import Client
from idpyoidc.message.oauth2 import is_error_message
from idpyoidc.server import ASConfiguration
from idpyoidc.server import Server
from idpyoidc.server.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from idpyoidc.util import rndstr

BASEDIR = os.path.abspath(os.path.dirname(__file__))
AS_ENTITY_ID = "https://as.example.com"


class TestDefConf(object):

    @pytest.fixture(autouse=True)
    def setup(self):
        self.server = Server(
            ASConfiguration(
                conf={"authentication":
                    {
                        "anon": {
                            "acr": INTERNETPROTOCOLPASSWORD,
                            "class": "idpyoidc.server.user_authn.user.NoAuthn",
                            "kwargs": {"user": "diana"},
                        }
                    }
                },
                base_path=BASEDIR),
            entity_id=AS_ENTITY_ID,
            cwd=BASEDIR)

        conf = {
            "redirect_uris": ["https://example.com/cli/authz_cb"],
            "client_id": "client_1",
            "client_secret": "abcdefghijklmnop",
            "response_types_supported": ["code"],
            "issuer": AS_ENTITY_ID
        }
        self.client = Client(
            client_type="oauth2",
            config=conf,
            keyjar=build_keyjar(DEFAULT_KEY_DEFS)
        )

        self.context = self.server.context
        self.context.cdb["client_1"] = conf
        self.context.keyjar.import_jwks(self.client.keyjar.export_jwks(), "client_1")

    def test_init(self):
        assert self.server
        assert set(self.server.endpoint.keys()) == {'token', 'authorization', 'server_metadata'}
        assert self.server.entity_id == self.server.issuer
        assert self.server.entity_id == AS_ENTITY_ID
        assert self.server.context.entity_id == AS_ENTITY_ID

    def do_query(self, service_type, endpoint_type, request_args, state):
        _client_service = self.client.get_service(service_type)
        req_info = _client_service.get_request_parameters(request_args=request_args)

        areq = req_info.get("request")
        headers = req_info.get("headers")

        _server_endpoint = self.server.get_endpoint(endpoint_type)
        if areq:
            if headers:
                argv = {"http_info": {"headers": headers}}
            else:
                argv = {}
            areq.lax = True
            _req = areq.serialize(_server_endpoint.request_format)
            _pr_resp = _server_endpoint.parse_request(_req, **argv)
        else:
            _pr_resp = _server_endpoint.parse_request(areq)

        if is_error_message(_pr_resp):
            return areq, _pr_resp

        _resp = _server_endpoint.process_request(_pr_resp)
        if is_error_message(_resp):
            return areq, _resp

        _response = _server_endpoint.do_response(**_resp)

        resp = _client_service.parse_response(_response["response"])
        _client_service.update_service_context(_resp["response_args"], key=state)
        return areq, resp

    def process_setup(self, token=None, scope=None):
        # ***** Discovery *********

        _req, _resp = self.do_query("server_metadata", "server_metadata", {}, "")

        # ***** Authorization Request **********
        _nonce = rndstr(24)
        _context = self.client.get_service_context()
        # Need a new state for a new authorization request
        _state = _context.cstate.create_state(iss=_context.get("issuer"))
        _context.cstate.bind_key(_nonce, _state)

        req_args = {"response_type": ["code"], "nonce": _nonce, "state": _state}

        if scope:
            _scope = scope
        else:
            _scope = ["openid"]

            if token and list(token.keys())[0] == "refresh_token":
                _scope = ["openid", "offline_access"]

        req_args["scope"] = _scope

        areq, auth_response = self.do_query("authorization", "authorization", req_args, _state)

        # ***** Token Request **********

        req_args = {
            "code": auth_response["code"],
            "state": auth_response["state"],
            "redirect_uri": areq["redirect_uri"],
            "grant_type": "authorization_code",
            "client_id": self.client.get_client_id(),
            "client_secret": _context.get_usage("client_secret"),
        }

        _token_request, resp = self.do_query("accesstoken", "token", req_args, _state)

        return resp, _state, _scope

    def test_flow(self):
        """
        Test that token exchange requests work correctly
        """

        resp, _state, _scope = self.process_setup(token="access_token", scope=["foobar"])
        assert resp