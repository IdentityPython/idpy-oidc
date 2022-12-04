import json
import os

import pytest

from idpyoidc.server import Server
from idpyoidc.server.configure import OPConfiguration
from idpyoidc.server.oidc.provider_config import ProviderConfiguration
from idpyoidc.server.oidc.token import Token
from tests import CRYPT_CONFIG
from tests import SESSION_PARAMS

BASEDIR = os.path.abspath(os.path.dirname(__file__))

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

RESPONSE_TYPES_SUPPORTED = [
    ["code"],
    ["token"],
    ["id_token"],
    ["code", "token"],
    ["code", "id_token"],
    ["id_token", "token"],
    ["code", "token", "id_token"],
    ["none"],
]

CAPABILITIES = {
    "response_types_supported": [" ".join(x) for x in RESPONSE_TYPES_SUPPORTED],
    "token_endpoint_auth_methods_supported": [
        "client_secret_post",
        "client_secret_basic",
        "client_secret_jwt",
        "private_key_jwt",
    ],
    "response_modes_supported": ["query", "fragment", "form_post"],
    "subject_types_supported": ["public", "pairwise" "ephemeral"],
    "grant_types_supported": [
        "authorization_code",
        "implicit",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "refresh_token",
    ],
    "claim_types_supported": ["normal", "aggregated", "distributed"],
    "claims_parameter_supported": True,
    "request_parameter_supported": True,
    "request_uri_parameter_supported": True,
}


class TestProviderConfigEndpoint(object):
    @pytest.fixture
    def conf(self):
        return {
            "issuer": "https://example.com/",
            "httpc_params": {"verify": False},
            "capabilities": CAPABILITIES,
            "keys": {"uri_path": "static/jwks.json", "key_defs": KEYDEFS},
            "endpoint": {
                "provider_config": {
                    "path": ".well-known/openid-configuration",
                    "class": ProviderConfiguration,
                    "kwargs": {},
                },
                "token": {"path": "token", "class": Token, "kwargs": {}},
            },
            "template_dir": "template",
            "session_params": SESSION_PARAMS,
            "token_handler_args": {
                "code": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
                "token": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
                "refresh": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
            },
        }

    @pytest.fixture(autouse=True)
    def create_endpoint(self, conf):
        server = Server(OPConfiguration(conf=conf, base_path=BASEDIR), cwd=BASEDIR)

        self.endpoint_context = server.endpoint_context
        self.endpoint = server.get_endpoint("provider_config")

    def test_do_response(self):
        args = self.endpoint.process_request()
        msg = self.endpoint.do_response(args["response_args"])
        assert isinstance(msg, dict)
        _msg = json.loads(msg["response"])
        assert _msg
        assert _msg["token_endpoint"] == "https://example.com/token"
        assert _msg["jwks_uri"] == "https://example.com/static/jwks.json"
        assert "claims_supported" not in _msg  # No default for this
        assert ("Content-type", "application/json; charset=utf-8") in msg["http_headers"]

    def test_scopes_supported(self, conf):
        scopes_supported = ["openid", "random", "profile"]
        conf["scopes_supported"] = scopes_supported

        server = Server(OPConfiguration(conf=conf, base_path=BASEDIR), cwd=BASEDIR)
        endpoint = server.get_endpoint("provider_config")
        args = endpoint.process_request()
        msg = endpoint.do_response(args["response_args"])
        assert isinstance(msg, dict)
        _msg = json.loads(msg["response"])
        assert set(_msg["scopes_supported"]) == set(scopes_supported)
