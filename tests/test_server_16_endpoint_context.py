import copy
import os

import pytest
from cryptojwt.key_jar import build_keyjar

from idpyoidc import work_environment
from idpyoidc.server import OPConfiguration
from idpyoidc.server import Server
from idpyoidc.server.endpoint import Endpoint
from idpyoidc.server.exception import OidcEndpointError
from idpyoidc.server.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from idpyoidc.server.util import allow_refresh_token
from . import CRYPT_CONFIG
from . import full_path
from . import SESSION_PARAMS

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

KEYJAR = build_keyjar(KEYDEFS)


class Endpoint_1(Endpoint):
    name = "userinfo"
    _supports = {
        "claim_types_supported": ["normal", "aggregated", "distributed"],
        "userinfo_signing_alg_values_supported": work_environment.get_signing_algs,
        "userinfo_encryption_alg_values_supported": work_environment.get_encryption_algs,
        "userinfo_encryption_enc_values_supported": work_environment.get_encryption_encs,
        "client_authn_method": ["bearer_header", "bearer_body"],
        "encrypt_userinfo_supported": False,
    }


conf = {
    "issuer": "https://example.com/",
    "template_dir": "template",
    "keys": {"uri_path": "static/jwks.json", "key_defs": KEYDEFS, "read_only": True},
    "client_authn_method": [
        "private_key_jwt",
        "client_secret_jwt",
        "client_secret_post",
        "client_secret_basic",
    ],
    "subject_types_supported": ["public", "pairwise"],
    "grant_types_supported": [
        "authorization_code",
        "implicit",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "refresh_token",
    ],
    "endpoint": {
        "userinfo": {
            "path": "userinfo",
            "class": Endpoint_1,
            "kwargs": {}
        }
    },
    "token_handler_args": {
        "jwks_def": {
            "private_path": "private/token_jwks.json",
            "read_only": False,
            "key_defs": [{"type": "oct", "bytes": "24", "use": ["enc"], "kid": "code"}],
        },
        "code": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
        "token": {
            "class": "idpyoidc.server.token.jwt_token.JWTToken",
            "kwargs": {
                "lifetime": 3600,
                "add_claims_by_scope": True,
                "aud": ["https://example.org/appl"],
            },
        },
        "refresh": {
            "class": "idpyoidc.server.token.jwt_token.JWTToken",
            "kwargs": {
                "lifetime": 3600,
                "aud": ["https://example.org/appl"],
            },
        },
        "id_token": {"class": "idpyoidc.server.token.id_token.IDToken", "kwargs": {}},
    },
    "userinfo": {
        "class": "idpyoidc.server.user_info.UserInfo",
        "kwargs": {"db_file": full_path("users.json")},
    },
    "claims_interface": {"class": "idpyoidc.server.session.claims.ClaimsInterface", "kwargs": {}},
    "session_params": SESSION_PARAMS,
}


class TestEndpointContext:

    @pytest.fixture(autouse=True)
    def create_endpoint_context(self):
        server = Server(conf)
        self.endpoint_context = server.endpoint_context

    def test(self):
        assert set(self.endpoint_context.provider_info.keys()) == {
            'grant_types_supported',
            'id_token_encryption_alg_values_supported',
            'id_token_encryption_enc_values_supported',
            'id_token_signing_alg_values_supported',
            'issuer',
            'jwks_uri',
            'scopes_supported',
            'userinfo_signing_alg_values_supported'}

    def test_allow_refresh_token(self):
        assert allow_refresh_token(self.endpoint_context)

        # Have the software but is not expected to use it.
        self.endpoint_context.set_preference("grant_types_supported", [
            "authorization_code",
            "implicit",
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
        ])
        assert allow_refresh_token(self.endpoint_context) is False

        # Don't have the software but are expected to use it.
        self.endpoint_context.set_preference("grant_types_supported", [
            "authorization_code",
            "implicit",
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "refresh_token",
        ])
        del self.endpoint_context.session_manager.token_handler.handler["refresh_token"]
        with pytest.raises(OidcEndpointError):
            assert allow_refresh_token(self.endpoint_context) is False


class Tokenish(Endpoint):
    _supports = {
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
            "client_secret_basic",
            "client_secret_jwt",
            "private_key_jwt",
        ],
        "token_endpoint_auth_signing_alg_values_supported": None,
    }


BASEDIR = os.path.abspath(os.path.dirname(__file__))

# Note no endpoints !!
CONF = {
    "issuer": "https://example.com/",
    "httpc_params": {"verify": False, "timeout": 1},
    "token_expires_in": 600,
    "grant_expires_in": 300,
    "refresh_token_expires_in": 86400,
    "subject_types_supported": ["public", "pairwise"],
    "grant_types_supported": [
        "authorization_code",
        "implicit",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "refresh_token",
    ],
    "keys": {
        "public_path": "jwks.json",
        "key_defs": KEYDEFS,
        "private_path": "own/jwks.json",
        "uri_path": "static/jwks.json",
    },
    "authentication": {
        "anon": {
            "acr": INTERNETPROTOCOLPASSWORD,
            "class": "idpyoidc.server.user_authn.user.NoAuthn",
            "kwargs": {"user": "diana"},
        }
    },
    "template_dir": "template",
}


@pytest.mark.parametrize(
    "kwargs",
    [
        {},
        {"client_authn_method": ["client_secret_jwt", "private_key_jwt"]},
        {"token_endpoint_auth_methods_supported": ["client_secret_jwt", "private_key_jwt"]},
    ],
)
def test_provider_configuration(kwargs):
    conf = copy.deepcopy(CONF)
    conf.update(kwargs)
    conf["endpoint"] = {
        "endpoint": {"path": "endpoint", "class": Tokenish, "kwargs": {}},
    }

    server = Server(OPConfiguration(conf=conf, base_path=BASEDIR), cwd=BASEDIR)
    server.endpoint_context.cdb["client_id"] = {}
    pi = server.endpoint_context.provider_info
    assert set(pi.keys()) == {'grant_types_supported',
                              'id_token_encryption_alg_values_supported',
                              'id_token_encryption_enc_values_supported',
                              'id_token_signing_alg_values_supported',
                              'issuer',
                              'jwks_uri',
                              'scopes_supported',
                              'token_endpoint_auth_methods_supported'}

    if kwargs:
        if 'token_endpoint_auth_methods_supported' in kwargs:
            assert pi["token_endpoint_auth_methods_supported"] == ['client_secret_jwt',
                                                                   'private_key_jwt']
        else:
            assert pi["token_endpoint_auth_methods_supported"] == ['client_secret_post',
                                                                   'client_secret_basic',
                                                                   'client_secret_jwt',
                                                                   'private_key_jwt']

    else:
        assert pi["token_endpoint_auth_methods_supported"] == ['client_secret_post',
                                                               'client_secret_basic',
                                                               'client_secret_jwt',
                                                               'private_key_jwt']
