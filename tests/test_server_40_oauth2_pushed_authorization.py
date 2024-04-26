import io
import os

import pytest
import yaml
from cryptojwt import JWT
from cryptojwt.jwt import remove_jwt_parameters
from cryptojwt.key_jar import init_key_jar

from idpyoidc.message import Message
from idpyoidc.message.oauth2 import AuthorizationRequest
from idpyoidc.server import Server
from idpyoidc.server.client_configure import verify_oidc_client_information
from idpyoidc.server.configure import ASConfiguration
from idpyoidc.server.cookie_handler import CookieHandler
from idpyoidc.server.oauth2.authorization import Authorization
from idpyoidc.server.oauth2.pushed_authorization import PushedAuthorization
from idpyoidc.server.oidc.provider_config import ProviderConfiguration
from idpyoidc.server.oidc.registration import Registration
from tests import CRYPT_CONFIG
from tests import SESSION_PARAMS

BASEDIR = os.path.abspath(os.path.dirname(__file__))

CAPABILITIES = {
    "subject_types_supported": ["public", "pairwise", "ephemeral"],
    "grant_types_supported": [
        "authorization_code",
        "implicit",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "refresh_token",
    ],
}

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]}
    # {"type": "EC", "crv": "P-256", "use": ["sig"]}
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

client_yaml = """
oidc_clients:
  s6BhdRkqt3:
    client_id: s6BhdRkqt3
    client_secret: 7Fjfp0ZBr1KtDRbnfVdmIw
    redirect_uris: 
        - 'https://client.example.org/cb'
    token_endpoint_auth_method: 'client_secret_post'
    response_types: 
        - 'code'
        - 'token'
        - 'code id_token'
        - 'id_token'
        - 'code id_token token'
"""

AUTHN_REQUEST = (
    "response_type=code&state=af0ifjsldkj&client_id=s6BhdRkqt3&redirect_uri"
    "=https%3A%2F%2Fclient.example.org%2Fcb&code_challenge=K2"
    "-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U&code_challenge_method=S256"
    "&scope=ais"
)


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        conf = {
            "issuer": "https://example.com/",
            "password": "mycket hemligt zebra",
            "token_handler_args": {
                "jwks_def": {
                    "private_path": "private/token_jwks.json",
                    "read_only": False,
                    "key_defs": [
                        {"type": "oct", "bytes": 24, "use": ["enc"], "kid": "code"},
                        {"type": "oct", "bytes": 24, "use": ["enc"], "kid": "refresh"},
                    ],
                },
                "code": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
                "token": {
                    "class": "idpyoidc.server.token.jwt_token.JWTToken",
                    "kwargs": {
                        "lifetime": 3600,
                        "add_claims": [
                            "email",
                            "email_verified",
                            "phone_number",
                            "phone_number_verified",
                        ],
                        "add_claims_by_scope": True,
                        "aud": ["https://example.org/appl"],
                    },
                },
                "refresh": {"lifetime": 86400},
            },
            "verify_ssl": False,
            "capabilities": CAPABILITIES,
            "keys": {"uri_path": "static/jwks.json", "key_defs": KEYDEFS},
            "endpoint": {
                "provider_config": {
                    "path": ".well-known/openid-configuration",
                    "class": ProviderConfiguration,
                    "kwargs": {},
                },
                "registration": {
                    "path": "registration",
                    "class": Registration,
                    "kwargs": {},
                },
                "authorization": {
                    "path": "authorization",
                    "class": Authorization,
                    "kwargs": {
                        "response_types_supported": [" ".join(x) for x in RESPONSE_TYPES_SUPPORTED],
                        "response_modes_supported": ["query", "fragment", "form_post"],
                        "claims_parameter_supported": True,
                        "request_parameter_supported": True,
                        "request_uri_parameter_supported": True,
                    },
                },
                "pushed_authorization": {
                    "path": "pushed_authorization",
                    "class": PushedAuthorization,
                    "kwargs": {
                        "client_authn_method": [
                            "client_secret_post",
                            "client_secret_basic",
                            "client_secret_jwt",
                            "private_key_jwt",
                        ]
                    }
                }
            },
            "authentication": {
                "anon": {
                    "acr": "http://www.swamid.se/policy/assurance/al1",
                    "class": "idpyoidc.server.user_authn.user.NoAuthn",
                    "kwargs": {"user": "diana"},
                }
            },
            "template_dir": "template",
            "cookie_handler": {
                "class": CookieHandler,
                "kwargs": {
                    "sign_key": "ghsNKDDLshZTPn974nOsIGhedULrsqnsGoBFBLwUKuJhE2ch",
                    "name": {
                        "session": "oidc_op",
                        "register": "oidc_op_reg",
                        "session_management": "oidc_op_sman",
                    },
                },
            },
            "session_params": SESSION_PARAMS,
        }
        server = Server(ASConfiguration(conf=conf, base_path=BASEDIR), cwd=BASEDIR)
        context = server.context
        _clients = yaml.safe_load(io.StringIO(client_yaml))
        context.cdb = verify_oidc_client_information(_clients["oidc_clients"])
        server.keyjar.import_jwks(server.keyjar.export_jwks(True, ""), conf["issuer"])

        self.rp_keyjar = init_key_jar(key_defs=KEYDEFS, issuer_id="s6BhdRkqt3")
        # Add RP's keys to the OP's keyjar
        server.keyjar.import_jwks(self.rp_keyjar.export_jwks(issuer_id="s6BhdRkqt3"), "s6BhdRkqt3")

        self.pushed_authorization_endpoint = server.get_endpoint("pushed_authorization")
        self.authorization_endpoint = server.get_endpoint("authorization")

    def test_init(self):
        assert self.pushed_authorization_endpoint

    def test_pushed_auth_urlencoded(self):
        http_info = {
            "headers": {"authorization": "Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3"}
        }

        _req = self.pushed_authorization_endpoint.parse_request(AUTHN_REQUEST, http_info=http_info)

        assert isinstance(_req, AuthorizationRequest)
        assert set(_req.keys()) == {
            "state",
            "redirect_uri",
            "response_type",
            "scope",
            "code_challenge_method",
            "client_id",
            "code_challenge",
            "authenticated",
        }

    def test_pushed_auth_request(self):
        _msg = Message().from_urlencoded(AUTHN_REQUEST)
        _jwt = JWT(key_jar=self.rp_keyjar, iss="s6BhdRkqt3")
        _jws = _jwt.pack(_msg.to_dict())

        authn_request = "request={}".format(_jws)
        http_info = {
            "headers": {"authorization": "Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3"}
        }

        _req = self.pushed_authorization_endpoint.parse_request(authn_request, http_info=http_info)

        assert isinstance(_req, AuthorizationRequest)
        _req = remove_jwt_parameters(_req)
        assert set(_req.keys()) == {
            "state",
            "redirect_uri",
            "response_type",
            "scope",
            "code_challenge_method",
            "client_id",
            "code_challenge",
            "request",
            "__verified_request",
            "authenticated",
        }

    def test_pushed_auth_urlencoded_process(self):
        http_info = {
            "headers": {"authorization": "Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3"}
        }

        _req = self.pushed_authorization_endpoint.parse_request(AUTHN_REQUEST, http_info=http_info)

        assert isinstance(_req, AuthorizationRequest)
        assert set(_req.keys()) == {
            "state",
            "redirect_uri",
            "response_type",
            "scope",
            "code_challenge_method",
            "client_id",
            "code_challenge",
            "authenticated",
        }

        _resp = self.pushed_authorization_endpoint.process_request(_req)

        _msg = Message().from_urlencoded(AUTHN_REQUEST)
        assert _resp["return_uri"] == _msg["redirect_uri"]

        # And now for the authorization request with the OP provided request_uri

        _msg["request_uri"] = _resp["http_response"]["request_uri"]
        for parameter in ["code_challenge", "code_challenge_method"]:
            del _msg[parameter]

        _req = self.authorization_endpoint.parse_request(_msg)

        assert "code_challenge" in _req
