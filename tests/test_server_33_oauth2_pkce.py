import io
import json
import os
import secrets
import string

import pytest
import yaml

from idpyoidc.message import Message
from idpyoidc.message.oauth2 import AuthorizationErrorResponse
from idpyoidc.message.oidc import AccessTokenRequest
from idpyoidc.message.oidc import AuthorizationRequest
from idpyoidc.message.oidc import AuthorizationResponse
from idpyoidc.message.oidc import TokenErrorResponse
from idpyoidc.server import Server
from idpyoidc.server.configure import ASConfiguration
from idpyoidc.server.configure import OPConfiguration
from idpyoidc.server.cookie_handler import CookieHandler
from idpyoidc.server.oidc.add_on.pkce import CC_METHOD
from idpyoidc.server.oidc.add_on.pkce import add_pkce_support
from idpyoidc.server.oidc.authorization import Authorization
from idpyoidc.server.oidc.token import Token

from . import CRYPT_CONFIG
from . import SESSION_PARAMS
from . import full_path

BASECH = string.ascii_letters + string.digits + "-._~"

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

CAPABILITIES = {
    "subject_types_supported": ["public", "pairwise"],
    "grant_types_supported": [
        "authorization_code",
        "implicit",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "refresh_token",
    ],
}

CLAIMS = {"id_token": {"given_name": {"essential": True}, "nickname": None}}

AUTH_REQ = AuthorizationRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    scope=["openid"],
    state="STATE",
    response_type="code",
)

TOKEN_REQ = AccessTokenRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    state="STATE",
    grant_type="authorization_code",
    client_secret="hemligt",
)

AUTH_REQ_DICT = AUTH_REQ.to_dict()

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


USERINFO_db = json.loads(open(full_path("users.json")).read())

client_yaml = """
oidc_clients:
  client_1:
    "client_secret": 'hemligt'
    "redirect_uris":
        - ['https://example.com/cb', '']
    "client_salt": "salted"
    'token_endpoint_auth_method': 'client_secret_post'
    'response_types':
        - 'code'
        - 'token'
        - 'code id_token'
        - 'id_token'
        - 'code id_token token'
  client2:
    client_secret: "spraket"
    redirect_uris:
      - ['https://app1.example.net/foo', '']
      - ['https://app2.example.net/bar', '']
    response_types:
      - code
  client3:
    client_secret: '2222222222222222222222222222222222222222'
    redirect_uris:
      - ['https://127.0.0.1:8090/authz_cb/bobcat', '']
    post_logout_redirect_uri: ['https://openidconnect.net/', '']
    response_types:
      - code
"""


@pytest.fixture
def conf():
    return {
        "issuer": "https://example.com/",
        "password": "mycket hemligt zebra",
        "verify_ssl": False,
        "capabilities": CAPABILITIES,
        "keys": {"uri_path": "static/jwks.json", "key_defs": KEYDEFS},
        "endpoint": {
            "authorization": {
                "path": "{}/authorization",
                "class": Authorization,
                "kwargs": {},
            },
            "token": {
                "path": "{}/token",
                "class": Token,
                "kwargs": {
                    "client_authn_method": [
                        "client_secret_post",
                        "client_secret_basic",
                        "client_secret_jwt",
                        "private_key_jwt",
                    ]
                },
            },
        },
        "authentication": {
            "anon": {
                "acr": "http://www.swamid.se/policy/assurance/al1",
                "class": "idpyoidc.server.user_authn.user.NoAuthn",
                "kwargs": {"user": "diana"},
            }
        },
        "template_dir": "template",
        "add_on": {
            "pkce": {
                "function": "idpyoidc.server.oidc.add_on.pkce.add_pkce_support",
                "kwargs": {"essential": True},
            }
        },
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
        "userinfo": {
            "class": "idpyoidc.server.user_info.UserInfo",
            "kwargs": {"db_file": full_path("users.json")},
        },
        "session_params": SESSION_PARAMS,
        "token_handler_args": {
            "code": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
            "token": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
            "refresh": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
        },
    }


def unreserved(size=64):
    return "".join(secrets.choice(BASECH) for _ in range(size))


def _code_challenge():
    """
    PKCE aka RFC 7636
    """
    # code_verifier: string of length cv_len
    code_verifier = unreserved(64)

    _method = "S256"

    # Pick hash method
    _hash_method = CC_METHOD[_method]
    # base64 encode the hash value
    code_challenge = _hash_method(code_verifier)

    return {
        "code_challenge": code_challenge,
        "code_challenge_method": _method,
        "code_verifier": code_verifier,
    }


def create_server(config):
    server = Server(ASConfiguration(conf=config, base_path=BASEDIR), cwd=BASEDIR)

    endpoint_context = server.endpoint_context
    _clients = yaml.safe_load(io.StringIO(client_yaml))
    endpoint_context.cdb = _clients["oidc_clients"]
    endpoint_context.keyjar.import_jwks(
        endpoint_context.keyjar.export_jwks(True, ""), config["issuer"]
    )
    return server


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self, conf):
        server = create_server(conf)
        self.session_manager = server.endpoint_context.session_manager
        self.authn_endpoint = server.server_get("endpoint", "authorization")
        self.token_endpoint = server.server_get("endpoint", "token")

    def test_unsupported_code_challenge_methods(self, conf):
        conf["add_on"]["pkce"]["kwargs"]["code_challenge_methods"] = ["dada"]

        with pytest.raises(ValueError) as exc:
            create_server(conf)

        assert exc.value.args[0] == "Unsupported method: dada"

    def test_parse(self):
        _cc_info = _code_challenge()
        _authn_req = AUTH_REQ.copy()
        _authn_req["code_challenge"] = _cc_info["code_challenge"]
        _authn_req["code_challenge_method"] = _cc_info["code_challenge_method"]

        _pr_resp = self.authn_endpoint.parse_request(_authn_req.to_dict())
        resp = self.authn_endpoint.process_request(_pr_resp)

        assert isinstance(resp["response_args"], AuthorizationResponse)

        _token_request = TOKEN_REQ.copy()
        _token_request["code"] = resp["response_args"]["code"]
        _token_request["code_verifier"] = _cc_info["code_verifier"]
        _req = self.token_endpoint.parse_request(_token_request)

        assert isinstance(_req, Message)

    def test_no_code_challenge_method(self):
        _cc_info = _code_challenge()
        _authn_req = AUTH_REQ.copy()
        _authn_req["code_challenge"] = _cc_info["code_challenge"]

        _pr_resp = self.authn_endpoint.parse_request(_authn_req.to_dict())
        resp = self.authn_endpoint.process_request(_pr_resp)

        assert isinstance(resp["response_args"], AuthorizationResponse)

        session_info = self.session_manager.get_branch_info_by_token(resp["response_args"]["code"])

        session_info["grant"].authorization_request["code_challenge_method"] = "plain"

        _token_request = TOKEN_REQ.copy()
        _token_request["code"] = resp["response_args"]["code"]
        _token_request["code_verifier"] = _cc_info["code_challenge"]
        _req = self.token_endpoint.parse_request(_token_request)

        assert isinstance(_req, Message)

    def test_no_code_challenge(self):
        _authn_req = AUTH_REQ.copy()

        _pr_resp = self.authn_endpoint.parse_request(_authn_req.to_dict())

        assert isinstance(_pr_resp, AuthorizationErrorResponse)
        assert _pr_resp["error"] == "invalid_request"
        assert _pr_resp["error_description"] == "Missing required code_challenge"

    def test_not_essential(self, conf):
        conf["add_on"]["pkce"]["kwargs"]["essential"] = False
        server = create_server(conf)
        authn_endpoint = server.server_get("endpoint", "authorization")
        token_endpoint = server.server_get("endpoint", "token")
        _authn_req = AUTH_REQ.copy()

        _pr_resp = authn_endpoint.parse_request(_authn_req.to_dict())
        resp = authn_endpoint.process_request(_pr_resp)

        assert isinstance(resp["response_args"], AuthorizationResponse)

        _token_request = TOKEN_REQ.copy()
        _token_request["code"] = resp["response_args"]["code"]
        _req = token_endpoint.parse_request(_token_request)

        assert isinstance(_req, Message)

    def test_essential_per_client(self, conf):
        conf["add_on"]["pkce"]["kwargs"]["essential"] = False
        server = create_server(conf)
        authn_endpoint = server.server_get("endpoint", "authorization")
        token_endpoint = server.server_get("endpoint", "token")
        _authn_req = AUTH_REQ.copy()
        endpoint_context = server.server_get("endpoint_context")
        endpoint_context.cdb[AUTH_REQ["client_id"]]["pkce_essential"] = True

        _pr_resp = authn_endpoint.parse_request(_authn_req.to_dict())

        assert isinstance(_pr_resp, AuthorizationErrorResponse)
        assert _pr_resp["error"] == "invalid_request"
        assert _pr_resp["error_description"] == "Missing required code_challenge"

    def test_not_essential_per_client(self, conf):
        conf["add_on"]["pkce"]["kwargs"]["essential"] = True
        server = create_server(conf)
        authn_endpoint = server.server_get("endpoint", "authorization")
        token_endpoint = server.server_get("endpoint", "token")
        _authn_req = AUTH_REQ.copy()
        endpoint_context = server.server_get("endpoint_context")
        endpoint_context.cdb[AUTH_REQ["client_id"]]["pkce_essential"] = False

        _pr_resp = authn_endpoint.parse_request(_authn_req.to_dict())
        resp = authn_endpoint.process_request(_pr_resp)

        assert isinstance(resp["response_args"], AuthorizationResponse)

        _token_request = TOKEN_REQ.copy()
        _token_request["code"] = resp["response_args"]["code"]
        _req = token_endpoint.parse_request(_token_request)

        assert isinstance(_req, Message)

    def test_unknown_code_challenge_method(self):
        _authn_req = AUTH_REQ.copy()
        _authn_req["code_challenge"] = "aba"
        _authn_req["code_challenge_method"] = "doupa"

        _pr_resp = self.authn_endpoint.parse_request(_authn_req.to_dict())

        assert isinstance(_pr_resp, AuthorizationErrorResponse)
        assert _pr_resp["error"] == "invalid_request"
        assert _pr_resp["error_description"] == "Unsupported code_challenge_method={}".format(
            _authn_req["code_challenge_method"]
        )

    def test_unsupported_code_challenge_method(self, conf):
        conf["add_on"]["pkce"]["kwargs"]["code_challenge_methods"] = ["plain"]
        server = create_server(conf)
        authn_endpoint = server.server_get("endpoint", "authorization")

        _cc_info = _code_challenge()
        _authn_req = AUTH_REQ.copy()
        _authn_req["code_challenge"] = _cc_info["code_challenge"]
        _authn_req["code_challenge_method"] = _cc_info["code_challenge_method"]

        _pr_resp = authn_endpoint.parse_request(_authn_req.to_dict())

        assert isinstance(_pr_resp, AuthorizationErrorResponse)
        assert _pr_resp["error"] == "invalid_request"
        assert _pr_resp["error_description"] == "Unsupported code_challenge_method={}".format(
            _authn_req["code_challenge_method"]
        )

    def test_wrong_code_verifier(self):
        _cc_info = _code_challenge()
        _authn_req = AUTH_REQ.copy()
        _authn_req["code_challenge"] = _cc_info["code_challenge"]
        _authn_req["code_challenge_method"] = _cc_info["code_challenge_method"]

        _pr_resp = self.authn_endpoint.parse_request(_authn_req.to_dict())
        resp = self.authn_endpoint.process_request(_pr_resp)

        _token_request = TOKEN_REQ.copy()
        _token_request["code"] = resp["response_args"]["code"]
        _token_request["code_verifier"] = "aba"
        resp = self.token_endpoint.parse_request(_token_request)

        assert isinstance(resp, TokenErrorResponse)
        assert resp["error"] == "invalid_grant"
        assert resp["error_description"] == "PKCE check failed"

    def test_no_code_verifier(self):
        _cc_info = _code_challenge()
        _authn_req = AUTH_REQ.copy()
        _authn_req["code_challenge"] = _cc_info["code_challenge"]
        _authn_req["code_challenge_method"] = _cc_info["code_challenge_method"]

        _pr_resp = self.authn_endpoint.parse_request(_authn_req.to_dict())
        resp = self.authn_endpoint.process_request(_pr_resp)

        _token_request = TOKEN_REQ.copy()
        _token_request["code"] = resp["response_args"]["code"]
        resp = self.token_endpoint.parse_request(_token_request)

        assert isinstance(resp, TokenErrorResponse)
        assert resp["error"] == "invalid_grant"
        assert resp["error_description"] == "Missing code_verifier"


def test_missing_authz_endpoint():
    conf = {
        "issuer": "https://example.com/",
        "capabilities": CAPABILITIES,
        "keys": {"uri_path": "static/jwks.json", "key_defs": KEYDEFS},
        "endpoint": {
            "introspection": {
                "path": "introspection",
                "class": "idpyoidc.server.oauth2.introspection.Introspection",
                "kwargs": {},
            }
        },
    }
    configuration = OPConfiguration(conf, base_path=BASEDIR, domain="127.0.0.1", port=443)
    server = Server(configuration)
    add_pkce_support(server.server_get("endpoints"))

    assert "pkce" not in server.server_get("endpoint_context").args


def test_missing_token_endpoint():
    conf = {
        "issuer": "https://example.com/",
        "capabilities": CAPABILITIES,
        "keys": {"uri_path": "static/jwks.json", "key_defs": KEYDEFS},
        "endpoint": {
            "authorization": {
                "path": "authorization",
                "class": "idpyoidc.server.oauth2.authorization.Authorization",
                "kwargs": {},
            },
            "introspection": {
                "path": "introspection",
                "class": "idpyoidc.server.oauth2.introspection.Introspection",
                "kwargs": {},
            },
        },
    }
    configuration = OPConfiguration(conf, base_path=BASEDIR, domain="127.0.0.1", port=443)
    server = Server(configuration)
    add_pkce_support(server.server_get("endpoints"))

    assert "pkce" not in server.server_get("endpoint_context").args
