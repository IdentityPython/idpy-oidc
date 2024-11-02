import json
import os
from typing import List

from cryptojwt.key_jar import build_keyjar

from idpyoidc.client.oauth2 import Client
from idpyoidc.key_import import import_jwks
from idpyoidc.message.oauth2 import is_error_message
from idpyoidc.message.oidc import AccessTokenRequest
from idpyoidc.message.oidc import AuthorizationRequest
from idpyoidc.message.oidc import RefreshAccessTokenRequest
from idpyoidc.server import Server
from idpyoidc.server.authz import AuthzHandling
from idpyoidc.server.client_authn import verify_client
from idpyoidc.server.configure import ASConfiguration
from idpyoidc.server.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from idpyoidc.server.user_info import UserInfo
from idpyoidc.util import rndstr
from tests import CRYPT_CONFIG
from tests import SESSION_PARAMS

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

CLIENT_KEYJAR = build_keyjar(KEYDEFS)

COOKIE_KEYDEFS = [
    {"type": "oct", "kid": "sig", "use": ["sig"]},
    {"type": "oct", "kid": "enc", "use": ["enc"]},
]

AUTH_REQ = AuthorizationRequest(
    client_id="client",
    redirect_uri="https://example.com/cb",
    scope=["openid"],
    state="STATE",
    response_type="code",
)

TOKEN_REQ = AccessTokenRequest(
    client_id="client",
    redirect_uri="https://example.com/cb",
    state="STATE",
    grant_type="authorization_code",
    client_secret="hemligt",
)

REFRESH_TOKEN_REQ = RefreshAccessTokenRequest(
    grant_type="refresh_token", client_id="https://example.com/", client_secret="hemligt"
)

TOKEN_REQ_DICT = TOKEN_REQ.to_dict()

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


USERINFO = UserInfo(json.loads(open(full_path("users.json")).read()))

_OAUTH2_SERVICES = {
    "metadata": {"class": "idpyoidc.client.oauth2.server_metadata.ServerMetadata"},
    "authorization": {"class": "idpyoidc.client.oauth2.authorization.Authorization"},
    "access_token": {"class": "idpyoidc.client.oauth2.access_token.AccessToken"},
    "resource": {"class": "idpyoidc.client.oauth2.resource.Resource"},
}

SERVER_CONF = {
    "issuer": "https://example.com/",
    "httpc_params": {"verify": False, "timeout": 1},
    "subject_types_supported": ["public", "pairwise", "ephemeral"],
    "keys": {"uri_path": "jwks.json", "key_defs": KEYDEFS},
    "endpoint": {
        "metadata": {
            "path": ".well-known/oauth-authorization-server",
            "class": "idpyoidc.server.oauth2.server_metadata.ServerMetadata",
            "kwargs": {},
        },
        "authorization": {
            "path": "authorization",
            "class": "idpyoidc.server.oauth2.authorization.Authorization",
            "kwargs": {},
        },
        "token": {
            "path": "token",
            "class": "idpyoidc.server.oauth2.token.Token",
            "kwargs": {},
        },
    },
    "authentication": {
        "anon": {
            "acr": INTERNETPROTOCOLPASSWORD,
            "class": "idpyoidc.server.user_authn.user.NoAuthn",
            "kwargs": {"user": "diana"},
        }
    },
    "userinfo": {"class": UserInfo, "kwargs": {"db": {}}},
    "client_authn": verify_client,
    "authz": {
        "class": AuthzHandling,
        "kwargs": {
            "grant_config": {
                "usage_rules": {
                    "authorization_code": {
                        "supports_minting": ["access_token", "refresh_token"],
                        "max_usage": 1,
                    },
                    "access_token": {
                        "supports_minting": ["access_token", "refresh_token"],
                        "expires_in": 600,
                    },
                    "refresh_token": {
                        "supports_minting": ["access_token"],
                        "audience": ["https://example.com", "https://example2.com"],
                        "expires_in": 43200,
                    },
                },
                "expires_in": 43200,
            }
        },
    },
    "token_handler_args": {
        "jwks_file": "private/token_jwks.json",
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
    },
    "session_params": SESSION_PARAMS,
    "add_ons": {
        "pkce": {
            "function": "idpyoidc.server.oauth2.add_on.pkce.add_support",
            "kwargs": {},
        },
    },
}

CLIENT_CONFIG = {
    "issuer": SERVER_CONF["issuer"],
    "client_secret": "hemligtlösenord",
    "client_id": "client",
    "redirect_uris": ["https://example.com/cb"],
    "client_salt": "salted_peanuts_cooking",
    "token_endpoint_auth_methods_supported": ["client_secret_post"],
    "response_types_supported": ["code"],
    "add_ons": {
        "pkce": {
            "function": "idpyoidc.client.oauth2.add_on.pkce.add_support",
            "kwargs": {"code_challenge_length": 64, "code_challenge_method": "S256"},
        },
    },
}


class Flow(object):

    def __init__(self, client, server):
        self.client = client
        self.server = server

    def do_query(self, service_type, endpoint_type, request_args=None, msg=None):
        if request_args is None:
            request_args = {}
        if msg is None:
            msg = {}

        _client_service = self.client.get_service(service_type)
        req_info = _client_service.get_request_parameters(request_args=request_args)

        areq = req_info.get("request")
        headers = req_info.get("headers")

        _server_endpoint = self.server.get_endpoint(endpoint_type)
        if headers:
            argv = {"http_info": {"headers": headers}}
        else:
            argv = {}

        if areq:
            if _server_endpoint.request_format == "json":
                _pr_req = _server_endpoint.parse_request(areq.to_json(), **argv)
            else:
                _pr_req = _server_endpoint.parse_request(areq.to_urlencoded(), **argv)
        else:
            if areq is None:
                _pr_req = _server_endpoint.parse_request(areq)
            else:
                _pr_req = _server_endpoint.parse_request(areq, **argv)

        if is_error_message(_pr_req):
            return areq, _pr_req

        _resp = _server_endpoint.process_request(_pr_req)
        if is_error_message(_resp):
            return areq, _resp

        _response = _server_endpoint.do_response(**_resp)

        resp = _client_service.parse_response(_response["response"])
        _state = msg.get("state", "")
        _client_service.update_service_context(_resp["response_args"], key=_state)
        return {"request": areq, "response": resp}

    def server_metadata_request(self, msg):
        return {}

    def authorization_request(self, msg):
        # ***** Authorization Request **********
        _nonce = (rndstr(24),)
        _context = self.client.get_service_context()
        # Need a new state for a new authorization request
        _state = _context.cstate.create_state(iss=_context.get("issuer"))
        _context.cstate.bind_key(_nonce, _state)

        req_args = {"response_type": ["code"], "nonce": _nonce, "state": _state}

        scope = msg.get("scope")
        if scope:
            _scope = scope
        else:
            _scope = ["openid"]

        req_args["scope"] = _scope

        return req_args

    def accesstoken_request(self, msg):
        # ***** Token Request **********
        _context = self.client.get_service_context()

        auth_resp = msg["authorization"]["response"]
        req_args = {
            "code": auth_resp["code"],
            "state": auth_resp["state"],
            "redirect_uri": msg["authorization"]["request"]["redirect_uri"],
            "grant_type": "authorization_code",
            "client_id": self.client.get_client_id(),
            "client_secret": _context.get_usage("client_secret"),
        }

        return req_args

    def __call__(self, request_responses: List[list], **kwargs):
        msg = kwargs
        for request, response in request_responses:
            func = getattr(self, f"{request}_request")
            req_args = func(msg)
            msg[request] = self.do_query(request, response, req_args, msg)
        return msg


def test_pkce():
    server_conf = SERVER_CONF.copy()
    server_conf["add_ons"] = {
        "pkce": {
            "function": "idpyoidc.server.oauth2.add_on.pkce.add_support",
            "kwargs": {},
        },
    }
    server = Server(ASConfiguration(conf=server_conf, base_path=BASEDIR), cwd=BASEDIR)

    client_config = CLIENT_CONFIG.copy()
    client_config["add_ons"] = {
        "pkce": {
            "function": "idpyoidc.client.oauth2.add_on.pkce.add_support",
            "kwargs": {"code_challenge_length": 64, "code_challenge_method": "S256"},
        },
    }

    client = Client(
        client_type="oauth2",
        config=client_config,
        keyjar=build_keyjar(KEYDEFS),
        services=_OAUTH2_SERVICES,
    )

    server.context.cdb["client"] = CLIENT_CONFIG
    server.context.keyjar = import_jwks(server.context.keyjar, client.keyjar.export_jwks(), "client")

    server.context.set_provider_info()

    flow = Flow(client, server)
    msg = flow(
        [
            ["server_metadata", "server_metadata"],
            ["authorization", "authorization"],
            ["accesstoken", "token"],
        ],
        scope=["foobar"],
    )
    assert msg


def test_jar():
    server_conf = SERVER_CONF.copy()
    # server_conf['add_ons'] = {
    #     "jar": {
    #         "function": "idpyoidc.server.oauth2.add_on.jar.add_support",
    #         "kwargs": {},
    #     },
    # }
    server = Server(ASConfiguration(conf=server_conf, base_path=BASEDIR), cwd=BASEDIR)

    client_config = CLIENT_CONFIG.copy()
    client_config["add_ons"] = {
        "jar": {
            "function": "idpyoidc.client.oauth2.add_on.jar.add_support",
            "kwargs": {},
        },
    }

    client = Client(
        client_type="oauth2",
        config=client_config,
        keyjar=build_keyjar(KEYDEFS),
        services=_OAUTH2_SERVICES,
    )

    server.context.cdb["client"] = CLIENT_CONFIG
    server.context.keyjar = import_jwks(server.context.keyjar, client.keyjar.export_jwks(), "client")

    server.context.set_provider_info()

    flow = Flow(client, server)
    msg = flow(
        [["server_metadata", "server_metadata"], ["authorization", "authorization"]],
        scope=["foobar"],
    )

    assert msg
