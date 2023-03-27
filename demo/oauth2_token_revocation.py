#!/usr/bin/env python3
import os

from cryptojwt.key_jar import build_keyjar

from flow import Flow
from idpyoidc.client.oauth2 import Client
from idpyoidc.server import ASConfiguration
from idpyoidc.server import Server
from idpyoidc.server.authz import AuthzHandling
from idpyoidc.server.client_authn import verify_client
from idpyoidc.server.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from idpyoidc.server.user_info import UserInfo
from tests import CRYPT_CONFIG
from tests import SESSION_PARAMS

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]
BASEDIR = os.path.abspath(os.path.dirname(__file__))

server_conf = {
    "issuer": "https://example.com/",
    "httpc_params": {"verify": False, "timeout": 1},
    "subject_types_supported": ["public", "pairwise", "ephemeral"],
    "keys": {"uri_path": "jwks.json", "key_defs": KEYDEFS},
    "endpoint": {
        'discovery': {
            'path': "/.well-known/oauth-authorization-server",
            'class': "idpyoidc.server.oauth2.server_metadata.ServerMetadata",
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
        "token_revocation": {
            'path': 'revocation',
            "class": "idpyoidc.server.oauth2.token_revocation.TokenRevocation",
            "kwargs": {},
        },
        'introspection': {
            'path': 'introspection',
            'class': "idpyoidc.server.oauth2.introspection.Introspection"
        }
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
    "template_dir": "template",
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
        "keys": {"uri_path": "jwks.json", "key_defs": KEYDEFS},
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
}
server = Server(ASConfiguration(conf=server_conf, base_path=BASEDIR), cwd=BASEDIR)

# -------------- Client -----------------------

client_conf = {
    "redirect_uris": ["https://example.com/cli/code_cb"],
    "client_id": "client_1",
    "client_secret": "abcdefghijklmnop",
    'issuer': 'https://example.com/',
    "response_types_supported": ["code"],
}
services = {
    "server_metadata": {"class": "idpyoidc.client.oauth2.server_metadata.ServerMetadata"},
    "authorization": {"class": "idpyoidc.client.oauth2.authorization.Authorization"},
    "access_token": {"class": "idpyoidc.client.oauth2.access_token.AccessToken"},
    'token_revocation': {
        'class': 'idpyoidc.client.oauth2.token_revocation.TokenRevocation'
    },
    'introspection': {
        'class': 'idpyoidc.client.oauth2.introspection.Introspection'
    }
}

client = Client(config=client_conf, keyjar=build_keyjar(KEYDEFS), services=services)

# ------- tell the server about the client ----------------
server.context.cdb["client_1"] = client_conf
server.context.keyjar.import_jwks(client.keyjar.export_jwks(), "client_1")

flow = Flow(client, server)
msg = flow(
    [
        ['server_metadata', 'server_metadata'],
        ['authorization', 'authorization'],
        ["accesstoken", 'token'],
        ['introspection', 'introspection'],
        ['token_revocation','token_revocation'],
        ['introspection', 'introspection'],
    ],
    scope=['foobar'],
    server_jwks=server.keyjar.export_jwks(''),
    server_jwks_uri=server.context.provider_info['jwks_uri']
)

