#!/usr/bin/env python3
"""
Displaying how Client Credentials works
"""

from common import BASEDIR
from common import KEYDEFS
from common import SESSION_PARAMS
from flow import Flow
from idpyoidc.client.oauth2 import Client
from idpyoidc.server import Server
from idpyoidc.server.authz import AuthzHandling
from idpyoidc.server.client_authn import verify_client
from idpyoidc.server.configure import ASConfiguration
from idpyoidc.server.oauth2.token import Token

SERVER_CONFIG = {
    "issuer": "https://example.net/",
    "httpc_params": {"verify": False},
    "preference": {
        "grant_types_supported": ["client_credentials", "password"]
    },
    "keys": {"uri_path": "jwks.json", "key_defs": KEYDEFS, 'read_only': False},
    "endpoint": {
        "token": {
            "path": "token",
            "class": Token,
            "kwargs": {
                "client_authn_method": ["client_secret_basic", "client_secret_post"],
            }
        }
    },
    "token_handler_args": {
        "jwks_defs": {"key_defs": KEYDEFS},
        "token": {
            "class": "idpyoidc.server.token.jwt_token.JWTToken",
            "kwargs": {
                "lifetime": 3600,
                "aud": ["https://example.org/appl"],
            }
        }
    },
    "client_authn": verify_client,
    "claims_interface": {
        "class": "idpyoidc.server.session.claims.OAuth2ClaimsInterface",
        "kwargs": {},
    },
    "authz": {
        "class": AuthzHandling,
        "kwargs": {
            "grant_config": {
                "usage_rules": {
                    "access_token": {},
                }
            }
        },
    },
    "session_params": {"encrypter": SESSION_PARAMS},
}

CLIENT_CONFIG = {
    "client_id": "client_1",
    "client_secret": "another password",
    "base_url": "https://example.com",
    'services': {
        "client_credentials": {
            "class": "idpyoidc.client.oauth2.client_credentials.CCAccessTokenRequest"
        }
    }
}

# Client side

client = Client(config=CLIENT_CONFIG)

client_credentials_service = client.get_service('client_credentials')
client_credentials_service.endpoint = "https://example.com/token"

# Server side

server = Server(ASConfiguration(conf=SERVER_CONFIG, base_path=BASEDIR), cwd=BASEDIR)
server.context.cdb["client_1"] = {
    "client_secret": CLIENT_CONFIG['client_secret'],
    "allowed_scopes": ["resourceA"],
}

flow = Flow(client, server)
msg = flow(
    [
        ["client_credentials", 'token']
    ]
)
