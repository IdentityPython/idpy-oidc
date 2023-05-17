#!/usr/bin/env python3

from common import BASEDIR
from common import KEYDEFS
from common import SESSION_PARAMS
from common import full_path
from flow import Flow
from idpyoidc.client.oauth2 import Client
from idpyoidc.server import ASConfiguration
from idpyoidc.server import Server
from idpyoidc.server.authz import AuthzHandling
from idpyoidc.server.client_authn import verify_client
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
            },
        },
    },
    "token_handler_args": {
        "jwks_defs": {"key_defs": KEYDEFS},
        "token": {
            "class": "idpyoidc.server.token.jwt_token.JWTToken",
            "kwargs": {
                "lifetime": 3600,
                "add_claims_by_scope": True,
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
                    "access_token": {"expires_in": 3600}
                }
            }
        }
    },
    "session_params": {"encrypter": SESSION_PARAMS},
    "authentication": {
        "user": {
            "acr": "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword",
            "class": "idpyoidc.server.user_authn.user.UserPass",
            "kwargs": {
                "db_conf": {
                    "class": "idpyoidc.server.util.JSONDictDB",
                    "kwargs": {"filename": full_path("passwd.json")}
                }
            }
        }
    }
}

CLIENT_BASE_URL = "https://example.com"

CLIENT_CONFIG = {
    "client_id": "client_1",
    "client_secret": "another password",
    "base_url": CLIENT_BASE_URL,
    'services': {
        "resource_owner_password_credentials": {
            "class": "idpyoidc.client.oauth2.resource_owner_password_credentials"
                     ".ROPCAccessTokenRequest"
        }
    }
}

# Client side

client = Client(config=CLIENT_CONFIG)

ropc_service = client.get_service('resource_owner_password_credentials')
ropc_service.endpoint = "https://example.com/token"

# Server side

server = Server(ASConfiguration(conf=SERVER_CONFIG, base_path=BASEDIR), cwd=BASEDIR)
server.context.cdb["client_1"] = {
    "client_secret": "another password",
    "redirect_uris": [("https://example.com/cb", None)],
    "client_salt": "salted",
    "endpoint_auth_method": "client_secret_post",
    "response_types": ["code", "code id_token", "id_token"],
    "allowed_scopes": ["resourceA"],
}

flow = Flow(client, server)
msg = flow(
    [
        ["resource_owner_password_credentials", 'token']
    ],
    request_additions={
        'resource_owner_password_credentials': {'username': 'diana', 'password': 'krall'}
    }
)
