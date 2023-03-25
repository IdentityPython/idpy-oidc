#!/usr/bin/env python3
import json
import os

from cryptojwt.key_jar import build_keyjar

from flow import Flow
from idpyoidc.client.oidc import RP
from idpyoidc.server import Server
from idpyoidc.server.authz import AuthzHandling
from idpyoidc.server.client_authn import verify_client
from idpyoidc.server.configure import ASConfiguration
from idpyoidc.server.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from idpyoidc.server.user_info import UserInfo
from tests import CRYPT_CONFIG
from tests import SESSION_PARAMS

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


# ================ Server side ===================================

USERINFO = UserInfo(json.loads(open(full_path("users.json")).read()))

SERVER_CONF = {
    "issuer": "https://example.com/",
    "httpc_params": {"verify": False, "timeout": 1},
    "subject_types_supported": ["public", "pairwise", "ephemeral"],
    "keys": {"uri_path": "jwks.json", "key_defs": KEYDEFS},
    "endpoint": {
        "metadata": {
            "path": ".well-known/oauth-authorization-server",
            "class": "idpyoidc.server.oidc.provider_config.ProviderConfiguration",
            "kwargs": {},
        },
        "authorization": {
            "path": "authorization",
            "class": "idpyoidc.server.oidc.authorization.Authorization",
            "kwargs": {},
        },
        "token": {
            "path": "token",
            "class": "idpyoidc.server.oidc.token.Token",
            "kwargs": {},
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
        "key_conf": {"key_defs": KEYDEFS},
        "code": {
            "lifetime": 600,
            "kwargs": {
                "crypt_conf": CRYPT_CONFIG
            }
        },
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

server = Server(ASConfiguration(conf=SERVER_CONF, base_path=BASEDIR), cwd=BASEDIR)

# ================ Client side ===================================

OIDC_SERVICES = {
    "provider_info": {
        "class": "idpyoidc.client.oidc.provider_info_discovery.ProviderInfoDiscovery"},
    "authorization": {"class": "idpyoidc.client.oidc.authorization.Authorization"},
    "access_token": {"class": "idpyoidc.client.oidc.access_token.AccessToken"},
    'userinfo': {'class': "idpyoidc.client.oidc.userinfo.UserInfo"}
}

CLIENT_CONFIG = {
    "issuer": SERVER_CONF["issuer"],
    "client_secret": "SUPERhemligtlösenord",
    "client_id": "client",
    "redirect_uris": ["https://example.com/cb"],
    "token_endpoint_auth_methods_supported": ["client_secret_post"],
    "allowed_scopes": ["foobar", "openid"],
    "response_types_supported": ["code"]
}

client = RP(config=CLIENT_CONFIG,
            keyjar=build_keyjar(KEYDEFS),
            services=OIDC_SERVICES)

server.context.cdb["client"] = CLIENT_CONFIG
server.context.keyjar.import_jwks(
    client.keyjar.export_jwks(), "client")

# server.context.set_provider_info()

flow = Flow(client, server)
msg = flow(
    [
        ['provider_info', 'provider_config'],
        ['authorization', 'authorization'],
        ["accesstoken", 'token']
    ],
    scope=['foobar'],
    server_jwks=server.keyjar.export_jwks(''),
    server_jwks_uri=server.context.provider_info['jwks_uri']
)
