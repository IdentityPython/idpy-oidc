#!/usr/bin/env python3

from common import BASEDIR
from common import KEYDEFS
from flow import Flow
from idpyoidc.client.oauth2 import Client
from idpyoidc.key_import import import_jwks
from idpyoidc.server import ASConfiguration
from idpyoidc.server import Server
from oauth2_client_conf import CLIENT_CONFIG
from oauth2_client_conf import CLIENT_ID
from oauth2_server_conf import SERVER_CONF

# ================ Server side ===================================

server_conf = SERVER_CONF.copy()
server_conf["keys"] = {"uri_path": "jwks.json", "key_defs": KEYDEFS}
server_conf["token_handler_args"]["key_conf"] = {"key_defs": KEYDEFS}
server_conf["authz"]["kwargs"] = {
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
}
server_conf['token_handler_args']["refresh"] = {
    "class": "idpyoidc.server.token.jwt_token.JWTToken",
    "kwargs": {
        "lifetime": 3600,
        "aud": ["https://example.org/appl"],
    }
}
server_conf['endpoint'] = {
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
}

server = Server(ASConfiguration(conf=server_conf, base_path=BASEDIR), cwd=BASEDIR)

# ================ Client side ===================================

client_conf = CLIENT_CONFIG.copy()
client_conf['issuer'] = SERVER_CONF['issuer']
client_conf['key_conf'] = {'key_defs': KEYDEFS}
client_conf["services"] = {
    "metadata": {"class": "idpyoidc.client.oauth2.server_metadata.ServerMetadata"},
    "authorization": {"class": "idpyoidc.client.oauth2.authorization.Authorization"},
    "access_token": {"class": "idpyoidc.client.oauth2.access_token.AccessToken"},
    'token_revocation': {
        'class': 'idpyoidc.client.oauth2.token_revocation.TokenRevocation'
    },
    'introspection': {
        'class': 'idpyoidc.client.oauth2.introspection.Introspection'
    }
}
client_conf["allowed_scopes"] = ["profile", "offline_access", "foobar"]

client = Client(config=client_conf)

# ==== What the server needs to know about the client.

server.context.cdb[CLIENT_ID] = {k: v for k, v in CLIENT_CONFIG.items() if k not in ['services']}
server.context.cdb[CLIENT_ID]['allowed_scopes'] = client_conf['allowed_scopes']

server.context.keyjar = import_jwks(server.context.keyjar, client.keyjar.export_jwks(), CLIENT_ID)

# Initiating the server's metadata

server.context.set_provider_info()

# ------- tell the server about the client ----------------

flow = Flow(client, server)
msg = flow(
    [
        ['server_metadata', 'server_metadata'],
        ['authorization', 'authorization'],
        ["accesstoken", 'token'],
        ['introspection', 'introspection'],
        ['token_revocation', 'token_revocation'],
        ['introspection', 'introspection'],
    ],
    scope=['foobar'],
    server_jwks=server.keyjar.export_jwks(''),
    server_jwks_uri=server.context.provider_info['jwks_uri']
)
