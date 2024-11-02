#!/usr/bin/env python3

from common import BASEDIR
from common import CRYPT_CONFIG
from common import KEYDEFS
from flow import Flow
from idpyoidc.client.oidc import RP
from idpyoidc.key_import import import_jwks
from idpyoidc.server import OPConfiguration
from idpyoidc.server import Server
from oidc_client_conf import CLIENT_CONFIG
from oidc_client_conf import CLIENT_ID
from oidc_server_conf import SERVER_CONF

# ================ Server side ===================================

server_conf = SERVER_CONF.copy()
server_conf["key_conf"] = {"uri_path": "jwks.json", "key_defs": KEYDEFS}
server_conf["token_handler_args"]["key_conf"] = {"key_defs": KEYDEFS}

del server_conf['endpoint']['userinfo']

server_conf['authz']['kwargs'] = {
    "grant_config": {
        "usage_rules": {
            "authorization_code": {
                "supports_minting": ["access_token"],
                "max_usage": 1,
                "expires_in": 300
            },
            "access_token": {
                "expires_in": 600,
            }
        }
    }
}

server_conf['token_handler_args'] = {
    "code": {
        "lifetime": 600,
        "kwargs": {
            "crypt_conf": CRYPT_CONFIG
        }
    },
    "token": {
        "class": "idpyoidc.server.token.jwt_token.JWTToken",
        "kwargs": {
            "add_claims_by_scope": True,
            "aud": ["https://example.org/appl"],
        },
    },
    "id_token": {
        "class": "idpyoidc.server.token.id_token.IDToken",
        "kwargs": {
            "lifetime": 86400,
            "add_claims_by_scope": True
        }
    }
}

server = Server(OPConfiguration(conf=server_conf, base_path=BASEDIR), cwd=BASEDIR)

# ================ Client side ===================================

client_conf = CLIENT_CONFIG.copy()
client_conf['issuer'] = SERVER_CONF['issuer']
client_conf['key_conf'] = {'key_defs': KEYDEFS}
client_conf["allowed_scopes"] = ["foobar", "openid", 'offline_access']
client_conf["response_types_supported"] = ["code id_token"]

client = RP(config=client_conf)

# ==== What the server needs to know about the client.

server.context.cdb[CLIENT_ID] = CLIENT_CONFIG
for claim in ['allowed_scopes', 'response_types_supported']:
    server.context.cdb["client"][claim] = client_conf[claim]

server.context.keyjar = import_jwks(server.context.keyjar, client.keyjar.export_jwks(), CLIENT_ID)

# Initiating the server's metadata

server.context.set_provider_info()

flow = Flow(client, server)
msg = flow(
    [
        ['provider_info', 'provider_config'],
        ['authorization', 'authorization'],
        ["accesstoken", 'token']
    ],
    scope=['foobar'],
    server_jwks=server.keyjar.export_jwks(''),
    server_jwks_uri=server.context.provider_info['jwks_uri'],
    response_type=['code id_token']
)
