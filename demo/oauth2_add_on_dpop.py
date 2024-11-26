#!/usr/bin/env python3
import json

from common import BASEDIR
from common import KEYDEFS
from common import full_path
from flow import Flow
from idpyoidc.alg_info import get_signing_algs
from idpyoidc.client.oauth2 import Client
from idpyoidc.server import Server
from idpyoidc.server.configure import ASConfiguration
from idpyoidc.server.user_info import UserInfo
from oauth2_client_conf import CLIENT_CONFIG
from oauth2_client_conf import CLIENT_ID
from oauth2_server_conf import SERVER_CONF

# ================ Server side ===================================

USERINFO = UserInfo(json.loads(open(full_path("users.json")).read()))

server_conf = SERVER_CONF.copy()
server_conf["keys"] = {"uri_path": "jwks.json", "key_defs": KEYDEFS}
server_conf["token_handler_args"]["key_conf"] = {"key_defs": KEYDEFS}

server_conf['add_ons'] = {
    "dpop": {
        "function": "idpyoidc.server.oauth2.add_on.dpop.add_support",
        "kwargs": {
            'dpop_signing_alg_values_supported': get_signing_algs()
        }
    }
}

server = Server(ASConfiguration(conf=server_conf, base_path=BASEDIR), cwd=BASEDIR)

# ================ Client side ===================================

client_conf = CLIENT_CONFIG
client_conf['issuer'] = SERVER_CONF['issuer']
client_conf['key_conf'] = {'key_defs': KEYDEFS}

client_conf['add_ons'] = {
    "dpop": {
        "function": "idpyoidc.client.oauth2.add_on.dpop.add_support",
        "kwargs": {
            "dpop_signing_alg_values_supported": ["ES256"]
        }
    }
}

client = Client(config=client_conf)

# ==== What the server needs to know about the client.

server.context.cdb[CLIENT_ID] = {k: v for k, v in CLIENT_CONFIG.items() if k not in ['services']}
server.context.keyjar.import_jwks(client.keyjar.export_jwks(), CLIENT_ID)

# Initiating the Server's metadata

server.context.set_provider_info()

# ==== And now for the protocol exchange sequence

flow = Flow(client, server)
msg = flow(
    [
        ['server_metadata', 'server_metadata'],
        ['authorization', 'authorization'],
        ["accesstoken", 'token'],
    ],
    scope=['foobar'],
    server_jwks=server.keyjar.export_jwks(''),
    server_jwks_uri=server.context.provider_info['jwks_uri']
)
