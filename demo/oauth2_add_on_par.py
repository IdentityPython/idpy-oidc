#!/usr/bin/env python3

from common import BASEDIR
from common import KEYDEFS
from flow import Flow
from idpyoidc.client.oauth2 import Client
from idpyoidc.key_import import import_jwks
from idpyoidc.server import Server
from idpyoidc.server.configure import ASConfiguration
from oauth2_client_conf import CLIENT_CONFIG
from oauth2_client_conf import CLIENT_ID
from oauth2_server_conf import SERVER_CONF

# ================ Server side ===================================

server_conf = SERVER_CONF.copy()
server_conf["keys"] = {"uri_path": "jwks.json", "key_defs": KEYDEFS}
server_conf["token_handler_args"]["key_conf"] = {"key_defs": KEYDEFS}
server_conf['endpoint'] = {
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
    "pushed_authorization": {
        "path": "pushed_authorization",
        "class": "idpyoidc.server.oauth2.pushed_authorization.PushedAuthorization",
        "kwargs": {
            "client_authn_method": [
                "client_secret_post",
                "client_secret_basic",
                "client_secret_jwt",
                "private_key_jwt",
            ]
        },
    },
}

# The server knows how to deal with JAR without an add-on

server = Server(ASConfiguration(conf=server_conf, base_path=BASEDIR), cwd=BASEDIR)

# ================ Client side ===================================


client_conf = CLIENT_CONFIG.copy()
client_conf['issuer'] = SERVER_CONF['issuer']
client_conf['key_conf'] = {'key_defs': KEYDEFS}

client_conf['add_ons'] = {
    "par": {
        "function": "idpyoidc.client.oauth2.add_on.par.add_support",
        "kwargs": {
            'http_client': {
                'class': 'utils.EmulatePARCall'
            },
            'authn_method': 'client_secret_basic'
        }
    }
}

client = Client(config=client_conf)

# ==== What the server needs to know about the client.

server.context.cdb[CLIENT_ID] = {k: v for k, v in CLIENT_CONFIG.items() if k not in ['services']}
server.context.keyjar = import_jwks(server.context.keyjar, client.keyjar.export_jwks(), CLIENT_ID)

# Initiating the server's metadata

server.context.set_provider_info()

# ==== And now for the protocol exchange sequence

client.context.add_on['pushed_authorization']['http_client'].server = server

flow = Flow(client, server)
msg = flow(
    [
        ['server_metadata', 'server_metadata'],
        ['authorization', 'authorization']
    ],
    scope=['foobar'],
    server_jwks=server.keyjar.export_jwks(''),
    server_jwks_uri=server.context.provider_info['jwks_uri'],
)
