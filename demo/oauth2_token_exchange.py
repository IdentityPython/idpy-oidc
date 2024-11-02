#!/usr/bin/env python3
import os

from flow import Flow
from idpyoidc.client.oauth2 import Client
from idpyoidc.key_import import import_jwks
from idpyoidc.server import Server
from idpyoidc.server.configure import ASConfiguration
from oauth2_client_conf import CLIENT_CONFIG
from oauth2_client_conf import CLIENT_ID
from oauth2_server_conf import SERVER_CONF

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


# ================ Server side ===================================

server_conf = SERVER_CONF.copy()
server_conf["keys"] = {"uri_path": "jwks.json", "key_defs": KEYDEFS}
server_conf["token_handler_args"]["key_conf"] = {"key_defs": KEYDEFS}
server_conf["authz"]["kwargs"]["grant_config"]["usage_rules"]["access_token"] = {
    "supports_minting": ["access_token"],
    "expires_in": 600,
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
    "token_exchange": {"class": "idpyoidc.client.oauth2.token_exchange.TokenExchange"}
}
client_conf["allowed_scopes"] = ["foobar"]

client = Client(config=client_conf)

# ==== What the server needs to know about the client.

server.context.cdb[CLIENT_ID] = {k: v for k, v in CLIENT_CONFIG.items() if k not in ['services']}
server.context.cdb[CLIENT_ID]['allowed_scopes'] = client_conf['allowed_scopes']

server.context.keyjar = import_jwks(server.context.keyjar, client.keyjar.export_jwks(), CLIENT_ID)

# Initiating the server's metadata

server.context.set_provider_info()

# ==== And now for the protocol exchange sequence

flow = Flow(client, server)
msg = flow(
    [
        ['server_metadata', 'server_metadata'],
        ['authorization', 'authorization'],
        ["accesstoken", 'token'],
        ['token_exchange', 'token']
    ],
    scope=['foobar'],
    server_jwks=server.keyjar.export_jwks(''),
    server_jwks_uri=server.context.provider_info['jwks_uri'],
    request_additions={
        'authorization': {'scope': 'foobar'}
    }
)
