#!/usr/bin/env python3
import os

from common import BASEDIR
from common import KEYDEFS
from flow import Flow
from idpyoidc.client.oidc import RP
from idpyoidc.server import OPConfiguration
from idpyoidc.server import Server
from oidc_client_conf import CLIENT_CONFIG
from oidc_client_conf import CLIENT_ID
from oidc_server_conf import SERVER_CONF


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


# ================ Server side ===================================

server_conf = SERVER_CONF.copy()
server_conf["key_conf"] = {"uri_path": "jwks.json", "key_defs": KEYDEFS}
server_conf["token_handler_args"]["key_conf"] = {"key_defs": KEYDEFS}

server = Server(OPConfiguration(conf=server_conf, base_path=BASEDIR), cwd=BASEDIR)

# ================ Client side ===================================

client_conf = CLIENT_CONFIG.copy()
client_conf['issuer'] = SERVER_CONF['issuer']
client_conf['key_conf'] = {'key_defs': KEYDEFS}
client_conf["allowed_scopes"] = ["foobar", "openid", 'offline_access']

client = RP(config=client_conf)

# ==== What the server needs to know about the client.

server.context.cdb[CLIENT_ID] = CLIENT_CONFIG
server.context.cdb[CLIENT_ID]['allowed_scopes'] = client_conf["allowed_scopes"]
server.context.keyjar.import_jwks(client.keyjar.export_jwks(), CLIENT_ID)

# Initiating the server's metadata

server.context.set_provider_info()

flow = Flow(client, server)
msg = flow(
    [
        ['provider_info', 'provider_config'],
        ['authorization', 'authorization'],
        ["accesstoken", 'token'],
        ['userinfo', 'userinfo']
    ],
    scope=['foobar', 'offline_access', 'email'],
    server_jwks=server.keyjar.export_jwks(''),
    server_jwks_uri=server.context.provider_info['jwks_uri']
)
