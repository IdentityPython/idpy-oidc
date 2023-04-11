#!/usr/bin/env python3
import json
import os

from cryptojwt.key_jar import build_keyjar

from demo.client_conf_oidc import CLIENT_CONFIG
from demo.server_conf_oidc import SERVER_CONF
from flow import Flow
from idpyoidc.client.oidc import RP
from idpyoidc.server import OPConfiguration
from idpyoidc.server import Server
from idpyoidc.server.authz import AuthzHandling
from idpyoidc.server.client_authn import verify_client
from idpyoidc.server.configure import ASConfiguration
from idpyoidc.server.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from idpyoidc.server.user_info import UserInfo

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

BASEDIR = os.path.abspath(os.path.dirname(__file__))


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
client_conf["allowed_scopes"] =  ["foobar", "openid", 'offline_access']

client = RP(config=client_conf)

# ==== What the server needs to know about the client.

server.context.cdb["client"] = CLIENT_CONFIG
server.context.cdb["client"]['allowed_scopes'] = client_conf["allowed_scopes"]
server.context.keyjar.import_jwks(
    client.keyjar.export_jwks(), "client")

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
