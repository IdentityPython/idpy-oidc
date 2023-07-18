#!/usr/bin/env python3
import os

from common import BASEDIR
from common import KEYDEFS
from flow import Flow
from idpyoidc.client.oidc import RP
from idpyoidc.server import OPConfiguration
from idpyoidc.server import Server
from oidc_client_conf import CLIENT_CONFIG
from oidc_server_conf import SERVER_CONF


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


# ================ Server side ===================================

server_conf = SERVER_CONF.copy()
server_conf["key_conf"] = {"uri_path": "jwks.json", "key_defs": KEYDEFS}
server_conf["token_handler_args"]["key_conf"] = {"key_defs": KEYDEFS}
server_conf["endpoint"] = {
    "provider_info": {
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
    },
    "registration": {
        "path": 'register',
        "class": "idpyoidc.server.oidc.registration.Registration"
    }
}

server = Server(OPConfiguration(conf=server_conf, base_path=BASEDIR), cwd=BASEDIR)

# ================ Client side ===================================

client_conf = CLIENT_CONFIG.copy()
client_conf['issuer'] = SERVER_CONF['issuer']
client_conf['key_conf'] = {'key_defs': KEYDEFS}
client_conf["allowed_scopes"] = ["foobar", "openid", 'offline_access']
client_conf['services'] = {
    "provider_info": {
        "class": "idpyoidc.client.oidc.provider_info_discovery.ProviderInfoDiscovery"},
    "register": {"class": "idpyoidc.client.oidc.registration.Registration"},
    "authorization": {"class": "idpyoidc.client.oidc.authorization.Authorization"},
    "access_token": {"class": "idpyoidc.client.oidc.access_token.AccessToken"},
}

client = RP(config=client_conf)

# Initiating the server's metadata

server.context.set_provider_info()

flow = Flow(client, server)
msg = flow(
    [
        ['provider_info', 'provider_config'],
        ['registration', 'registration'],
        ['authorization', 'authorization'],
        ["accesstoken", 'token']
    ],
    scope=['foobar'],
    server_jwks=server.keyjar.export_jwks(''),
    server_jwks_uri=server.context.provider_info['jwks_uri']
)
