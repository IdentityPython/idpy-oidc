import os
from urllib.parse import urlparse

from flask.app import Flask

from idpyoidc.server import Server

folder = os.path.dirname(os.path.realpath(__file__))

def init_oidc_op(app):
    _op_config = app.srv_config

    server = Server(_op_config, cwd=folder)

    server.context.cdb = {"myclient":{
        "client_secret": "CYpBPBiWF5jUtEB1difPkQiKEe9M3afi",
        "allowed_scopes": [
            'openid',
            'offline_access',
            'one-time-password-sms:send-validate',
            'serviceregistry',
            'qod-sessions-write',
            'mc_vm_match_hash',
            'serviceprofile:write',
            'microprofile-jwt',
            'fed-mgmt',
            'edge:serviceprofile:write',
            'qod-sessions-read',
            'discovery',
            'number-verification-verify-read',
            'number-verification-share-read',
            'edge:serviceprofile:read',
            'serviceregistry:write',
            'net-resources',
            'edge:discovery:read',
            "qod-sessions-delete'",
            'discovery:read',
            'mc_atp',
            'carrier-billing-checkout-purchase-digital-good-user-write',
            'edge:traffic-influences:read',
            'edge:traffic-influences:write',
            'device-location-read',
            'carrier-billing-checkout-user-notifications',
            'serviceprofile:read',
            'carrier-billing-checkout-purchase-digital-good-user-read',
            'mc_vm_match',
            'edge:serviceregistry:write',
            'serviceregistry:read',
            'device-status-roaming-read',
            'qod-profiles-read',
            'carrier-billing-checkout-payment-user-write',
            'edge:serviceregistry:read',
            'retrieve-sim-swap-date',
            'check-sim-swap',
            'serviceprofile',
            'nbi-mgmt'
        ],
        "redirect_uris": [("http://ktopenlab.iptime.org:5000/oauth/authorize", None), 
                          ("http://localhost:5000/kc/callback", None),
                          ],
        "client_salt": "salted",
        "endpoint_auth_method": "client_secret_post",
        "response_types_supported": ["code", "code id_token", "id_token"],
    }}


    for endp in server.endpoint.values():
        p = urlparse(endp.endpoint_path)
        _vpath = p.path.split('/')
        if _vpath[0] == '':
            endp.vpath = _vpath[1:]
        else:
            endp.vpath = _vpath

    return server


def oidc_provider_init_app(op_config, name=None, **kwargs):
    name = name or __name__
    app = Flask(name, static_url_path='', **kwargs)
    app.srv_config = op_config

    try:
        from .views import oidc_op_views
    except ImportError:
        from views import oidc_op_views
    app.register_blueprint(oidc_op_views)

    # Initialize the oidc_provider after views to be able to set correct urls
    app.server = init_oidc_op(app)

    return app
