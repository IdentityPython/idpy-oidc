#!/usr/bin/env python3
import os
import sys

from cryptojwt.utils import importer
from fedservice.combo import FederationCombo
from fedservice.utils import make_federation_combo

from idpyoidc.client.util import lower_or_upper
from idpyoidc.logging import configure_logging
from idpyoidc.ssl_context import create_context
from idpyoidc.util import load_config_file

dir_path = os.path.dirname(os.path.realpath(__file__))

template_dir = os.path.join(dir_path, 'templates')

import os
from urllib.parse import urlparse

from flask.app import Flask

from idpyoidc.server import Server


def init_oidc_op(app):
    _op_config = app.srv_config

    server = Server(_op_config, cwd=dir_path)

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


def init_app(dir_name, **kwargs) -> Flask:
    name = dir_name or __name__
    app = Flask(name, static_url_path='', **kwargs)
    sys.path.insert(0, dir_path)

    entity = importer(f"{dir_name}.views.entity")
    app.register_blueprint(entity)

    # Initialize the oidc_provider after views to be able to set correct urls
    app.cnf = load_config_file(f"{dir_name}/conf.json")
    app.cnf["cwd"] = dir_path
    app = oidc_provider_init_app(config.op, 'oidc_op')
    app.server = make_federation_combo(**app.cnf["entity"])
    if isinstance(app.server, FederationCombo):
        app.federation_entity = app.server["federation_entity"]
    else:
        app.federation_entity = app.server

    return app


if __name__ == "__main__":
    print(sys.argv)
    directory_name = sys.argv[1]
    template_dir = os.path.join(dir_path, 'templates')
    app = init_app(directory_name, template_folder=template_dir)
    if "logging" in app.cnf:
        configure_logging(config=app.cnf["logging"])
    _web_conf = app.cnf["webserver"]
    context = create_context(dir_path, _web_conf)
    _cert = "{}/{}".format(dir_path, lower_or_upper(_web_conf, "server_cert"))

    print('Listening on {}:{}'.format(_web_conf.get('domain'), _web_conf.get('port')))
    # app.rph.federation_entity.collector.web_cert_path = _cert
    app.run(host=_web_conf.get('domain'), port=_web_conf.get('port'),
            debug=_web_conf.get("debug"), ssl_context=context)
