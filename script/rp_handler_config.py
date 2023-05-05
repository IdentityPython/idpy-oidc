#!/usr/bin/env python3
import json
import sys

from cryptojwt.utils import qualified_name

from idpyoidc.client.configure import RPHConfiguration
from idpyoidc.client.rp_handler import RPHandler
from idpyoidc.configure import create_from_config_file


def display(rp, id):
    print(10 * '*' + " "+ id+ " " + 10 * '*')
    print(10 * '=' + "CLIENT" + 10 * '=')
    _context = rp.client_get("service_context")
    _info = {
        "base_url": _context.base_url,
        "httpc_params": _context.httpc_params,
    }
    if rp.extra:
        _info["extras"] = rp.extra
    print(json.dumps(_info, indent=4, sort_keys=True))

    print(10 * '=' + "GLOBAL METADATA" + 10 * '=')
    print(json.dumps(_context.metadata, indent=4, sort_keys=True))

    print(10 * '=' + "GLOBAL USAGE" + 10 * '=')
    print(json.dumps(_context.usage, indent=4, sort_keys=True))

    print(10 * '=' + "SERVICES" + 10 * '=')
    _info = {}
    _services = rp.client_get("services")
    for srv, item in _services.db.items():
        _data = {"class": qualified_name(item.__class__)}
        for attr in ["claims", "usage", "default_request_args", "callback_uri"]:
            _val = getattr(item, attr)
            if _val:
                _data[attr] = _val
        _info[srv] = _data
    print(json.dumps(_info, indent=4, sort_keys=True))

    if _context.add_on:
        print(10 * '=' + "ADD_ON" + 10 * '=')
        print(json.dumps(_context.add_on, indent=4, sort_keys=True))


configuration = create_from_config_file(RPHConfiguration, filename=sys.argv[1])
rp_handler = RPHandler(config=configuration)
rp = rp_handler.init_client('flask_provider')
display(rp, "flask_provider")
