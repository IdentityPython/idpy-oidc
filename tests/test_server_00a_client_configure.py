import json
import os

from idpyoidc.server import OPConfiguration
from idpyoidc.server import Server
from idpyoidc.server.client_configure import verify_oidc_client_information
from idpyoidc.util import load_config_file
from tests import full_path

BASEDIR = os.path.abspath(os.path.dirname(__file__))

EXTRA = {
    "token_usage_rules": {
        "authorization_code": {
            "expires_in": 600,
            "supports_minting": ["access_token", "refresh_token"],
        },
        "refresh_token": {"supports_minting": ["access_token"]},
    },
    "revoke_refresh_on_issue": True,
    "token_exchange": {
        "urn:ietf:params:oauth:grant-type:token-exchange": {
            "class": "idpyoidc.server.oidc.token.TokenExchangeHelper",
            "kwargs": {
                "subject_token_types_supported": [
                    "urn:ietf:params:oauth:token-type:access_token",
                    "urn:ietf:params:oauth:token-type:refresh_token",
                    "urn:ietf:params:oauth:token-type:id_token",
                ],
                "requested_token_types_supported": [
                    "urn:ietf:params:oauth:token-type:access_token",
                    "urn:ietf:params:oauth:token-type:refresh_token",
                    "urn:ietf:params:oauth:token-type:id_token",
                ],
                "policy": {
                    "urn:ietf:params:oauth:token-type:access_token": {
                        "callable": "/path/to/callable",
                        "kwargs": {"audience": ["https://example.com"], "scopes": ["openid"]},
                    },
                    "urn:ietf:params:oauth:token-type:refresh_token": {
                        "callable": "/path/to/callable",
                        "kwargs": {"resource": ["https://example.com"], "scopes": ["openid"]},
                    },
                    "": {"callable": "/path/to/callable", "kwargs": {"scopes": ["openid"]}},
                },
            },
        },
        "allowed_scopes": ["scope"],
        "scopes_to_claims": {"scope_a": ["claim1", "claim2"], "scope_b": []},
        "add_claims": {
            "always": {
                "userinfo": ["email", "phone"],
                # Always add "email" and "phone" in the userinfo response if such claims exists
                "id_token": {"email": None},
                # Always add "email" in the id_token if such a claim exists
                "introspection": {"email": {"value": "a@a.com"}},
                # Add "email" in the introspection response only if its value is "a@a.com"
            },
            "by_scope": {
                "id_token": False,
            },
        },
    },
}


def test_op_configure_oidc_clients_simple():
    _str = open(full_path(full_path("op_config.json"))).read()
    _conf = json.loads(_str)
    _conf["oidc_clients"] = {
        "client1": {
            "client_id": "client1",
            "client_secret": "Namnam",
            "redirect_uris": ["https://openidconnect.net/callback", ""],
            "response_types": ["code"],
        },
        "client2": {
            "client_id": "client2",
            "client_secret": "spraket",
            "redirect_uris": ["https://app1.example.net/foo", "https://app2.example.net/bar"],
            "response_types": ["code"],
        },
        "client3": {
            "client_id": "client3",
            "client_secret": "2222222222222222222222222222222222222222",
            "redirect_uris": ["https://127.0.0.1:8090/authz_cb/bobcat"],
            "post_logout_redirect_uri": "https://openidconnect.net/",
            "response_types": ["code"],
        },
    }

    op_conf = OPConfiguration(conf=_conf, base_path=BASEDIR)
    assert op_conf


def test_verify_oidc_client_information_complext():
    _conf = load_config_file(full_path("op_config.json"))
    server = Server(OPConfiguration(conf=_conf, base_path=BASEDIR))

    client_conf = {
        "client1": {
            "client_id": "client1",
            "client_secret": "Namnam",
            "redirect_uris": ["https://openidconnect.net/callback", ""],
            "response_types": ["code"],
        }
    }

    client_conf["client1"].update(EXTRA)

    res = verify_oidc_client_information(client_conf, server_get=server.server_get)
    assert res
    for cli, _cli_conf in res.items():
        print(_cli_conf.extra())


def test_verify_oidc_client_information_2():
    _conf = load_config_file(full_path("op_config.json"))
    server = Server(OPConfiguration(conf=_conf, base_path=BASEDIR), cwd=full_path(""))

    client_conf = {
        "client1": {
            "client_id": "client1",
            "client_secret": "Namnam",
            "redirect_uris": ["https://openidconnect.net/callback", ""],
            "response_types": ["code"],
            "token_usage_rules": {
                "authorization_code": {
                    "expires_in": 600,
                    "supports_minting": ["access_token", "refresh_token"],
                },
                "refresh_token": {"supports_minting": ["access_token"]},
                "dummy_token": {"supports_minting": ["foobar_token"]},
            },
        }
    }

    res = verify_oidc_client_information(client_conf, server_get=server.server_get)
    assert res
