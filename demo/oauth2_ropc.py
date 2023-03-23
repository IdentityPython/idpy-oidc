import json
import os

from idpyoidc.client.oauth2 import Client

from idpyoidc.server import Server
from idpyoidc.server.authz import AuthzHandling
from idpyoidc.server.client_authn import verify_client
from idpyoidc.server.configure import ASConfiguration
from idpyoidc.server.oauth2.token import Token
from idpyoidc.server.user_info import UserInfo

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]
CRYPT_CONFIG = {
    "kwargs": {
        "keys": {
            "key_defs": [
                {"type": "OCT", "use": ["enc"], "kid": "password"},
                {"type": "OCT", "use": ["enc"], "kid": "salt"},
            ]
        },
        "iterations": 1,
    }
}

SESSION_PARAMS = {"encrypter": CRYPT_CONFIG}

CONFIG = {
    "issuer": "https://example.net/",
    "httpc_params": {"verify": False},
    "preference": {
        "grant_types_supported": ["client_credentials", "password"]
    },
    "keys": {"uri_path": "jwks.json", "key_defs": KEYDEFS, 'read_only': False},
    "token_handler_args": {
        "jwks_defs": {"key_defs": KEYDEFS},
        "token": {
            "class": "idpyoidc.server.token.jwt_token.JWTToken",
            "kwargs": {
                "lifetime": 3600,
                "add_claims_by_scope": True,
                "aud": ["https://example.org/appl"],
            }
        }
    },
    "endpoint": {
        "token": {
            "path": "token",
            "class": Token,
            "kwargs": {
                "client_authn_method": ["client_secret_basic", "client_secret_post"],
                # "grant_types_supported": ['client_credentials', 'password']
            },
        },
    },
    "client_authn": verify_client,
    "claims_interface": {
        "class": "idpyoidc.server.session.claims.OAuth2ClaimsInterface",
        "kwargs": {},
    },
    "authz": {
        "class": AuthzHandling,
        "kwargs": {
            "grant_config": {
                "usage_rules": {
                    "authorization_code": {
                        "expires_in": 300,
                        "supports_minting": ["access_token", "refresh_token"],
                        "max_usage": 1,
                    },
                    "access_token": {"expires_in": 600},
                    "refresh_token": {
                        "expires_in": 86400,
                        "supports_minting": ["access_token", "refresh_token"],
                    },
                },
                "expires_in": 43200,
            }
        },
    },
    "session_params": {"encrypter": SESSION_PARAMS},
    "userinfo": {"class": UserInfo, "kwargs": {"db": {}}},
    "authentication": {
        "user": {
            "acr": "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword",
            "class": "idpyoidc.server.user_authn.user.UserPass",
            "kwargs": {
                "db_conf": {
                    "class": "idpyoidc.server.util.JSONDictDB",
                    "kwargs": {"filename": full_path("passwd.json")}
                }
            }
        }
    }
}

CLIENT_BASE_URL = "https://example.com"

CLIENT_CONFIG = {
    "client_id": "client_1",
    "client_secret": "another password",
    "base_url": CLIENT_BASE_URL
}
CLIENT_SERVICES = {
    "resource_owner_password_credentials": {
        "class": "idpyoidc.client.oauth2.resource_owner_password_credentials.ROPCAccessTokenRequest"
    }
}


# Client side

client = Client(config=CLIENT_CONFIG, services=CLIENT_SERVICES)

ropc_service = client.get_service('resource_owner_password_credentials')
ropc_service.endpoint = "https://example.com/token"

client_request_info = ropc_service.get_request_parameters(
    request_args={'username': 'diana', 'password': 'krall'}
)

# Server side

server = Server(ASConfiguration(conf=CONFIG, base_path=BASEDIR), cwd=BASEDIR)
server.context.cdb["client_1"] = {
    "client_secret": "another password",
    "redirect_uris": [("https://example.com/cb", None)],
    "client_salt": "salted",
    "endpoint_auth_method": "client_secret_post",
    "response_types": ["code", "code id_token", "id_token"],
    "allowed_scopes": ["resourceA"],
    # "grant_types_supported": ['client_credentials', 'password']
}

token_endpoint = server.get_endpoint("token")
request = token_endpoint.parse_request(client_request_info['request'])
print(request)
print(json.dumps(request.to_dict(), indent=4, sort_keys=True))

_resp = token_endpoint.process_request(request)
_response = token_endpoint.do_response(**_resp)

resp = ropc_service.parse_response(_response["response"])
print(json.dumps(resp.to_dict(), indent=4, sort_keys=True))