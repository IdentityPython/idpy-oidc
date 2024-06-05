import hashlib
import string

from idpyoidc.message.oidc import APPLICATION_TYPE_WEB

SUCCESSFUL = [200, 201, 202, 203, 204, 205, 206]

SERVICE_NAME = "OIC"
CLIENT_CONFIG = {}

DEFAULT_OIDC_SERVICES = {
    "discovery": {"class": "idpyoidc.client.oidc.provider_info_discovery.ProviderInfoDiscovery"},
    "registration": {"class": "idpyoidc.client.oidc.registration.Registration"},
    "authorization": {"class": "idpyoidc.client.oidc.authorization.Authorization"},
    "access_token": {"class": "idpyoidc.client.oidc.access_token.AccessToken"},
    "refresh_access_token": {
        "class": "idpyoidc.client.oidc.refresh_access_token.RefreshAccessToken"
    },
    "userinfo": {"class": "idpyoidc.client.oidc.userinfo.UserInfo"},
}

DEFAULT_OAUTH2_SERVICES = {
    "discovery": {"class": "idpyoidc.client.oauth2.server_metadata.ServerMetadata"},
    "authorization": {"class": "idpyoidc.client.oauth2.authorization.Authorization"},
    "access_token": {"class": "idpyoidc.client.oauth2.access_token.AccessToken"},
    "refresh_access_token": {
        "class": "idpyoidc.client.oauth2.refresh_access_token.RefreshAccessToken"
    },
}

DEFAULT_CLIENT_PREFERENCES = {
    "application_type": APPLICATION_TYPE_WEB,
    "response_types": [
        "code",
        "id_token",
        "code id_token",
    ],
    "token_endpoint_auth_method": "client_secret_basic",
    "scopes_supported": ["openid"],
}

DEFAULT_USAGE = {
    "jwks_uri": True,
    "scope": ["openid"],
}

# Using PKCE is default
DEFAULT_CLIENT_CONFIGS = {
    "": {
        "client_type": "oidc",
        "preference": DEFAULT_CLIENT_PREFERENCES,
        "add_ons": {
            "pkce": {
                "function": "idpyoidc.client.oauth2.add_on.pkce.add_support",
                "kwargs": {"code_challenge_length": 64, "code_challenge_method": "S256"},
            }
        },
    }
}

DEFAULT_KEY_DEFS = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

DEFAULT_RP_KEY_DEFS = {
    "private_path": "private/jwks.json",
    "key_defs": DEFAULT_KEY_DEFS,
    "public_path": "static/jwks.json",
    "read_only": False,
}

OIDCONF_PATTERN = "{}/.well-known/openid-configuration"
OAUTH2_SERVER_METADATA_URL = "{}/.well-known/oauth-authorization-server"

CC_METHOD = {
    "S256": hashlib.sha256,
    "S384": hashlib.sha384,
    "S512": hashlib.sha512,
}

# Map the signing context to a signing algorithm
DEF_SIGN_ALG = {
    "id_token": "RS256",
    "userinfo": "RS256",
    "request_object": "RS256",
    "client_secret_jwt": "HS256",
    "private_key_jwt": "RS256",
}

HTTP_ARGS = ["headers", "redirections", "connection_type"]

JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
SAML2_BEARER_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:saml2-bearer"

BASECHR = string.ascii_letters + string.digits

DEFAULT_RESPONSE_MODE = {
    "code": "query",
    "id_token": "fragment",
    "token": "fragment",
    "code token": "fragment",
    "code id_token": "fragment",
    "id_token token": "fragment",
    "code id_token token": "fragment",
}
