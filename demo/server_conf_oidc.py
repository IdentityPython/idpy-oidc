from idpyoidc.server.authz import AuthzHandling
from idpyoidc.server.client_authn import verify_client
from idpyoidc.server.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from tests import CRYPT_CONFIG
from tests import SESSION_PARAMS
from tests import full_path

SERVER_CONF = {
    "issuer": "https://example.com/",
    "httpc_params": {"verify": False, "timeout": 1},
    "subject_types_supported": ["public", "pairwise", "ephemeral"],
    "endpoint": {
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
        "userinfo": {
            "path": "userinfo",
            "class": "idpyoidc.server.oidc.userinfo.UserInfo",
            "kwargs": {
                "client_authn_method": ["bearer_header", "bearer_body"],
                "base_claims": {
                    "email": {"essential": True},
                    "email_verified": {"essential": True},
                }
            },
        }
    },
    "authentication": {
        "anon": {
            "acr": INTERNETPROTOCOLPASSWORD,
            "class": "idpyoidc.server.user_authn.user.NoAuthn",
            "kwargs": {"user": "diana"},
        }
    },
    "userinfo": {
        "class": "idpyoidc.server.user_info.UserInfo",
        "kwargs": {"db_file": full_path("users.json")},
    },
    "client_authn": verify_client,
    "authz": {
        "class": AuthzHandling,
        "kwargs": {
            "grant_config": {
                "usage_rules": {
                    "authorization_code": {
                        "supports_minting": ["access_token", "refresh_token", "id_token"],
                        "max_usage": 1,
                        "expires_in": 300
                    },
                    "access_token": {
                        "expires_in": 600,
                    },
                    "refresh_token": {
                        "supports_minting": ["access_token"],
                        "audience": ["https://example.com", "https://example2.com"],
                        "expires_in": 43200,
                    },
                },
                "expires_in": 43200,
            }
        },
    },
    "token_handler_args": {
        "code": {
            "kwargs": {
                "crypt_conf": CRYPT_CONFIG
            }
        },
        "token": {
            "class": "idpyoidc.server.token.jwt_token.JWTToken",
            "kwargs": {
                "add_claims_by_scope": True,
                "aud": ["https://example.org/appl"],
            },
        },
        "refresh": {
            "class": "idpyoidc.server.token.jwt_token.JWTToken",
            "kwargs": {
                "aud": ["https://example.org/appl"],
            },
        },
        "id_token": {
            "class": "idpyoidc.server.token.id_token.IDToken",
            "kwargs": {
                "lifetime": 86400,
                "add_claims_by_scope": True
            },
        }
    },
    "session_params": SESSION_PARAMS,
}
