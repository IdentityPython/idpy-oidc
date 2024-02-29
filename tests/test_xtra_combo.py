import json
import os

from idpyoidc.combo import Combo
from idpyoidc.server import ASConfiguration
from idpyoidc.server.configure import OPConfiguration
from idpyoidc.server.oauth2.authorization import Authorization
from tests import CRYPT_CONFIG
from tests import SESSION_PARAMS

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


USERINFO_db = json.loads(open(full_path("users.json")).read())

CONF = {
    "entity": {
        "httpc_params": {
            "verify": False
        },
        "keys": {
            "private_path": "private/jwks.json",
            "key_defs": [
                {
                    "type": "RSA",
                    "use": [
                        "sig"
                    ]
                },
                {
                    "type": "EC",
                    "crv": "P-256",
                    "use": [
                        "sig"
                    ]
                }
            ],
            "public_path": "static/jwks.json",
            "read_only": False,
            "uri_path": "static/jwks.json"
        },
        "entity_id": "https://127.0.0.1",
        "openid_provider": {
            "class": "idpyoidc.server.Server",
            "kwargs": {
                "server_type": "oidc",
                "conf": {
                    "add_on": {
                        "pkce": {
                            "function": "idpyoidc.server.oauth2.add_on.pkce.add_support",
                            "kwargs": {
                                "essential": False,
                                "code_challenge_method": "S256 S384 S512"
                            }
                        }
                    },
                    "authz": {
                        "class": "idpyoidc.server.authz.AuthzHandling",
                        "kwargs": {
                            "grant_config": {
                                "usage_rules": {
                                    "authorization_code": {
                                        "supports_minting": [
                                            "access_token",
                                            "refresh_token",
                                            "id_token"
                                        ],
                                        "max_usage": 1
                                    },
                                    "access_token": {},
                                    "refresh_token": {
                                        "supports_minting": [
                                            "access_token",
                                            "refresh_token"
                                        ]
                                    }
                                },
                                "expires_in": 43200
                            }
                        }
                    },
                    "authentication": {
                        "user": {
                            "acr":
                                "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword",
                            "class": "idpyoidc.server.user_authn.user.UserPassJinja2",
                            "kwargs": {
                                "verify_endpoint": "/verify/user",
                                "template": "user_pass.jinja2",
                                "db": {
                                    "class": "idpyoidc.server.util.JSONDictDB",
                                    "kwargs": {
                                        "filename": full_path("passwd.json")
                                    }
                                },
                                "page_header": "Testing log in",
                                "submit_btn": "Get me in!",
                                "user_label": "Nickname",
                                "passwd_label": "Secret sauce"
                            }
                        }
                    },
                    "preference": {
                        "subject_types_supported": [
                            "public",
                            "pairwise"
                        ],
                        "grant_types_supported": [
                            "authorization_code",
                            "implicit",
                            "urn:ietf:params:oauth:grant-type:jwt-bearer",
                            "refresh_token"
                        ]
                    },
                    "claims_interface": {
                        "class": "idpyoidc.server.session.claims.ClaimsInterface",
                        "kwargs": {}
                    },
                    "endpoint": {
                        "provider_info": {
                            "path": ".well-known/openid-configuration",
                            "class":
                                "idpyoidc.server.oidc.provider_config.ProviderConfiguration",
                            "kwargs": {
                                "client_authn_method": None
                            }
                        },
                        "authorization": {
                            "path": "authorization",
                            "class": "idpyoidc.server.oidc.authorization.Authorization",
                            "kwargs": {
                                "client_authn_method": None,
                                "claims_parameter_supported": True,
                                "request_parameter_supported": True,
                                "request_uri_parameter_supported": True,
                                "response_types_supported": [
                                    "code",
                                    "id_token",
                                    "code id_token"
                                ],
                                "response_modes_supported": [
                                    "query",
                                    "fragment",
                                    "form_post"
                                ]
                            }
                        },
                        "token": {
                            "path": "token",
                            "class": "idpyoidc.server.oidc.token.Token",
                            "kwargs": {
                                "client_authn_method": [
                                    "client_secret_post",
                                    "client_secret_basic",
                                    "client_secret_jwt",
                                    "private_key_jwt"
                                ]
                            }
                        },
                        "userinfo": {
                            "path": "userinfo",
                            "class": "idpyoidc.server.oidc.userinfo.UserInfo",
                            "kwargs": {
                                "claim_types_supported": [
                                    "normal",
                                    "aggregated",
                                    "distributed"
                                ]
                            }
                        },
                    },
                    "template_dir": "templates",
                    "token_handler_args": {
                        "jwks_file": "private/token_jwks.json",
                        "code": {
                            "kwargs": {
                                "lifetime": 600
                            }
                        },
                        "token": {
                            "class": "idpyoidc.server.token.jwt_token.JWTToken",
                            "kwargs": {
                                "lifetime": 3600,
                                "add_claims": [
                                    "email",
                                    "email_verified",
                                    "phone_number",
                                    "phone_number_verified"
                                ],
                                "add_claims_by_scope": True,
                                "aud": [
                                    "https://example.org/appl"
                                ]
                            }
                        },
                        "refresh": {
                            "kwargs": {
                                "lifetime": 86400
                            }
                        },
                        "id_token": {
                            "class": "idpyoidc.server.token.id_token.IDToken",
                            "kwargs": {
                                "base_claims": {
                                    "email": {
                                        "essential": True
                                    },
                                    "email_verified": {
                                        "essential": True
                                    }
                                }
                            }
                        }
                    },
                    "userinfo": {
                        "class": "idpyoidc.server.user_info.UserInfo",
                        "kwargs": {
                            "db_file": full_path("users.json")
                        }
                    }
                }
            }
        },
        "oauth_authorization_server": {
            "class": "idpyoidc.server.Server",
            "kwargs": {
                "server_type": "oauth2",
                "conf": {
                    "token_handler_args": {
                        "jwks_def": {
                            "private_path": "private/token_jwks.json",
                            "read_only": False,
                            "key_defs": [
                                {"type": "oct", "bytes": "24", "use": ["enc"], "kid": "code"}],
                        },
                        "code": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
                        "token": {
                            "class": "idpyoidc.server.token.jwt_token.JWTToken",
                            "kwargs": {
                                "lifetime": 3600,
                                "add_claims_by_scope": True,
                                "aud": ["https://example.org/appl"],
                            },
                        },
                        "refresh": {
                            "class": "idpyoidc.server.token.jwt_token.JWTToken",
                            "kwargs": {
                                "lifetime": 3600,
                                "aud": ["https://example.org/appl"],
                            },
                        },
                        "id_token": {
                            "class": "idpyoidc.server.token.id_token.IDToken",
                            "kwargs": {
                                "base_claims": {
                                    "email": {"essential": True},
                                    "email_verified": {"essential": True},
                                }
                            },
                        },
                    },
                    "endpoint": {
                        "authorization": {
                            "path": "{}/authorization",
                            "class": Authorization,
                            "kwargs": {
                                "response_types_supported": ["code"],
                                "response_modes_supported": ["query", "form_post"],
                                "claims_parameter_supported": True,
                                "request_parameter_supported": True,
                                "request_uri_parameter_supported": True,
                            },
                        }
                    },
                    "authentication": {
                        "anon": {
                            "acr": "http://www.swamid.se/policy/assurance/al1",
                            "class": "idpyoidc.server.user_authn.user.NoAuthn",
                            "kwargs": {"user": "diana"},
                        }
                    },
                    "userinfo": {
                        "class": "idpyoidc.server.user_info.UserInfo",
                        "kwargs": {"db": USERINFO_db}},
                    "template_dir": "template",
                    "authz": {
                        "class": "idpyoidc.server.authz.AuthzHandling",
                        "kwargs": {
                            "grant_config": {
                                "usage_rules": {
                                    "authorization_code": {
                                        "supports_minting": [
                                            "access_token",
                                            "refresh_token",
                                            "id_token",
                                        ],
                                        "max_usage": 1,
                                    },
                                    "access_token": {},
                                    "refresh_token": {
                                        "supports_minting": [
                                            "access_token",
                                            "refresh_token",
                                            "id_token",
                                        ]
                                    }
                                },
                                "expires_in": 43200
                            }
                        },
                    },
                    "session_params": SESSION_PARAMS
                }
            }
        }
    }
}


def test_entity():
    _entity = Combo(config=CONF["entity"])
    assert _entity
    _op = _entity["openid_provider"]
    assert isinstance(_op.conf, OPConfiguration)
    assert _op.server_type == "oidc"
    _as = _entity["oauth_authorization_server"]
    assert isinstance(_as.conf, ASConfiguration)
    assert _as.server_type == "oauth2"

    op_metadata = _op.get_metadata()
    assert op_metadata
