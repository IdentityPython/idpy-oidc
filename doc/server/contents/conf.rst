*************
Configuration
*************

================================
General Configuration directives
================================

------
issuer
------

The issuer ID of the OP, a unique value in URI format.


--------------
session params
--------------

Configuration parameters used by session manager::

    "session_params": {
      "password": "__password_used_to_encrypt_access_token_sid_value",
      "salt": "salt involved in session sub hash",
      "sub_func": {
        "public": {
          "class": "idpyoidc.server.session.manager.PublicID",
          "kwargs": {
            "salt": "sdfsdfdsf"
          }
        },
        "pairwise": {
          "class": "idpyoidc.server.session.manager.PairWiseID",
          "kwargs": {
            "salt": "sdfsdfsdf"
          }
        }
      },
      "remove_inactive_token": True,
      "remember_token": {
         "function": remember_token,
      }
    },


password
########

Optional. Encryption key used to encrypt the SessionID (sid) in access_token.
If unset it will be assigned a random string.

remove_inactive_token
#####################

If set to true a token that has been revoked or just passed its expiration date
will be removed from the token database. This is to stop the database from
growing out of bands.

remember_token
##############

If `remove_inactive` is True then the function specified here will be used to
store the token in a secondary storage (could just be a line in the log file).
This can be important when someone at a later date wants to do an audit.

salt
####

Optional. Salt, value or filename, used in sub_funcs (pairwise, public) for
creating the opaque hash of *sub* claim.

sub_funcs
#########

Optional. Functions involved in subject value creation.


----------------
scopes_to_claims
----------------

A dict defining the scopes that are allowed to be used per client and the claims
they map to (defaults to the scopes mapping described in the spec). If we want
to define a scope that doesn't map to claims (e.g. offline_access) then we
simply map it to an empty list. E.g.::

    {
        "scope_a": ["claim1", "claim2"],
        "scope_b": []
    }

*Note*: For OIDC the `openid` scope must be present in this mapping.

The default set is::

    {
        "openid": ["sub"],
        "profile": [
            "name",
            "given_name",
            "family_name",
            "middle_name",
            "nickname",
            "profile",
            "picture",
            "website",
            "gender",
            "birthdate",
            "zoneinfo",
            "locale",
            "updated_at",
            "preferred_username",
        ],
        "email": ["email", "email_verified"],
        "address": ["address"],
        "phone": ["phone_number", "phone_number_verified"],
        "offline_access": [],
    }

*Note*: If you define `scopes_to_claims` in the configuration you MUST list
ALL the mappings you want. Not just the changes you want to make to the default.

--------------
allowed_scopes
--------------

A list with the scopes that are allowed to be used (defaults to the keys in scopes_to_claims).

----------------
scopes_supported
----------------

A list with the scopes that will be advertised in the well-known endpoint (defaults to allowed_scopes).


------
add_on
------

An example::

    "add_on": {
        "pkce": {
          "function": "idpyoidc.server.oidc.add_on.pkce.add_pkce_support",
          "kwargs": {
            "essential": false,
            "code_challenge_method": "S256 S384 S512"
          }
        },
      }

The provided add-ons can be seen in the following sections.

pkce
####

The pkce add on is activated using the ``idpyoidc.server.oidc.add_on.pkce.add_pkce_support``
function. The possible configuration options can be found below.

essential
---------

Whether pkce is mandatory, authentication requests without a ``code_challenge``
will fail if this is True. This option can be overridden per client by defining
``pkce_essential`` in the client metadata.

code_challenge_method
---------------------

The allowed code_challenge methods. The supported code challenge methods are:
``plain, S256, S384, S512``

--------------
authentication
--------------

The set of allow authentication methods.

An example::

    "authentication": {
        "user": {
          "acr": "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword",
          "class": "idpyoidc.server.user_authn.user.UserPassJinja2",
          "kwargs": {
            "verify_endpoint": "verify/user",
            "template": "user_pass.jinja2",
            "db": {
              "class": "idpyoidc.server.util.JSONDictDB",
              "kwargs": {
                "filename": "passwd.json"
              }
            },
            "page_header": "Testing log in",
            "submit_btn": "Get me in!",
            "user_label": "Nickname",
            "passwd_label": "Secret sauce"
          }
        }
      },

------------
capabilities
------------

This covers most of the basic functionality of the OP. The key words are the
same as defined in `OIDC Discovery <https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata>`_.
A couple of things are defined else where. Like the endpoints, issuer id,
jwks_uri and the authentication methods at the token endpoint.

An example::

    response_types_supported:
        - code
        - token
        - id_token
        - "code token"
        - "code id_token"
        - "id_token token"
        - "code id_token token"
        - none
      response_modes_supported:
        - query
        - fragment
        - form_post
      subject_types_supported:
        - public
        - pairwise
      grant_types_supported:
        - authorization_code
        - implicit
        - urn:ietf:params:oauth:grant-type:jwt-bearer
        - refresh_token
        - urn:ietf:params:oauth:grant-type:token-exchange
      claim_types_supported:
        - normal
        - aggregated
        - distributed
      claims_parameter_supported: True
      request_parameter_supported: True
      request_uri_parameter_supported: True
      frontchannel_logout_supported: True
      frontchannel_logout_session_supported: True
      backchannel_logout_supported: True
      backchannel_logout_session_supported: True
      check_session_iframe: https://127.0.0.1:5000/check_session_iframe
      scopes_supported: ["openid", "profile", "random"]
      claims_supported: ["sub", "given_name", "birthdate"]

---------
client_db
---------

If you're running an OP with static client registration you want to keep the
registered clients in a database separate from the session database since
it will change independent of the OP process. In this case you need *client_db*.
If you are on the other hand only allowing dynamic client registration then
keeping registered clients only in the session database makes total sense.

The class you reference in the specification MUST be a subclass of
idpyoidc.storage.DictType and have some of the methods a dictionary has.

Note also that this class MUST support the dump and load methods as defined
in :py:class:`idpyoidc.impexp.ImpExp`.

An example::

    client_db: {
        "class": 'idpyoidc.abfile.AbstractFileSystem',
        "kwargs": {
            'fdir': full_path("afs"),
            'value_conv': 'idpyoidc.util.JSON'
        }
    }

--------------
cookie_handler
--------------

An example::

      "cookie_handler": {
        "class": "idpyoidc.server.cookie_handler.CookieHandler",
        "kwargs": {
          "keys": {
            "private_path": f"{OIDC_JWKS_PRIVATE_PATH}/cookie_jwks.json",
            "key_defs": [
              {"type": "OCT", "use": ["enc"], "kid": "enc"},
              {"type": "OCT", "use": ["sig"], "kid": "sig"}
            ],
            "read_only": False
          },
          "flags": {
              "samesite": "None",
              "httponly": True,
              "secure": True,
          },
          "name": {
            "session": "oidc_op",
            "register": "oidc_op_rp",
            "session_management": "sman"
          }
        }
    },

--------
endpoint
--------

An example::

      "endpoint": {
        "webfinger": {
          "path": ".well-known/webfinger",
          "class": "idpyoidc.server.oidc.discovery.Discovery",
          "kwargs": {
            "client_authn_method": null
          }
        },
        "provider_info": {
          "path": ".well-known/openid-configuration",
          "class": "idpyoidc.server.oidc.provider_config.ProviderConfiguration",
          "kwargs": {
            "client_authn_method": null
          }
        },
        "registration": {
          "path": "registration",
          "class": "idpyoidc.server.oidc.registration.Registration",
          "kwargs": {
            "client_authn_method": None,
            "client_secret_expiration_time": 432000,
            "client_id_generator": {
               "class": 'idpyoidc.server.oidc.registration.random_client_id',
               "kwargs": {
                    "seed": "that-optional-random-value"
               }
           }
          }
        },
        "registration_api": {
          "path": "registration_api",
          "class": "idpyoidc.server.oidc.read_registration.RegistrationRead",
          "kwargs": {
            "client_authn_method": [
              "bearer_header"
            ]
          }
        },
        "introspection": {
          "path": "introspection",
          "class": "idpyoidc.server.oauth2.introspection.Introspection",
          "kwargs": {
            "client_authn_method": [
              "client_secret_post",
              "client_secret_basic",
              "client_secret_jwt",
              "private_key_jwt"
            ]
            "release": [
              "username"
            ]
          }
        },
        "authorization": {
          "path": "authorization",
          "class": "idpyoidc.server.oidc.authorization.Authorization",
          "kwargs": {
            "client_authn_method": null,
            "claims_parameter_supported": true,
            "request_parameter_supported": true,
            "request_uri_parameter_supported": true,
            "response_types_supported": [
              "code",
              "token",
              "id_token",
              "code token",
              "code id_token",
              "id_token token",
              "code id_token token",
              "none"
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
              "private_key_jwt",
            ],
            "revoke_refresh_on_issue": True
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
        "end_session": {
          "path": "session",
          "class": "idpyoidc.server.oidc.session.Session",
          "kwargs": {
            "logout_verify_url": "verify_logout",
            "post_logout_uri_path": "post_logout",
            "signing_alg": "ES256",
            "frontchannel_logout_supported": true,
            "frontchannel_logout_session_supported": true,
            "backchannel_logout_supported": true,
            "backchannel_logout_session_supported": true,
            "check_session_iframe": "check_session_iframe"
          }
        }
      }

You can specify which algoritms are supported, for example in userinfo_endpoint::

    "userinfo_signing_alg_values_supported": OIDC_SIGN_ALGS,
    "userinfo_encryption_alg_values_supported": OIDC_ENC_ALGS,

Or in authorization endpoint::

    "request_object_encryption_alg_values_supported": OIDC_ENC_ALGS,

------------
httpc_params
------------

Parameters submitted to the web client (python requests).
In this case the TLS certificate will not be verified, to be intended exclusively for development purposes

Example ::

    "httpc_params": {
        "verify": false
      },

----
keys
----

JWK Set (JWKS) files
####################

see: [cryptojwt documentation](https://cryptojwt.readthedocs.io/en/latest/keyhandling.html<https://cryptojwt.readthedocs.io/en/latest/keyhandling.html)


You can use `cryptojwt.key_jar.init_key_jar` to create JWKS file.
An easy way can be to configure the auto creation of JWKS files directly in your conf.yaml file.
Using `read_only: False` in `OIDC_KEYS` it will create the path within the JWKS files.
Change it to `True` if you don't want to overwrite them on each execution.

In the JWTConnect-Python-CryptoJWT distribution there is also a script you can use to construct a JWK.
You can for instance do::

    $ jwkgen --kty=RSA
    {
        "d": "b9ucfay9vxDvz_nRZMVSUR9eRvHNMo0tc8Bl7tWkwxTis7LBXxmbMH1yzLs8omUil_u2a-Z_6VlKENxacuejYYcOhs6bfaU3iOqJbGi2p4t2i1oxjuF-cX6BZ5aHB5Wfb1uTXXobHokjcjVVDmBr_fNYBEPtZsVYqyN9sR9KE_ZLHEPks3IER09aX9G3wiB_PgcxQDRAl72qucsBz9_W9KS-TVWs-qCEqtXLmx9AAN6P8SjUcHAzEb0ZCJAYCkVu34wgNjxVaGyYN1qMA-1iOOVz--wtMyBwc5atSDBDgUApxFyj_DHSeBl81IHedcPjS9azxqFhumP7oJJyfecfSQ",
        "e": "AQAB",
        "kid": "cHZQbWRrMzRZak53U1pfSUNjY0dKd2xXaXRKenktdUduUjVBVTl3VE5ndw",
        "kty": "RSA",
        "n": "73XCXV2iiubSCEaFe26OpVnsBFlXwXh_yDCDyBqFgAFi5WdZTpRMJZoK0nn_vv2MvrXqFnw6IfXkwdsRGlMsNldVy36003gKa584CNksxfenwJZcF-huASUrSJEFr-3c0fMT_pLyAc7yf3rNCdRegzbBXSvIGKQpaeIjIFYftAPd9tjGA_SuYWVQDsSh3MeGbB4wt0lArAyFZ4f5o7SSxSDRCUF3ng3CB_QKUAaDHHgXrcNG_gPpgqQZjsDJ0VwMXjFKxQmskbH-dfsQ05znQsYn3pjcd_TEZ-Yu765_L5uxUrkEy_KnQXe1iqaQHcnfBWKXt18NAuBfgmKsv8gnxQ",
        "p": "_RPgbiQcFu8Ekp-tC-Kschpag9iaLc9aDqrxE6GWuThEdExGngP_p1I7Qd7gXHHTMXLp1c4gH2cKx4AkfQyKny2RJGtV2onQButUU5r0gwnlqqycIA2Dc9JiH85PX2Z889TKJUlVETfYbezHbKhdsazjjsXCQ6p9JfkmgfBQOXM",
        "q": "8jmgnadtwjMt96iOaoL51irPRXONO82tLM2AAZAK5Obsj23bZ9LFiw2Joh5oCSFdoUcRhbbIhCIv2aT4T_XKnDGnddrkxpF5Xgu0-hPNYnJx5m4kuzerot4j79Tx6qO-bshaaGz50MHs1vHSeFaDVN4fvh_hDWpV1BCNI0PKK-c"
    }
    SHA-256: pvPmdk34YjNwSZ_ICccGJwlWitJzy-uGnR5AU9wTNgw

Example: create a JWK for cookie signing

    jwkgen --kty=SYM --kid cookie > private/cookie_sign_jwk.json

A configuration example::

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
        "read_only": false,
        "uri_path": "static/jwks.json"
      },

*read_only* means that on each restart the keys will created and overwritten with new ones.
This can be useful during the first time the project have been executed, then to keep them
as they are *read_only* would be configured to *True*.

---------------
login_hint2acrs
---------------

OIDC Login hint support, it's optional.
It matches the login_hint parameter to one or more Authentication Contexts.

An example::

      "login_hint2acrs": {
        "class": "idpyoidc.server.login_hint.LoginHint2Acrs",
        "kwargs": {
          "scheme_map": {
            "email": [
              "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword"
            ]
          }
        }
      },

oidc-op supports the following authn contexts:

- UNSPECIFIED, urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified
- INTERNETPROTOCOLPASSWORD, urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword
- MOBILETWOFACTORCONTRACT, urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract
- PASSWORDPROTECTEDTRANSPORT, urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
- PASSWORD, urn:oasis:names:tc:SAML:2.0:ac:classes:Password
- TLSCLIENT, urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient
- TIMESYNCTOKEN, urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken


-----
authz
-----

This configuration section refers to the authorization/authentication endpoint behaviour.
Scopes bound to an access token are strictly related to grant management, as part of what that endpoint does.
Regarding grant authorization we should have something like the following example.

If you omit this section from the configuration (thus using some sort of default profile)
you'll have an Implicit grant authorization that leads granting nothing.
Add the below to your configuration and you'll see things changing.


An example::

      "authz": {
        "class": "idpyoidc.server.authz.AuthzHandling",
        "kwargs": {
            "grant_config": {
                "usage_rules": {
                    "authorization_code": {
                        "supports_minting": ["access_token", "refresh_token", "id_token"],
                        "max_usage": 1
                    },
                    "access_token": {},
                    "refresh_token": {
                        "supports_minting": ["access_token", "refresh_token"]
                    }
                },
                "expires_in": 43200,
                "audience": ['https://www.example.com']
            }
        }
      },

------------
template_dir
------------

The HTML Template directory used by Jinja2, used by endpoint context
 template loader, as::

    Environment(loader=FileSystemLoader(template_dir), autoescape=True)

An example::

      "template_dir": "templates"

For any further customization of template here an example of what used in django-oidc-op::

      "authentication": {
        "user": {
          "acr": "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword",
          "class": "oidc_provider.users.UserPassDjango",
          "kwargs": {
            "verify_endpoint": "verify/oidc_user_login/",
            "template": "oidc_login.html",

            "page_header": "Testing log in",
            "submit_btn": "Get me in!",
            "user_label": "Nickname",
            "passwd_label": "Secret sauce"
          }
        }
      },

------------------
token_handler_args
------------------

Token handler is an intermediate interface used by and endpoint to manage
 the tokens' default behaviour, like lifetime and minting policies.
 With it we can create a token that's linked to another, and keep relations between many tokens
 in session and grants management.

An example::

    "token_handler_args": {
        "jwks_def": {
          "private_path": "private/token_jwks.json",
          "read_only": false,
          "key_defs": [
            {
              "type": "oct",
              "bytes": 24,
              "use": [
                "enc"
              ],
              "kid": "code"
            },
            {
              "type": "oct",
              "bytes": 24,
              "use": [
                "enc"
              ],
              "kid": "refresh"
            }
          ]
        },
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
              "add_claims_by_scope": true,
              "aud": ["https://example.org/appl"]
           }
        },
        "refresh": {
            "kwargs": {
                "lifetime": 86400
            }
        }
        "id_token": {
            "class": "idpyoidc.server.token.id_token.IDToken",
            "kwargs": {
                "base_claims": {
                    "email": None,
                    "email_verified": None,
            },
        }
      }

jwks_defs can be replaced eventually by `jwks_file`::

    "jwks_file": f"{OIDC_JWKS_PRIVATE_PATH}/token_jwks.json",

You can even select which algorithms to support in id_token, eg::

    "id_token": {
        "class": "idpyoidc.server.token.id_token.IDToken",
        "kwargs": {
            "id_token_signing_alg_values_supported": [
                    "RS256",
                    "RS512",
                    "ES256",
                    "ES512",
                    "PS256",
                    "PS512",
                ],
            "id_token_encryption_alg_values_supported": [
                    "RSA-OAEP",
                    "RSA-OAEP-256",
                    "A192KW",
                    "A256KW",
                    "ECDH-ES",
                    "ECDH-ES+A128KW",
                    "ECDH-ES+A192KW",
                    "ECDH-ES+A256KW",
                ],
            "id_token_encryption_enc_values_supported": [
                    'A128CBC-HS256',
                    'A192CBC-HS384',
                    'A256CBC-HS512',
                    'A128GCM',
                    'A192GCM',
                    'A256GCM'
                ],
        }
    }

--------
userinfo
--------

An example::

    "userinfo": {
        "class": "idpyoidc.server.user_info.UserInfo",
        "kwargs": {
          "db_file": "users.json"
        }
    }

This is something that can be customized.
For example in the django-oidc-op implementation it uses something like
the following::

    "userinfo": {
        "class": "oidc_provider.users.UserInfo",
        "kwargs": {
            "claims_map": {
                "phone_number": "telephone",
                "family_name": "last_name",
                "given_name": "first_name",
                "email": "email",
                "verified_email": "email",
                "gender": "gender",
                "birthdate": "get_oidc_birthdate",
                "updated_at": "get_oidc_lastlogin"
            }
        }
    }

================================
Special Configuration directives
================================

--------------
Token exchange
--------------
There are two possible ways to configure Token Exchange in OIDC-OP, globally and per-client.
For the first case the configuration is passed in the Token Exchange handler through the
`urn:ietf:params:oauth:grant-type:token-exchange` dictionary in token's `grant_types_supported`.

If present, the token exchange configuration should contain a `policy` dictionary
that defines the behaviour for each subject token type. Each subject token type
is mapped to a dictionary with the keys `callable` (mandatory), which must be a
python callable or a string that represents the path to a python callable, and
`kwargs` (optional), which must be a dict of key-value arguments that will be
passed to the callable.

The key `""` represents a fallback policy that will be used if the subject token
type can't be found. If a subject token type is defined in the `policy` but is
not in the `subject_token_types_supported` list then it is ignored.

The token exchange configuration should also contain a `requested_token_types_supported`
list that defines the supported token types that can be requested through the
`requested_token_type` parameter of a Token Exchange request. In addition, a
default token type that will be returned in the absence of the `requested_token_type`
in the Token Exchange request should be defined through the `default_requested_token_type`
configuration parameter::

    "grant_types_supported":{
      "urn:ietf:params:oauth:grant-type:token-exchange": {
        "class": "idpyoidc.server.oauth2.token.TokenExchangeHelper",
        "kwargs": {
          "subject_token_types_supported": [
            "urn:ietf:params:oauth:token-type:access_token",
            "urn:ietf:params:oauth:token-type:refresh_token",
            "urn:ietf:params:oauth:token-type:id_token"
          ],
          "requested_token_types_supported": [
            "urn:ietf:params:oauth:token-type:access_token",
            "urn:ietf:params:oauth:token-type:refresh_token",
            "urn:ietf:params:oauth:token-type:id_token"
          ],
          "policy": {
            "urn:ietf:params:oauth:token-type:access_token": {
              "callable": "/path/to/callable",
              "kwargs": {
                "audience": ["https://example.com"],
                "scopes": ["openid"]
              }
            },
            "urn:ietf:params:oauth:token-type:refresh_token": {
              "callable": "/path/to/callable",
              "kwargs": {
                "resource": ["https://example.com"],
                "scopes": ["openid"]
              }
            },
            "": {
              "callable": "/path/to/callable",
              "kwargs": {
                "scopes": ["openid"]
              }
            }
          }
        }
      }
    }

For the per-client configuration a similar configuration scheme should be present in the client's
metadata under the `token_exchange` key.

For example::

    "token_exchange":{
      "urn:ietf:params:oauth:grant-type:token-exchange": {
        "class": "idpyoidc.server.oidc.token.TokenExchangeHelper",
        "kwargs": {
          "subject_token_types_supported": [
            "urn:ietf:params:oauth:token-type:access_token",
            "urn:ietf:params:oauth:token-type:refresh_token",
            "urn:ietf:params:oauth:token-type:id_token"
          ],
          "requested_token_types_supported": [
            "urn:ietf:params:oauth:token-type:access_token",
            "urn:ietf:params:oauth:token-type:refresh_token",
            "urn:ietf:params:oauth:token-type:id_token"
          ],
          "policy": {
            "urn:ietf:params:oauth:token-type:access_token": {
              "callable": "/path/to/callable",
              "kwargs": {
                "audience": ["https://example.com"],
                "scopes": ["openid"]
              }
            },
            "urn:ietf:params:oauth:token-type:refresh_token": {
              "callable": "/path/to/callable",
              "kwargs": {
                "resource": ["https://example.com"],
                "scopes": ["openid"]
              }
            },
            "": {
              "callable": "/path/to/callable",
              "kwargs": {
                "scopes": ["openid"]
              }
            }
          }
        }
      }
    }

The policy callable accepts a specific argument list and must return the altered token exchange
request or raise an exception.

For example::

    def custom_token_exchange_policy(request, context, subject_token, **kwargs):
        if some_condition in request:
          return TokenErrorResponse(
                error="invalid_request", error_description="Some error occured"
            )

        return request


==================================
idpyoidc\.server\.configure module
==================================

.. automodule:: idpyoidc.server.configure
    :members:
    :undoc-members:
    :show-inheritance:


==============
Resource Indicators
==============
There are two possible ways to configure Resource Indicators in OIDC-OP, globally and per-client.
For the first case the configuration is passed in the Authorization or Access Token endpoint arguments throught the
`resource_indicators` dictionary.

If present, the resource indicators configuration should contain a `policy` dictionary
that defines the behaviour of the specific endpoint. The policy
is mapped to a dictionary with the keys `callable` (mandatory), which must be a
python callable or a string that represents the path to a python callable, and
`kwargs` (optional), which must be a dict of key-value arguments that will be
passed to the callable.

The resource indicators configuration may also contain a `resource_servers_per_client`
dictionary that defines a mapping between oidc-op registered clients with key the equivalent `client id` and resources to whom this client
is eligible to request access.

    "resource_indicators":{
      "policy": {
          "callable": validate_authorization_resource_indicators_policy,
          "kwargs": {
            "resource_servers_per_client": {
              "CLIENT_1": ["RESOURCE_1"],
              "CLIENT_2": ["RESOURCE_1", "RESOURCE_2"]
            },
          },
        },
      },
    }

For the per-client configuration a similar configuration scheme should be present in the client's
metadata under the `resource_indicators` key with slight difference. The `policy` mapping should be set a value for a 
key `authorization_code` or `access_token` in order to indicate the endpoint that this resource indicators policy is reffered to.
In addition, the `resource_servers_per_client` value is a list of the permitted resources.

For example::

    "resource_indicators":{
        "authorization_code": {
          "policy": {
            "callable": validate_authorization_resource_indicators_policy,
            "kwargs": {
              "resource_servers_per_client": ["RESOURCE_1"],
            },
          },
       },
      },
    }

The policy callable accepts a specific argument list and must return the altered token
request or raise an exception.

For example::

    def validate_resource_indicators_policy(request, context, **kwargs):
        if some_condition in request:
          return TokenErrorResponse(
                error="invalid_request", error_description="Some error occured"
            )

        return request

