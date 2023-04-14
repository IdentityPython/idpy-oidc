# Usage stories

This is a set of usage stories.
Here to display what you can do with IdpyOIDC using OAuth2 or OIDC.

Every story follows the same pattern it starts by initiating one client/RP and 
one AS/OP.
After that a sequence of requests/responses are performed. Each one follows this
pattern:

- The client/RP constructs the request and possible client authentication information
- The request and client authentication information is printed
- The AS/OP does client authentication
- The AS/OP parses and verifies the client request
- The AS/OP constructs the server response
- The client/RP parses and verifies the server response
- The parsed and verified response is printed

This pattern is repeated for each request/response in the sequence.

To understand the following you have to know that an AS/OP provides a 
set of endpoints while a client/RP accesses services. An endpoint can
support more than one service. A service can only reside at one endpoint.

## OAuth2 Stories

These are based on the two basic OAuth2 RFCs;
* [The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749)
* [The OAuth 2.0 Authorization Framework: Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750)

### Client Credentials Grant (oauth2_cc.py)

Displays the usage of the
[client credentials grant](https://www.rfc-editor.org/rfc/rfc6749#section-4.4) .

The client can request an access token using only its client
credentials (or other supported means of authentication).

The request/response sequence only contains the client credential exchange.

The client is statically registered with the AS.

#### configuration

The server configuration expresses these points:

- The server needs only one endpoint, the token endpoint. 
- The token released form the token endpoint is a signed JSON Web token (JWT)
- The server deals only with access tokens. The default lifetime of a token is 3600
seconds.
- The server can deal with 2 client authentication methods at the token endpoint: 
  client_secret_basic and client_secret_post
- In this example the audience for the token (the resource server) is statically set.


    "endpoint": {
        "token": {
            "path": "token",
            "class": Token,
            "kwargs": {
                "client_authn_method": ["client_secret_basic", "client_secret_post"],
            },
        },
    },
    "token_handler_args": {
        "jwks_defs": {"key_defs": KEYDEFS},
        "token": {
            "class": "idpyoidc.server.token.jwt_token.JWTToken",
            "kwargs": {
                "lifetime": 3600,
                "aud": ["https://example.org/appl"],
            }
        }
    }

The client configuration

- lists only one service - client credentials
- specifies client ID and client secret since the client is statically 
  registered with the server.


    "client_id": "client_1",
    "client_secret": "another password",
    "base_url": "https://example.com",
    "services": {
        "client_credentials": {
            "class": "idpyoidc.client.oauth2.client_credentials.CCAccessTokenRequest"
        }
    }

**services** is a dictionary. The keys in that dictionary is for your usage only.
Internally the software uses identifiers that are assigned every Service class.
This means that you can not have two instances of the same class in a _services_
definition.

### Resource Owners Password Credentials (oauth2_ropc.py)

Displays the usage of the 
[resource owners username and password](https://www.rfc-editor.org/rfc/rfc6749#section-4.3)
for doing authorization.

The resource owner password credentials grant type is suitable in
cases where the resource owner has a trust relationship with the
client, such as the device operating system or a highly privileged application.

#### Configuration

The big difference between Client Credentials and Resource Owners Passsword credentials
is that the server also most support user authentication. Therefor this 
part is added to the server configuration:

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

This allows for a very simple username/password check against a static file.

On the client side the change is that the service configuration now looks
like this:
 
    services = {
        "ropc": {
            "class": "idpyoidc.client.oauth2.resource_owner_password_credentials.ROPCAccessTokenRequest"
        }
    }


### Authorization Code Grant (oauth2_code.py)

The 
[authorization code grant](https://www.rfc-editor.org/rfc/rfc6749#section-4.1) 
is used to obtain both access tokens and possibly refresh tokens and is optimized 
for confidential clients.

Since this is a redirection-based flow, the client must be capable of
interacting with the resource owner's user-agent (typically a web
browser) and capable of receiving incoming requests (via redirection)
from the authorization server.

In the demon the response is transmitted directly from the server to the client
no user agent is involved.

In this story the flow contains three request/responses

- Fetching server metadata
- Authorization 
- Access token

#### Configuration

Let's take it part by part.
First the endpoints, straight forward support for the sequence of exchanges we 
want to display.

    "endpoint": {
        "metadata": {
            "path": ".well-known/oauth-authorization-server",
            "class": "idpyoidc.server.oauth2.server_metadata.ServerMetadata",
            "kwargs": {},
        },
        "authorization": {
            "path": "authorization",
            "class": "idpyoidc.server.oauth2.authorization.Authorization",
            "kwargs": {},
        },
        "token": {
            "path": "token",
            "class": "idpyoidc.server.oauth2.token.Token",
            "kwargs": {},
        }
    },

Next comes the type of tokens the grant manager can issue.
In this case authorization codes and access tokens.

    "token_handler_args": {
        "key_conf": {"key_defs": KEYDEFS},
        "code": {
            "lifetime": 600,
            "kwargs": {
                "crypt_conf": CRYPT_CONFIG
            }
        },
        "token": {
            "class": "idpyoidc.server.token.jwt_token.JWTToken",
            "kwargs": {
                "lifetime": 3600,
                "aud": ["https://example.org/appl"],
            },
        }
    },

The software can produce 3 types of tokens. 

- An encrypted value, unreadable by anyone but the server
- A signed JSON Web Token following the pattern described in 
[JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens](https://datatracker.ietf.org/doc/rfc9068/)
- An IDToken which only is used to represent ID Tokens.

In this example only the two first types are used since no ID Tokens are produced.

The next part is about the grant manager.

    "authz": {
        "class": AuthzHandling,
        "kwargs": {
            "grant_config": {
                "usage_rules": {
                    "authorization_code": {
                        "supports_minting": ["access_token"],
                        "max_usage": 1,
                    },
                    "access_token": {
                        "expires_in": 600,
                    }
                }
            }
        },
    },

What this says is that an authorization code can only be used once and 
only to mint an access token. The lifetime for an authorization code is
the default which is 300 seconds (5 minutes).
The access token can not be used to mint anything. Note that in the
token handler arguments the lifetime is set to 3600 seconds for a token
while in the authz part and access tokens lifetime is defined to be 
600 seconds. It's the later that is used since it is more specific. 

    "authentication": {
        "anon": {
            "acr": INTERNETPROTOCOLPASSWORD,
            "class": "idpyoidc.server.user_authn.user.NoAuthn",
            "kwargs": {"user": "diana"},
        }
    },

It's convenient to use this no-authentication method in this context since we 
can't deal with user interaction.
What happens is that authentication is assumed to have happened and that
it resulted in that **diana** was authenticated.

### PKCE (oauth2_add_on_pkce.py)

[Proof Key for Code Exchange by OAuth Public Clients](https://datatracker.ietf.org/doc/rfc7636/).
A technique to mitigate against the authorization code interception attack through
the use of Proof Key for Code Exchange (PKCE).

#### Configuration

On the server side only one thing is added:

    "add_ons": {
        "pkce": {
            "function": "idpyoidc.server.oauth2.add_on.pkce.add_support",
            "kwargs": {},
        },
    }

Similar on the client side:

    "add_ons": {
        "pkce": {
            "function": "idpyoidc.client.oauth2.add_on.pkce.add_support",
            "kwargs": {
                "code_challenge_length": 64,
                "code_challenge_method": "S256"
            },
        },
    }

### JAR 