# Usage stories

This is a set of usage stories.
Here to display what you can do with IdpyOIDC both for OAuth2 and OIDC.

The basic idea is that a demo starts by initiating one client/RP and one AS/OP.
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

## OAuth2 Stories

These are based on the two basic OAuth2 RFCs;
* [The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749)
* [The OAuth 2.0 Authorization Framework: Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750)

### Client Credentials (oauth2_cc.py)

Displays the usage of Client credentials for doing authorization.

The client can request an access token using only its client
credentials (or other supported means of authentication) when the
client is requesting access to the protected resources under its
control, or those of another resource owner that have been previously
arranged with the authorization server (the method of which is beyond
the scope of this specification).

The request/response sequence only contains one request and one response.

#### configuration

The server configuration expresses these points.

- The server needs only one endpoint, the token endpoint. 
- The token released form the token endpoint is a signed JSON Web token (JWT)
- The server deals only with access tokens. The default lifetime of a token is 3600
seconds.
- The server can deal with 2 client authentication methods: client_secret_basic and client_secret_post


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
                "add_claims_by_scope": True,
                "aud": ["https://example.org/appl"],
            }
        }
    }

The client configuration

- lists only one service - client credentials
- specifies client ID and client secret


    CLIENT_SERVICES = {
        "client_credentials": {
            "class": "idpyoidc.client.oauth2.client_credentials.CCAccessTokenRequest"
        }
    }
    CLIENT_CONFIG = {
        "client_id": "client_1",
        "client_secret": "another password",
        "base_url": CLIENT_BASE_URL
    }

### Resource Owners Password Credentials (oauth2_ropc.py)

Displays the usage of the resource owners username and password for doing authorization.

The resource owner password credentials grant type is suitable in
cases where the resource owner has a trust relationship with the
client, such as the device operating system or a highly privileged application.

#### Configuration


### Normal Code Flow (oauth2_code.py)

The authorization code grant type is used to obtain both access
tokens and refresh tokens and is optimized for confidential clients.

Since this is a redirection-based flow, the client must be capable of
interacting with the resource owner's user-agent (typically a web
browser) and capable of receiving incoming requests (via redirection)
from the authorization server.

In the demon the response is transmitted directly from the server to the client
no user agent is involved.

### Proof Key for Code Exchange by OAuth Public Clients, RFC 7636 (oauth2_add_on_pkce.py)

A technique to mitigate against the authorization code interception attack through
the use of Proof Key for Code Exchange (PKCE).

### JAR 