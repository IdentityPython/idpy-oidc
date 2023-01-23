# Introduction to IdpyOIDC

# foundation

OAuth2 (
[The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749) and
[The OAuth 2.0 Authorization Framework: Bearer Token Usage](https://tools.ietf.org/html/rfc6750)) 
and 
OpenID Connect [OIDC](https://openid.net/specs/openid-connect-core-1_0.html)
which is built on top of OAuth2 are request-response protocols.
The basic model is that a client sends a request to a server and the
server returns a response.

Requests and responses are sets of claims. IdpyOIDC defines those sets as 
messages. The content of a message are then described using the 
Message class.

More about messages in [Message](message.md).

OAuth2 and OIDC defines endpoints that a client can send requests to and upon
which servers listen.

A [Client](client.md) in IdpyOIDC therefor can access a number of services at endpoints
(there is no one to one match an endpoint can support more than one service).

And a [Server](server.md) supports one or more endpoints. A server need not support all
services that are connected to one endpoint.
