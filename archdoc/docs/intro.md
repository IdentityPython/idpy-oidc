# Introduction to IdpyOIDC

# foundation

OAuth2 (
[The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749) and
[The OAuth 2.0 Authorization Framework: Bearer Token Usage](https://tools.ietf.org/html/rfc6750)) 
and 
OpenID Connect [OIDC](https://openid.net/specs/openid-connect-core-1_0.html)
(which is built on top of OAuth2) are request-response protocols.
The basic model is that a client sends a request to a server and the
server returns a response.

Requests and responses are sets of claims. IdpyOIDC regards those sets as 
messages. The content of a message is then described using the 
Message class.

More about messages in [Message](message.md).

OAuth2 and OIDC defines endpoints that a client can send requests to and upon
which servers listens and responds.

A [Client](client/index.md) in IdpyOIDC therefor can access a number of services at endpoints
(there is no one to one match, an endpoint can support more than one service).

And a [Server](server.md) supports one or more endpoints. A server need not support all
services that are connected to one endpoint.

Services defined by OIDC are:

- Discovery (WebFinger)
- Provider Info
- Client Registration
- Authorization
- Access Token
- Refresh Access Token
- User Info

The normal request/response process can be described by:

1. On the client side:
   1. Collects request information
   2. Formats the message, chooses HTTP method
   3. Sends the message to the Server
2. On the Server side
   1. Parses the request (deserializes the message)
   2. Verifies client authentication
   3. Performs necessary action
   4. Collect response information
   5. Sends response
3. On the client side
   1. Parses the response
   2. Verifies the response
   3. Stores information from the response
   4. Acts
