# The IdpyOIDC client

A client can send requests to an endpoint and deal with the response.

IdpyOIDC assumes that there is one Relying Party(RP)/Client instance per 
OpenID Connect Provider(OP)/Authorization Server (AS).

If you have a service that expects to talk to several OPs/ASs
then you must use **idpyoidc.client.rp_handler.RPHandler** to manage the RPs.

RPHandler has methods like:
- begin()
- finalize()
- refresh_access_token()
- logout()

More about RPHandler at the end of this section.

## Client

A client is configured to talk to a set of services each of them represented by
a Service Instance.

# Context

# Service

A Service instance is expected to be able to:

1. Collect all the request arguments
2. If necessary collect and add authentication information to the request attributes or HTTP header
3. Formats the message 
4. chooses HTTP method
5. Add HTTP headers

and then after having received the response: 

1. Parses the response
2. Gather verification information and verify the response
3. Do any special post-processing.
3. Store information from the response

Doesn't matter which service is considered they all have to be able to do this.

## Request

## Response

# AddOn

# Endpoints
    
## OAuth2

- Access Token
- Authorization
- Refresh Access Token
- Server Metadata
- Token Exchange
