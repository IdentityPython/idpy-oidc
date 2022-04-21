======
Server
======

This is what holds it all together. It's the scaffolding/framework to which
you can add the functionality you want.

The server provides a very useful method *server_get*. All instances that
must get access to an endpoint or the endpoint context will have a link to
this method. Usage examples are::

    server_get("endpoint_context")

which returns a link to the endpoint context or::

    server_get("endpoint", "authorization")

which will return a link to the authorization endpoint.

Having server_get allows for changing the set of endpoints at run-time
because every one that wants access to an endpoint instance needs to go through
the server to get it.
It also is the basis for the interface to persistent storage of the state of
the server.

Server parts
============

An OP (or AS for that matter) contains an endpoint context and a number
of endpoints.

The endpoint context contains information and functions that more then one endpoint
must have access to. This includes things like the KeyJar that keeps all the
OP's keys, the provider configuration, client authentication methods
and a list of all the endpoints. This is not an exhausting list there are more
in there but we'll leave that for later.

You can find out more about the endpoint context in :ref:`endpoint-context` .

OAuth2 and thereby OpenID Connect (OIDC) are built on a request-response paradigm.
The RP issues a request and the OP returns a response.

The OIDC core standard defines a set of such request-responses.
This is a basic list of request-responses and the normal sequence in which they
occur:

1. Provider discovery (WebFinger)
2. Provider Info Discovery
3. Client registration
4. Authorization/Authentication
5. Access token
6. User info

All these are services you can access at endpoints. The total set of endpoints
are listed in :ref:`server-endpoints` .

.. _WebFinger: https://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery
.. _dynamic discovery: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
.. _dynamic client registration: https://openid.net/specs/openid-connect-registration-1_0.html


module
======

.. automodule:: idpyoidc.server
    :members:
    :undoc-members:
    :show-inheritance:
