.. _endpoint-context:

================
Endpoint Context
================

This is where modules and information that more then one endpoint needs to access.
Things like the Key Jar, client authentication methods, the client and user
databases and so on.

**NOTE**: Endpoint context also contains all the endpoints, which means that there is
a possibility for circular references. To deal with this an endpoint should
always use the *get_endpoint_context* method of the server if it wants to
access something kept in the endpoint context.

module
======

.. automodule:: idpyoidc.server.endpoint_context
    :members:
    :undoc-members:
    :show-inheritance:
