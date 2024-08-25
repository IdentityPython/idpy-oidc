.. _par:

********************
Pushed Authorization
********************

------------
Introduction
------------

https://datatracker.ietf.org/doc/html/rfc9126

The Internet draft defines the pushed authorization request (PAR) endpoint,
which allows clients to push the payload of an OAuth 2.0 authorization
request to the authorization server via a direct request and provides
them with a request URI that is used as reference to the data in a
subsequent authorization request.

-------------
Configuration
-------------

There is basically one things you can configure:

- authn_method
    Which client authentication method that should be used at the pushed authorization endpoint.
    Default is none.

-------
Example
-------

What you have to do is to add a *par* section to an *add_ons* section
in a client configuration.

.. code:: python

    'add_ons': {
        "par": {
            "function": "idpyoidc.client.oauth2.add_on.par.add_support",
            "kwargs": {
                "authn_method": "private_key_jwt"
            }
        }
    }

