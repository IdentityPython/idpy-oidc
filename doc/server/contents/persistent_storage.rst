.. _persistent-storage:

==================
Persistent Storage
==================

Persistent storage per se is not supported by this software.

What we provide is a way of collecting information that then can be
written to persistent storage or to apply information that has been
retrieved from persistent storage.

An example might make it clearer (taken from test_11_impext).
To begin with we create a class with a couple of attributes with
different types of values::

    from cryptojwt import KeyBundle

    from idpyoidc.impexp import ImpExp
    from idpyoidc.message.oauth2 import AuthorizationResponse
    from idpyoidc.message.oidc import AuthorizationRequest

    KEYSPEC = [
        {"type": "RSA", "use": ["sig"]},
        {"type": "EC", "crv": "P-256", "use": ["sig"]},
    ]

    class ImpExpTest(ImpExp):
        parameter = {
            "string": "",
            "list": [],
            "dict": {},
            "message": AuthorizationRequest,
            "response_class": object,
            "key_bundle": KeyBundle,
            "bundles": [KeyBundle],
        }


Next we assign some values::

    b = ImpExpTest()
    b.string = "foo"
    b.list = ["a", "b", "c"]
    b.dict = {"a": 1, "b": 2}
    b.message = AuthorizationRequest(
        scope="openid",
        redirect_uri="https://example.com/cb",
        response_type="code",
        client_id="abcdefg",
    )
    b.response_class = AuthorizationResponse
    b.key_bundle = build_key_bundle(key_conf=KEYSPEC)
    b.bundles = [build_key_bundle(key_conf=KEYSPEC)]
    b.bundles.append(build_key_bundle(key_conf=KEYSPEC))


Now for the magic::

    dump = b.dump()

The produced value *dump* is a dictionary ready to be converted to JSON.
That is it should contain nothing that can not be converted to JSON.
So, at this point imaging that you have written the JSON representation to
a database. Since it's just text it should be simple to store and retrieve.

Sometime later you retrieve the dump from the database and creates a
new ImpExpTest instance with the stored information.::

    a = ImpExpTest()
    a.load(dump)

And that's it.

As you would expect some of the key classes in IdpyOIDC are subclasses of
ImpExp. Your problem is to decide what is going to be dump'ed/load'ed and
with what frequency.

You have this sequence of classes::

1. Server

2. EndpointContext

3. SessionManager

4. Grant

Which gets more and more detailed.
Dumping everything kept in the Server instance is not something I expect
anyone to do often. Probably only after initiating everything at start up and
just before taking down a server.
Dumping a Grant instance on the other hand should probably be done everytime
something has changed in the Grant instance. Like issuing a new Access Token.

Dump/load is, by design, not supposed to touch information in an instance
that comes from configuration information. Dump/load is only supposed to
deal with information that is created/modified/deleted due to server activity.

ImpExp Class hierarchy
----------------------

Here you can see which of the classes that are subclasses of ImpExp or
are subclasses of classes that are subclasses of ImpExp and so on..

This means that the smallest amount of data you can dump to persistent storage
it was is kept in an instance of either of these classes.

This doesn't tell you what is contained in what.
For instance a SessionManager instance contains NodeInfo and Grant instances.
So you can chose to dump a whole SessionManager instance or just the
affected NodeInfo or Grant instances.

 *   ImpExp

     +   TokenHandler

     +   Item

         -   SessionToken

             -   IDToken

             -   AuthorizationCode

             -   RefreshToken

         -   Grant

             -   ExchangeGrant

     +   Database

         -   GrantManager

             -   SessionManager

     +   GrantMessage

     +   NodeInfo

         -   UserSessionInfo

         -   ClientSessionInfo

     +   OidcContext

         -   EndpointContext

         -   ServiceContext

     +   Service

         -   ServerMetadata

         -   Registration

         -   UserInfo

         -   BackChannelAuthentication

         -   ClientNotification

         -   RegistrationRead

         -   TokenExchange

         -   CCRefreshAccessToken

         -   CCAccessToken

         -   EndSession

         -   CheckID

         -   WebFinger

         -   CheckSession

     +   StateInterface

     +   DLDict


module
======

.. automodule:: idpyoidc.impexp
    :members:
    :undoc-members:
    :show-inheritance:

.. automodule:: idpyoidc.item
    :members:
    :undoc-members:
    :show-inheritance:
