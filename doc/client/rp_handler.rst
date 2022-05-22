.. _oidcrp_rp:

*************************
The Relying Party Handler
*************************

------------
Introduction
------------

Imaging that you have a web service where some of the functions that the service
provides are protected and should only be accessible to authenticated users or
that some of the functions the service provides, needs access to some user
related resources on a resource server. That's when you need OpenID Connect
(OIDC) or Oauth2.

The RPHandler is implemented in :py:class:`idpyoidc.client.rp_handler.RPHandler`
It is a service within the web service that handles user authentication and access
authorization on behalf of the web service.

---------------
Some background
---------------

In the following description I will talk about Relying Party (RP)
and OpenID Connect Provider (OP) but I could have talked about Oauth2 Client
and OAuth2 Authorization Server instead. There are some differences
in the details between the two sets but overall the entities work much the same
way.

OAuth2 and thereby OpenID Connect (OIDC) are built on a request-response paradigm.
The RP issues a request and the OP returns a response.

The OIDC and OAuth2 core standards defines a set of such request-responses.
This is a basic list of the OIDC request-responses and the normal sequence in
which they occur:

1. Provider discovery (WebFinger)
2. Provider Info Discovery
3. Client registration
4. Authorization/Authentication
5. Access token
6. User info

When a user accessing the web service for some reason needs to be authenticate
or the service needs an access token that allows it to access some resources
at a resource service on behalf of the user a number of things will happen:

Find out which OP to talk to.
    If the RP handler is configured to only communicate to a defined set of OPs
    then the user is probable presented a list to choose from.
    If the OP the user wants to authenticated at is unknown to the RP Handler
    it will use some discovery service to, given some information provided by
    the user, find out where to learn more about the OP.

Gather information about the OP
    This can be done out-of-band in which case the administrator of the service
    has gathered the information by contacting the administrator of the OP.
    In most cases this is done by reading the necessary information on a web
    page provided by the organization responsible for the OP.
    One can also chose to gather the information on-the-fly by using the
    provider info discovery service provided by OIDC.

Register the client with the OP
    Again, this can be done beforehand or it can be done on-the-fly when needed.
    If it's done before you will have to use a registration service provided by
    the organization responsible for the OP.
    If it's to be done on-the-fly you will have to use the dynamic client
    registration service OIDC provides

Authentication/Authorization
    This is done by the user at the OP.

What happens after this depends on which *response_type* is used. If the
*response_type* is **code** then the following step is done:

Access token request
    Base on the information received in the authorization response a request
    for an access token is made to the OP

And if the web service wants user information it might also have to do:

Obtain user info
    Using the access token received above a userinfo request will be sent to the
    OP.

Which of the above listed services that your RP will use when talking to an OP
are usually decided by the OP. Just to show you how it can differ between
different OPs I'll give you a couple of examples below:

Google
    If you want to use the Google OP as authentication service you should know
    that it is a true OIDC OP `certified`_ by the OpenID Foundation. You will
    have to manually register you RP at Google but getting Provider info can be
    done dynamically using an OIDC service. With Google you will use the
    response_type *code*. This means that you will need services 2,4,5 and 6
    from the list above. More about how you will accomplish this below

Microsoft
    Microsoft have chosen to only support response_type *id_token* and to
    return all the user information in the **id_token**. Microsoft's OP
    supports dynamic Provider info discovery but client registration is
    done manual. What it comes down to is that you will only need services
    2 and 4.

GitHub
    Now, to begin with GitHub is not running an OP they basically have an
    Oauth2 AS with some additions. It doesn't support dynamic provider info
    discovery or client registration. If expects response_type to be *code*
    so services 4,5 and 6 are needed.

.. _certified : http://openid.net/certification/

After this background you should now be prepared to dive into how the RP handler
should be used.

--------------
RP handler API
--------------

A session is defined as a sequence of request/responses used to cope with
authorization/authentication for one user at one OP,
starting with the authorization request.

Tier 1 API
----------

The high-level methods you have access to (in the order they are to be
used) are:

:py:meth:`idpyoidc.client.rp_handler.RPHandler.begin`
    This method will initiate a RP/Client instance if none exists for the
    OP/AS in question. It will then run service 1 if needed, services 2 and 3
    according to configuration and finally will construct the authorization
    request.

    Usage example::

        $ from idpyoidc.client import RPHandler
        $ rph = RPHandler()
        $ issuer_id = "https://example.org/"
        $ info = rph.begin(issuer_id)
        $ print(info['url'])
        https://example.org/op/authorization?state=Oh3w3gKlvoM2ehFqlxI3HIK5&nonce=UvudLKz287YByZdsY3AJoPAlEXQkJ0dK&redirect_uri=https%3A%2F%2Fexample.com%2Frp%2Fauthz_cb&response_type=code&scope=openid&client_id=zls2qhN1jO6A

What happens next is that the user is redirected to the URL shown above.
After the user has authenticated, handled consent and access management
the user will be redirect back to the URL provided as value to the
redirect_uri parameter in the URL above. The query part may look something
like this::

    state=Oh3w3gKlvoM2ehFqlxI3HIK5&scope=openid&code=Z0FBQUFBQmFkdFFjUVpFWE81SHU5N1N4N01&iss=https%3A%2F%2Fexample.org%2Fop&client_id=zls2qhN1jO6A

After the RP has received this response the processing continues with:

:py:meth:`idpyoidc.client.rp_handler.RPHandler.get_session_information`
    In the authorization response there MUST be a state parameter. The value
    of that parameter is the key into a data store that will provide you
    with information about the session so far.

    Usage example (kwargs are the set of claims in the authorization response)::

        session_info = rph.state_db_interface.get_state(kwargs['state'])

:py:meth:`idpyoidc.client.rp_handler.RPHandler.finalize`
    Will parse the authorization response and depending on the configuration
    run the services 5 and 6.

    Usage example::

        res = rph.finalize(session_info['iss'], kwargs)


Tier 2 API
----------

The tier 1 API is good for getting you started with authenticating a user and
getting user information but if you're look at a long-term engagement you need
a finer grained set of methods. These I call the tier 2 API:

:py:meth:`idpyoidc.client.rp_handler.RPHandler.do_provider_info`
    Either get the provider info from configuration or through dynamic
    discovery. Will overwrite previously saved provider metadata.

:py:meth:`idpyoidc.client.rp_handler.RPHandler.do_client_registration`
    Do dynamic client registration is configured to do so and the OP supports it.

:py:meth:`idpyoidc.client.rp_handler.RPHandler.init_authorization`
    Initialize an authorization/authentication event. If the user has a
    previous session stored this will not overwrite that but will create a new
    one.

    Usage example (note that you can modify what would be used by default)::

        res = self.rph.init_authorization(state_key,
                                          {'scope': ['openid', 'email']})

The state_key you see mentioned here and below is the value of the state
parameter in the authorization request.

:py:meth:`idpyoidc.client.rp_handler.RPHandler.get_access_token`
    Will use an access code received as the response to an
    authentication/authorization to get an access token from the OP/AS.
    Access codes can only be used once.

    Usage example::

        res = self.rph.get_access_token(state_key)

:py:meth:`idpyoidc.client.rp_handler.RPHandler.refresh_access_token`
    If the client has received a refresh token this method can be used to get
    a new access token.

    Usage example::

        res = self.rph.refresh_access_token(state_key, scope='openid email')

You may change the set of scopes that are bound to the new access token but
that change can only be a downgrade from what was specified in the
authorization request and accepted by the user.

:py:meth:`idpyoidc.client.rp_handler.RPHandler.get_user_info`
    If the client is allowed to do so, it can refresh the user info by
    requesting user information from the userinfo endpoint.

    Usage example::

        resp = self.rph.get_user_info(state_key)

:py:meth:`idpyoidc.client.rp_handler.RPHandler.has_active_authentication`
    After a while when the user returns after having been away for a while
    you may want to know if you should let her reauthenticate or not.
    This method will tell you if the last done authentication is still
    valid or of it has timed out.

    Usage example::

        resp = self.rph.has_active_authentication(state_key)

    response will be True or False depending in the state of the authentication.

:py:meth:`idpyoidc.client.rp_handler.RPHandler.get_valid_access_token`
    When you are issued a access token it normally comes with a life time.
    After that time you are expected to use the refresh token to get a new
    access token. There are 2 ways of finding out if the access token you have is
    past its life time. You can use this method or you can just try using
    the access token and see what happens.

    Now, if you use this method and it tells you that you have an access token
    that should still be usable, that is no guarantee it is still usable.
    Things may have happened on the OPs side that makes the access token
    invalid. So if this method only returns a hint as to the usability of the
    access token.

    Usage example::

        resp = self.rph.get_valid_access_token(state_key)

    Response will be a tuple containing with the access token and the
    expiration time (in epoch) if there is a valid access token otherwise an
    exception will be raised.

