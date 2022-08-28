Grants
======
.. _`Grants`:

Grants are created by an authorization subsystem in an AS/OP. If the grant is
created in connection with an user authentication the authorization system
might normally ask the user for usage consent and then base the construction
of the grant on that consent.

If an authorization server can act as a Security Token Service (STS) as
defined by `Token Exchange [RFC-8693] <https://tools.ietf.org/html/rfc8693>`_
then no user is involved. In the context of branch management the STS is
equivalent to a user.

Grant information contains information about user consent and issued tokens.::

    {
        "type": "grant",
        "scope": ["openid", "research_and_scholarship"],
        "authorization_details": null,
        "claims": {
            "userinfo": {
                "sub": null,
                "name": null,
                "given_name": null,
                "family_name": null,
                "email": null,
                "email_verified": null,
                "eduperson_scoped_affiliation": null
            }
        },
        "resources": ["client_1"],
        "issued_at": 1605452123,
        "not_before": 0,
        "expires_at": 0,
        "revoked": false,
        "issued_token": [
            {
                "type": "authorization_code",
                "issued_at": 1605452123,
                "not_before": 0,
                "expires_at": 1605452423,
                "revoked": false,
                "value": "Z0FBQUFBQmZzVUZieDFWZy1fbjE2ckxvZkFTVC1ZTHJIVlk0Z09tOVk1M0RsOVNDbkdfLTIxTUhILWs4T29kM1lmV015UEN1UGxrWkxLTkVXOEg1WVJLNjh3MGlhMVdSRWhYcUY4cGdBQkJEbzJUWUQ3UGxTUWlJVDNFUHFlb29PWUFKcjNXeHdRM1hDYzRIZnFrYjhVZnIyTFhvZ2Y0NUhjR1VBdzE0STVEWmJ3WkttTk1OYXQtTHNtdHJwYk1nWnl3MUJqSkdWZGFtdVNfY21VNXQxY3VzalpIczBWbGFueVk0TVZ2N2d2d0hVWTF4WG56TDJ6bz0=",
                "usage_rules": {
                    "expires_in": 300,
                    "supports_minting": [
                        "access_token",
                        "refresh_token",
                        "id_token"
                    ],
                    "max_usage": 1
                    },
                "used": 0,
                "based_on": null,
                "id": "96d19bea275211eba43bacde48001122"
           },
           {
                "type": "access_token",
                "issued_at": 1605452123,
                "not_before": 0,
                "expires_at": 1605452723,
                "revoked": false,
                "value": "Z0FBQUFBQmZzVUZiaWVRbi1IS2k0VW4wVDY1ZmJHeEVCR1hVODBaQXR6MWkzelNBRFpOS2tRM3p4WWY5Y1J6dk5IWWpnelRETGVpSG52b0d4RGhjOWphdWp4eW5xZEJwQzliaS16cXFCcmRFbVJqUldsR1Z3SHdTVVlWbkpHak54TmJaSTV2T3NEQ0Y1WFkxQkFyamZHbmd4V0RHQ3k1MVczYlYwakEyM010SGoyZk9tUVVxbWdYUzBvMmRRNVlZMUhRSnM4WFd2QzRkVmtWNVJ1aVdJSXQyWnpVTlRiZnMtcVhKTklGdzBzdDJ3RkRnc1A1UEw2Yz0=",
                "usage_rules": {
                    "expires_in": 600,
                },
                "used": 0,
                "based_on": "Z0FBQUFBQmZzVUZieDFWZy1fbjE2ckxvZkFTVC1ZTHJIVlk0Z09tOVk1M0RsOVNDbkdfLTIxTUhILWs4T29kM1lmV015UEN1UGxrWkxLTkVXOEg1WVJLNjh3MGlhMVdSRWhYcUY4cGdBQkJEbzJUWUQ3UGxTUWlJVDNFUHFlb29PWUFKcjNXeHdRM1hDYzRIZnFrYjhVZnIyTFhvZ2Y0NUhjR1VBdzE0STVEWmJ3WkttTk1OYXQtTHNtdHJwYk1nWnl3MUJqSkdWZGFtdVNfY21VNXQxY3VzalpIczBWbGFueVk0TVZ2N2d2d0hVWTF4WG56TDJ6bz0=",
                "id": "96d1c840275211eba43bacde48001122"
           }
        ],
        "id": "96d16d3c275211eba43bacde48001122"
    }


Attributes
----------

scope
:::::

This is the scope that was chosen for this grant. Either by the user or by
some rules that the Authorization Server runs by.

authorization_details
:::::::::::::::::::::

Presently a place hold. But this is expected to be information on how the
authorization was performed. What input was used and so on.
Defined in draft-lodderstedt-oauth-rar .

authentication_event
::::::::::::::::::::

Information about the authentication event.

authorization_request
:::::::::::::::::::::

The authorization request that this grant is based on. In some case there
is no authorization so this parameter may be absent (=None)

claims
::::::

The set of claims that should be returned in different circumstances. The
syntax that is defined in
https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
is used. With one addition, beside *userinfo* and *id_token* we have added
*introspection*.

expires_at
::::::::::
When the grant expires.
Its value is a JSON number representing the number
of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time.

id
::
The grant identifier.

issued_at
:::::::::

When the grant was created. Its value is a JSON number representing the number
of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time.

issued_token
::::::::::::
Tokens that has been issued based on this grant. There is no limitation
as to which tokens can be issued. Though presently we only have:

- authorization_code,
- access_token and
- refresh_token

not_before
::::::::::
If the usage of the grant should be delay, this is when it can start being used.
Its value is a JSON number representing the number
of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time.

remove_inactive_token
:::::::::::::::::::::

A boolean. If True means that inactive tokens should be removed from the
database. If there is a remember_token function is specified then that function
will be called with the token as argument before the token is removed from the
database.

remember_token
::::::::::::::

Points to a callable function that can be used to store a token in some
permanent place from which it can be retrieved at a later date.

resources
:::::::::

This are the resource servers and other entities that should be accepted
as users of issued access tokens.

revoked
:::::::
If the grant has been revoked. If a grant is revoked all tokens issued
based on that grant are also revoked.

Module
------

.. automodule:: idpyoidc.server.session.grant
    :members:
    :undoc-members:
    :show-inheritance:
