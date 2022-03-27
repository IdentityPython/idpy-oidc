********************
The clients database
********************

Information kept about clients in the client database are to begin with the
client metadata as defined in
https://openid.net/specs/openid-connect-registration-1_0.html .

To that we have the following additions specified in OIDC extensions.

* https://openid.net/specs/openid-connect-rpinitiated-1_0.html
    + post_logout_redirect_uri
* https://openid.net/specs/openid-connect-frontchannel-1_0.html
    + frontchannel_logout_uri
    + frontchannel_logout_session_required
* https://openid.net/specs/openid-connect-backchannel-1_0.html#Backchannel
    + backchannel_logout_uri
    + backchannel_logout_session_required
* https://openid.net/specs/openid-connect-federation-1_0.html#rfc.section.3.1
    + client_registration_types
    + organization_name
    + signed_jwks_uri

And finally we add a number of parameters that are IdPyOidc specific.
These are described in this document.

===========================
Static Client configuration
===========================

In this section there are some client configuration examples. That can be used
to override the global configuration of the OP.

How to configure the release of the user claims per clients::

    endpoint_context.cdb["client_1"] = {
        "client_secret": "hemligt",
        "redirect_uris": [("https://example.com/cb", None)],
        "response_types": ["code", "token", "code id_token", "id_token"],
        "add_claims": {
            "always": {
                "introspection": ["nickname", "eduperson_scoped_affiliation"],
                "userinfo": ["picture", "phone_number"],
            },
            # this overload the general endpoint configuration for this client
            # self.server.server_get("endpoint", "id_token").kwargs = {"add_claims_by_scope": True}
            "by_scope": {
                "id_token": False,
            },
        },

The available configuration options are:

-------------
client_secret
-------------

The client secret. This parameter is required.

------------------------
client_secret_expires_at
------------------------

When the client_secret expires.

-------------
redirect_uris
-------------

The client's redirect uris.

-----------
auth_method
-----------

The auth_method that can be used per endpoint.
E.g::

    {
        "AccessTokenRequest": "client_secret_basic",
        ...
    }

------------
request_uris
------------

A list of `request_uris`.

See https://openid.net/specs/openid-connect-registration-1_0-29.html#ClientMetadata.

--------------
response_types
--------------

The allowed `response_types` for this client.

See https://openid.net/specs/openid-connect-registration-1_0-29.html#ClientMetadata.

---------------------
grant_types_supported
---------------------

Configure the allowed grant types on the token endpoint.

See https://openid.net/specs/openid-connect-registration-1_0-29.html#ClientMetadata.

----------------
scopes_to_claims
----------------

A dict defining the scopes that are allowed to be used per client and the claims
they map to (defaults to the scopes mapping described in the spec). If we want
to define a scope that doesn't map to claims (e.g. offline_access) then we
simply map it to an empty list. E.g.::

  {
    "scope_a": ["claim1", "claim2"],
    "scope_b": []
  }

--------------
allowed_scopes
--------------

A list with the scopes that are allowed to be used (defaults to the keys in the
clients scopes_to_claims).

-----------------------
revoke_refresh_on_issue
-----------------------

Configure whether to revoke the refresh token that was used to issue a new refresh token.

----------
add_claims
----------

A dictionary with the following keys

always
######

A dictionary with the following keys: `userinfo`, `id_token`, `introspection`, `access_token`.
The keys are used to describe the claims we want to add to the corresponding interface.
The keys can be a list of claims to be added or a dict in the format described
in https://openid.net/specs/openid-connect-core-1_0.html#IndividualClaimsRequests
E.g.::

    {
        "add_claims": {
            "always": {
              "userinfo": ["email", "phone"], # Always add "email" and "phone" in the userinfo response if such claims exists
              "id_token": {"email": null}, # Always add "email" in the id_token if such a claim exists
              "introspection": {"email": {"value": "a@a.com"}}, # Add "email" in the introspection response only if its value is "a@a.com"
            }
        }
    }

by_scope
########

A dictionary with the following keys: `userinfo`, `id_token`, `introspection`, `access_token`.
The keys are boolean values that describe whether the scopes should be mapped
to claims and added to the response.
E.g.::

    {
        "add_claims": {
            "by_scope": {
                id_token: True, # Map the requested scopes to claims and add them to the id token
    }

-----------------
token_usage_rules
-----------------

There are usage rules for tokens. Rules are set per token type (the basic set
of tokens are authorization_code, refresh_token, access_token and id_token).
The possible rules are:

+ how many times a token can be used
+ if other tokens can be minted based on this token
+ how fast they expire

A typical example (this is the default) would be::

    "token_usage_rules": {
        "authorization_code": {
            "max_usage": 1
            "supports_minting": ["access_token", "refresh_token"],
            "expires_in": 600,
        },
        "refresh_token": {
            "supports_minting": ["access_token"],
            "expires_in": -1
        },
    }

This then means that access_tokens can be used any number of times,
can not be used to mint other tokens and will expire after 300 seconds.
These are the default for any token. An authorization_code can only be used once
and it can be used to mint access_tokens and refresh_tokens. Note that normally
an authorization_code is used to mint several different types of tokens
at the same time. Such a multiple minting is counted as one usage.
And lastly an refresh_token can be used to mint access_tokens any number of
times. An *expires_in* of -1 means that the token will never expire.

If token_usage_rules are defined in the client metadata then it will be used
whenever a token is minted unless circumstances makes the OP modify the rules.

Also this does not mean that what is valid for a token can not be changed
during run time.

--------------
pkce_essential
--------------

Whether pkce is essential for this client.

------------------------
post_logout_redirect_uri
------------------------

The client's post logout redirect uris.

See https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout.

----------------------
backchannel_logout_uri
----------------------

The client's `backchannel_logout_uri`.

See https://openid.net/specs/openid-connect-backchannel-1_0.html#BCRegistration

-----------------------
frontchannel_logout_uri
-----------------------

The client's `frontchannel_logout_uri`.

See https://openid.net/specs/openid-connect-frontchannel-1_0.html#RPLogout

--------------------------
request_object_signing_alg
--------------------------

A list with the allowed algorithms for signing the request object.

See https://openid.net/specs/openid-connect-registration-1_0-29.html#ClientMetadata

-----------------------------
request_object_encryption_alg
-----------------------------

A list with the allowed alg algorithms for encrypting the request object.

See https://openid.net/specs/openid-connect-registration-1_0-29.html#ClientMetadata

-----------------------------
request_object_encryption_enc
-----------------------------

A list with the allowed enc algorithms for signing the request object.

See https://openid.net/specs/openid-connect-registration-1_0-29.html#ClientMetadata

----------------------------
userinfo_signed_response_alg
----------------------------

JWS alg algorithm [JWA] REQUIRED for signing UserInfo Responses.

See https://openid.net/specs/openid-connect-registration-1_0-29.html#ClientMetadata

-------------------------------
userinfo_encrypted_response_enc
-------------------------------

The alg algorithm [JWA] REQUIRED for encrypting UserInfo Responses.

See https://openid.net/specs/openid-connect-registration-1_0-29.html#ClientMetadata

-------------------------------
userinfo_encrypted_response_alg
-------------------------------

JWE enc algorithm [JWA] REQUIRED for encrypting UserInfo Responses.

See https://openid.net/specs/openid-connect-registration-1_0-29.html#ClientMetadata

----------------------------
id_token_signed_response_alg
----------------------------

JWS alg algorithm [JWA] REQUIRED for signing ID Token issued to this Client.

See https://openid.net/specs/openid-connect-registration-1_0-29.html#ClientMetadata

-------------------------------
id_token_encrypted_response_enc
-------------------------------

The alg algorithm [JWA] REQUIRED for encrypting ID Token issued to this Client.

See https://openid.net/specs/openid-connect-registration-1_0-29.html#ClientMetadata

-------------------------------
id_token_encrypted_response_alg
-------------------------------

JWE enc algorithm [JWA] REQUIRED for encrypting ID Token issued to this Client.

See https://openid.net/specs/openid-connect-registration-1_0-29.html#ClientMetadata

--------
dpop_jkt
--------

