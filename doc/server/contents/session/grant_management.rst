.. _grant-management:

Grant_management
================

About grant management
------------------------
.. _`About grant management`:

We needed a way of connecting a set of nodes with information in such a way
that they formed a directed path: a branch. Such a branch has a root, a
number of intermediate nodes and then a leaf. In our case the leaf is always
a Grant instance.

Furthermore any node (except the leaf node) may have more then one subordinates.

Database layout
+++++++++++++++
.. _`Database layout`:

The database has any number of layers. But there might only be one
branch pattern within a database instance.

A pattern represnts the type of object each node represents and the order
they appear in. For instance: user, client and grant. Where user is the
root node, client and intermediate and grant the leaf.

Patterns are represented as a list of types (defined by the parameter node_type).
Each item in the list is then
bound to a specific information class. Like 'user' to UserBranchInfo. This uses
the parameter node_info_class.

The branch pattern stipulates what nodes there are and in what order they
will appear. Each node has a unique type and and identifier.
The type is something like 'user' and 'client'. The identifier must be
unique among the nodes of a special type.

The information structure
-------------------------
.. _`The information structure`:

Branch identifier
+++++++++++++++++
.. _`Branch identifier`:

The key to the information kept in a branch is based
on the list identifiers for the objects in the branch.
If you only want the information kept in the root then you can construct the
key from a list with one item, namely the identifier of the object the root
is representing.
Adding one more identifier to the list allow you to construct the key to the
next node and so forth.

Example of a list of node identifiers::
    ["diana", "KtEST70jZx1x", "85544c9cace411ebab53559c5425fcc0"]

A *branch identifier* is constructed using the **branch_key** function.
It takes as input a list of identifiers.::

    branch_id = Database.branch_key(id_1, id_2)


Using the function **unpack_branch_key** you can get the node identifier from a
branch_id.::

    id_1, id_2 = Database.unpack_branch_id(branch_id)


Node information
++++++++++++++++
.. _`Node information`:

This is the basic class that keeps node information.

Expressed as a dictionary this can be::

    {
        'id': "diana",
        'revoked': False,
        'subordinate': ['KtEST70jZx1x']
    }


The parameters are:

id
::

An identifier for the node

revoked
:::::::

If a node is removed from the database, it and all it's subordinates are
removed. If a node is revoked then the subtree remains in the database.
This is useful if it's possible that the node and all its subordinates will
be restored in the near future.

subordinate
:::::::::::

A list of keys that points to subordinates to this node.

type
::::

The type of node this instance represents.

Grant information
+++++++++++++++++
.. _`Grant information`:

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

The parameters are described below

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

Token
+++++
.. _`Token`:

As mention above there are presently only 3 token types that are defined:

- authorization_code,
- access_token and
- refresh_token

A token can be described as follows::

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
    }


based_on
::::::::
    Reference to the token that was used to mint this token. Might be empty if the
    token was minted based on the grant it belongs to.

expires_at
::::::::::
When the token expires.
Its value is a JSON number representing the number
of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time.

id
::

An identifier

issued_at
:::::::::
When the token was created. Its value is a JSON number representing the number
of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time.

not_before
::::::::::
If the start of the usage of the token is to be delay, this is until when.
Its value is a JSON number representing the number
of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time.

revoked
:::::::
If the token has been revoked.

type
::::
The type of token.

value
:::::
This is the value that appears in OIDC protocol exchanges.

usage_rules
:::::::::::
Rules as to how this token can be used:

expires_in
    Used to calculate expires_at

supports_minting
    The tokens types that can be minted based on this token. Typically a code
    can be used to mint ID tokens and access and refresh tokens.

max_usage
    How many times this token can be used (being used is presently defined as
    used to mint other tokens). An authorization_code token can according to
    the OIDC standard only be used once but then to, in the same branch,
    mint more then one token.

used
::::
How many times the token has been used

The APIs
--------

NodeInfo API
++++++++++++
.. _`Node Info API`:

add_subordinate
:::::::::::::::
.. _`add_subordinate`:

    ...

remove_subordinate
::::::::::::::::::
.. _`removed_subordinate`:

    ...

revoke
::::::
.. _`revoke`:

    ...

is_revoked
::::::::::
.. _`is_revoked`:

    ...

keys
::::
.. _`keys`:

...


Grant API
+++++++++
.. _`Grant API`:

    ...

Token API
+++++++++
.. _`Token API`:

    ...

Branch Manager API
-------------------
.. _`Branch Manager API`:

    ...

add_grant
+++++++++
.. _add_grant:

    add_grant(self, user_id, client_id, \*\*kwargs)


add_exchange_grant
++++++++++++++++++
.. _add_exchange_grant:

    add_exchange_grant(self, user_id, client_id, \*\*kwargs)

get_node_info
+++++++++++++
.. _get_node_info:

    get_node_info(self, branch_id: str, level: Optional[int] = None)

branch_info
+++++++++++
.. _branch_info:

    branch_info(self, branch_id: str, \*args) -> dict


get_subordinates
+++++++++++++++++++++++
.. _get_subordinates:

    get_subordinates(self, path: List[str]) -> List[Union[NodeInfo, Grant]]

get_grant_argument
++++++++++++++++++++++++++
.. _get_grant_argument:

    get_grant_argument(self, branch_id: str, arg: str)

revoke_sub_tree
++++++++++++++++
.. _revoke_sub_tree:

    revoke_sub_tree(self, branch_id: str, level: Optional[int] = None)

grants
+++++++++++++++++++++++++
.. _grants:

    grants(self, path)

remove_branch
+++++++++++++
.. _remove_branch:

    remove_branch(self, branch_id: str)

flush
+++++
.. _flush:

    flush(self)


Module
++++++

.. automodule:: idpyoidc.server.session.grant_manager
    :members:
    :undoc-members:
    :show-inheritance:
