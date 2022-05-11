.. _config:

-----------------------
RP/Client Configuration
-----------------------

As you may have guessed by now a lot of the work you have to do to use this
packages lies in the RP configuration.

The configuration parameters fall into 2 groups, one general that is the
same for all RP/clients and one which is specific for a specific
OP/AS

General configuration parameters
--------------------------------

Among the general parameters you have to define:

port
    Which port the RP is listening on

domain
    The domain the RP belongs to

these 2 together then defines the base_url. which is normally defined as::

    base_url: "https://{domain}:{port}"

You can use the {domain} and {port} placeholders anywhere in the
configuration. It will automatically be replaced with the domain and
port values when the configuration is evaluated.

logging
    How the process should log

httpc_params
    Defines how the process performs HTTP requests to other entities.
    Parameters here are typically **verify** which controls whether the http
    client will verify the server TLS certificate or not.
    Other parameters are **client_cert**/**client_key** which are needed only
    if you expect the TLS server to ask for the clients TLS certificate.
    Something that happens if you run in an environment where mutual TLS is
    expected.

key_conf
    Definition of the private keys that all RPs are going to use in the OIDC
    protocol exchange.

There might be other parameters that you need dependent on which web framework
you chose to use.

OP/AS specific configuration parameters
---------------------------------------

The client configuration is keyed to an OP/AS name. This name should
be something human readable it does not have to in anyway be linked to the
issuer ID of the OP/AS.

The key **""** (the empty string) is chosen to represent all OP/ASs that
are dynamically discovered.

Disregarding if doing everything dynamically or statically you **MAY**
define which services the RP/Client should be able to use.
If you don't the default set it used.
The default set consists of the discovery, authorization, access_token and
refresh_access_token services if we're talking OAuth2 and the discovery,
registration, authorization, access_token, refresh_access_token and
userinfo services if we are talking OIDC.

services
    A specification of the usable services which possible changes to the
    default configuration of those service.

Static configuration
....................

If you have done manual client registration you will have to fill in these:

client_id
    The client identifier.

client_secret
    The client secret

redirect_uris
    A set of URLs from which the RP can chose one to be added to the
    authorization request. The expectation is that the OP/AS will redirect
    the use back to this URL after the authorization/authentication has
    completed. These URLs should be OP/AS specific.

behaviour
    Information about how the RP should behave towards the OP/AS. This is
    a set of attributes with values. The attributes taken from the
    `client metadata`_ specification. *behaviour* is used when the client
    has been registered statically and it is know what the client wants to
    use and the OP supports.

    Usage example::

        "behaviour": {
            "response_types": ["code"],
            "scope": ["openid", "profile", "email"],
            "token_endpoint_auth_method": ["client_secret_basic",
                                           'client_secret_post']
        }



Dynamic Configuration
.....................

If the provider info discovery is done dynamically you need these

client_preferences
    How the RP should prefer to behave against the OP/AS. The content are the
    same as for *behaviour*. The difference is that this is specified if the
    RP is expected to do dynamic client registration which means that at the
    point of writing the configuration it is only known what the RP can and
    wants to do but unknown what the OP supports.

issuer
    The Issuer ID of the OP.

allow
    If there is a deviation from the standard as to how the OP/AS behaves this
    gives you the possibility to say you are OK with the deviation.
    Presently there is only one thing you can allow and that is the *issuer*
    in the provider info is not the same as the URL you used to fetch the
    information.

.. _client metadata: https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata

-------------------------
RP configuration - Google
-------------------------

A working configuration where the client_id and client_secret is replaced
with dummy values::

    {
        "issuer": "https://accounts.google.com/",
        "client_id": "xxxxxxxxx.apps.googleusercontent.com",
        "client_secret": "2222222222",
        "redirect_uris": ["{}/authz_cb/google".format(BASEURL)],
        "behaviour": {
            "response_types": ["code"],
            "scope": ["openid", "profile", "email"],
            "token_endpoint_auth_method": ["client_secret_basic",
                                           'client_secret_post']
        },
        "services": {
            'ProviderInfoDiscovery': {},
            'Authorization': {},
            'AccessToken': {},
            'UserInfo': {}
        }
    }


Now piece by piece

Information provided by Google::

        "issuer": "https://accounts.google.com/",

Information about the client. When you register your RP with Google you will
in return get a client_id and client_secret::

        "client_id": "xxxxxxxxx.apps.googleusercontent.com",
        "client_secret": "2222222222",
        "redirect_uris": ["{}/authz_cb/google".format(BASEURL)],

Now to the behaviour of the client. Google specifies response_type *code* which
is reflected here. The scopes are picked form the set of possible scopes that
Google provides. And lastly the *token_endpoint_auth_method*, where Google
right now supports 2 variants both listed here. The RP will by default pick
the first if a list of possible values. Which in this case means the RP will
authenticate using the *client_secret_basic* if allowed by Google::

        "behaviour": {
            "response_types": ["code"],
            "scope": ["openid", "profile", "email"],
            "token_endpoint_auth_method": ["client_secret_basic",
                                           'client_secret_post']
        },

And lastly, which service the RP has access to. *ProviderInfoDiscovery* since
Google supports dynamic provider info discovery. *Authorization* always must be
there. *AccessToken* and *UserInfo* since response_type is *code* and Google
return the user info at the userinfo endpoint::


        "services": {
            'ProviderInfoDiscovery': {},
            'Authorization': {},
            'AccessToken': {},
            'UserInfo': {}
        }


----------------------------
RP configuration - Microsoft
----------------------------

Configuration that allows you to use a Microsoft OP as identity provider::

    {
        'issuer': 'https://login.microsoftonline.com/<tenant_id>/v2.0',
        'client_id': '242424242424',
        'client_secret': 'ipipipippipipippi',
        "redirect_uris": ["{}/authz_cb/microsoft".format(BASEURL)],
        "behaviour": {
            "response_types": ["id_token"],
            "scope": ["openid"],
            "token_endpoint_auth_method": ['client_secret_post'],
            "response_mode": 'form_post'
        },
        "allow": {
            "issuer_mismatch": True
        },
        "services": {
            'ProviderInfoDiscovery':{},
            'Authorization': {}
        }
    }

One piece at the time. Microsoft has something called a tenant. Either you
specify your RP to only one tenant in which case the issuer returned
as *iss* in the id_token will be the same as the *issuer*. If our RP
is expected to work in a multi-tenant environment then the *iss* will **never**
match issuer. Let's assume our RP works in a single-tenant context::

        'issuer': 'https://login.microsoftonline.com/<tenant_id>/v2.0',
        "allow": {
            "issuer_mismatch": True
        },

Information about the client. When you register your RP with Microsoft you will
in return get a client_id and client_secret::

        'client_id': '242424242424',
        'client_secret': 'ipipipippipipippi',
        "redirect_uris": ["{}/authz_cb/microsoft".format(BASEURL)],

Regarding the behaviour of the RP, Microsoft have chosen to only support the
response_type *id_token*. Microsoft have also chosen to return the authorization
response not in the fragment of the redirect URL which is the default but
instead using the response_mode *form_post*. *client_secret_post* is a
client authentication that Microsoft supports at the token enpoint::

        "behaviour": {
            "response_types": ["id_token"],
            "scope": ["openid"],
            "token_endpoint_auth_method": ['client_secret_post'],
            "response_mode": 'form_post'
        },

And lastly, which service the RP has access to. *ProviderInfoDiscovery* since
Microsoft supports dynamic provider info discovery. *Authorization* always must be
there. And in this case this is it. All the user info will be included in the
*id_token* that is returned in the authorization response::

        "services": {
            'ProviderInfoDiscovery':{},
            'Authorization': {}
        }


-------------------------
RP configuration - GitHub
-------------------------

As mentioned before GitHub runs an OAuth2 AS not an OP.
Still we can talk to it using this configuration::

    {
        "issuer": "https://github.com/login/oauth/authorize",
        'client_id': 'eeeeeeeee',
        'client_secret': 'aaaaaaaaaaaaa',
        "redirect_uris": ["{}/authz_cb/github".format(BASEURL)],
        "behaviour": {
            "response_types": ["code"],
            "scope": ["user", "public_repo"],
            "token_endpoint_auth_method": ['']
        },
        "provider_info": {
            "authorization_endpoint":
                "https://github.com/login/oauth/authorize",
            "token_endpoint":
                "https://github.com/login/oauth/access_token",
            "userinfo_endpoint":
                "https://api.github.com/user"
        },
        'services': {
            'Authorization': {},
            'AccessToken': {'response_body_type': 'urlencoded'},
            'UserInfo': {'default_authn_method': ''}
        }
    }

Part by part.
Like with Google and Microsoft, GitHub expects you to register your client in
advance. You register the redirect_uris and in return will get *client_id* and
*client_secret*::

        'client_id': 'eeeeeeeee',
        'client_secret': 'aaaaaaaaaaaaa',
        "redirect_uris": ["{}/authz_cb/github".format(BASEURL)],

Since GitHub doesn't support dynamic provder info discovery you have to enter
that information in the configuration::

        "issuer": "https://github.com/login/oauth/authorize",
        "provider_info": {
            "authorization_endpoint":
                "https://github.com/login/oauth/authorize",
            "token_endpoint":
                "https://github.com/login/oauth/access_token",
            "userinfo_endpoint":
                "https://api.github.com/user"
        },

Regarding the client behaviour the GitHub AS expects response_type *code*.
The number of scope values is rather large I've just chose 2 here.
No client authentication at the token endpoint is expected::

        "behaviour": {
            "response_types": ["code"],
            "scope": ["user", "public_repo"],
            "token_endpoint_auth_method": ['']
        },

And about services, *Authorization* as always, *AccessToken* to convert the
received *code* in the authorization response into an access token which later
can be used to access user info at the userinfo endpoint.
GitHub deviates from the standard in a number of way. First the Oauth2
standard doesn't mention anything like an userinfo endpoint, that is OIDC.
So GitHub has implemented something that is in between OAuth2 and OIDC.
What's more disturbing is that the access token response by default is not
encoded as a JSON document which the standard say but instead it's
urlencoded. Lucky for us, we can deal with both these things by configuration
rather then writing code.::

        'services': {
            'Authorization': {},
            'AccessToken': {'response_body_type': 'urlencoded'},
            'UserInfo': {'default_authn_method': ''}
        }

