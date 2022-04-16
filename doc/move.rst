.. _move:

********************************************************
How to move from oidcmsg,oidcrp and oidc-op to idpy-oidc
********************************************************

Since you are here the chance that you are using OidcRP and/or oidc-op is very
high. Hopefully you are happy with what the packages has provided you with
so far. But somehow you have now learned that idpy-oidc is where the
action will be in the future so you want to know what it takes to move
from OidcRP and/or oidc-op to idpy-oidc.

idpy-oidc is collecting the three original packages into one:

* OidcMsg -> idpy-oidc/message
* OidcRP -> idpy-oidc/client
* oidc-op -> idpy-oidc/server

Some of the functionality that was in OidcMsg because it was needed by
both OidcRP and oidc-op is now placed at the root of idpy-oidc.
We will do them one by one

OidcRP
------

If you have kept yourself to always using the high level api moving

You probably can get away only doing what I descibe below.
These are the steps I had to take to get the example/flask_rp RP working.

1) Created a file, named script_py.sed with this content::

    s/from oidcop.server import Server/from idpyoidc.server import Server/g
    s/oidcop/idpyoidc.server/g
    s/oidcrp/idpyoidc.client/g
    s/oidcmsg/idpyoidc.message/g
    s/idpyoidc.message.configure/idpyoidc.configure/g
    s/idpyoidc.message.client/idpyoidc.client/g
    s/idpyoidc.message.ssl_context/idpyoidc.ssl_context/g
    s/from idpyoidc.client.util import create_context/from idpyoidc.ssl_context import create_context/g

2) Create another file, named script_json.sed with this content::

    s/oidcop/idpyoidc.server/g
    s/oidcrp/idpyoidc.client/g
    s/oidcmsg/idpyoidc.message/g

3) Ran the commands::

    find . -name "*.py" -exec sed -i '' -f script_py.sed {} \;
    find . -name "*.json" -exec sed -i '' -f script_json.sed {} \;

And I was able to successfully launch the RP.
This worked for me, it might be enough for you too. If not you can probably
figure out what needs changing. If you do I'd appreciate letting me know
so I can add those steps to this document.

oidc-op
-------

Getting oidc-op/example/flask_op running was a bit trickier but not a lot.

Started of with creating the sed script files:

1) Created a file, named script_py.sed with this content::

    s/from oidcop.server import Server/from idpyoidc.server import Server/g
    s/oidcop/idpyoidc.server/g
    s/oidcrp/idpyoidc.client/g
    s/oidcmsg/idpyoidc.message/g
    s/idpyoidc.message.configure/idpyoidc.configure/g
    s/idpyoidc.message.client/idpyoidc.client/g
    s/idpyoidc.message.ssl_context/idpyoidc.ssl_context/g
    s/from idpyoidc.server.utils import create_context/from idpyoidc.ssl_context import create_context/g

2) Create another file, named script_json.sed with this content::

    s/oidcop/idpyoidc.server/g
    s/oidcrp/idpyoidc.client/g
    s/oidcmsg/idpyoidc.message/g

3) Ran the commands::

    find . -name "*.py" -exec sed -i '' -f script_py.sed {} \;
    find . -name "*.json" -exec sed -i '' -f script_json.sed {} \;

Now, I had to edit 2 files.

views.py
++++++++

Removed the single line (22)::

    from oidcop.exception import TokenAuthenticationError

and the lines (233-238::

         except TokenAuthenticationError as err:
             _log.error(err)
             return make_response(json.dumps({
                 'error': 'invalid_token',
                 'error_description': str(err)
             }), 401)


config.json
+++++++++++

Removed the line (312) ::

    "jwks_file": "private/token_jwks.json",

And that was it.