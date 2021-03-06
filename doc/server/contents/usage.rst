Examples
********

Some examples, how to run [flask_op](https://github.com/IdentityPython/tree/master/example/flask_op) and
[django_op](https://github.com/peppelinux/django-oidc-op) but also some typical configuration in relation to common use cases.

Configure flask-rp
------------------

The client part of _idpyoidc_ is Relaying Party for tests.
You can run a working instance of `idpy-oidc.flask_rp` with:

    pip install git+https://github.com/IdentityPython/idpy-oidc.git

get entire project to have examples files
git clone https://github.com/IdentityPython/idpy-oidc.git
cd idpy-oidc/example/flask_rp

run it as it comes

    bash run.sh

Now you can connect to `https://127.0.0.1:8090/` to see the RP landing page and select your authentication endpoint.

Authentication examples
+++++++++++++++++++++++

![RP](../_images/1.png)

Get to the RP landing page to choose your authentication endpoint. The first option aims to use Provider Discovery.

![OP Auth](../_images/2.png)

The AS/OP supports dynamic client registration, it accepts the authentication request and prompt to us the login form. Read [passwd.json](https://github.com/IdentityPython/oidc-op/blob/master/example/flask_op/passwd.json) file to get credentials.

![Access](../_images/3.png)

The identity representation with the information fetched from the user info endpoint.

![Logout](../_images/4.png)

We can even test the single logout


Refresh token
-------------

Here an example about how to refresh a token.
It is important to consider that only scope=offline_access will get a usable refresh token::


    import requests

    CLIENT_ID = "DBP60x3KUQfCYWZlqFaS_Q"
    CLIENT_SECRET="8526270403788522b2444e87ea90c53bcafb984119cec92eeccc12f1"
    REFRESH_TOKEN = "Z0FBQUFBQ ... lN2JNODYtZThjMnFsZUNDcg=="

    data = {
        "grant_type" : "refresh_token",
        "client_id" : f"{CLIENT_ID}",
        "client_secret" : f"{CLIENT_SECRET}",
        "refresh_token" : f"{REFRESH_TOKEN}"
    }
    headers = {'Content-Type': "application/x-www-form-urlencoded" }
    response = requests.post(
        'https://127.0.0.1:8000/oidcop/token', verify=False, data=data, headers=headers
    )

The idpyoidc OP will return a json response like this::

    {
     'access_token': 'eyJhbGc ... CIOH_09tT_YVa_gyTqg',
     'token_type': 'Bearer',
     'scope': 'openid profile email address phone offline_access',
     'refresh_token': 'Z0FBQ ... 1TE16cm1Tdg=='
    }



Introspection endpoint
----------------------

Here an example about how to use a idpyoidc OP introspection endpoint.
This example uses a client with an HTTP Basic Authentication::

    import base64
    import requests

    TOKEN = "eyJhbGciOiJFUzI1NiIsImtpZCI6IlQwZGZTM1ZVYUcxS1ZubG9VVTQwUXpJMlMyMHpjSHBRYlMxdGIzZ3hZVWhCYzNGaFZWTlpTbWhMTUEifQ.eyJzY29wZSI6IFsib3BlbmlkIiwgInByb2ZpbGUiLCAiZW1haWwiLCAiYWRkcmVzcyIsICJwaG9uZSJdLCAiYXVkIjogWyJvTHlSajdzSkozWHZBWWplRENlOHJRIl0sICJqdGkiOiAiOWQzMjkzYjZiYmNjMTFlYmEzMmU5ODU0MWIwNzE1ZWQiLCAiY2xpZW50X2lkIjogIm9MeVJqN3NKSjNYdkFZamVEQ2U4clEiLCAic3ViIjogIm9MeVJqN3NKSjNYdkFZamVEQ2U4clEiLCAic2lkIjogIlowRkJRVUZCUW1keGJIVlpkRVJKYkZaUFkxQldaa0pQVUVGc1pHOUtWWFZ3VFdkZmVEY3diMVprYmpSamRrNXRMVzB4YTNnelExOHlRbHBHYTNRNVRHZEdUUzF1UW1sMlkzVnhjRE5sUm01dFRFSmxabGRXYVhJeFpFdHVSV2xtUzBKcExWTmFaRzV3VjJodU0yNXlSbTU0U1ZWVWRrWTRRM2x2UWs1TlpVUk9SazlGVlVsRWRteGhjWGx2UWxWRFdubG9WbTFvZGpORlVUSnBkaTFaUTFCcFptZFRabWRDVWt0YVNuaGtOalZCWVhkcGJFNXpaV2xOTTFCMk0yaE1jMDV0ZGxsUlRFc3dObWxsYUcxa1lrTkhkemhuU25OaWFWZE1kVUZzZDBwWFdWbzFiRWhEZFhGTFFXWTBPVzl5VjJOUk4zaGtPRDA9IiwgInR0eXBlIjogIlQiLCAiaXNzIjogImh0dHBzOi8vMTI3LjAuMC4xOjgwMDAiLCAiaWF0IjogMTYyMTc3NzMwNSwgImV4cCI6IDE2MjE3ODA5MDV9.pVqxUNznsoZu9ND18IEMJIHDOT6_HxzoFiTLsniNdbAdXTuOoiaKeRTqtDyjT9WuUPszdHkVjt5xxeFX8gQMuA"

    data = {
     'token': TOKEN,
     'token_type_hint': 'access_token'
    }

    _basic_secret = base64.b64encode(
        f'{"oLyRj7sJJ3XvAYjeDCe8rQ"}:{"53fb49f2a6501ec775355c89750dc416744a3253138d5a04e409b313"}'.encode()
    )
    headers = {
        'Authorization': f"Basic {_basic_secret.decode()}"
    }

    requests.post('https://127.0.0.1:8000/introspection', verify=False, data=data, headers=headers)


The idpyoidc OP will return a json response like this::

    {
      "active": true,
      "scope": "openid profile email address phone",
      "client_id": "oLyRj7sJJ3XvAYjeDCe8rQ",
      "token_type": "access_token",
      "exp": 0,
      "iat": 1621777305,
      "sub": "a7b0dea2958aec275a789d7d7dc8e7d09c6316dd4fc6ae92742ed3297e14dded",
      "iss": "https://127.0.0.1:8000",
      "aud": [
        "oLyRj7sJJ3XvAYjeDCe8rQ"
      ]
    }

Token exchange
--------------

Here an example about how to exchange an access token for a new access token.::

    import requests

    CLIENT_ID=""
    CLIENT_SECRET=""
    SUBJECT_TOKEN=""
    REQUESTED_TOKEN_TYPE="urn:ietf:params:oauth:token-type:access_token"

    data = {
        "grant_type" : "urn:ietf:params:oauth:grant-type:token-exchange",
        "requested_token_type" : f"{REQUESTED_TOKEN_TYPE}",
        "client_id" : f"{CLIENT_ID}",
        "client_secret" : f"{CLIENT_SECRET}",
        "subject_token" : f"{SUBJECT_TOKEN}"
    }
    headers = {'Content-Type': "application/x-www-form-urlencoded" }
    response = requests.post(
        'https://example.com/OIDC/token', verify=False, data=data, headers=headers
    )

The idpyoidc OP will return a json response like this::

    {
        "access_token": "eyJhbGciOiJFUzI1NiIsI...Bo6aQcOKEN-1U88jjKxLb-9Q",
        "scope": "openid email",
        "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "expires_in": 86400
    }

In order to request a refresh token the value of `requested_token_type` should be set to
`urn:ietf:params:oauth:token-type:refresh_token`.

The [RFC-8693](https://datatracker.ietf.org/doc/html/rfc8693) describes the `audience` parameter that
defines the authorized targets of a token exchange request.
If `subject_token = urn:ietf:params:oauth:token-type:refresh_token` then `audience` should not be
included in the token exchange request.
