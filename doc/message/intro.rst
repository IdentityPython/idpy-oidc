.. _oidcmsg_intro:

***********************
Introduction to message
***********************

The OpenID Connect and OAuth2 standards both defines lots of messages.
Requests that are sent from clients to servers and responses returned from
servers to clients.

For each of these messages a number of parameters (claims) are listed, some
of them required and some optional. Each parameter are also assigned a data type.

What is also defined in the standard is the on-the-wire representation of
these messages. Like if they are the fragment component of a redirect URI or a
JSON document transferred in the body of a response.

The :py:class:`idpyoidc.message.Message` class is supposed to capture all of this.

Using this class you should be able to:

    - build a message,
    - verify that a message's parameters are correct, that all that are marked as required are present and all (required and optional) are of the right type
    - serialize the message into the correct on-the-wire representation
    - deserialize a received message from the on-the-wire representation into a :py:class:`idpyoidc.message.Message` instance.
    - gracefully handle extra claims.

I will try to walk you through these steps below using example from RFC6749 (section
4.1 and 4.2).

The :py:class:`idpyoidc.message.Message` class is the base class. The idpyoidc
package contains subclasses representing all the messages defined in
OpenID Connect and OAuth2.

This intro hopes to give you an overview of what you can do with the package.
More specific descriptions can be found under *howto*.

Entity sending a message
------------------------

Going from a set of attributes with values how would you go about creating an
authorization request ? You could do something like this::

    from idpyoidc.message.oauth2 import AuthorizationRequest

    request_parameters = {
        "response_type": "code",
        "client_id": "s6BhdRkqt3",
        "state": "xyz",
        "redirect_uri": "https://client.example.com/cb"
    }

    message = AuthorizationRequest(**request_parameters)

    authorization_endpoint = "https://server.example.com/authorize"

    authorization_request = message.request(authorization_endpoint)

The resulting request will look like this ::

    https://server.example.com/authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb


If we continue with the client sending an access token request there is a
pattern emerging::

    from idpyoidc.message.oauth2 import AccessTokenRequest

    request = {
        'grant_type':'authorization_code',
        'code':'SplxlOBeZQQYbYS6WxSbIA',
        'redirect_uri':'https://client.example%2Ecom%2Fcb'
    }

    message = AccessTokenRequest(**request)

    access_token_request = message.to_urlencoded()

The resulting request will look like this::

    grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA&redirect_uri=https%3A%2F%2Fclient.example%252Ecom%252Fcb

Ready to be put in the HTTP POST body sent to the token endpoint.

The pattern is:

    1. Collect the parameters (with values) that are to appear in the request
    2. Chose the appropriate Message subclass
    3. Initiate the sub class with the collected information
    4. Serialize the message into whatever format is appropriate

Now, I have given examples on how a client would construct a request but of course
there is not difference between this and a server constructing a response.
The set of parameters might differ and the message sub class to be used is
definitely different but the process is the same.

Entity receiving a message
--------------------------

Now the other side of the coin. An entity receives a message from its opponent.
What to do ?

Again I'll start with an example and again we'll take the view of the client.
The client has sent an authorization request, the user has been redirected to
authenticate and decide on what permissions to grant and finally the server
has redirect the user-agent back to the client by sending the HTTP response::

    https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz

On the client it would get hold of the query part and then go from there::

    from idpyoidc.message.oauth2 import AuthorizationResponse

    query_component = 'code=SplxlOBeZQQYbYS6WxSbIA&state=xyz'

    response = AuthorizationResponse().from_urlencoded(query_conponent)

    print(response.verify())
    print(response)

The result of this will be::

    True
    {'code': 'SplxlOBeZQQYbYS6WxSbIA', 'state': 'xyz'}

Similar when it comes to the response from the token endpoint::

    from idpyoidc.message.oauth2 import AccessTokenResponse

    http_response_body = '{"access_token":"2YotnFZFEjr1zCsicMWpAA",' \
                         '"token_type":"example","expires_in":3600,' \
                         '"refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",' \
                         '"example_parameter":"example_value"}'

    response = AccessTokenResponse().from_json(http_response_body)

    print(response.verify())
    print(response)

and this time the result will be::

    True
    {'access_token': '2YotnFZFEjr1zCsicMWpAA', 'token_type': 'example', 'expires_in': 3600, 'refresh_token': 'tGzv3JOkF0XG5Qx2TlKWIA', 'example_parameter': 'example_value'}

The processing pattern on the receiving end is:

    1. Pick out the protocol message part of the response
    2. Initiate the correct message subclass and run the appropriate
       deserializer method.
    3. Verify the correctness of the response


What if the response received was an error message ?
----------------------------------------------------

All the response subclasses are subclasses of
:py:class:`idpyoidc.message.oauth2.ResponseMessage` and that class provides you with one
method that is useful in this case::

    >>> from idpyoidc.message.oauth2 import AccessTokenResponse
    >>> response = {'error':'invalid_client'}
    >>> message = AccessTokenResponse(**response)
    >>> message.is_error_message()
    True

Serialization methods
---------------------

*idpyoidc* supports 3 different serialization/deserialization methods:

    urlencoded
        URL encoding converts characters into a format that can be transmitted
        over the Internet. URL encoding is described in RFC 3986
    json
        JavaScript Object Notation is a lightweight data-interchange format
        (https://www.json.org/)
    jwt
        Json Web Token specified in `RFC7519`__

There is a forth but that is just for internal use and that is to/from
a python dictionary.

To use either of these there are a number of direct methods you can use:

    - to_urlencoded/from_urlencoded
    - to_json/from_json
    - to_jwt/from_jwt

An example::

    >>> from idpyoidc.message.oic import AccessTokenRequest
    >>> params = {
    ...     'grant_type':'authorization_code',
    ...     'code':'SplxlOBeZQQYbYS6WxSbIA',
    ...     'redirect_uri':'https://client.example%2Ecom%2Fcb'
    ...     }
    >>> request = AccessTokenRequest(**params)
    >>> print(request.to_urlencoded())
    grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA&redirect_uri=https%3A%2F%2Fclient.example%252Ecom%252Fcb
    >>> print(request.to_json())
    {"grant_type": "authorization_code", "code": "SplxlOBeZQQYbYS6WxSbIA", "redirect_uri": "https://client.example%2Ecom%2Fcb"}

*to_jwt* is a little bit more difficult since you need a couple of arguments.
Starting with the same request as in the example above and using symmetric key
crypto::

    >>> from cryptojwt.jwk import SYMKey
    >>> keys = [SYMKey(key="A1B2C3D4")]
    >>> print(request.to_jwt(keys, algorithm="HS256")
    eyJhbGciOiJIUzI1NiJ9.eyJncmFudF90eXBlIjogImF1dGhvcml6YXRpb25fY29kZSIsICJjb2RlIjogIlNwbHhsT0JlWlFRWWJZUzZXeFNiSUEiLCAicmVkaXJlY3RfdXJpIjogImh0dHBzOi8vY2xpZW50LmV4YW1wbGUlMkVjb20lMkZjYiJ9.PuzT0r7iEV99fRA9d6zz0Farf2qhQR2Tua0Z4Luar9g

Deserializing
-------------

Deserializing is as easy as serializing::

    >>> from idpyoidc.message.oic import AccessTokenRequest
    >>> params = {
    ...     'grant_type':'authorization_code',
    ...     'code':'SplxlOBeZQQYbYS6WxSbIA',
    ...     'redirect_uri':'https://client.example%2Ecom%2Fcb'
    ...     }
    >>> request = AccessTokenRequest(**params)
    >>> msg_url = request.to_urlencoded()
    >>> parsed_urlenc = AccessTokenRequest().from_urlencoded(msg_url)
    >>> print(parsed_urlenc)
    {'grant_type': 'authorization_code', 'code': 'SplxlOBeZQQYbYS6WxSbIA', 'redirect_uri': 'https://client.example%2Ecom%2Fcb'}
    >>> msg_json = request.to_json()
    >>> parsed_json = AccessTokenRequest().from_json(msg_json)
    >>> print(parsed_json)
    {'grant_type': 'authorization_code', 'code': 'SplxlOBeZQQYbYS6WxSbIA', 'redirect_uri': 'https://client.example%2Ecom%2Fcb'}
    >>> from cryptojwt.jwk.hmac import SYMKey
    >>> keys = [SYMKey(key="A1B2C3D4")]
    >>> msg_jws = request.to_jwt(keys, algorithm="HS256")
    >>> parsed_jwt = AccessTokenRequest().from_jwt(msg_jws, keys)
    >>> print(parsed_jwt)
    {'grant_type': 'authorization_code', 'code': 'SplxlOBeZQQYbYS6WxSbIA', 'redirect_uri': 'https://client.example%2Ecom%2Fcb'}
    >>> print(parsed_jwt.jws_header)
    >>> {'alg': 'HS256'}

Note the last line. When you have parsed a signed JWT the resulting class
instance contains as extra information the header of the signed JWT.
Note also that a signed JWT constructed this way will **not** contain any
extra information beside the information in the request.
If you want to create a signed JWT which contains issuer, intended audience
and more then you should use the :py:class:`cryptojwt.jwt.JWT` class.
More about that below.

Json Web Token
--------------

There as cases in OpenID connect where you want to fill a signed JWT with
a lot of metadata. One such is when you construct an ID Token.
The *to_jwt* method in :py:class:`idpyoidc.message.Message` will not add
any extra information for you. :py:class:`cryptojwt.jwt.JWT` does.

Nothing beats an example::


    >>> BOB = 'https://bob.example.com'
    >>> kj = KeyJar()
    >>> kj.add_symmetric(owner='', key='client_secret', usage=['sig'])
    >>> alice = JWT(kj, iss=ALICE, alg="HS256")
    >>> payload = {'sub': 'subject_id'}
    >>> _jws = alice.pack(payload=payload, recv=BOB)
    >>> kj[ALICE] = kj['']
    >>> bob = JWT(kj, iss=BOB, alg='HS256)
    >>> info = bob.unpack(_jws)
    >>> print(info)
    {'iss': 'https://alice.example.org', 'iat': 1518619782, 'aud': ['https://bob.example.com'], 'sub': 'subject_id'}
    >>> type(info)
    <class 'idpyoidc.oic.JsonWebToken'>
    >>> print(info.jws_header)
    {'alg': 'HS256'}

To walk through what's happening about. We first need a
:py:class:`cryptojwt.key_jar.KeyJar` instance with the needed keys.
We only have one key in this example, a symmetric key.
This *keyjar* is what alice uses when she wants to sign the JWT.
When she initiates the :py:class:`cryptojwt.jwt.JWT` class she sets a set of default
values, like signing algorithm and her own issuer ID.
When constructing the signed JWT she uses the *pack* method that as
arguments takes payload and receiver.

Now we turn to Bob. He has his own *keyjar* containing the symmetric key marked
to belong to alice. This is important since that binding will be used when
unpacking the signed JWT. The method will look inside the payload to find the
issuer and from there find usable keys in the *keyjar*.

To set the issuer to BOB when initiating the JWT is necessary because the
value on that will be matched against the audience of the signed JWT.

Let's assume that Eve wanted to listen in and had access to the key::

    >>> eve = JWT(kj, iss='https://eve.example.com')
    >>> info = eve.unpack(_jws)
    Traceback (most recent call last):
      File "<stdin>", line 1, in <module>
      File "/Library/Frameworks/Python.framework/Versions/3.6/lib/python3.6/site-packages/cryptojwt-0.0.1-py3.6.egg/cryptojwt/jwt.py", line 297, in unpack
        _info = self.verify_profile(_msg_cls, _info, **vp_args)
      File "/Library/Frameworks/Python.framework/Versions/3.6/lib/python3.6/site-packages/cryptojwt-0.0.1-py3.6.egg/cryptojwt/jwt.py", line 234, in verify_profile
        if not _msg.verify(**kwargs):
      File "/Library/Frameworks/Python.framework/Versions/3.6/lib/python3.6/site-packages/idpyoidc-0.0.1-py3.6.egg/idpyoidc/oic/__init__.py", line 946, in verify
        raise NotForMe('Not among intended audience')
    idpyoidc.exception.NotForMe: Not among intended audience

Now Eve probably wouldn't care but there you are.

__ https://www.rfc-editor.org/rfc/rfc7519.txt