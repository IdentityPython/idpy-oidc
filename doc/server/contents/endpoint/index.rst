.. _server-endpoints:

================
Server Endpoints
================

.. toctree::

    oauth2/index.rst
    oidc/index.rst

==================
Endpoint behaviour
==================

All the endpoint behave in a similar manner.

When an endpoint receives a request it has to do a number of things:

- Verify that the client can issue the request (client authentication/authorization)
- Verify that the request is correct and that it contains the necessary information.
- Process the request, which includes applying server policies and gathering information.
- Construct the response
- Return the response

I should note at this point that this package is expected to work within the
confines of a web server framework such that the actual receiving and sending
of the HTTP messages are dealt with by the framework.

Based on the actions an endpoint has to perform, a method call structure
has been constructed. It looks like this:

1. parse_request

    - client_authentication (*)
    - post_parse_request (*)

2. process_request

3. do_response

    - response_info
        - construct
            - pre_construct (*)
            - _parse_args
            - post_construct (*)
    - update_http_args

Steps marked with '*' are places where extensions can be applied.

*parse_request* expects as input the request itself in a number of formats and
also, if available, information about the HTTP request.

*do_response* returns a dictionary that can look like this::

    {
      'response':
        _response as a string or as a Message instance_
      'http_headers': [
        ('Content-type', 'application/json'),
        ('Pragma', 'no-cache'),
        ('Cache-Control', 'no-store')
      ],
      'cookie': _list of cookies_,
      'response_placement': 'body'
    }

cookie
    MAY be present
http_headers
    MAY be present
http_response
    MAY be present. A formatted HTTP response
response
    MUST be present. An instance of a ResponseMessage class.
response_placement
    If absent defaults to the endpoints response_placement parameter value or
    if that is also missing 'url'
redirect_location
    Where to send a redirect

=======
Example
=======

Let's assume we are an OP and we want to follow the path of an access token request.
We furthermore assume that a user has authentication at the authentication endpoint
and that a session has been created (more about sessions here :ref:`session-management`) .

The process at the token endpoint starts with a request coming in.
Something like this (if the private_key_jwt authentication method is used)::

    request = AccessTokenRequest(
        grant_type: 'authorization_code',
        redirect_uri: 'https://example.com/cb',
        state: 'STATE',
        client_assertion: 'eyJhbGciOiJSUzI1NiIsImtpZCI6IlJYZFRYekZLYnpsWldIQmhaVEpDTVUxVVZIbFpSVTVUYTJGNWFFcElTMjFKZVhkcWJWRndabWN4VVEifQ.eyJhdWQiOiBbImh0dHBzOi8vZXhhbXBsZS5jb20vdG9rZW4iXSwgImlzcyI6ICJjbGllbnRfMSIsICJpYXQiOiAxNjYxMzI3Nzc2LCAianRpIjogImUwZDU4ZTUwODM2MzRkYTk5MTY4Y2VkNjY0ZjcyMGJjIn0.Vk_huS2LPRlgqBILhA3o8X6yGPFo2YezO4SA8P-4hl05yMgtEgIYNoAJSq1nFdwcYsTSnU27n3gb-aFFPPCpL_Mk4ps-b6sSXc-ZvY2CC4A66U_rVb38UhN90LSgTtBTFYL2daIJs31-ED4kuHPsNA40PkkJgliAX9O_V-TtyzVMd2Hsc9adO3ymIbixSQrJjb-exFjKw_EuoYBCiLxA2FZCGoPKMxlxs4UP9j-Q-TdtrfTHFRkBUzlhQ_8Djibc0v4ORrSpe0gXDyxs3RKt3BQ_yxLJHFxoCAq6a701FQTqWE7-xh_dNOT2UZMYwai6xD3llpBVj3Q1jlAO5hHkEw',
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        code: 'Z0FBQUFBQmpCZHFJaklCd0dXNGFvUFdKYXNMcl9keEJRNmczYXktMDhMNjVhcXozOEI5SUlpTDhXcEFPUFlWb2dWTDFXdVBIOFhNdGR5cFhTUFQ5TktNNkxXSm5UWTYxVWJxOWh6ekxfRGo4V3JWeG8weHU2U19US0stQlZBWXJYTGNhcW12WTBNcmhiWF9LUTdHV1pnUXdwUGdNekNiWVAwbEs4dnRpUlI5b1VXUUY2dEdBTUljSjNQT0JXYm14c3diX2FySEdKbFFSaEhORkIyZmI1dHV5djJ2R0lEQ1lGSnEwV1lKNUpBbmlicVRZWFl6bU5hLUQ5QkpyUUFmbEZ6cEJRdmsyaWN2TlNsMmVBSmlHdll6UXJkMU5GZjVheUd0eklDZDA3aDBveXktWXJuZTZmbHc4QmVSbC0ySE5LaGUwNDNuYklBZkRHTFBGR2U0alB0ZlByME5QTzBDNFVvUFY5WjJETllqeGpxcDYzSFhCWkJPS0JBUXczekxuV2hjajRZSW5sbC1IemgtWFd3V2I0QllUbHNjVHpSNXJaUVF3LXk1Sk81M2drSEtSUmtRRHRseG9oY1g3Rm5YRUluOHlPRjN2QkxOTjJ5S3k4cklJY1NqYXBlVVJnNXNqWkV4aU1GYmQ3ak9QRVdUa1duQWgwUnV1TmltM0c3bVo0RnNpSGNtbHdWQks3enhFRTdaQU9zd1k0OUMxQ3drYnhiajVOTzYzX19lb21hVGtiN0Z3SmR6UHBxbEFjODNQYjgyWDFoUjFtZDFZT3lNenRvUnJwQWJFelotNjYwbEIxZ1UyUkl0aVFaNVJBdDBUbmFxdFZVNlJ1QjlyZk9SMUpOeVc2RDdWS2RObA=='
    )


The *parse_request* method will:

1. Parse the request
2. Verify the client authentication. If there is more then one available then
    the list is gone through until one returns OK or the list is empty.
3. Verify the request
4. Do endpoint specific parsing. Before doing that the method checks if any
    error has been encountered so far and if so return an error message.
    Since the token endpoint handles more the one service (access token,
    refresh token, token exchange, ...) the post_parse method is chosen
    dependent on the grant type. The endpoint specific post_parse method
    verifies that the method grant type is supported for the specific client
    involved. When dealing with the *authorization_code* grant type the
    code is used to find the session. It's verified that the session is still
    active.

**Note** that there might be more then one endpoint specific post parse method.

If everything is OK the *parse_request* method returns a dictionary containing::

    {
        'grant_type': 'authorization_code',
        'redirect_uri': 'https://example.com/cb',
        'state': 'STATE',
        'client_assertion': 'eyJhbGciOiJSUzI1NiIsImtpZCI6IlptWklPRUoyT1cxb1NFUXpVV3RYYVdSUlExQTRUMUJLZVZOVmR6RXRjVUZaUWw5T1lrY3dTWGt0VVEifQ.eyJhdWQiOiBbImh0dHBzOi8vZXhhbXBsZS5jb20vdG9rZW4iXSwgImlzcyI6ICJjbGllbnRfMSIsICJpYXQiOiAxNjYxMzI4MDA4LCAianRpIjogImRiYzlmZTA4NDc2NTQ4ZWM4MjQ5NmJiYzUwYTBjMTZjIn0.JM2IxczJse3TROLJNwIlP7Hk9RmHTXR5iZuin5zcJiorI6oyCFFiMUQ5IyKMCUrEQuKJ00wfBzOa17B0wMUmFla5NYLrunBcvl4m-_CHm0xpVl-IngGkkYs8KfLamq6sYDaDCRJybM9lLSpgQDactX8cByLUD2uHaSZO87J94GEA-QOKI9KWn4ZozqKmkv_aczO2SfLfW9PFLvWvERHRxwIXM3rP4Z-F3xi_r0dFv9-J8RU9kndD1mAHfpH98ljvxjhwiVKJX_Zgezc1arzaClE442weU-JDxP20NxnehBUpEiw5Z3VFzqqGs58cSLyTniq-fLWHnjia-SAg4KQ-IQ',
        'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'code': 'Z0FBQUFBQmpCZHFJaklCd0dXNGFvUFdKYXNMcl9keEJRNmczYXktMDhMNjVhcXozOEI5SUlpTDhXcEFPUFlWb2dWTDFXdVBIOFhNdGR5cFhTUFQ5TktNNkxXSm5UWTYxVWJxOWh6ekxfRGo4V3JWeG8weHU2U19US0stQlZBWXJYTGNhcW12WTBNcmhiWF9LUTdHV1pnUXdwUGdNekNiWVAwbEs4dnRpUlI5b1VXUUY2dEdBTUljSjNQT0JXYm14c3diX2FySEdKbFFSaEhORkIyZmI1dHV5djJ2R0lEQ1lGSnEwV1lKNUpBbmlicVRZWFl6bU5hLUQ5QkpyUUFmbEZ6cEJRdmsyaWN2TlNsMmVBSmlHdll6UXJkMU5GZjVheUd0eklDZDA3aDBveXktWXJuZTZmbHc4QmVSbC0ySE5LaGUwNDNuYklBZkRHTFBGR2U0alB0ZlByME5QTzBDNFVvUFY5WjJETllqeGpxcDYzSFhCWkJPS0JBUXczekxuV2hjajRZSW5sbC1IemgtWFd3V2I0QllUbHNjVHpSNXJaUVF3LXk1Sk81M2drSEtSUmtRRHRseG9oY1g3Rm5YRUluOHlPRjN2QkxOTjJ5S3k4cklJY1NqYXBlVVJnNXNqWkV4aU1GYmQ3ak9QRVdUa1duQWgwUnV1TmltM0c3bVo0RnNpSGNtbHdWQks3enhFRTdaQU9zd1k0OUMxQ3drYnhiajVOTzYzX19lb21hVGtiN0Z3SmR6UHBxbEFjODNQYjgyWDFoUjFtZDFZT3lNenRvUnJwQWJFelotNjYwbEIxZ1UyUkl0aVFaNVJBdDBUbmFxdFZVNlJ1QjlyZk9SMUpOeVc2RDdWS2RObA==',
        '__verified_client_assertion': <idpyoidc.message.oidc.JsonWebToken object at 0x7f86c82b21d0>,
        'client_id': 'client_1'
    }

**Note** that two pieces of information has been added. The client_id and
a representation of the verified client assertion.
If you look into the latter you can see what the JWS header looks like and the JWT
content of the *client_assertion* ::

    {
        'aud': ['https://example.com/token'],
        'iss': 'client_1',
        'iat': 1661328008,
        'jti': 'dbc9fe08476548ec82496bbc50a0c16c'
    }


These two pieces of information is available to the post parse methods.

The next step is then *process_request*.
Again what will happen is dependent on the *grant_type* but basically the
process is to check if the session allows a token to be created/minted and
if so what it should give access to and what format it should be in.
Added to that whether other types of tokens (refresh token,
Id token, ...) should be constructed.
The response from *process_request* looks like this::

    {
        'response_args': {
            'token_type': 'Bearer',
            'scope': ['openid'],
            'access_token': 'eyJhbGciOiJFUzI1NiIsImtpZCI6IkxVUkxhMG80YjNrMU1XbHlWMDlYYTNGaWFEUkJNekY2VUhGQ2RuTjZUbEJKWVZVd1RIbDZObVY1UVEifQ.eyJzY29wZSI6IFsib3BlbmlkIl0sICJqdGkiOiAiZTA3NzlmNmMyNDQyMTFlZDk4N2JhY2RlNDgwMDExMjIiLCAiY2xpZW50X2lkIjogImNsaWVudF8xIiwgInN1YiI6ICIxNjZkZmI4YWJlY2IwZDQ0NWUwMzgwMDc4ZmFjMmEyMTgzNzMwYTliMGFjZDRiNTdiZDlmODA3ZmVhZDhkMTg1IiwgInNpZCI6ICJaMEZCUVVGQlFtcENaSEZKVEhaRExVOVRjV3RaVG0xVWFHRnhOMEUxZFcxUmNXazJTbFJqWmxka2NVVkdTa3A2ZHpBeU9FdFJMVmhrTkZCdVYwTkVjbGN5TFZscmRFWkpjRGRPVGpKU1YwdFpNMVozV25sTldqRjVhMUV3VWxCTWJtUm1kMGh5VjFBNFMwMVlSV3hoUzNCMk9HdFVRbFpJUkhKR05XZFdiMEkzTkd4RlYwSTBkSFJ1YlhrM1pqSkRObkl6YjBSeVFqQnRjamRqUTNOeVUxTlRjV3cxYWs1NmVscHlNM1EwYW5GcldVVk5WbGt3Y2sxSlowZDFXamxNTjBsdE1rdzJVV3RHVDFVM1JFTklTbkJxWVhOZmEwRk1UelJ1TFRCa01WcDVWMmhOV1MxVlJrVTRhbWt4U1hkck4zRkhjR04yWnowPSIsICJ0b2tlbl9jbGFzcyI6ICJhY2Nlc3NfdG9rZW4iLCAiaXNzIjogImh0dHBzOi8vZXhhbXBsZS5jb20vIiwgImlhdCI6IDE2NjE0MTA1MTcsICJleHAiOiAxNjYxNDE0MTE3fQ.3G_p8lY0DFt0Zq0S0N9Fq4v0QIOOBQDDA5AKI-Y7BdR2xUIVuSTE5HQMIqkh7INDDwQxLiG7VubeUugwwD7DLg',
            'expires_in': 1800,
            'id_token': 'eyJhbGciOiJSUzI1NiIsImtpZCI6IlkweHRVRU5EV2s1ZllucDJlakpDWmxoaU1VdFZOV0psTXkwNVFtbHFMVlp4YXpWM2RWQk5XRGhGV1EifQ.eyJzdWIiOiAiMTY2ZGZiOGFiZWNiMGQ0NDVlMDM4MDA3OGZhYzJhMjE4MzczMGE5YjBhY2Q0YjU3YmQ5ZjgwN2ZlYWQ4ZDE4NSIsICJzaWQiOiAiWjBGQlFVRkJRbXBDWkhGSlRIWkRMVTlUY1d0WlRtMVVhR0Z4TjBFMWRXMVJjV2syU2xSalpsZGtjVVZHU2twNmR6QXlPRXRSTFZoa05GQnVWME5FY2xjeUxWbHJkRVpKY0RkT1RqSlNWMHRaTTFaM1dubE5XakY1YTFFd1VsQk1ibVJtZDBoeVYxQTRTMDFZUld4aFMzQjJPR3RVUWxaSVJISkdOV2RXYjBJM05HeEZWMEkwZEhSdWJYazNaakpETm5JemIwUnlRakJ0Y2pkalEzTnlVMU5UY1d3MWFrNTZlbHB5TTNRMGFuRnJXVVZOVmxrd2NrMUpaMGQxV2psTU4wbHRNa3cyVVd0R1QxVTNSRU5JU25CcVlYTmZhMEZNVHpSdUxUQmtNVnA1VjJoTldTMVZSa1U0YW1reFNYZHJOM0ZIY0dOMlp6MD0iLCAiYXV0aF90aW1lIjogMTY2MTMyODAwOCwgInNjb3BlIjogWyJvcGVuaWQiXSwgImp0aSI6ICJlMDc4NGUxYzI0NDIxMWVkOTg3YmFjZGU0ODAwMTEyMiIsICJjbGllbnRfaWQiOiAiY2xpZW50XzEiLCAiaXNzIjogImh0dHBzOi8vZXhhbXBsZS5jb20vIiwgImlhdCI6IDE2NjE0MTA1MTcsICJleHAiOiAxNjYxNDEwODE3LCAiYXVkIjogWyJjbGllbnRfMSJdfQ.kTUWdBb_HE-dfcejvJKtKzr1xOma9dSLg8HtAjjjCLj266ZrrZPC3hYmh8GW0tFGKOooUd7xNi4jRCaaXkqFM-VK8bZKbVtjJ2PP_c0d2FVXuAwtqW5fHesKlPmsmjAkEBBKyM4QommO1eogsmwWlX0ss4wDyF9BukERPB1_g0xY1eH-ab11rPYyYhqQbBDUVA5PM5Gz_ckLxHZ6y4oi_hsF-OzZKbSzbftVHFDExSuajuf-uL3fHVeLWk8hP6FW2r4d1c1L4tyY3uc03nGjVD8ChpEYnVIAnlgGiOKo18zuP7FWeJEOwKEA3Z1TesSFOB_tpWY3mGhk62R5Lmxu-A'
        },
        'http_headers': [
            ('Content-type', 'application/json')
        ],
        'cookie': [
            {
                'name': 'oidc_op',
                'value': '1661410517|i2bIT5BcJqAt8r4T|nLGr9fPqOQT0qUPs2sXBAvIJYNiwSSvd9doRZ8lj1sTVjrI1+zR1hnjMU21oYtoWtKehuiRmDqnJIVzydERIXK9YiwTqXfBy8kice9DNbYQMzVMbIR7CU1OWXw5YkzhAWcTku7VhGAWxArXDdWQmBK3P4n2o4pqatghXVvNmxRH7QTw0zr0Voo1tl/7cyEKfK5KyNdkeiNQr+k+FIpjmgckJ0Xjw69TjuhlWZg3/uq1IzwNUnL10E0Hem3TZxsD2GcnW9z/XfoEl|uJkOb6UfOpKk56zfsmi33Q==',
                'samesite': 'None',
                'httponly': True,
                'secure': True
            }
        ]
    }

Finally it's time for *do_response*. It takes the response *process_request*
produced and dependent on what kind of response it should construct

- something to go in the body (urlencoded, JSON, JWS, JWE) or
- something that gets added to an url (query part or fragment).

it produces the correct information. *do_response* will also add content type
information to the HTTP headers.

The end result then is something like this::

    {
        'response': '{"access_token": "eyJhbGciOiJFUzI1NiIsImtpZCI6Ik1UTm1TVTFsTVdRMU9GVjNSbVZFYnpaTVpHbG5hbGhWTkd0T1ZFWm5TMFZxVkhOeE1XRlZia1UwZHcifQ.eyJzY29wZSI6IFsib3BlbmlkIiwgIm9mZmxpbmVfYWNjZXNzIl0sICJhdWQiOiBbImNsaWVudF8xIl0sICJqdGkiOiAiYjY3YWI0NGEyNDQ0MTFlZGJkMWRhY2RlNDgwMDExMjIiLCAiY2xpZW50X2lkIjogImNsaWVudF8xIiwgInN1YiI6ICI1ZmQwZDJkZTJjZGQ1NTE2ZWY2YTk3OTAzZjJlMzFmODhmNTAzM2FmYzUxYzBlNzllZTI1NGI1YzcwMGFmMGU4IiwgInNpZCI6ICJaMEZCUVVGQlFtcENlRjl3ZWkxSFdVOWxUSEV5ZVVoQ1ZuQnFOV3R3VlY4M2MwbEpPRTQwYWxWMVYzSm9WRll4Tm5ZelgyeHZia05uZG05elMwVllPWFl6WkZGNWNsSlZPSE5tU3kxYVlsTnZhQzFOYW5oWFQybFNjR2N6UjI5NFIyUmhVbTF0UWtWcFpVdGFNblpvYTBkWFVsVllabUZJYW13d2JuVjBSbmxLWVdWaVRuaFBRV2gyUW0xdFV6ZDBaVXA1ZDNGYVVHUXRWRUpGUW5jMWNFbGxhM2x2VG14QlUxaERZV1pCUzNwb1drVlFaMkk0TW1WaFFtWlVSbTVpZUZaU1Mwb3lSVlowTkZsMFQzSkNTVFZhYlhOb1RDMXRhRU5QUWxCT2VFWXlVbWh5Wm5oRk9VRmZTakl6TlhaQ2VqVkxjbHBrY3owPSIsICJ0b2tlbl9jbGFzcyI6ICJhY2Nlc3NfdG9rZW4iLCAiaXNzIjogImh0dHBzOi8vZXhhbXBsZS5jb20vIiwgImlhdCI6IDE2NjE0MTEzMDUsICJleHAiOiAxNjYxNDExOTA1fQ.KJRXIjyd1lDQwZBKTj-DRZZMwAkmSjrB9MoqyZKp1mWqLuPDh009X0zhbAL-6HekFqyWpKnWUJ14SO4tHEZueg", "token_type": "Bearer", "scope": "openid offline_access", "expires_in": 600, "refresh_token": "eyJhbGciOiJFUzI1NiIsImtpZCI6Ik1UTm1TVTFsTVdRMU9GVjNSbVZFYnpaTVpHbG5hbGhWTkd0T1ZFWm5TMFZxVkhOeE1XRlZia1UwZHcifQ.eyJzY29wZSI6IFsib3BlbmlkIiwgIm9mZmxpbmVfYWNjZXNzIl0sICJhdWQiOiBbImNsaWVudF8xIl0sICJqdGkiOiAiYjY3YWUxMDQyNDQ0MTFlZGJkMWRhY2RlNDgwMDExMjIiLCAiY2xpZW50X2lkIjogImNsaWVudF8xIiwgInN1YiI6ICI1ZmQwZDJkZTJjZGQ1NTE2ZWY2YTk3OTAzZjJlMzFmODhmNTAzM2FmYzUxYzBlNzllZTI1NGI1YzcwMGFmMGU4IiwgInNpZCI6ICJaMEZCUVVGQlFtcENlRjl3ZWkxSFdVOWxUSEV5ZVVoQ1ZuQnFOV3R3VlY4M2MwbEpPRTQwYWxWMVYzSm9WRll4Tm5ZelgyeHZia05uZG05elMwVllPWFl6WkZGNWNsSlZPSE5tU3kxYVlsTnZhQzFOYW5oWFQybFNjR2N6UjI5NFIyUmhVbTF0UWtWcFpVdGFNblpvYTBkWFVsVllabUZJYW13d2JuVjBSbmxLWVdWaVRuaFBRV2gyUW0xdFV6ZDBaVXA1ZDNGYVVHUXRWRUpGUW5jMWNFbGxhM2x2VG14QlUxaERZV1pCUzNwb1drVlFaMkk0TW1WaFFtWlVSbTVpZUZaU1Mwb3lSVlowTkZsMFQzSkNTVFZhYlhOb1RDMXRhRU5QUWxCT2VFWXlVbWh5Wm5oRk9VRmZTakl6TlhaQ2VqVkxjbHBrY3owPSIsICJ0b2tlbl9jbGFzcyI6ICJyZWZyZXNoX3Rva2VuIiwgImlzcyI6ICJodHRwczovL2V4YW1wbGUuY29tLyIsICJpYXQiOiAxNjYxNDExMzA1LCAiZXhwIjogMTY2MTQ5NzcwNX0.pmnWqfMtm-uks2b6eengQjd7KUlmn9k-HHHrD7GKToyBz9FjREdNteIYtuq6v181vGPJNrvNODZuGGn_MtyQ7g", "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6Ik9WY3lRelJ4WnpnMVNXSTBSVnBOT1ZWNmJYcERMWFl0VlRoYU5HVm1NRmRGVUZkQldEZE9WRVpJV1EifQ.eyJzdWIiOiAiNWZkMGQyZGUyY2RkNTUxNmVmNmE5NzkwM2YyZTMxZjg4ZjUwMzNhZmM1MWMwZTc5ZWUyNTRiNWM3MDBhZjBlOCIsICJzaWQiOiAiWjBGQlFVRkJRbXBDZUY5d2VpMUhXVTlsVEhFeWVVaENWbkJxTld0d1ZWODNjMGxKT0U0MGFsVjFWM0pvVkZZeE5uWXpYMnh2YmtObmRtOXpTMFZZT1hZelpGRjVjbEpWT0hObVN5MWFZbE52YUMxTmFuaFhUMmxTY0djelIyOTRSMlJoVW0xdFFrVnBaVXRhTW5ab2EwZFhVbFZZWm1GSWFtd3diblYwUm5sS1lXVmlUbmhQUVdoMlFtMXRVemQwWlVwNWQzRmFVR1F0VkVKRlFuYzFjRWxsYTNsdlRteEJVMWhEWVdaQlMzcG9Xa1ZRWjJJNE1tVmhRbVpVUm01aWVGWlNTMG95UlZaME5GbDBUM0pDU1RWYWJYTm9UQzF0YUVOUFFsQk9lRVl5VW1oeVpuaEZPVUZmU2pJek5YWkNlalZMY2xwa2N6MD0iLCAiYXV0aF90aW1lIjogMTY2MTQxMTMwNSwgInNjb3BlIjogWyJvcGVuaWQiLCAib2ZmbGluZV9hY2Nlc3MiXSwgImp0aSI6ICJiNjdiMGMyNDI0NDQxMWVkYmQxZGFjZGU0ODAwMTEyMiIsICJjbGllbnRfaWQiOiAiY2xpZW50XzEiLCAiaXNzIjogImh0dHBzOi8vZXhhbXBsZS5jb20vIiwgImlhdCI6IDE2NjE0MTEzMDUsICJleHAiOiAxNjYxNDExNjA1LCAiYXVkIjogWyJjbGllbnRfMSJdfQ.unzZR3au0-N78CctDNYt3BjoFmsnA7iGZ1NHZjJxJosmRIhY-rXwy7PIupVS8iBa1VKRpbIwWaKxP8vj3hX6cZhQtFbhmJ1a0uVpTBNDSc2UWMpnfx49GDEtdRS4ZpPV8-TUtITR15GXXbp3ERep5nFiFhYYN-f15DxjrE1HzVeI1L_2P8eO9oQiQxxp_SxUL7cJWI-UMyT_6UEdNSPRccr1zt_ydelSLb3ZPYi2pyJ_jDVIO5rrmKs1KkT_p-oUAKlHeODk54BRHAIX07K3BrpX4ALFvYX2lM5Q_1OsXM_VnZAsTeU_pjoc-ruSwyRPB1Y5_e0H2Wg9LXeqE-BCdw"}',
        'http_headers': [
            ('Content-type', 'application/json; charset=utf-8'),
            ('Pragma', 'no-cache'),
            ('Cache-Control', 'no-store')],
        'cookie': [
            {
                'name': 'oidc_op',
                'value': '1661410517|i2bIT5BcJqAt8r4T|nLGr9fPqOQT0qUPs2sXBAvIJYNiwSSvd9doRZ8lj1sTVjrI1+zR1hnjMU21oYtoWtKehuiRmDqnJIVzydERIXK9YiwTqXfBy8kice9DNbYQMzVMbIR7CU1OWXw5YkzhAWcTku7VhGAWxArXDdWQmBK3P4n2o4pqatghXVvNmxRH7QTw0zr0Voo1tl/7cyEKfK5KyNdkeiNQr+k+FIpjmgckJ0Xjw69TjuhlWZg3/uq1IzwNUnL10E0Hem3TZxsD2GcnW9z/XfoEl|uJkOb6UfOpKk56zfsmi33Q==',
                'samesite': 'None',
                'httponly': True,
                'secure': True
            }
        ]
    }

As you can see the response is a JSON string.

Submodules
----------

idpyoidc\.server\.configure module
----------------------------------

.. automodule:: idpyoidc.server.configure
    :members:
    :undoc-members:
    :show-inheritance:

idpyoidc\.server\.scopes module
-------------------------------

.. automodule:: idpyoidc.server.scopes
    :members:
    :undoc-members:
    :show-inheritance:

idpyoidc\.server\.util module
-----------------------------

.. automodule:: idpyoidc.server.util
    :members:
    :undoc-members:
    :show-inheritance:
