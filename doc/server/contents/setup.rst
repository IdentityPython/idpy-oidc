Setup
-----

Create an environment::

    virtualenv -ppython3 env
    source env/bin/activate

Install::

    pip install idpyoidc

Get the usage examples::

    git clone https://github.com/identitypython/idpy-oidc.git
    cd idpyoidc/example/flask_op/
    bash run.sh


To configure a standard OIDC Provider you have to edit the oidcop configuration file.
See `example/flask_op/config.json` to get in.

::

    flask_op % bash run.sh
    2022-03-25 08:49:22,801 root DEBUG Configured logging using dictionary
     * Serving Flask app "oidc_op" (lazy loading)
     * Environment: production
       WARNING: This is a development server. Do not use it in a production deployment.
       Use a production WSGI server instead.
     * Debug mode: on
    2022-03-25 08:49:22,841 werkzeug INFO  * Running on https://127.0.0.1:5000/ (Press CTRL+C to quit)
    2022-03-25 08:49:22,842 werkzeug INFO  * Restarting with stat
    2022-03-25 08:49:23,202 root DEBUG Configured logging using dictionary
    2022-03-25 08:49:23,240 werkzeug WARNING  * Debugger is active!
    2022-03-25 08:49:23,245 werkzeug INFO  * Debugger PIN: 162-062-616



Then open your browser to `https://127.0.0.1:5000/.well-known/openid-configuration`
to get the OpenID Provider Configuration resource.


--------------------
JWK Set (JWKS) files
--------------------
see: [cryptojwt documentation](https://cryptojwt.readthedocs.io/en/latest/keyhandling.html<https://cryptojwt.readthedocs.io/en/latest/keyhandling.html)


You can use `cryptojwt.key_jar.init_key_jar` to create JWKS file.
An easy way can be to configure the auto creation of JWKS files directly in your conf.yaml file.
Using `read_only: False` in `OIDC_KEYS` it will create the path within the JWKS files.
Change it to `True` if you don't want to overwrite them on each execution.

In general configuration::

  "port": 5000,
  "domain": "127.0.0.1",
  "server_name": "{domain}:{port}",
  "base_url": "https://{domain}:{port}",
  "op": {
    "server_info": {
      "keys": {
        "private_path": "private/jwks.json",
        "key_defs": [
          {
            "type": "RSA",
            "use": [
              "sig"
            ]
          },
          {
            "type": "EC",
            "crv": "P-256",
            "use": [
              "sig"
            ]
          }
        ],
        "public_path": "static/jwks.json",
        "read_only": false,
        "uri_path": "static/jwks.json"
      },


In the JWTConnect-Python-CryptoJWT distribution there is also a script you can use to construct a JWK.
You can for instance do::

    $ jwkgen --kty=RSA
    {
        "d": "b9ucfay9vxDvz_nRZMVSUR9eRvHNMo0tc8Bl7tWkwxTis7LBXxmbMH1yzLs8omUil_u2a-Z_6VlKENxacuejYYcOhs6bfaU3iOqJbGi2p4t2i1oxjuF-cX6BZ5aHB5Wfb1uTXXobHokjcjVVDmBr_fNYBEPtZsVYqyN9sR9KE_ZLHEPks3IER09aX9G3wiB_PgcxQDRAl72qucsBz9_W9KS-TVWs-qCEqtXLmx9AAN6P8SjUcHAzEb0ZCJAYCkVu34wgNjxVaGyYN1qMA-1iOOVz--wtMyBwc5atSDBDgUApxFyj_DHSeBl81IHedcPjS9azxqFhumP7oJJyfecfSQ",
        "e": "AQAB",
        "kid": "cHZQbWRrMzRZak53U1pfSUNjY0dKd2xXaXRKenktdUduUjVBVTl3VE5ndw",
        "kty": "RSA",
        "n": "73XCXV2iiubSCEaFe26OpVnsBFlXwXh_yDCDyBqFgAFi5WdZTpRMJZoK0nn_vv2MvrXqFnw6IfXkwdsRGlMsNldVy36003gKa584CNksxfenwJZcF-huASUrSJEFr-3c0fMT_pLyAc7yf3rNCdRegzbBXSvIGKQpaeIjIFYftAPd9tjGA_SuYWVQDsSh3MeGbB4wt0lArAyFZ4f5o7SSxSDRCUF3ng3CB_QKUAaDHHgXrcNG_gPpgqQZjsDJ0VwMXjFKxQmskbH-dfsQ05znQsYn3pjcd_TEZ-Yu765_L5uxUrkEy_KnQXe1iqaQHcnfBWKXt18NAuBfgmKsv8gnxQ",
        "p": "_RPgbiQcFu8Ekp-tC-Kschpag9iaLc9aDqrxE6GWuThEdExGngP_p1I7Qd7gXHHTMXLp1c4gH2cKx4AkfQyKny2RJGtV2onQButUU5r0gwnlqqycIA2Dc9JiH85PX2Z889TKJUlVETfYbezHbKhdsazjjsXCQ6p9JfkmgfBQOXM",
        "q": "8jmgnadtwjMt96iOaoL51irPRXONO82tLM2AAZAK5Obsj23bZ9LFiw2Joh5oCSFdoUcRhbbIhCIv2aT4T_XKnDGnddrkxpF5Xgu0-hPNYnJx5m4kuzerot4j79Tx6qO-bshaaGz50MHs1vHSeFaDVN4fvh_hDWpV1BCNI0PKK-c"
    }
    SHA-256: pvPmdk34YjNwSZ_ICccGJwlWitJzy-uGnR5AU9wTNgw

Example: create a JWK for cookie signing

    jwkgen --kty=SYM --kid cookie > private/cookie_sign_jwk.json
