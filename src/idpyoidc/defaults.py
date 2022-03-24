import string

# Map the signing context to a signing algorithm
DEF_SIGN_ALG = {"id_token": "RS256",
                "userinfo": "RS256",
                "request_object": "RS256",
                "client_secret_jwt": "HS256",
                "private_key_jwt": "RS256"}

JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

BASECHR = string.ascii_letters + string.digits
