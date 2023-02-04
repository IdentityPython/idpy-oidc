# from cryptojwt.jwe.fernet import DEFAULT_ITERATIONS

DEF_SIGN_ALG = {
    "id_token": "RS256",
    "userinfo": "RS256",
    "request_object": "RS256",
    "client_secret_jwt": "HS256",
    "private_key_jwt": "RS256",
}

HTTP_ARGS = ["headers", "redirections", "connection_type"]

JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

DIVIDER = ";;"

DEFAULT_TOKEN_LIFETIME = 1800

DEFAULT_REQUESTED_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
