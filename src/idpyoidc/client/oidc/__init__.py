WF_URL = "https://{}/.well-known/webfinger"
OIC_ISSUER = "http://openid.net/specs/connect/1.0/issuer"

IDT2REG = {
    "sigalg": "id_token_signed_response_alg",
    "encalg": "id_token_encrypted_response_alg",
    "encenc": "id_token_encrypted_response_enc",
}

ENDPOINT2SERVICE = {
    "authorization": ["authorization"],
    "token": ["accesstoken", "refresh_token"],
    "userinfo": ["userinfo"],
    "registration": ["registration"],
    "end_sesssion": ["end_session"],
}

# This should probably be part of the configuration
MAX_AUTHENTICATION_AGE = 86400

PREFERENCE2PROVIDER = {
    # "require_signed_request_object": "request_object_algs_supported",
    "request_object_signing_alg": "request_object_signing_alg_values_supported",
    "request_object_encryption_alg": "request_object_encryption_alg_values_supported",
    "request_object_encryption_enc": "request_object_encryption_enc_values_supported",
    "userinfo_signed_response_alg": "userinfo_signing_alg_values_supported",
    "userinfo_encrypted_response_alg": "userinfo_encryption_alg_values_supported",
    "userinfo_encrypted_response_enc": "userinfo_encryption_enc_values_supported",
    "id_token_signed_response_alg": "id_token_signing_alg_values_supported",
    "id_token_encrypted_response_alg": "id_token_encryption_alg_values_supported",
    "id_token_encrypted_response_enc": "id_token_encryption_enc_values_supported",
    "default_acr_values": "acr_values_supported",
    "subject_type": "subject_types_supported",
    "token_endpoint_auth_method": "token_endpoint_auth_methods_supported",
    "token_endpoint_auth_signing_alg": "token_endpoint_auth_signing_alg_values_supported",
    "response_types": "response_types_supported",
    "response_modes": "response_modes_supported",
    "grant_types": "grant_types_supported",
}

PROVIDER2PREFERENCE = dict([(v, k) for k, v in PREFERENCE2PROVIDER.items()])

PROVIDER_DEFAULT = {
    "token_endpoint_auth_method": "client_secret_basic",
    "id_token_signed_response_alg": "RS256",
}

