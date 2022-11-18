import logging
from typing import Optional

from idpyoidc.message.oidc import RegistrationResponse

logger = logging.getLogger(__name__)

REGISTER2PREFERRED = {
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
    "grant_types": "grant_types_supported",
    "scope": "scopes_supported",
    "display": "display_values_supported",
    "claims": "claims_supported",
    "request": "request_parameter_supported",
    "request_uri": "request_uri_parameter_supported",
    'claims_locales': 'claims_locales_supported',
    'ui_locales': 'ui_locales_supported',
}

PREFERRED2REGISTER = dict([(v, k) for k, v in REGISTER2PREFERRED.items()])

REQUEST2REGISTER = {
    'client_id': "client_id",
    "client_secret": "client_secret",
    #    'acr_values': "default_acr_values" ,
    #    'max_age': "default_max_age",
    'redirect_uri': "redirect_uris",
    'response_type': "response_types",
    'request_uri': "request_uris",
    'grant_type': "grant_types"
}


# AUTHORIZATION_REQUEST = [
#     "acr_values",
#     "claims",
#     "claims_locales",
#     "client_id",
#     "display",
#     "id_token_hint",
#     "login_hint",
#     "max_age",
#     "nonce",
#     "prompt",
#     "redirect_uri",
#     "registration",
#     "request",
#     "request_uri",
#     "response_mode"
#     "response_type",
#     "scope",
#     "state",
#     "ui_locales",
# ]


def supported_to_preferred(supported: dict,
                           preference: dict,
                           base_url: str,
                           info: Optional[dict] = None,
                           ):
    if info:  # The provider info
        for key, val in supported.items():
            if key in preference:
                _pref_val = preference.get(key)  # defined in configuration
                _info_val = info.get(key)
                if _info_val:
                    # Only use provider setting if less or equal to what I support
                    if key.endswith('supported'):  # list
                        preference[key] = [x for x in _pref_val if x in _info_val]
                    else:
                        pass
            elif val is None:  # No default
                # if key not in ['jwks_uri', 'jwks']:
                pass
            else:
                # there is a default
                _info_val = info.get(key)
                if _info_val:  # The OP has an opinion
                    if key.endswith('supported'):  # list
                        preference[key] = [x for x in val if x in _info_val]
                    else:
                        pass
                else:
                    preference[key] = val

        # special case -> must have a request_uris value
        if 'require_request_uri_registration' in info:
            # only makes sense if I want to use request_uri
            if preference.get('request_parameter') == 'request_uri':
                if 'request_uri' not in preference:
                    preference['request_uris'] = [f'{base_url}/requests']
            else:  # just ignore
                logger.info('Asked for "request_uri" which it did not plan to use')
    else:
        # Add defaults
        for key, val in supported.items():
            if val is None:
                continue
            if key not in preference:
                preference[key] = val

    return preference


def preferred_to_register(prefers: dict, use: Optional[dict] = None):
    if not use:
        use = {}

    for key, spec in RegistrationResponse.c_param.items():
        _pref_key = REGISTER2PREFERRED.get(key, key)

        _preferred_values = prefers.get(_pref_key)
        if not _preferred_values:
            continue

        if isinstance(spec[0], list):
            if _preferred_values:
                use[key] = _preferred_values
        else:
            if _preferred_values:
                if isinstance(_preferred_values, list):
                    use[key] = _preferred_values[0]
                else:
                    use[key] = _preferred_values

    # transfer those claims that are not part of the registration request
    _rr_keys = list(RegistrationResponse.c_param.keys())
    for key, val in prefers.items():
        if PREFERRED2REGISTER.get(key):
            continue
        if key not in _rr_keys:
            use[key] = val

    logger.debug(f"Entity uses: {use}")
    return use
