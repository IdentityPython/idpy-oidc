import logging
from typing import Optional

from idpyoidc.message.oidc import RegistrationRequest
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
    "response_types": "response_types_supported",
    "response_modes": "response_modes_supported",
    "grant_types": "grant_types_supported",
    # In OAuth2 but not in OIDC
    "scope": "scopes_supported",
    "token_endpoint_auth_signing_alg": "token_endpoint_auth_signing_alg_values_supported",
    # "display": "display_values_supported",
    # "claims": "claims_supported",
    # "request": "request_parameter_supported",
    # "request_uri": "request_uri_parameter_supported",
    # 'claims_locales': 'claims_locales_supported',
    # 'ui_locales': 'ui_locales_supported',
}

PREFERRED2REGISTER = dict([(v, k) for k, v in REGISTER2PREFERRED.items()])

REQUEST2REGISTER = {
    "client_id": "client_id",
    "client_secret": "client_secret",
    #    'acr_values': "default_acr_values" ,
    #    'max_age': "default_max_age",
    "redirect_uri": "redirect_uris",
    "response_type": "response_types",
    "request_uri": "request_uris",
    "grant_type": "grant_types",
    "scope": "scopes_supported",
    "post_logout_redirect_uri": "post_logout_redirect_uris",
}


def supported_to_preferred(
    supported: dict,
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
                    if isinstance(_info_val, bool):
                        if _info_val is False and _pref_val is True:
                            # Turn off support if server doesn't support
                            preference[key] = _info_val
                    else:
                        # Only use provider setting if less or equal to what I support
                        if key.endswith("supported"):  # list
                            preference[key] = [x for x in _pref_val if x in _info_val]
                        else:
                            pass
            elif val is None:  # No default, means the RP does not have a preference
                # if key not in ['jwks_uri', 'jwks']:
                pass
            else:
                # there is a default
                _info_val = info.get(key)
                if _info_val:  # The OP has an opinion
                    if key.endswith("supported"):  # list
                        preference[key] = [x for x in val if x in _info_val]
                    else:
                        pass
                else:
                    preference[key] = val

        # special case -> must have a request_uris value
        if "require_request_uri_registration" in info:
            # only makes sense if I want to use request_uri
            if preference.get("request_parameter") == "request_uri":
                if "request_uri" not in preference:
                    preference["request_uris"] = [f"{base_url}/requests"]
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


def array_or_singleton(claim_spec, values):
    if isinstance(claim_spec[0], list):
        if isinstance(values, list):
            return values
        else:
            return [values]
    else:
        if isinstance(values, list):
            return values[0]
        else:  # singleton
            return values


def _is_subset(a, b):
    # Is 'a' a subset of 'b'
    if isinstance(a, list):
        if isinstance(b, list):
            return set(a).issubset(set(b))
    elif isinstance(b, list):
        return a in b
    else:
        return a == b


def _intersection(a, b):
    res = None
    if isinstance(a, list):
        if isinstance(b, list):
            res = list(set(a).intersection(set(b)))
        else:
            if b in a:
                res = b
            else:
                res = []
    elif isinstance(b, list):
        if a in b:
            res = [a]
        else:
            res = []
    return res


def preferred_to_registered(
    prefers: dict, supported: dict, registration_response: Optional[dict] = None
):
    """
    The claims with values that are returned from the OP is what goes unless (!!)
    the values returned are not within the supported values.

    @param prefers:
    @param registration_response:
    @return:
    """
    registered = {}

    if registration_response:
        for key, val in registration_response.items():
            if key in REGISTER2PREFERRED:
                # Is the response value with in what this instance supports
                _supports = supported.get(REGISTER2PREFERRED[key])
                if _is_subset(val, _supports):
                    registered[key] = val
                else:
                    logger.warning(
                        f"OP tells me to do something I do not support: {key} = {val} not within "
                        f"{_supports}"
                    )
                    _val = _intersection(val, _supports)
                    if _val:
                        registered[key] = _val
                    else:
                        raise ValueError(f"Not able to support the OPs choice: {key}={val}")
            else:
                registered[key] = val  # Should I just accept with the OP says ??

    for key, spec in RegistrationResponse.c_param.items():
        if key in registered:
            continue
        _pref_key = REGISTER2PREFERRED.get(key, key)

        _preferred_values = prefers.get(_pref_key, prefers.get(key))
        if not _preferred_values:
            continue

        registered[key] = array_or_singleton(spec, _preferred_values)

    # transfer those claims that are not part of the registration request
    _rr_keys = list(RegistrationResponse.c_param.keys())
    for key, val in prefers.items():
        _reg_key = PREFERRED2REGISTER.get(key, key)
        if _reg_key not in _rr_keys:
            # If they are not part of the registration request I do not knoe if it is supposed to
            # be a singleton or an array. So just add it as is.
            registered[_reg_key] = val

    logger.debug(f"Entity registered: {registered}")
    return registered


def create_registration_request(prefers: dict, supported: dict) -> dict:
    _request = {}
    for key, spec in RegistrationRequest.c_param.items():
        _pref_key = REGISTER2PREFERRED.get(key, key)
        if _pref_key in prefers:
            value = prefers[_pref_key]
        elif _pref_key in supported:
            value = supported[_pref_key]
        else:
            continue

        if not value:
            continue

        _request[key] = array_or_singleton(spec, value)
    return _request
