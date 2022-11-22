from cryptojwt.key_jar import init_key_jar

from idpyoidc.client.entity import Entity
from idpyoidc.message.oidc import RegistrationRequest

ISS = "http://example.org/op"
CLIENT_CONFIG = {
    "base_url": "https://example.com/cli",
    "client_secret": "a longesh password",
    "issuer": ISS,
    "application_name": "rphandler",
    "preference": {
        "application_type": "web",
        "contacts": "support@example.com",
        "response_types": ["code"],
        "client_id": "client_id",
        "redirect_uris": ["https://example.com/cli/authz_cb"],
        'request_parameter': "request_uri",
        "request_object_signing_alg_values_supported": ["ES256"],
        "scope": ["openid", "profile", "email", "address", "phone"],
        "token_endpoint_auth_methods_supported": ["private_key_jwt"],
        "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
        "userinfo_signing_alg_values_supported": ["ES256"],
        "post_logout_redirect_uris": ["https://rp.example.com/post"],
        "backchannel_logout_uri": "https://rp.example.com/back",
        "backchannel_logout_session_required": True
    },

    "services": {
        "discovery": {
            "class": "idpyoidc.client.oidc.provider_info_discovery.ProviderInfoDiscovery",
            "kwargs": {}
        },
        "registration": {
            "class": "idpyoidc.client.oidc.registration.Registration",
            "kwargs": {}
        },
        "authorization": {
            "class": "idpyoidc.client.oidc.authorization.Authorization",
            "kwargs": {}
        },
        "accesstoken": {
            "class": "idpyoidc.client.oidc.access_token.AccessToken",
            "kwargs": {}
        },
        "userinfo": {
            "class": "idpyoidc.client.oidc.userinfo.UserInfo",
            "kwargs": {}
        },
        "end_session": {
            "class": "idpyoidc.client.oidc.end_session.EndSession",
            "kwargs": {}
        }
    }
}

KEY_CONF = {
    "private_path": "private/jwks.json",
    "key_defs": [{"type": "RSA", "key": "", "use": ["sig"]},
                 {"type": "EC", "crv": "P-256", "use": ["sig"]}],
    "read_only": False
}


def test_create_client():
    client = Entity(config=CLIENT_CONFIG, client_type='oidc')
    client.get_service_context().map_supported_to_preferred()
    _pref = client.prefers()
    assert set(_pref.keys()) == {'application_type',
                                 'backchannel_logout_session_required',
                                 'backchannel_logout_uri',
                                 'callback_uris',
                                 'client_id',
                                 'client_secret',
                                 'contacts',
                                 'default_max_age',
                                 'grant_types_supported',
                                 'id_token_encryption_alg_values_supported',
                                 'id_token_encryption_enc_values_supported',
                                 'id_token_signing_alg_values_supported',
                                 'jwks',
                                 'post_logout_redirect_uris',
                                 'redirect_uris',
                                 'request_object_encryption_alg_values_supported',
                                 'request_object_encryption_enc_values_supported',
                                 'request_object_signing_alg_values_supported',
                                 'request_parameter',
                                 'response_modes_supported',
                                 'response_types_supported',
                                 'scopes_supported',
                                 'subject_types_supported',
                                 'token_endpoint_auth_methods_supported',
                                 'token_endpoint_auth_signing_alg_values_supported',
                                 'userinfo_encryption_alg_values_supported',
                                 'userinfo_encryption_enc_values_supported',
                                 'userinfo_signing_alg_values_supported'}

    # What's in service configuration has higher priority then what's just supported.
    _context = client.get_service_context()
    assert _context.get_preference("contacts") == 'support@example.com'
    #
    assert _context.get_preference("userinfo_signing_alg_values_supported") == ['ES256']
    # How to act
    _context.map_preferred_to_register()

    assert _context.get_usage("request_uris") is None

    _conf_args = list(_context.collect_usage().keys())
    assert _conf_args
    assert len(_conf_args) == 21
    rr = set(RegistrationRequest.c_param.keys())
    # The ones that are not defined
    d = rr.difference(set(_conf_args))
    assert d == {'initiate_login_uri', 'client_name', 'post_logout_redirect_uri', 'tos_uri',
                 'logo_uri', 'jwks_uri', 'federation_type', 'frontchannel_logout_session_required',
                 'require_auth_time', 'client_uri', 'frontchannel_logout_uri', 'request_uris',
                 'sector_identifier_uri', 'organization_name', 'policy_uri',
                 'default_acr_values', 'userinfo_encrypted_response_alg',
                 'id_token_encrypted_response_alg', 'request_object_encryption_alg',
                 'userinfo_encrypted_response_enc', 'request_object_encryption_enc',
                 'id_token_encrypted_response_enc'}


def test_create_client_key_conf():
    client_config = CLIENT_CONFIG.copy()
    client_config.update({"key_conf": KEY_CONF})

    client = Entity(config=client_config, client_type='oidc')
    _jwks = client.get_service_context().get_preference("jwks")
    assert _jwks


def test_create_client_keyjar():
    _keyjar = init_key_jar(**KEY_CONF)
    client_config = CLIENT_CONFIG.copy()

    client = Entity(config=client_config, keyjar=_keyjar, client_type='oidc')
    _jwks = client.get_service_context().get_preference("jwks")
    assert _jwks


def test_create_client_jwks_uri():
    client_config = CLIENT_CONFIG.copy()
    client = Entity(config=client_config, jwks_uri="https://rp.example.com/jwks_uri.json")
    assert client.get_service_context().get_preference("jwks_uri")
