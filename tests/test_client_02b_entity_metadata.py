from cryptojwt.key_jar import init_key_jar

from idpyoidc.client.entity import Entity
from idpyoidc.message.oidc import RegistrationRequest

ISS = "http://example.org/op"
CLIENT_CONFIG = {
    "base_url": "https://example.com/cli",
    "client_secret": "a longesh password",
    "issuer": ISS,
    "application_name": "rphandler",
    "metadata": {
        "application_type": "web",
        "contacts": "support@example.com",
        "response_types": ["code"],
        "client_id": "client_id",
        "redirect_uris": ["https://example.com/cli/authz_cb"],
        "request_object_signing_alg": "ES256"
    },
    "usage": {
        "scope": ["openid", "profile", "email", "address", "phone"],
        "request_uri": True
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
            "kwargs": {
                "metadata": {
                    "token_endpoint_auth_method": "private_key_jwt",
                    "token_endpoint_auth_signing_alg": "ES256"
                }
            }
        },
        "userinfo": {
            "class": "idpyoidc.client.oidc.userinfo.UserInfo",
            "kwargs": {
                "metadata": {
                    "userinfo_signed_response_alg": "ES256"
                },
            }
        },
        "end_session": {
            "class": "idpyoidc.client.oidc.end_session.EndSession",
            "kwargs": {
                "metadata": {
                    "post_logout_redirect_uris": ["https://rp.example.com/post"],
                    "backchannel_logout_uri": "https://rp.example.com/back",
                    "backchannel_logout_session_required": True
                },
                "usage": {
                    "backchannel_logout": True
                }
            }
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
    _md = client.collect_metadata()
    assert set(_md.keys()) == {'application_type',
                               'backchannel_logout_uri',
                               "backchannel_logout_session_required",
                               'client_id',
                               'contacts',
                               'grant_types',
                               'id_token_signed_response_alg',
                               'post_logout_redirect_uris',
                               'redirect_uris',
                               'request_object_signing_alg',
                               'request_uris',
                               'response_types',
                               'token_endpoint_auth_method',
                               'token_endpoint_auth_signing_alg',
                               'userinfo_signed_response_alg'}

    # What's in service configuration has higher priority then metadata.
    assert client.get_metadata_claim("contacts") == 'support@example.com'
    # Two ways of looking at things
    assert client.get_metadata_claim("userinfo_signed_response_alg") == "ES256"
    assert client.metadata_claim_contains_value("userinfo_signed_response_alg", "ES256")
    # How to act
    assert client.get_usage_value("request_uri") is True

    _conf_args = client.config_args()
    assert _conf_args
    total_metadata_args = {}
    for key, val in _conf_args.items():
        total_metadata_args.update(val["metadata"])
    ma = list(total_metadata_args.keys())
    ma.sort()
    assert len(ma) == 36
    rr = set(RegistrationRequest.c_param.keys())
    d = rr.difference(set(ma))
    assert d == {'federation_type', 'organization_name', 'post_logout_redirect_uri'}


def test_create_client_key_conf():
    client_config = CLIENT_CONFIG.copy()
    client_config.update({"key_conf": KEY_CONF})

    client = Entity(config=client_config)
    _jwks = client.get_metadata_claim("jwks")
    assert _jwks


def test_create_client_keyjar():
    _keyjar = init_key_jar(**KEY_CONF)
    client_config = CLIENT_CONFIG.copy()

    client = Entity(config=client_config, keyjar=_keyjar)
    _jwks = client.get_metadata_claim("jwks")
    assert _jwks


def test_create_client_jwks_uri():
    client_config = CLIENT_CONFIG.copy()
    client = Entity(config=client_config, jwks_uri="https://rp.example.com/jwks_uri.json")
    assert client.get_metadata_claim("jwks_uri")
