from idpyoidc.client.claims.oauth2resource import Claims
from idpyoidc.message.oauth2 import OAuthProtectedResourceRequest


def test_claims_oauth2resource():
    claims = Claims()
    config = {
        'preference': {
            "resource": 'https://foo.bar',
        },
        'capabilities': {
            "jwks_uri": 'https://foo.bar/jwks.json',
            "resource_documentation": 'https://foo.bar/documentation.html',
            "scopes_supported": ['foo', 'bar'],
            "resource_signing_alg_values_supported": ['ES256', 'ES384', 'ES512'],
            "resource_encryption_alg_values_supported": ['ECDH-ES'],
            "resource_encryption_enc_values_supported": ['A128GCM']
        }
    }
    claims.load_conf(config, supports={},
                     entity_id="https://example.org",
                     metadata_class=OAuthProtectedResourceRequest)

    req = claims.create_registration_request()
    assert req
    assert set(req.keys()) == {'jwks_uri',
                               'resource',
                               'resource_documentation',
                               'resource_encryption_alg_values_supported',
                               'resource_encryption_enc_values_supported',
                               'resource_signing_alg_values_supported',
                               'scopes_supported'}
