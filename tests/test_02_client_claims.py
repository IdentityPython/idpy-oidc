from cryptojwt import KeyJar
from cryptojwt.jwk.hmac import SYMKey
import pytest

from idpyoidc.client.claims import Claims


@pytest.mark.parametrize(
    "configuration, result",
    [
        ({'base_url': 'https://example.com'}, "https://example.com"),
        ({'entity_id': 'https://example.com'}, "https://example.com"),
        ({'client_id': 'https://example.com'}, "https://example.com"),
        ({'base_url': 'https://example.com', 'entity_id': 'https://entity.example.com'},
         "https://example.com"),
        ({'base_url': 'https://example.com', 'client_id': 'https://client.example.com'},
         "https://example.com"),
        ({'entity_id': 'https://entity.example.com', 'client_id': 'https://client.example.com'},
         "https://entity.example.com")
    ]
)
def test_get_base_url(configuration, result):
    #
    claims = Claims()
    _base_url = claims.get_base_url(configuration)
    assert _base_url == result

@pytest.mark.parametrize(
    "configuration",
    [
        {'client_id': 'abcdefghijklmnopqr'},
        {'entity_id': 'abcdefghijklmnopqr'},
        {}
    ])
def test_fail_get_base_url(configuration):
    claims = Claims()
    with pytest.raises(ValueError):
        claims.get_base_url(configuration)

def test_add_extra_keys():
    claims = Claims()
    claims.set_preference('client_secret', 'abcdefghijklmnopqr')
    keyjar = claims.add_extra_keys(keyjar=None, id='foobar')
    assert isinstance(keyjar, KeyJar)
    assert set(keyjar.owners()) == {'foobar', ''}
    sig_keys = keyjar.get_issuer_keys('')
    assert len(sig_keys) == 1
    assert isinstance(sig_keys[0], SYMKey)
