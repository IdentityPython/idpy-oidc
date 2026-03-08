import pytest

from idpyoidc.client.configure import Configuration
from idpyoidc.client.configure import get_configuration
from idpyoidc.configure import Base


@pytest.mark.parametrize(
    "configuration",
    [
        {
            'domain': 'https://example.com',
            'conf': {
                'foo': 1,
                'bar': 2
            },
        },
        Configuration({'foo': 1, 'bar': 2}, domain='https://example.com'),
        Base({'foo': 1, 'bar': 2}, domain='https://example.com'),
    ]
)
def test_configure(configuration):
    config = get_configuration(configuration)
    assert isinstance(config, Base)
    assert config.getargs("foo") == 1
    assert config.getargs("bar") == 2
    assert config.domain == "https://example.com"


def test_domain_configure():
    CONF = {
        "port": 5000,
        "domain": "127.0.0.1",
        "conf": {
            "server_name": "{domain}:{port}",
            "base_url": "https://{domain}:{port}",
            'foo': {
                'entity_id': "https://{domain}:{port}",
            },
            'bar': "https://{domain}/bar",
            'xyz': 'pool:{port}'
        }
    }
    config = get_configuration(CONF)
    assert isinstance(config, Base)
    assert set(config.args.keys()) == {'server_name', 'foo', 'bar', 'base_url', 'xyz'}

    assert config.getargs("foo") == {'entity_id': 'https://127.0.0.1:5000'}
    assert config.getargs("bar") == "https://127.0.0.1/bar"
    assert config.getargs("server_name") == "127.0.0.1:5000"
    assert config.getargs("base_url") == "https://127.0.0.1:5000"
    assert config.getargs("xyz") == "pool:5000"

    assert config.domain == '127.0.0.1'
    assert config.port == 5000


def test_attributes():
    config = get_configuration({'conf': {'template_dir': 'templates'}, 'base_path': '/Users/erik'})
    assert isinstance(config, Base)
    assert set(config.args.keys()) == {'template_dir'}
    assert config.getargs("template_dir") == "/Users/erik/templates"
