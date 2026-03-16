import pytest

from idpyoidc.client.configure import RPConfiguration
from idpyoidc.configure import Base
from idpyoidc.configure import get_configuration


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
        RPConfiguration({'foo': 1, 'bar': 2}, domain='https://example.com'),
        Base({'foo': 1, 'bar': 2}, domain='https://example.com'),
    ]
)
def test_configure(configuration):
    config = get_configuration(configuration)
    assert isinstance(config, Base)
    assert config.getarg("foo") == 1
    assert config.getarg("bar") == 2
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

    assert config.getarg("foo") == {'entity_id': 'https://127.0.0.1:5000'}
    assert config.getarg("bar") == "https://127.0.0.1/bar"
    assert config.getarg("server_name") == "127.0.0.1:5000"
    assert config.getarg("base_url") == "https://127.0.0.1:5000"
    assert config.getarg("xyz") == "pool:5000"

    assert config.domain == '127.0.0.1'
    assert config.port == 5000


def test_attributes():
    config = get_configuration({'conf': {'template_dir': 'templates'}, 'base_path': '/Users/erik'})
    assert isinstance(config, Base)
    assert set(config.args.keys()) == {'template_dir'}
    assert config.getarg("template_dir") == "/Users/erik/templates"
