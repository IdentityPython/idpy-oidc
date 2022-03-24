import os
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

import pytest

from idpyoidc.configure import Base
from idpyoidc.configure import Configuration
from idpyoidc.configure import create_from_config_file
from idpyoidc.configure import lower_or_upper
from idpyoidc.util import rndstr

_dirname = os.path.dirname(os.path.abspath(__file__))

URIS = ["base_url"]


class EntityConfiguration(Base):
    def __init__(self,
                 conf: Dict,
                 entity_conf: Optional[Any] = None,
                 base_path: Optional[str] = '',
                 domain: Optional[str] = "",
                 port: Optional[int] = 0,
                 file_attributes: Optional[List[str]] = None,
                 uris: Optional[List[str]] = None,
                 dir_attributes: Optional[List[str]] = None
                 ):
        Base.__init__(self, conf, base_path=base_path, file_attributes=file_attributes,
                      dir_attributes=dir_attributes)

        self.keys = lower_or_upper(conf, 'keys')

        self.hash_seed = lower_or_upper(conf, 'hash_seed', rndstr(32))
        self.base_url = conf.get("base_url")
        self.httpc_params = conf.get("httpc_params", {"verify": False})


def test_server_config():
    configuration = create_from_config_file(Configuration,
                                            entity_conf=[
                                                {"class": EntityConfiguration, "attr": "entity"}],
                                            filename=os.path.join(_dirname, 'server_conf.json'),
                                            base_path=_dirname)
    assert configuration
    assert set(configuration.web_conf.keys()) == {'port', 'domain', 'server_cert', 'server_key',
                                                  'debug'}

    entity_config = configuration.entity
    assert entity_config.base_url == "https://127.0.0.1:8090"
    assert entity_config.httpc_params == {"verify": False}


@pytest.mark.parametrize("filename", ['entity_conf.json', 'entity_conf.py'])
def test_entity_config(filename):
    configuration = create_from_config_file(EntityConfiguration,
                                            filename=os.path.join(_dirname, filename),
                                            base_path=_dirname)
    assert configuration

    assert configuration.base_url == "https://127.0.0.1:8090"
    assert configuration.httpc_params == {"verify": False}
    assert configuration['keys']
    ni = dict(configuration.items())
    assert len(ni) == 9
    assert set(ni.keys()) == {'base_url', '_dir_attributes', '_file_attributes', 'hash_seed',
                              'httpc_params', 'keys', 'conf', 'port', 'domain'}
