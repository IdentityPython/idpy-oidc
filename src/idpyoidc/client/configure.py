"""Configuration management for Client"""
import logging
from typing import Dict
from typing import List
from typing import Optional

from idpyoidc.configure import Base
from idpyoidc.logging import configure_logging

from .util import lower_or_upper

try:
    from secrets import token_urlsafe as rnd_token
except ImportError:
    from cryptojwt import rndstr as rnd_token

URIS = [
    "redirect_uris", 'post_logout_redirect_uris', 'frontchannel_logout_uri',
    'backchannel_logout_uri', 'issuer', 'base_url']


class RPConfiguration(Base):
    def __init__(self,
                 conf: Dict,
                 base_path: Optional[str] = '',
                 entity_conf: Optional[List[dict]] = None,
                 domain: Optional[str] = "127.0.0.1",
                 port: Optional[int] = 80,
                 file_attributes: Optional[List[str]] = None,
                 dir_attributes: Optional[List[str]] = None,
                 ):

        Base.__init__(self, conf,
                      base_path=base_path,
                      domain=domain,
                      port=port,
                      file_attributes=file_attributes,
                      dir_attributes=dir_attributes)

        self.key_conf = lower_or_upper(conf, 'rp_keys') or lower_or_upper(conf, 'oidc_keys')

        hash_seed = lower_or_upper(conf, 'hash_seed')
        if not hash_seed:
            hash_seed = rnd_token(32)
        self.hash_seed = hash_seed

        self.base_url = lower_or_upper(conf, "base_url")
        self.httpc_params = lower_or_upper(conf, "httpc_params", {"verify": True})

        self.default = lower_or_upper(conf, "default", {})

        for param in ["services", "client_preferences", "add_ons"]:
            _val = lower_or_upper(conf, param, {})
            if _val and param not in self.default:
                self.default[param] = _val

        self.clients = lower_or_upper(conf, "clients")
        for id, client in self.clients.items():
            for param in ["services", "client_preferences", "add_ons"]:
                if param not in client:
                    if param in self.default:
                        client[param] = self.default[param]

        if entity_conf:
            self.extend(entity_conf=entity_conf, conf=conf, base_path=base_path,
                        file_attributes=file_attributes, domain=domain, port=port)


class Configuration(Base):
    """RP Configuration"""

    def __init__(self,
                 conf: Dict,
                 base_path: str = '',
                 entity_conf: Optional[List[dict]] = None,
                 file_attributes: Optional[List[str]] = None,
                 domain: Optional[str] = "",
                 port: Optional[int] = 0,
                 dir_attributes: Optional[List[str]] = None,
                 ):
        Base.__init__(self, conf, base_path=base_path, file_attributes=file_attributes,
                      dir_attributes=dir_attributes)

        log_conf = conf.get('logging')
        if log_conf:
            self.logger = configure_logging(config=log_conf).getChild(__name__)
        else:
            self.logger = logging.getLogger('client')

        self.web_conf = lower_or_upper(conf, "webserver")

        if entity_conf:
            self.extend(entity_conf=entity_conf, conf=conf, base_path=base_path,
                        file_attributes=file_attributes, domain=domain, port=port,
                        dir_attributes=dir_attributes)
