"""Configuration management for Client"""
import copy
from typing import Dict
from typing import List
from typing import Optional
from typing import Union

from idpyoidc.configure import Base
from idpyoidc.logging import configure_logging
from .util import lower_or_upper

try:
    from secrets import token_urlsafe as rnd_token
except ImportError:
    from cryptojwt import rndstr as rnd_token

URIS = [
    "redirect_uris",
    "post_logout_redirect_uris",
    "frontchannel_logout_uri",
    "backchannel_logout_uri",
    "issuer",
    "base_url",
]


class Configuration(Base):
    """Configuration for a single RP"""

    def __init__(
            self,
            conf: Dict,
            base_path: str = "",
            entity_conf: Optional[List[dict]] = None,
            file_attributes: Optional[List[str]] = None,
            domain: Optional[str] = "",
            port: Optional[int] = 0,
            dir_attributes: Optional[List[str]] = None,
    ):
        Base.__init__(
            self,
            conf,
            base_path=base_path,
            file_attributes=file_attributes,
            dir_attributes=dir_attributes,
            domain=domain,
            port=port,
        )

        # move kwargs upstairs
        _del_key = []
        for attr, val in self.args.items():
            if attr in ["issuer", "key_conf"]:
                setattr(self, attr, val)
                _del_key.append(attr)

        for _key in _del_key:
            del self.args[_key]

        log_conf = conf.get("logging")
        if log_conf:
            self.logger = configure_logging(config=log_conf).getChild(__name__)

        self.web_conf = lower_or_upper(conf, "webserver")

        if entity_conf:
            self.extend(
                entity_conf=entity_conf,
                conf=conf,
                base_path=base_path,
                file_attributes=file_attributes,
                domain=domain,
                port=port,
                dir_attributes=dir_attributes,
            )

def get_configuration(config: Optional[Union[dict, Base]] = None,
                      config_class: Optional[type(Base)] = Configuration) -> Base:
    if config is None:
        config = config_class({})
    elif isinstance(config, dict):
        if not isinstance(config, Base):
            _c = copy.deepcopy(config)
            config = config_class(**_c)
    else:  # not None and not a dict or a Configure instance ??
        raise ValueError("Configuration in a format I don't support")

    return config
