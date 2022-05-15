"""Configuration management for Client"""
import copy
from typing import Dict
from typing import List
from typing import Optional
from typing import Union

from idpyoidc.configure import Base
from idpyoidc.logging import configure_logging
from idpyoidc.message.oidc import RegistrationResponse
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


class RPHConfiguration(Base):
    def __init__(
            self,
            conf: Dict,
            base_path: Optional[str] = "",
            entity_conf: Optional[List[dict]] = None,
            domain: Optional[str] = "127.0.0.1",
            port: Optional[int] = 80,
            file_attributes: Optional[List[str]] = None,
            dir_attributes: Optional[List[str]] = None,
    ):

        Base.__init__(
            self,
            conf,
            base_path=base_path,
            domain=domain,
            port=port,
            file_attributes=file_attributes,
            dir_attributes=dir_attributes,
        )

        for _attr in ["key_conf", "rp_keys", "oidc_keys"]:
            _val = lower_or_upper(conf, _attr)
            if _val:
                self.key_conf = _val
                break

        hash_seed = lower_or_upper(conf, "hash_seed")
        if not hash_seed:
            hash_seed = rnd_token(32)
        self.hash_seed = hash_seed

        self.base_url = lower_or_upper(conf, "base_url")
        self.httpc_params = lower_or_upper(conf, "httpc_params", {"verify": True})

        self.default = lower_or_upper(conf, "default", {})

        for param in ["services", "metadata", "add_ons", "usage"]:
            _val = lower_or_upper(conf, param, {})
            if _val and param not in self.default:
                self.default[param] = _val

        self.clients = lower_or_upper(conf, "clients")
        if self.clients:
            for id, client in self.clients.items():
                for param in ["services", "usage", "add_ons", 'metadata']:
                    if param not in client:
                        if param in self.default:
                            client[param] = self.default[param]

        if entity_conf:
            self.extend(
                entity_conf=entity_conf,
                conf=conf,
                base_path=base_path,
                file_attributes=file_attributes,
                domain=domain,
                port=port,
            )


class Configuration(Base):
    """ Configuration for a single RP """

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
        )

        _del_key = []
        for attr, val in self.conf.items():
            if attr in ["issuer", "base_url", "key_conf"]:
                setattr(self, attr, val)
                _del_key.append(attr)

        for _key in _del_key:
            del self.conf[_key]

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


def get_configuration(config: Optional[Union[dict, Configuration]] = None):
    if config is None:
        config = Configuration({})
    elif isinstance(config, dict):
        if not isinstance(config, Base):
            config = Configuration(copy.deepcopy(config))
    else:  # not None and not a dict ??
        raise ValueError("Configuration in a format I don't support")

    return config
