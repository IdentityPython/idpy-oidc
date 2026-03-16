"""Configuration management for Client"""
from typing import Dict
from typing import List
from typing import Optional

from idpyoidc.configure import Base
from idpyoidc.logging import configure_logging
from .util import lower_or_upper
from ..impexp import ignore_item

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


class RPConfiguration(Base):
    """Configuration for a single RP"""

    special_load_dump = {'logger': {'dump': ignore_item}}

    def __init__(
            self,
            conf: Optional[Dict] = None,
            base_path: Optional[str] = "",
            entity_conf: Optional[List[dict]] = None,
            file_attributes: Optional[List[str]] = None,
            domain: Optional[str] = "",
            port: Optional[int] = 0,
            dir_attributes: Optional[List[str]] = None,
            **kwargs
    ):
        if conf is None:
            conf = {}

        Base.__init__(
            self,
            conf,
            base_path=base_path,
            file_attributes=file_attributes,
            dir_attributes=dir_attributes,
            domain=domain,
            port=port,
            **kwargs
        )

        # move kwargs upstairs
        _del_key = []
        for attr in ["issuer", "key_conf"]:
            if attr in self.args:
                setattr(self, attr, self.args[attr])
                del self.args[attr]
            if attr in kwargs:
                setattr(self, attr, kwargs[attr])

        log_conf = conf.get("logging")
        if log_conf:
            self._logger = configure_logging(config=log_conf).getChild(__name__)
            self.log_conf = log_conf

        self.web_conf = kwargs.get("web_conf")
        if not self.web_conf:
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

    def to_dict(self):
        return {k: v for k, v in self.items() if k != 'logger'}
