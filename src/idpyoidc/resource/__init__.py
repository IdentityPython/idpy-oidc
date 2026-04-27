import os
from typing import Any
from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt import KeyJar
from cryptojwt.utils import importer

from idpyoidc.client.service import init_services
from idpyoidc.configure import Base
from idpyoidc.configure import Configuration
from idpyoidc.configure import init_config
from idpyoidc.message import Message
from idpyoidc.message.oauth2 import OAuthProtectedResourceRequest
from idpyoidc.node import Unit
from idpyoidc.resource.context import ResourceContext
from idpyoidc.server import do_endpoints
from idpyoidc.server import Endpoint
from idpyoidc.server.configure import OAuthResourceConfiguration
from idpyoidc.server.endpoint_context import init_service
from idpyoidc.server.util import execute


class ResourceEntity(Unit):
    name = 'oauth_resource'
    parameter = {"endpoint": [Endpoint], "context": ResourceContext}
    config_class = OAuthResourceConfiguration
    metadata_schema = OAuthProtectedResourceRequest


    def __init__(
            self,
            config: Optional[Union[dict, Configuration]] = None,
            upstream_get: Optional[Callable] = None,
            keyjar: Optional[KeyJar] = None,
            httpc: Optional[Any] = None,
            httpc_params: Optional[dict] = None,
            entity_id: Optional[str] = "",
            key_conf: Optional[dict] = None,
            server_type: Optional[str] = "",
            entity_type: Optional[str] = '',
            metadata_schema: Optional[str] = "",
            # preference: Optional[dict] = None,
            **kwargs
    ):
        config = init_config(config, config_class=self.config_class)

        # Or should I just add all kwargs args to config
        for attr in ['preference', 'endpoint', 'template_dir', 'session_params']:
            _val = kwargs.get(attr)
            if _val:
                config[attr] = _val

        self.server_type = server_type or config.getarg("server_type", "")
        self.entity_type = entity_type or config.getarg("entity_type", "")
        if not self.server_type:
            if self.entity_type == "oauth_resource":
                self.server_type = "oauth_resource"

        if metadata_schema:
            self.metadata_schema = importer(metadata_schema)
        else:
            if self.server_type == "oauth_resource":
                self.metadata_schema = OAuthProtectedResourceRequest()

        Unit.__init__(self, upstream_get=upstream_get, keyjar=keyjar, httpc=httpc,
                      httpc_params=httpc_params, entity_id=entity_id, key_conf=key_conf,
                      config=config)

        if not isinstance(config, Base):
            config['issuer'] = entity_id
            config['base_url'] = entity_id
            if self.server_type == "oauth_resource":
                config = OAuthResourceConfiguration(config)
            else:
                raise ValueError("Server type not supported")

        if self.server_type == "oauth_resource" and not isinstance(config, OAuthResourceConfiguration):
            raise ValueError("Server type and configuration type does not match")

        self.config = config

        self.endpoint = do_endpoints(config, self.unit_get)

        self.service = {}
        _srvs = self.config.getarg("services")
        if _srvs:
            self.service = init_services(_srvs, self.unit_get)

        self.context = ResourceContext(
            config=config,
            entity_id=entity_id,
            upstream_get=self.unit_get,
            key_conf=key_conf,
            keyjar=keyjar,
            metadata_schema=self.metadata_schema
        )

        for endpoint_name, item in self.endpoint.items():
            item.context = self.context

        self.context.claims_interface = init_service(config.getarg("claims_interface"), self.unit_get,
                                                     context=self.context)

        _per_conf = config.get("persistence", None)
        if _per_conf:
            _storage = execute(_per_conf["kwargs"]["storage"])
            _class = _per_conf["class"]
            kwargs = {"storage": _storage, "upstream_get": self.unit_get}
            if isinstance(_class, str):
                self.persistence = importer(_class)(**kwargs)
            else:
                self.persistence = _per_conf["class"](**kwargs)

    def get_metadata(self,
                     schema: Optional[Message] = None,
                     entity_type: Optional[str] = '',
                     server_entity_id: Optional[str] = "",
                     ):

        if not schema:
            schema = self.metadata_schema

        _context = self.context
        _metadata = _context.get_metadata(_context.supports(), schema)

        _jwks_uri = getattr(self, 'jwks_uri', '')
        if _jwks_uri:
            _metadata['jwks_uri'] = os.path.join(self.base_url, _jwks_uri)
        elif _context.keyjar is not None:
            _metadata['jwks'] = _context.keyjar.export_jwks(issuer_id="")

        if self.upstream_get:
            return {self.name: _metadata}
        else:
            return _metadata
