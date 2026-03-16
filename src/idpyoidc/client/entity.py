import json
import logging
import os
from typing import Callable
from typing import Optional
from typing import Union
from urllib.parse import urljoin

from cryptojwt import KeyBundle
from cryptojwt import KeyJar
from cryptojwt.jwk.rsa import RSAKey
from cryptojwt.jwk.rsa import import_private_rsa_key_from_file
from cryptojwt.key_jar import init_key_jar

from idpyoidc.client import get_base_url
from idpyoidc.client.client_auth import client_auth_setup
from idpyoidc.client.client_auth import method_to_item
from idpyoidc.client.configure import RPConfiguration
from idpyoidc.client.exception import ConfigurationError
from idpyoidc.client.exception import OidcServiceError
from idpyoidc.client.service_context import ServiceContext
from idpyoidc.client.service_context import create_new_context
from idpyoidc.configure import Base
from idpyoidc.configure import get_configuration
from idpyoidc.configure import init_config
from idpyoidc.message import Message
from idpyoidc.node import Unit
from idpyoidc.server.util import init_keyjar
from idpyoidc.util import keyjar_combination
from idpyoidc.util import keyjar_dump
from idpyoidc.util import keyjar_load

logger = logging.getLogger(__name__)

RESPONSE_TYPES2GRANT_TYPES = {
    "code": ["authorization_code"],
    "id_token": ["implicit"],
    # "id_token token": ["implicit"],
    "code id_token": ["authorization_code", "implicit"],
    # "code token": ["authorization_code", "implicit"],
    # "code id_token token": ["authorization_code", "implicit"],
}


def response_types_to_grant_types(response_types):
    _res = set()

    for response_type in response_types:
        _rt = response_type.split(" ")
        _rt.sort()
        try:
            _gt = RESPONSE_TYPES2GRANT_TYPES[" ".join(_rt)]
        except KeyError:
            logger.warning("No such response type combination: {}".format(response_types))
        else:
            _res.update(set(_gt))

    return list(_res)


def _set_jwks(service_context, config: RPConfiguration, keyjar: Optional[KeyJar]):
    _key_conf = config.getarg("key_conf")

    if _key_conf:
        keys_args = {k: v for k, v in _key_conf.items() if k != "uri_path"}
        _keyjar = init_key_jar(**keys_args)
        service_context.set_preference("jwks", _keyjar.export_jwks())
    elif keyjar:
        service_context.set_preference("jwks", keyjar.export_jwks())


def set_jwks_uri_or_jwks(service_context, config, jwks_uri, keyjar):
    # lots of different ways to configure the RP's keys
    if jwks_uri:
        service_context.set_preference("jwks_uri", jwks_uri)
    else:
        if config.get("jwks_uri"):
            service_context.set_preference("jwks_uri", jwks_uri)
        else:
            _set_jwks(service_context, config, keyjar)


def redirect_uris_from_callback_uris(callback_uris):
    res = []
    for k, v in callback_uris["redirect_uris"].items():
        res.extend(v)
    return res


class Entity(Unit):  # This is a Client. What type is undefined here.
    parameter = {
        "entity_id": None,
        "jwks_uri": None,
        "httpc_params": None,
        "key_conf": None,
        # "keyjar": KeyJar,
        "context": {"": ServiceContext},
    }

    special_load_dump = {
        "keyjar": {"load": keyjar_load, 'dump': keyjar_dump}
    }

    def __init__(
            self,
            keyjar: Optional[KeyJar] = None,
            config: Optional[Union[dict, RPConfiguration]] = None,
            services: Optional[dict] = None,
            jwks_uri: Optional[str] = "",
            httpc: Optional[Callable] = None,
            httpc_params: Optional[dict] = None,
            client_type: Optional[str] = "oauth2",
            context: Optional[dict] = None,
            upstream_get: Optional[Callable] = None,
            key_conf: Optional[list] = None,
            entity_id: Optional[str] = "",
            client_configs: Optional[dict] = None,
            base_url: Optional[str] = None,
            **kwargs
    ):
        self.config = init_config(config, RPConfiguration)

        # Client ID is set through configuration or at registration
        self.set_entity_id(config=self.config, entity_id=entity_id)

        Unit.__init__(
            self,
            upstream_get=upstream_get,
            keyjar=keyjar,
            httpc=httpc,
            httpc_params=httpc_params,
            config=self.config,
            key_conf=key_conf,
            # client_id=_id,
        )

        # get base URL
        base_url = get_base_url(base_url, self.config)

        # Keys used by all contexts
        self.keyjar = init_keyjar(self.config, keyjar, key_conf, issuer_id=self.entity_id, **kwargs)
        self.jwks_uri = jwks_uri or self.config.getarg("jwks_uri", '')
        if self.jwks_uri and not self.jwks_uri.startswith("https"):
            self.jwks_uri = urljoin(base_url, self.jwks_uri)

        _client_type = getattr(self, "client_type", client_type)

        _context_args = {
            "keyjar": None,
            "upstream_get": self.unit_get,
            "client_type": _client_type,
            "entity_id": self.entity_id,
            "base_url": base_url,
            "services": services
        }
        for attr in ['metadata_class', 'register2preferred']:
            if attr in kwargs:
                _context_args[attr] = kwargs.get(attr)
            elif attr == 'metadata_class':
                _mc = getattr(self, attr, None)
                if _mc:
                    _context_args[attr] = _mc

        if self.jwks_uri:
            _context_args['jwks_uri'] = self.jwks_uri

        if context:
            self.context = context
        else:
            _client_configs = client_configs or self.config.getarg("client_configs", {})
            if _client_configs:
                self.context = {}
                for server_id, conf in _client_configs.items():
                    issuer = conf.get("issuer", server_id)
                    self.context[issuer] = ServiceContext(
                        issuer,
                        config=conf,
                        **_context_args
                    )
            else:
                self.context = {
                    "": ServiceContext(
                        server_entity_id='',
                        config=self.config,
                        **_context_args
                    )
                }

        # '' MUST always be present
        if '' not in self.context:
            raise ValueError("Default context description missing")

        self.default_context = self.context['']

        self.setup_client_authn_methods(self.config, self.default_context)
        self.upstream_get = upstream_get

    def set_entity_id(self, config=None, entity_id: Optional[str] = ""):
        if entity_id:
            self.entity_id = entity_id

        if config is None:
            raise ValueError("config cannot be None if entity_id is empty")
        else:
            self.entity_id = config.getarg("client_id", '')

    def get_services(self, context, *arg):
        return context.service

    def get_context(self, server_entity_id="", *arg) -> ServiceContext:
        return self.context[server_entity_id]

    def get_service(self, context, service_name, *arg):
        try:
            return context.service[service_name]
        except KeyError:
            return None

    def get_service_by_endpoint_name(self, context, endpoint_name, *arg):
        for service in context.service.values():
            if service.endpoint_name == endpoint_name:
                return service

        return None

    def get_client_id(self, context):
        _val = context.claims.get_usage("client_id")
        if _val:
            return _val
        else:
            return context.claims.get_preference("client_id")

    def setup_client_authn_methods(self, config, context):
        if config:
            _methods = config.getarg("client_authn_methods")
            if _methods:
                context.client_authn_methods = client_auth_setup(method_to_item(_methods))
                for k, v in context.client_authn_methods.items():
                    v.context = context
                    v.upstream_get = self.unit_get
            else:
                context.client_authn_methods = {}
        else:
            context.client_authn_methods = {}

    def get_metadata(self, server_entity_id="",
                     metadata_schema: Optional[Message] = None,
                     with_entity_type: Optional[bool] = False
                     ):
        if with_entity_type:
            _entity_type = self.entity_type
        else:
            _entity_type = ''

        _context = self.get_context(server_entity_id)
        _metadata = _context.get_metadata(_entity_type, _context.supports(), metadata_schema)
        if with_entity_type:
            _md = _metadata[_entity_type]
        else:
            _md = _metadata
        _jwks_uri = getattr(self, 'jwks_uri', '')
        if _jwks_uri:
            _md['jwks_uri'] = os.path.join(self.base_url, _jwks_uri)
        else:
            _keyjar = keyjar_combination(self)
            _md['jwks'] = _keyjar.export_jwks(issuer_id="")
        return _metadata

    def import_keys(self, keyspec):
        """
        The client needs its own set of keys. It can either dynamically
        create them or load them from local storage.
        This method can also fetch other entities keys provided the
        URL points to a JWKS.

        :param keyspec:
        """
        _keyjar = self.keyjar
        if _keyjar is None:
            self.keyjar = _keyjar = KeyJar()

        for where, spec in keyspec.items():
            if where == "file":
                for typ, files in spec.items():
                    if typ == "rsa":
                        for fil in files:
                            _key = RSAKey(priv_key=import_private_rsa_key_from_file(fil), use="sig")
                            _bundle = KeyBundle()
                            _bundle.append(_key)
                            _keyjar.add_kb("", _bundle)
            elif where == "url":
                for iss, url in spec.items():
                    _bundle = KeyBundle(source=url)
                    _keyjar.add_kb(iss, _bundle)
        return _keyjar

    def get_callback_uris(self, context):
        return context.claims.get_preference("callback_uris")

    def add_new_context(self, server_entity_id: str, client_id: Optional[str] = '',
                        client_secret: Optional[str] = ''):
        context = create_new_context(self.context[''], server_entity_id)
        # context.issuer = server_entity_id
        self.context[server_entity_id] = context

        if client_id:
            context.client_id = client_id
            context.claims.use['client_id'] = client_id
            if client_secret:
                context.client_secret = client_secret
                context.claims.use['client_secret'] = client_secret
                # Add symmetric key to keyjar
                context.keyjar.add_symmetric(issuer_id="", key=client_secret)
                context.keyjar.add_symmetric(issuer_id=client_id, key=client_secret)

        self.setup_client_authn_methods(self.config, context)
        return self.context[server_entity_id]

    def get_context_by_client_id(self, client_id):
        for cntx in self.context.values():
            if cntx.client_id == client_id:
                return cntx
        return None


def load_registration_response(client, context, request_args: Optional[dict] = None):
    """
    If the client has been statically registered that information
    must be provided during the configuration. If expected to be
    done dynamically this method will do dynamic client registration.

    :param client: A :py:class:`idpyoidc.client.oidc.Client` instance
    """

    try:
        response = client.do_request(context, "registration", request_args=request_args)
    except KeyError:
        raise ConfigurationError("No registration info")
    except Exception as err:
        logger.error(err)
        raise
    else:
        if "error" in response:
            if isinstance(response, dict):
                raise OidcServiceError(json.dumps(response))
            else:
                raise OidcServiceError(response.to_json())
