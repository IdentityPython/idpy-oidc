import logging
from typing import Optional
from typing import Union

from cryptojwt import KeyJar
from cryptojwt.key_jar import init_key_jar

from idpyoidc.client.client_auth import CLIENT_AUTHN_METHOD
from idpyoidc.client.client_auth import client_auth_setup
from idpyoidc.client.configure import Configuration
from idpyoidc.client.configure import get_configuration
from idpyoidc.client.defaults import DEFAULT_OAUTH2_SERVICES
from idpyoidc.client.defaults import DEFAULT_OIDC_SERVICES
from idpyoidc.client.service import init_services
from idpyoidc.client.service_context import ServiceContext
from idpyoidc.context import OidcContext
from idpyoidc.node import Unit

logger = logging.getLogger(__name__)

RESPONSE_TYPES2GRANT_TYPES = {
    "code": ["authorization_code"],
    "id_token": ["implicit"],
    "id_token token": ["implicit"],
    "code id_token": ["authorization_code", "implicit"],
    "code token": ["authorization_code", "implicit"],
    "code id_token token": ["authorization_code", "implicit"],
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


def _set_jwks(service_context, config: Configuration, keyjar: Optional[KeyJar]):
    _key_conf = config.get("key_conf") or config.conf.get('key_conf')

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
    for k, v in callback_uris['redirect_uris'].items():
        res.extend(v)
    return res


class Entity(Unit):
    def __init__(
            self,
            keyjar: Optional[KeyJar] = None,
            config: Optional[Union[dict, Configuration]] = None,
            services: Optional[dict] = None,
            jwks_uri: Optional[str] = "",
            httpc: Optional[Callable] = None,
            httpc_params: Optional[dict] = None,
            client_type: Optional[str] = "oauth2",
            context: Optional[OidcContext] = None,
            upstream_get: Optional[Callable] = None,
            key_conf: Optional[dict] = None,
            entity_id: Optional[str] = ''
    ):
        Unit.__init__(self, upstream_get=upstream_get, keyjar=keyjar, httpc=httpc,
                      httpc_params=httpc_params, config=config, key_conf=key_conf,
                      entity_id=entity_id)

        if context:
            self._service_context = context
        else:
            self._service_context = ServiceContext(config=config, jwks_uri=jwks_uri,
                                                   upstream_get=self.unit_get)

        if services:
            _srvs = services
        elif config:
            _srvs = config.get("services")
        else:
            _srvs = None

        if not _srvs:
            _srvs = DEFAULT_OAUTH2_SERVICES

        self._service = init_services(service_definitions=_srvs, upstream_get=self.unit_get)

        self.keyjar = self._service_context.get_preference('keyjar')

        self.setup_client_authn_methods(config)
        self.upstream_get = upstream_get

    def get_services(self, *arg):
        return self._service

    def get_service_context(self, *arg):  # Want to get rid of this
        return self._service_context

    def get_context(self, *arg):
        return self._service_context

    def get_service(self, service_name, *arg):
        try:
            return self._service[service_name]
        except KeyError:
            return None

    def get_service_by_endpoint_name(self, endpoint_name, *arg):
        for service in self._service.values():
            if service.endpoint_name == endpoint_name:
                return service

        return None

    def get_entity(self):
        return self

    def get_client_id(self):
        _val = self._service_context.work_environment.get_usage('client_id')
        if _val:
            return _val
        else:
            return self._service_context.work_environment.get_preference('client_id')

    def setup_client_authn_methods(self, config):
        if config and "client_authn_methods" in config:
            self._service_context.client_authn_method = client_auth_setup(
                config.get("client_authn_methods")
            )
        else:
            _default_methods = set(
                [s.default_authn_method for s in self._service.db.values() if
                 s.default_authn_method])
            _methods = {m: CLIENT_AUTHN_METHOD[m] for m in _default_methods if
                        m in CLIENT_AUTHN_METHOD}
            self._service_context.client_authn_method = client_auth_setup(_methods)
