from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt import KeyJar
from idpyoidc.context import OidcContext

from idpyoidc.client.client_auth import client_auth_setup
from idpyoidc.client.configure import Configuration
from idpyoidc.client.defaults import DEFAULT_OAUTH2_SERVICES
from idpyoidc.client.service import init_services
from idpyoidc.client.service_context import ServiceContext


class Entity(object):
    def __init__(
        self,
        keyjar: Optional[KeyJar] = None,
        config: Optional[Union[dict, Configuration]] = None,
        services: Optional[dict] = None,
        jwks_uri: Optional[str] = "",
        httpc_params: Optional[dict] = None,
        context: Optional[OidcContext] = None,
        superior_get: Optional[Callable] = None
    ):

        if httpc_params:
            self.httpc_params = httpc_params
        else:
            self.httpc_params = {"verify": True}

        if context:
            self._service_context = context
        else:
            self._service_context = ServiceContext(
                keyjar=keyjar, config=config, jwks_uri=jwks_uri, httpc_params=self.httpc_params
            )

        if config:
            _srvs = config.get("services")
        else:
            _srvs = None

        if not _srvs:
            _srvs = services or DEFAULT_OAUTH2_SERVICES

        self._service = init_services(service_definitions=_srvs, superior_get=self.entity_get)

        self.setup_client_authn_methods(config)
        self.superior_get = superior_get

    def entity_get(self, what, *arg):
        _func = getattr(self, "get_{}".format(what), None)
        if _func:
            return _func(*arg)
        return None

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
        return self._service_context.client_id

    def get_keyjar(self):
        if self.get_service_context().keyjar:
            return self.get_service_context().keyjar
        else:
            return self.superior_get('application','keyjar')

    def setup_client_authn_methods(self, config):
        if config and "client_authn_methods" in config:
            self._service_context.client_authn_method = client_auth_setup(
                config.get("client_authn_methods")
            )
        else:
            self._service_context.client_authn_method = {}


