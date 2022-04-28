from typing import Optional
from typing import Union

from cryptojwt import KeyJar

from idpyoidc.client.client_auth import client_auth_setup
from idpyoidc.client.configure import Configuration
from idpyoidc.client.defaults import DEFAULT_OAUTH2_SERVICES
from idpyoidc.client.service import init_services
from idpyoidc.client.service_context import ServiceContext

from src.idpyoidc.client.configure import get_configuration


class Entity(object):
    metadata_attributes = {
        "grant_types": ["authorization_code", "implicit", "refresh_token"],
        "application_type": "web",
        "contacts": [],
        "client_name": "",
        "logo_uri": "",
        "client_uri": "",
        "policy_uri": "",
        "tos_uri": "",
        "jwks_uri": "",
        "jwks": "",
        "sector_identifier_uri": "",
        "id_token_signed_response_alg": "RS256",
        "id_token_encrypted_response_alg": "",
        "id_token_encrypted_response_enc": "",
        "initiate_login_uri": ""
    }

    def __init__(
            self,
            keyjar: Optional[KeyJar] = None,
            config: Optional[Union[dict, Configuration]] = None,
            services: Optional[dict] = None,
            jwks_uri: Optional[str] = "",
            httpc_params: Optional[dict] = None,
    ):

        if httpc_params:
            self.httpc_params = httpc_params
        else:
            self.httpc_params = {"verify": True}

        config = get_configuration(config)

        self._service_context = ServiceContext(
            keyjar=keyjar, config=config, jwks_uri=jwks_uri, httpc_params=self.httpc_params
        )

        if config:
            _srvs = config.get("services")
        else:
            _srvs = None

        if not _srvs:
            _srvs = services or DEFAULT_OAUTH2_SERVICES

        self._service = init_services(service_definitions=_srvs, client_get=self.client_get)

        self.setup_client_authn_methods(config)

    def client_get(self, what, *arg):
        _func = getattr(self, "get_{}".format(what), None)
        if _func:
            return _func(*arg)
        return None

    def get_services(self, *arg):
        return self._service

    def get_service_context(self, *arg):
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

    def setup_client_authn_methods(self, config):
        self._service_context.client_authn_method = client_auth_setup(
            config.get("client_authn_methods")
        )
