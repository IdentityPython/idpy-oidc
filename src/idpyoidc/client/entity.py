import logging
from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt import KeyBundle
from cryptojwt import KeyJar
from cryptojwt.jwk.rsa import RSAKey
from cryptojwt.jwk.rsa import import_private_rsa_key_from_file
from cryptojwt.key_jar import init_key_jar

from idpyoidc.client.client_auth import client_auth_setup
from idpyoidc.client.client_auth import method_to_item
from idpyoidc.client.configure import Configuration
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


def _set_jwks(service_context, config: Configuration, keyjar: Optional[KeyJar]):
    _key_conf = config.get("key_conf") or config.conf.get("key_conf")

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
        "keyjar": KeyJar,
        "context": None,
    }

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
        entity_id: Optional[str] = "",
    ):
        if config is None:
            config = {}

        _id = config.get("client_id")
        self.client_id = self.entity_id = entity_id or config.get("entity_id", _id)

        Unit.__init__(
            self,
            upstream_get=upstream_get,
            keyjar=keyjar,
            httpc=httpc,
            httpc_params=httpc_params,
            config=config,
            key_conf=key_conf,
            client_id=self.client_id,
        )

        if services:
            _srvs = services
        elif config:
            _srvs = config.get("services")
        else:
            _srvs = None

        if not _srvs:
            if client_type == "oauth2":
                _srvs = DEFAULT_OAUTH2_SERVICES
            else:
                _srvs = DEFAULT_OIDC_SERVICES

        self._service = init_services(service_definitions=_srvs, upstream_get=self.unit_get)

        if context:
            self.context = context
        else:
            self.context = ServiceContext(
                config=config,
                jwks_uri=jwks_uri,
                keyjar=self.keyjar,
                upstream_get=self.unit_get,
                client_type=client_type,
                entity_id=self.entity_id,
            )

        self.setup_client_authn_methods(config)
        self.upstream_get = upstream_get

    def get_services(self, *arg):
        return self._service

    def get_service_context(self, *arg):  # Want to get rid of this
        return self.context

    def get_context(self, *arg):
        return self.context

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

    # def get_entity(self):
    #     return self

    def get_client_id(self):
        _val = self.context.claims.get_usage("client_id")
        if _val:
            return _val
        else:
            return self.context.claims.get_preference("client_id")

    def setup_client_authn_methods(self, config):
        if config and "client_authn_methods" in config:
            _methods = config.get("client_authn_methods")
            self.context.client_authn_methods = client_auth_setup(method_to_item(_methods))
        else:
            self.context.client_authn_methods = {}

    def import_keys(self, keyspec):
        """
        The client needs its own set of keys. It can either dynamically
        create them or load them from local storage.
        This method can also fetch other entities keys provided the
        URL points to a JWKS.

        :param keyspec:
        """
        _keyjar = self.get_attribute("keyjar")
        if _keyjar is None:
            _keyjar = KeyJar()

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

    def get_callback_uris(self):
        return self.context.claims.get_preference("callback_uris")
