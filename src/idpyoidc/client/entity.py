import hashlib
import logging
import os
from typing import Optional
from typing import Union

from cryptojwt import KeyJar
from cryptojwt.key_jar import init_key_jar
from cryptojwt.utils import as_bytes

from idpyoidc.client.client_auth import client_auth_setup
from idpyoidc.client.configure import Configuration
from idpyoidc.client.configure import get_configuration
from idpyoidc.client.defaults import DEFAULT_OAUTH2_SERVICES
from idpyoidc.client.defaults import DEFAULT_OIDC_SERVICES
from idpyoidc.client.service import init_services
from idpyoidc.client.service_context import ServiceContext

logger = logging.getLogger(__name__)

rt2gt = {
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
            _gt = rt2gt[" ".join(_rt)]
        except KeyError:
            logger.warning("No such response type combination: {}".format(response_types))
        else:
            _res.update(set(_gt))

    return list(_res)


def set_jwks_uri_or_jwks(entity, service_context, config, jwks_uri, keyjar):
    # lots of different ways to configure the RP's keys
    if jwks_uri:
        entity.set_support("jwks_uri", True)
        entity.set_metadata_claim("jwks_uri", jwks_uri)
    else:
        if config.get("jwks_uri"):
            entity.set_support("jwks_uri", True)
            entity.set_support("jwks", False)
        elif config.get("jwks"):
            entity.set_support("jwks", True)
            entity.set_support("jwks_uri", False)
        else:
            entity.set_support("jwks_uri", False)
            if config.get("key_conf"):
                keys_args = {k: v for k, v in config.get("key_conf").items() if k != "uri_path"}
                _keyjar = init_key_jar(**keys_args)
                entity.set_support("jwks", True)
                entity.set_metadata_claim("jwks", _keyjar.export_jwks())
                return
            elif keyjar:
                entity.set_support("jwks", True)
                entity.set_metadata_claim("jwks", keyjar.export_jwks())
                return

        for attr in ["jwks_uri", "jwks"]:
            if entity.will_use(attr):
                _val = getattr(service_context, attr)
                if _val:
                    entity.set_metadata_claim(attr, _val)
                    return


class Entity(object):
    def __init__(
            self,
            keyjar: Optional[KeyJar] = None,
            config: Optional[Union[dict, Configuration]] = None,
            services: Optional[dict] = None,
            jwks_uri: Optional[str] = "",
            httpc_params: Optional[dict] = None,
            client_type: Optional[str] = "oauth2"
    ):
        self.extra = {}
        if httpc_params:
            self.httpc_params = httpc_params
        else:
            self.httpc_params = {"verify": True}

        config = get_configuration(config)

        if keyjar:
            _kj = keyjar.copy()
        else:
            _kj = None

        self._service_context = ServiceContext(
            keyjar=keyjar, config=config, jwks_uri=jwks_uri, httpc_params=self.httpc_params,
            client_type=client_type, client_get=self.client_get
        )

        if config:
            _srvs = config.conf.get("services")
        else:
            _srvs = None

        if not _srvs:
            if services:
                _srvs = services
            elif client_type == "oauth2":
                _srvs = DEFAULT_OAUTH2_SERVICES
            else:
                _srvs = DEFAULT_OIDC_SERVICES

        self._service = init_services(service_definitions=_srvs, client_get=self.client_get,
                                      metadata=config.conf.get("metadata", {}),
                                      support=config.conf.get("support", {}))

        self.setup_client_authn_methods(config)

        jwks_uri = jwks_uri or self.get_metadata_claim("jwks_uri")
        set_jwks_uri_or_jwks(self, self._service_context, config, jwks_uri, _kj)

        # Deal with backward compatibility
        self.backward_compatibility(config)

        self.construct_uris(self._service_context.issuer,
                            self._service_context.hash_seed,
                            config.conf.get("callback"))

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
        return self._service_context.work_condition.get_usage_claim('client_id')

    def setup_client_authn_methods(self, config):
        self._service_context.client_authn_method = client_auth_setup(
            config.get("client_authn_methods")
        )

    def backward_compatibility(self, config):
        _uris = config.get("redirect_uris")
        if _uris:
            self.set_metadata_claim("redirect_uris", _uris)

        _dir = config.conf.get("requests_dir")
        if _dir:
            authz_serv = self.get_service('authorization')
            if authz_serv:  # If this isn't true that's weird. Tests perhaps ?
                self.set_support("request_uri", True)
                if not os.path.isdir(_dir):
                    os.makedirs(_dir)
                authz_serv.callback_path["request_uris"] = _dir

        _pref = config.get("client_preferences", {})
        for key, val in _pref.items():
            if self.set_metadata_claim(key, val) is False:
                if self.set_support(key, val) is False:
                    setattr(self, key, val)

        for key, val in config.conf.items():
            if key not in ["port", "domain", "httpc_params", "metadata", "client_preferences",
                           "support", "services", "add_ons"]:
                self.extra[key] = val

        auth_request_args = config.conf.get("request_args", {})
        if auth_request_args:
            authz_serv = self.get_service('authorization')
            authz_serv.default_request_args.update(auth_request_args)

    def config_args(self):
        res = {}
        for id, service in self._service.items():
            res[id] = {
                "metadata": service.metadata_claims,
                "support": service.can_support
            }
        res[""] = {
            "metadata": self._service_context.work_condition.metadata_claims,
            "support": self._service_context.work_condition.can_support
        }
        return res

    def get_callback_uris(self):
        res = []
        for service in self._service.values():
            res.extend(service.callback_uris)
        res.extend(self._service_context.work_condition.callback_uris)
        return res
