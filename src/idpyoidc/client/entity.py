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
        entity.set_usage_value("jwks_uri", True)
        entity.set_metadata_value("jwks_uri", jwks_uri)
    else:
        if config.get("jwks_uri"):
            entity.set_usage_value("jwks_uri", True)
            entity.set_usage_value("jwks", False)
        elif config.get("jwks"):
            entity.set_usage_value("jwks", True)
            entity.set_usage_value("jwks_uri", False)
        else:
            entity.set_usage_value("jwks_uri", False)
            if config.get("key_conf"):
                _keyjar = init_key_jar(**config.get("key_conf"))
                entity.set_usage_value("jwks", True)
                entity.set_metadata_value("jwks", _keyjar.export_jwks())
                return
            elif keyjar:
                entity.set_usage_value("jwks", True)
                entity.set_metadata_value("jwks", keyjar.export_jwks())
                return

        for attr in ["jwks_uri", "jwks"]:
            if entity.will_use(attr):
                _val = getattr(service_context, attr)
                if _val:
                    entity.set_metadata_value(attr, _val)
                    return


class Entity(object):
    def __init__(
            self,
            keyjar: Optional[KeyJar] = None,
            config: Optional[Union[dict, Configuration]] = None,
            services: Optional[dict] = None,
            jwks_uri: Optional[str] = "",
            httpc_params: Optional[dict] = None,
            client_type: Optional[str] = ""
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
            client_type=client_type
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
                                      usage=config.conf.get("usage", {}))

        self.setup_client_authn_methods(config)

        jwks_uri = jwks_uri or self.get_metadata_value("jwks_uri")
        set_jwks_uri_or_jwks(self, self._service_context, config, jwks_uri, _kj)

        # Deal with backward compatible
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
        return self._service_context.get_client_id()

    def setup_client_authn_methods(self, config):
        self._service_context.client_authn_method = client_auth_setup(
            config.get("client_authn_methods")
        )

    def collect_metadata(self):
        res = {}
        for service in self._service.values():
            res.update(service.metadata)
        res.update(self._service_context.specs.get_all())
        return res

    def collect_usage(self):
        res = {}
        for service in self._service.values():
            res.update(service.usage)
        res.update(self._service_context.specs.usage)
        return res

    def get_metadata_value(self, attribute, default=None):
        for service in self._service.values():
            if attribute in service.metadata_attributes:
                return service.get_metadata(attribute, default)

        if attribute in self._service_context.specs.attributes:
            return self._service_context.specs.get_metadata(attribute, default)

        raise KeyError(f"Unknown specs attribute: {attribute}")

    def get_metadata_attributes(self):
        attr = []
        for service in self._service.values():
            attr.extend(list(service.metadata_attributes.keys()))

        attr.extend(list(self._service_context.specs.attributes.keys()))

        return attr

    def value_in_metadata_attribute(self, attribute, value):
        for service in self._service.values():
            if attribute in service.metadata_attributes.keys():
                _val = service.get_metadata(attribute)
                if isinstance(_val, list):
                    if value in _val:
                        return True
                else:
                    if value == _val:
                        return True

        if attribute in self._service_context.specs.attributes.keys():
            _val = self._service_context.specs.get_metadata(attribute)
            if isinstance(_val, list):
                if value in _val:
                    return True
            else:
                if value == _val:
                    return True

        return False

    def will_use(self, attribute):
        for service in self._service.values():
            if attribute in service.usage_rules.keys():
                if service.usage.get(attribute):
                    return True

        if attribute in self._service_context.specs.rules.keys():
            if self._service_context.specs.get_usage(attribute):
                return True
        return False

    def set_metadata_value(self, attribute, value):
        """
        Only OK to overwrite a value if the value is the default value
        """
        for service in self._service.values():
            if attribute in service.metadata_attributes:
                _def_val = service.metadata_attributes[attribute]
                if _def_val is None:
                    service.metadata[attribute] = value
                    return True
                else:
                    if service.metadata.get(attribute, _def_val) == _def_val:
                        service.metadata[attribute] = value
                        return True

        if attribute in self._service_context.specs.attributes:
            _def_val = self._service_context.specs.attributes[attribute]
            if _def_val is None:
                self._service_context.specs.set_metadata(attribute, value)
                return True
            else:
                if self._service_context.specs.get_metadata(attribute, _def_val):
                    self._service_context.specs.set_metadata(attribute, value)
                    return True
            return True

        logger.info(f"Unknown set specs attribute: {attribute}")
        return False

    def set_usage_value(self, attribute, value):
        """
        Only OK to overwrite a value if the value is the default value
        """
        for service in self._service.values():
            if attribute in service.usage_rules:
                _def_val = service.usage_rules[attribute]
                if _def_val is None:
                    service.usage[attribute] = value
                    return True
                else:
                    if service.usage[attribute] == _def_val:
                        service.usage[attribute] = value
                        return True

        if attribute in self._service_context.specs.rules:
            _def_val = self._service_context.specs.rules[attribute]
            if _def_val is None:
                self._service_context.specs.set_usage(attribute, value)
                return True
            else:
                if self._service_context.specs.usage[attribute] == _def_val:
                    self._service_context.specs.set_usage(attribute, value)
                    return True

        logger.info(f"Unknown set usage attribute: {attribute}")
        return False

    def get_usage_value(self, attribute, default=None):
        for service in self._service.values():
            if attribute in service.usage_rules:
                if attribute in service.usage:
                    return service.usage[attribute]
                else:
                    return default

        if attribute in self._service_context.specs.rules:
            _val = self._service_context.specs.get_usage(attribute)
            if _val:
                return _val
            else:
                return default

        logger.info(f"Unknown usage attribute: {attribute}")

    def construct_uris(self, issuer, hash_seed, callback):
        _hash = hashlib.sha256()
        _hash.update(hash_seed)
        _hash.update(as_bytes(issuer))
        _hex = _hash.hexdigest()

        self._service_context.iss_hash = _hex

        _base_url = self._service_context.get("base_url")
        for service in self._service.values():
            service.construct_uris(_base_url, _hex)

        if not self._service_context.specs.get_metadata("redirect_uris"):
            self._service_context.specs.construct_redirect_uris(_base_url, _hex, callback)

        self._service_context.specs.construct_uris(_base_url, _hex)

    def backward_compatibility(self, config):
        _uris = config.get("redirect_uris")
        if _uris:
            self.set_metadata_value("redirect_uris", _uris)

        _dir = config.conf.get("requests_dir")
        if _dir:
            authz_serv = self.get_service('authorization')
            if authz_serv:  # If this isn't true that's weird. Tests perhaps ?
                self.set_usage_value("request_uri", True)
                if not os.path.isdir(_dir):
                    os.makedirs(_dir)
                authz_serv.callback_path["request_uris"] = _dir

        _pref = config.get("client_preferences", {})
        for key, val in _pref.items():
            if self.set_metadata_value(key, val) is False:
                if self.set_usage_value(key, val) is False:
                    setattr(self, key, val)

        for key, val in config.conf.items():
            if key not in ["port", "domain", "httpc_params", "metadata", "client_preferences",
                           "usage", "services", "add_ons"]:
                self.extra[key] = val

    def config_args(self):
        res = {}
        for id, service in self._service.items():
            res[id] = {
                "metadata": service.metadata_attributes,
                "usage": service.usage_rules
            }
        res[""] = {
            "metadata": self._service_context.specs.attributes,
            "usage": self._service_context.specs.rules
        }
        return res

    def get_callback_uris(self):
        res = []
        for service in self._service.values():
            res.extend(service.callback_uris)
        res.extend(self._service_context.specs.callback_uris)
        return res
