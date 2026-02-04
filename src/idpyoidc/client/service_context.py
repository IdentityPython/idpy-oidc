"""
Implements a service context. A Service context is used to keep information that are
common between all the services that are used by OAuth2 client or OpenID Connect Relying Party.
"""
import base64
import hashlib
import logging
import os
from typing import Callable
from typing import List
from typing import Optional
from typing import Union

from cryptojwt.jwk.hmac import SYMKey
from cryptojwt.jwk.rsa import import_private_rsa_key_from_file
from cryptojwt.jwk.rsa import RSAKey
from cryptojwt.key_bundle import KeyBundle
from cryptojwt.key_bundle import keybundle_from_local_file
from cryptojwt.key_jar import KeyJar
from cryptojwt.utils import as_bytes

from idpyoidc.claims import Claims
from idpyoidc.claims import claims_dump
from idpyoidc.claims import claims_load
from idpyoidc.client.claims.oauth2 import Claims as OAUTH2_Specs
from idpyoidc.client.claims.oauth2resource import Claims as OAUTH2RESOURCE_Specs
from idpyoidc.client.claims.oidc import Claims as OIDC_Specs
from idpyoidc.client.configure import Configuration
from idpyoidc.client.defaults import DEFAULT_OAUTH2_SERVICES
from idpyoidc.client.defaults import DEFAULT_OIDC_SERVICES
from idpyoidc.client.service import init_services
from idpyoidc.client.util import do_add_ons
from idpyoidc.key_import import add_kb
from idpyoidc.key_import import import_jwks_from_file
from idpyoidc.transform import preferred_to_registered
from idpyoidc.transform import supported_to_preferred
from idpyoidc.util import conf_get
from idpyoidc.util import rndstr
from .current import Current
from .entity_metadata import EntityMetadata
from ..impexp import ImpExp
from ..message import Message
from ..message.oidc import RegistrationResponse
from ..transform import REGISTER2PREFERRED

logger = logging.getLogger(__name__)

CLI_REG_MAP = {
    "userinfo": {
        "sign": "userinfo_signed_response_alg",
        "alg": "userinfo_encrypted_response_alg",
        "enc": "userinfo_encrypted_response_enc",
    },
    "id_token": {
        "sign": "id_token_signed_response_alg",
        "alg": "id_token_encrypted_response_alg",
        "enc": "id_token_encrypted_response_enc",
    },
    "request_object": {
        "sign": "request_object_signing_alg",
        "alg": "request_object_encryption_alg",
        "enc": "request_object_encryption_enc",
    },
}

PROVIDER_INFO_MAP = {
    "id_token": {
        "sign": "id_token_signing_alg_values_supported",
        "alg": "id_token_encryption_alg_values_supported",
        "enc": "id_token_encryption_enc_values_supported",
    },
    "userinfo": {
        "sign": "userinfo_signing_alg_values_supported",
        "alg": "userinfo_encryption_alg_values_supported",
        "enc": "userinfo_encryption_enc_values_supported",
    },
    "request_object": {
        "sign": "request_object_signing_alg_values_supported",
        "alg": "request_object_encryption_alg_values_supported",
        "enc": "request_object_encryption_enc_values_supported",
    },
    "token_enpoint_auth": {"sign": "token_endpoint_auth_signing_alg_values_supported"},
}

DEFAULT_VALUE = {
    "client_secret": "",
    "client_id": "",
    "redirect_uris": [],
    "provider_info": {},
    "callback": {},
    "issuer": "",
}


class ServiceContext(ImpExp):
    """
    This class keeps information that a client needs to be able to talk
    to a server. Some of this information comes from configuration and some
    from dynamic provider info discovery or client registration.
    But information is also picked up during the conversation with a server.
    """

    parameter = {
        "add_on": None,
        "allow": None,
        "args": None,
        "base_url": None,
        # "behaviour": None,
        # "client_secret_expires_at": 0,
        "client_id": None,
        "client_secret": None,
        "clock_skew": None,
        "config": None,
        "hash_seed": b"",
        "httpc_params": None,
        "iss_hash": None,
        "issuer": None,
        "server_entity_id": None,
        "server_metadata": EntityMetadata,
        "keyjar": KeyJar,
        "claims": Claims,
        "provider_info": None,
        "requests_dir": None,
        "registration_response": None,
        "cstate": Current,
        # 'usage': None,
        "verify_args": None,
    }

    special_load_dump = {
        "specs": {"load": claims_load, "dump": claims_dump},
    }

    init_args = ["upstream_get"]

    def __init__(
            self,
            server_entity_id: str,
            upstream_get: Optional[Callable] = None,
            base_url: Optional[str] = "",
            # keyjar: Optional[KeyJar] = None,
            config: Optional[Union[dict, Configuration]] = None,
            cstate: Optional[Current] = None,
            client_type: Optional[str] = "",
            services: Optional[dict] = None,
            entity_id: Optional[str] = "",
            **kwargs,
    ):
        ImpExp.__init__(self)
        # config = get_configuration(config)
        self.config = config or {}  # This is entity configuration
        self.upstream_get = upstream_get

        self.client_type = self.config.get("client_type", None) or client_type or "oidc"
        if self.client_type == "oidc":
            self.claims = OIDC_Specs()
        elif self.client_type == "oauth2":
            self.claims = OAUTH2_Specs()
        elif self.client_type == "oauth2resource":
            self.claims = OAUTH2RESOURCE_Specs()
        else:
            raise ValueError(f"Unknown client type: {self.client_type}")

        if self.upstream_get:
            _publish_as = self.upstream_get("attribute", "publish_keyjar_as")
            if _publish_as:
                for attr, val in _publish_as.items():
                    self.claims.prefer[attr] = val

        self.entity_id = entity_id or kwargs.get("client_id", "")
        if not self.entity_id:
            self.entity_id = conf_get(self.config, "entity_id", conf_get(self.config, "client_id"))

        self.client_id = kwargs.get("client_id", "") or conf_get(self.config, "client_id", '')

        self.cstate = cstate or Current()

        self.kid = {"sig": {}, "enc": {}}

        self.allow = conf_get(self.config, "allow", {})
        self.base_url = base_url or conf_get(self.config, "base_url", self.entity_id)
        self.provider_info = conf_get(self.config, "provider_info", {})
        self.server_metadata = conf_get(self.config, "server_metadata", EntityMetadata())

        self.issuer = self.server_entity_id = server_entity_id
        self.client_secret = conf_get(self.config, "client_secret", "")

        # Below so my IDE won't complain
        self.args = {}
        self.add_on = {}
        self.iss_hash = ""
        self.httpc_params = {}
        self.client_secret_expires_at = 0
        self.registration_response = {}
        self.client_authn_methods = {}

        # These needs to be carried over to copies
        self.metadata_class = kwargs.get("metadata_class", None)
        self.register2preferred = kwargs.get("register2preferred", {})

        # _def_value = copy.deepcopy(DEFAULT_VALUE)

        self.clock_skew = self.config.get("clock_skew", 15)

        _seed = kwargs.get("seed", None)
        if _seed:
            if _seed.startswith("BYTES"):
                _seed.lstrip("BYTES:")
        _seed = self.config.get("hash_seed", rndstr(32))
        self.hash_seed = as_bytes(_seed)

        for key, val in kwargs.items():
            if key == 'claims':
                continue
            elif key == "keyjar":  # dealt with further ahead
                if val is None:
                    self.keyjar = KeyJar()
                    # client secret key
                    _client_secret = conf_get(self.config, "client_secret", None)
                    _client_id = conf_get(self.config, "client_id", None)
                    if _client_id and _client_secret:
                        self.keyjar.add_symmetric(issuer_id=_client_id, key=_client_secret, usage=['sig'])
                        self.keyjar.add_symmetric(issuer_id='', key=_client_secret, usage=['sig'])
                        if self.entity_id and self.entity_id != _client_id:
                            self.keyjar.add_symmetric(issuer_id=self.entity_id, key=_client_secret, usage=['sig'])
                elif isinstance(val, KeyJar):
                    self.keyjar = val
                else:
                    self.keyjar = KeyJar()
                    self.keyjar.load(val)
            elif key == "hash_seed":
                if val:
                    if val.startswith("BYTES"):
                        self.hash_seed = base64.b64decode(val[len("BYTES:"):].encode("utf-8"))
            else:
                setattr(self, key, val)

        if services:
            _srvs = services
        elif self.config:
            _srvs = self.config.get("services")
        else:
            _srvs = None

        if not _srvs:
            if client_type == "oauth2":
                _srvs = DEFAULT_OAUTH2_SERVICES
            else:
                _srvs = DEFAULT_OIDC_SERVICES

        self.services_conf = _srvs
        self.service = init_services(service_definitions=_srvs, upstream_get=upstream_get)
        self.include_provider_info()

        # Import of server's key
        _jwks_uri = self.provider_info.get("jwks_uri")
        if _jwks_uri:
            self.keyjar.load_keys(self.provider_info.get("issuer"), jwks_uri=_jwks_uri)

        _claims = kwargs.get("claims", None)
        if _claims:
            self.claims = Claims(prefer=_claims["prefer"])
            self.claims.use = _claims['use']
        else:
            self.claims.load_conf(self.config, supports=self.supports(),
                                  entity_id=self.entity_id,
                                  metadata_class=kwargs.get("metadata_class", None))

            #             self.prefer_jwks_uri_or_jwks(base_url, **kwargs)

            _response_types = self.get_preference(
                "response_types_supported", self.supports().get("response_types_supported", [])
            )

            self.construct_uris(response_types=_response_types)

            self.map_supported_to_preferred()

            args = {}
            for attr in ['metadata_class', 'register2preferred']:
                if attr in kwargs:
                    args[attr] = kwargs[attr]
                    setattr(self, attr, kwargs[attr])

            self.map_preferred_to_registered(**args)

        _add_ons = conf_get(self.config, "add_ons")

        if _add_ons:
            do_add_ons(self, _add_ons, self.service)
        else:  # pkce is default
            _add_ons = {
                "pkce": {
                    "function": "idpyoidc.client.oauth2.add_on.pkce.add_support",
                    "kwargs": {
                        "code_challenge_length": 64,
                        "code_challenge_method": "S256"
                    },
                },
            }
            do_add_ons(self, _add_ons, self.service)

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def filename_from_webname(self, webname):
        """
        A 1<->1 map is maintained between a URL pointing to a file and
        the name of the file in the file system.

        As an example if the base_url is 'https://example.com' and a jwks_uri
        is 'https://example.com/jwks_uri.json' then the filename of the
        corresponding file on the local filesystem would be 'jwks_uri'.
        Relative to the directory from which the RP instance is run.

        :param webname: The published URL
        :return: local filename
        """
        if not webname.startswith(self.base_url):
            raise ValueError("Webname doesn't match base_url")

        _name = webname[len(self.base_url):]
        if _name.startswith("/"):
            return _name[1:]

        return _name

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
            _keyjar = KeyJar()
            new = True
        else:
            new = False

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

        if new:
            _unit = self.upstream_get("unit")
            _unit.setattribute("keyjar", _keyjar)

    def _get_crypt(self, typ, attr):
        _item_typ = CLI_REG_MAP.get(typ)
        _alg = ""
        if _item_typ:
            _alg = self.claims.get_usage(_item_typ[attr])
            if not _alg:
                _alg = self.claims.get_preference(_item_typ[attr])

        if not _alg:
            _item_typ = PROVIDER_INFO_MAP.get(typ)
            if _item_typ:
                _alg = self.provider_info.get(_item_typ[attr])

        return _alg

    def get_sign_alg(self, typ):
        """

        :param typ: ['id_token', 'userinfo', 'request_object']
        :return: signing algorithm
        """
        return self._get_crypt(typ, "sign")

    def get_enc_alg_enc(self, typ):
        """

        :param typ:
        :return:
        """

        res = {}
        for attr in ["enc", "alg"]:
            res[attr] = self._get_crypt(typ, attr)

        return res

    def get(self, key, default=None):
        return getattr(self, key, default)

    def set(self, key, value):
        setattr(self, key, value)

    def get_client_id(self):
        res = self.claims.get_usage("client_id")
        if not res:
            res = self.entity_id
            if not res and self.upstream_get:
                res = self.upstream_get("unit").entity_id

        return res

    def collect_usage(self):
        _use = self.claims.use.copy()
        _use['client_id'] = self.client_id
        _secret = getattr(self, 'client_secret')
        if _secret:
            _use['client_secret'] = _secret
        return _use

    def supports(self):
        res = {}
        for service in self.service.values():
            res.update(service.supports())
            res = service.extends(res)
        res.update(self.claims.supports())
        return res

    def prefers(self):
        return self.claims.prefer

    def get_preference(self, claim, default=None):
        return self.claims.get_preference(claim, default=default)

    def set_preference(self, key, value):
        self.claims.set_preference(key, value)

    def get_usage(self, claim, default: Optional[str] = None):
        return self.claims.get_usage(claim, default)

    def set_usage(self, claim, value):
        return self.claims.set_usage(claim, value)

    def _callback_per_service(self):
        _cb = {}
        for service in self.service.values():
            _cbs = service._callback_path.keys()
            if _cbs:
                _cb[service.service_name] = _cbs
        return _cb

    def construct_uris(self, response_types: Optional[list] = None):
        _base_url = self.get("base_url")

        _callback_uris = self.get_preference("callback_uris", {})
        for service in self.service.values():
            _callback_uris.update(
                service.construct_uris(
                    context=self,
                    base_url=_base_url,
                    response_types=response_types,
                )
            )

        if _callback_uris:
            self.set_preference("callback_uris", _callback_uris)

        if "redirect_uris" in _callback_uris:
            _redirect_uris = set()
            for flow, _uris in _callback_uris["redirect_uris"].items():
                _redirect_uris.update(set(_uris))
            self.set_preference("redirect_uris", list(_redirect_uris))

    def prefer_or_support(self, claim):
        if claim in self.claims.prefer:
            return "prefer"
        else:
            for service in self.service.values():
                _res = service.prefer_or_support(claim)
                if _res:
                    return _res

        if claim in self.claims.supported(claim):
            return "support"
        return None

    def map_supported_to_preferred(self, info: Optional[dict] = None):
        self.claims.prefer = supported_to_preferred(
            self.supports(), self.claims.prefer, base_url=self.base_url, info=info
        )
        return self.claims.prefer

    def map_service_against_endpoint(self, provider_config):
        # Check endpoints against services
        remove = []
        for srv_name, srv in self.service.items():
            if srv.endpoint_name:
                _match = provider_config.get(srv.endpoint_name)
                if _match is None:
                    for key in srv._supports.keys():
                        if key in self.claims.prefer:
                            del self.claims.prefer[key]
                    remove.append(srv_name)

        for item in remove:
            del self.service[item]

    def map_preferred_to_registered(self,
                                    registration_response: Optional[dict] = None,
                                    uri_claims: Optional[list] = None,
                                    metadata_class: Optional[Message] = RegistrationResponse,
                                    register2preferred: Optional[dict] = REGISTER2PREFERRED,
                                    ):
        self.claims.use = preferred_to_registered(
            self.claims.prefer,
            supported=self.supports(),
            registration_response=registration_response,
            uri_claims=uri_claims,
            metadata_class=metadata_class,
            register2preferred=register2preferred
        )

        return self.claims.use

    def get_metadata_claim(self, claim, entity_types: Optional[List[str]] = "") -> Optional[dict]:
        if entity_types:
            for _type in entity_types:
                _ent = self.server_metadata.get(_type, None)
                if _ent:
                    _val = _ent.get(claim, None)
                    if _val:
                        return _val
        else:
            for _type in self.server_metadata.keys():
                _val = self.server_metadata[_type].get(claim, None)
                if _val:
                    return _val

        return None

    def get_metadata(self,
                     entity_type: Optional[str] = "",
                     supports: Optional[dict] = None,
                     schema: Optional[Message] = None):
        if supports is None:
            supports = self.supports()
        _metadata = self.claims.get_client_metadata(entity_type, supports=supports, metadata_schema=schema)

        _entity = self.upstream_get('unit')
        _jwks_uri = getattr(_entity, 'jwks_uri', None)
        _jwks_arg = {}
        if _jwks_uri:
            _jwks_arg['jwks_uri'] = _jwks_uri
        else:
            _jwks_arg['jwks'] = _entity.keyjar.export_jwks()
        if _jwks_arg:
            if entity_type:
                _metadata[entity_type].update(_jwks_arg)
            else:
                _metadata.update(_jwks_arg)

        return _metadata

    def get_service(self, service_name, *arg):
        try:
            return self.service[service_name]
        except KeyError:
            return None

    def get_services(self, *arg):
        return self.service

    def get_service_by_endpoint_name(self, endpoint_name, server_entity_id="", *arg):
        for service in self.service.values():
            if service.endpoint_name == endpoint_name:
                return service

        return None

    def include_provider_info(self):
        _pi = self.provider_info
        if not _pi:
            return

        for key, val in _pi.items():
            # All service endpoint parameters in the provider info has
            # a name ending in '_endpoint' so I can look specifically
            # for those
            if key.endswith("_endpoint"):
                for _srv in self.service.values():
                    # Every service has an endpoint_name assigned
                    # when initiated. This name *MUST* match the
                    # endpoint names used in the provider info
                    if _srv.endpoint_name == key:
                        _srv.endpoint = val

        if "keys" in _pi:
            _kj = self.upstream_get('attribute', "keyjar")
            for typ, _spec in _pi["keys"].items():
                if typ == "url":
                    for _iss, _url in _spec.items():
                        _kj.add_url(_iss, _url)
                elif typ == "file":
                    for kty, _name in _spec.items():
                        if kty == "jwks":
                            _kj = import_jwks_from_file(_kj, _name, self.issuer)
                        elif kty == "rsa":  # PEM file
                            _kb = keybundle_from_local_file(_name, "der", ["sig"])
                            _kj = add_kb(_kj, self.entity_id, _kb)
                else:
                    raise ValueError("Unknown provider JWKS type: {}".format(typ))

    def prefer_jwks_uri_or_jwks(self, base_url, **kwargs):
        _ju = kwargs.get('jwks_uri', '') or conf_get(self.config, "jwks_uri", '')
        if _ju:
            self.claims.set_preference('jwks_uri', _ju)
        else:
            kc = kwargs.get("key_conf", conf_get(self.config, "key_conf", {}))
            if kc:
                _jwks_uri = kc.get("jwks_uri")
                if _jwks_uri:
                    if base_url:
                        self.claims.set_preference('jwks_uri', os.path.join(base_url, _jwks_uri))
                    else:
                        self.claims.set_preference('jwks_uri', os.path.join(self.entity_id, _jwks_uri))
                else:
                    self.claims.set_preference('jwks', self.get_jwks())
            else:  # defal
                self.claims.set_preference('jwks', self.get_jwks())


def create_new_context(template_context, server_entity_id: str):
    sc = ServiceContext(
        server_entity_id=server_entity_id,
        config=template_context.config,
        upstream_get=template_context.upstream_get,
        keyjar=template_context.keyjar,
        client_type=template_context.client_type,
        entity_id=template_context.entity_id,
        base_url=template_context.base_url,
        services=template_context.services_conf,
        metadata_class=template_context.metadata_class,
        register2preferred=template_context.register2preferred
    )
    # remove client_secret
    if template_context.client_id != '':
        if template_context.client_secret:
            key = SYMKey(use=['sig'], key=template_context.client_secret)
            for id in ['', template_context.client_id]:
                _issuer = sc.keyjar._issuers[id]
                _kbs = []
                for kb in _issuer.get_bundles():
                    kb._keys = [k for k in kb.keys() if k != key]
                    if kb._keys:
                        _kbs.append(kb)
                _issuer._bundles = _kbs

    return sc
