"""
Implements a service context. A Service context is used to keep information that are
common between all the services that are used by OAuth2 client or OpenID Connect Relying Party.
"""
import hashlib
import logging
from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt.jwk.rsa import RSAKey
from cryptojwt.jwk.rsa import import_private_rsa_key_from_file
from cryptojwt.key_bundle import KeyBundle
from cryptojwt.key_jar import KeyJar
from cryptojwt.utils import as_bytes

from idpyoidc.claims import Claims
from idpyoidc.claims import claims_dump
from idpyoidc.claims import claims_load
from idpyoidc.client.claims.oauth2 import Claims as OAUTH2_Specs
from idpyoidc.client.claims.oauth2resource import Claims as OAUTH2RESOURCE_Specs
from idpyoidc.client.claims.oidc import Claims as OIDC_Specs
from idpyoidc.client.configure import Configuration
from idpyoidc.util import rndstr

from ..impexp import ImpExp
from .claims.transform import preferred_to_registered
from .claims.transform import supported_to_preferred
from .configure import get_configuration
from .current import Current

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
        "clock_skew": None,
        "config": None,
        "hash_seed": b"",
        "httpc_params": None,
        "iss_hash": None,
        "issuer": None,
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
        upstream_get: Optional[Callable] = None,
        base_url: Optional[str] = "",
        keyjar: Optional[KeyJar] = None,
        config: Optional[Union[dict, Configuration]] = None,
        cstate: Optional[Current] = None,
        client_type: Optional[str] = "oauth2",
        **kwargs,
    ):
        ImpExp.__init__(self)
        config = get_configuration(config)
        self.config = config
        self.upstream_get = upstream_get

        if not client_type or client_type == "oidc":
            self.claims = OIDC_Specs()
        elif client_type == "oauth2":
            self.claims = OAUTH2_Specs()
        elif client_type == "oauth2resource":
            self.claims = OAUTH2RESOURCE_Specs()
        else:
            raise ValueError(f"Unknown client type: {client_type}")

        self.entity_id = kwargs.get("entity_id", kwargs.get("client_id", ""))
        if not self.entity_id:
            self.entity_id = config.conf.get("entity_id", config.conf.get("client_id"))

        self.cstate = cstate or Current()

        self.kid = {"sig": {}, "enc": {}}

        self.allow = config.conf.get("allow", {})
        self.base_url = base_url or config.conf.get("base_url", self.entity_id)
        self.provider_info = config.conf.get("provider_info", {})

        # Below so my IDE won't complain
        self.args = {}
        self.add_on = {}
        self.iss_hash = ""
        self.issuer = ""
        self.httpc_params = {}
        self.client_secret_expires_at = 0
        self.registration_response = {}
        self.client_authn_methods = {}

        # _def_value = copy.deepcopy(DEFAULT_VALUE)

        _issuer = config.get("issuer")
        if _issuer:
            self.issuer = _issuer
        else:
            self.issuer = self.provider_info.get("issuer", "")

        self.clock_skew = config.get("clock_skew", 15)

        _seed = config.get("hash_seed", rndstr(32))
        self.hash_seed = as_bytes(_seed)

        for key, val in kwargs.items():
            setattr(self, key, val)

        self.keyjar = self.claims.load_conf(config.conf, supports=self.supports(), keyjar=keyjar,
                                            entity_id=self.entity_id)

        _jwks_uri = self.provider_info.get("jwks_uri")
        if _jwks_uri:
            self.keyjar.load_keys(self.provider_info.get("issuer"), jwks_uri=_jwks_uri)

        _response_types = self.get_preference(
            "response_types_supported", self.supports().get("response_types_supported", [])
        )

        self.construct_uris(response_types=_response_types)

        self.map_supported_to_preferred()
        self.map_preferred_to_registered()

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

        _name = webname[len(self.base_url) :]
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
        _keyjar = self.upstream_get("attribute", "keyjar")
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
        return self.claims.get_usage("client_id")

    def collect_usage(self):
        return self.claims.use

    def supports(self):
        res = {}
        if self.upstream_get:
            services = self.upstream_get("services")
            if not services:
                pass
            else:
                for service in services.values():
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
        for service in self.upstream_get("services").values():
            _cbs = service._callback_path.keys()
            if _cbs:
                _cb[service.service_name] = _cbs
        return _cb

    def construct_uris(self, response_types: Optional[list] = None):
        _hash = hashlib.sha256()
        _hash.update(self.hash_seed)
        _hash.update(as_bytes(self.issuer))
        _hex = _hash.hexdigest()

        self.iss_hash = _hex

        _base_url = self.get("base_url")

        _callback_uris = self.get_preference("callback_uris", {})
        if self.upstream_get:
            services = self.upstream_get("services")
            if services:
                for service in services.values():
                    _callback_uris.update(
                        service.construct_uris(
                            base_url=_base_url,
                            hex=_hex,
                            context=self,
                            response_types=response_types,
                        )
                    )

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
            for service in self.upstream_get("services").values():
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
        for srv_name, srv in self.upstream_get("services").items():
            if srv.endpoint_name:
                _match = provider_config.get(srv.endpoint_name)
                if _match is None:
                    for key in srv._supports.keys():
                        if key in self.claims.prefer:
                            del self.claims.prefer[key]
                    remove.append(srv_name)

        for item in remove:
            del self.upstream_get("services")[item]

    def map_preferred_to_registered(self, registration_response: Optional[dict] = None):
        self.claims.use = preferred_to_registered(
            self.claims.prefer,
            supported=self.supports(),
            registration_response=registration_response,
        )

        return self.claims.use
