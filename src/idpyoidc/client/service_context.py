"""
Implements a service context. A Service context is used to keep information that are
common between all the services that are used by OAuth2 client or OpenID Connect Relying Party.
"""
import copy
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

from idpyoidc.client.configure import Configuration
from idpyoidc.client.work_condition.oauth2 import WorkCondition as OAUTH2_Specs
from idpyoidc.client.work_condition.oidc import WorkCondition as OIDC_Specs
from idpyoidc.context import OidcContext
from idpyoidc.util import rndstr
from .configure import get_configuration
from .state_interface import StateInterface
from .work_condition import WorkCondition
from .work_condition import work_condition_dump
from .work_condition import work_condition_load
from .work_condition.transform import preferred_to_register
from .work_condition.transform import supported_to_preferred

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
    "issuer": ""
}


class ServiceContext(OidcContext):
    """
    This class keeps information that a client needs to be able to talk
    to a server. Some of this information comes from configuration and some
    from dynamic provider info discovery or client registration.
    But information is also picked up during the conversation with a server.
    """

    parameter = OidcContext.parameter.copy()
    parameter.update(
        {
            "add_on": None,
            "allow": None,
            "args": None,
            "base_url": None,
            "behaviour": None,
            "client_secret_expires_at": 0,
            "clock_skew": None,
            "config": None,
            "hash_seed": b"",
            "httpc_params": None,
            "iss_hash": None,
            "issuer": None,
            "work_condition": WorkCondition,
            "provider_info": None,
            "requests_dir": None,
            "registration_response": None,
            "state": StateInterface,
            'usage': None,
            "verify_args": None,
        }
    )

    special_load_dump = {
        "specs": {"load": work_condition_load, "dump": work_condition_dump},
    }

    def __init__(self,
                 client_get: Optional[Callable] = None,
                 base_url: Optional[str] = "",
                 keyjar: Optional[KeyJar] = None,
                 config: Optional[Union[dict, Configuration]] = None,
                 state: Optional[StateInterface] = None,
                 client_type: Optional[str] = 'oauth2',
                 **kwargs):
        config = get_configuration(config)
        self.config = config
        self.client_get = client_get

        if not client_type or client_type == "oidc":
            self.work_condition = OIDC_Specs()
        elif client_type == "oauth2":
            self.work_condition = OAUTH2_Specs()
        else:
            raise ValueError(f"Unknown client type: {client_type}")

        OidcContext.__init__(self, config, keyjar, entity_id=config.conf.get("client_id", ""))
        self.state = state or StateInterface()

        self.kid = {"sig": {}, "enc": {}}

        self.base_url = base_url or config.get("base_url", "")
        # Below so my IDE won't complain
        self.allow = config.conf.get('allow', {})
        self.args = {}
        self.add_on = {}
        self.iss_hash = ""
        self.issuer = ""
        self.httpc_params = {}
        self.client_secret_expires_at = 0
        self.provider_info = {}
        # self.post_logout_redirect_uri = ""
        # self.redirect_uris = []
        self.registration_response = {}
        # self.requests_dir = ""

        _def_value = copy.deepcopy(DEFAULT_VALUE)

        _val = config.conf.get("client_secret")
        if _val:
            self.keyjar.add_symmetric("", _val)

        self.provider_info = config.conf.get("provider_info", {})

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
        for where, spec in keyspec.items():
            if where == "file":
                for typ, files in spec.items():
                    if typ == "rsa":
                        for fil in files:
                            _key = RSAKey(priv_key=import_private_rsa_key_from_file(fil), use="sig")
                            _bundle = KeyBundle()
                            _bundle.append(_key)
                            self.keyjar.add_kb("", _bundle)
            elif where == "url":
                for iss, url in spec.items():
                    _bundle = KeyBundle(source=url)
                    self.keyjar.add_kb(iss, _bundle)

    def _get_crypt(self, typ, attr):
        _item_typ = CLI_REG_MAP.get(typ)
        _alg = ''
        if _item_typ:
            _alg = self.work_condition.get_usage(_item_typ[attr])
            if not _alg:
                _alg = self.work_condition.get_preference(_item_typ[attr])

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
        return self._get_crypt(typ, 'sign')

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
        return self.work_condition.get_usage("client_id")

    def collect_usage(self):
        return self.work_condition.use

    def supports(self):
        res = {}
        if self.client_get:
            services = self.client_get('services')
            for service in services.values():
                res.update(service.supports())
        res.update(self.work_condition.supports())
        return res

    def prefers(self):
        return self.work_condition.prefer

    def get_preference(self, claim, default=None):
        return self.work_condition.get_preference(claim, default=default)

    def set_preference(self, key, value):
        self.work_condition.set_preference(key, value)

    def get_usage(self, claim, default: Optional[str] = None):
        return self.work_condition.get_usage(claim, default)

    def set_usage(self, claim, value):
        return self.work_condition.set_usage(claim, value)

    def construct_uris(self,
                       issuer: str,
                       hash_seed: bytes,
                       callback: Optional[dict] = None,
                       response_types: Optional[list] = None):
        _hash = hashlib.sha256()
        _hash.update(hash_seed)
        _hash.update(as_bytes(issuer))
        _hex = _hash.hexdigest()

        self.iss_hash = _hex

        _base_url = self.get("base_url")
        _uris = {}
        if self.client_get:
            services = self.client_get('services')
            for service in services.values():
                _uris.update(service.construct_uris(base_url=_base_url, hex=_hex,
                                                    preference=self.work_condition.prefer,
                                                    response_types=response_types))
        return _uris

    def prefer_or_support(self, claim):
        if claim in self.work_condition.prefer:
            return 'prefer'
        else:
            for service in self.client_get('services').values():
                _res = service.prefer_or_support(claim)
                if _res:
                    return _res

        if claim in self.work_condition.supported(claim):
            return 'support'
        return None

    def map_supported_to_preferred(self, info: Optional[dict] = None):
        self.work_condition.prefer = supported_to_preferred(self.supports(),
                                                            self.work_condition.prefer,
                                                            base_url=self.base_url,
                                                            info=info)
        return self.work_condition.prefer

    def map_preferred_to_register(self):
        self.work_condition.use = preferred_to_register(self.work_condition.prefer,
                                                        self.work_condition.use)
        return self.work_condition.use
