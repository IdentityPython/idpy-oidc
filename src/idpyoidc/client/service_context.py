"""
Implements a service context. A Service context is used to keep information that are
common between all the services that are used by OAuth2 client or OpenID Connect Relying Party.
"""
import copy
from typing import Optional
from typing import Union

from cryptojwt.jwk.rsa import RSAKey
from cryptojwt.jwk.rsa import import_private_rsa_key_from_file
from cryptojwt.key_bundle import KeyBundle
from cryptojwt.key_jar import KeyJar
from cryptojwt.utils import as_bytes

from idpyoidc.client.configure import Configuration
from idpyoidc.client.specification.oauth2 import Specification as OAUTH2_Specs
from idpyoidc.client.specification.oidc import Specification as OIDC_Specs
from idpyoidc.context import OidcContext
from idpyoidc.util import rndstr
from .configure import get_configuration
from .specification import Specification
from .specification import specification_dump
from .specification import specification_load
from .state_interface import StateInterface

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
    "behaviour": {},
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
            "callback": None,
            "client_secret": None,
            "client_secret_expires_at": 0,
            "clock_skew": None,
            "config": None,
            "hash_seed": b"",
            "httpc_params": None,
            "iss_hash": None,
            "issuer": None,
            "specs": Specification,
            "provider_info": None,
            "requests_dir": None,
            "registration_response": None,
            "state": StateInterface,
            'usage': None,
            "verify_args": None,
        }
    )

    special_load_dump = {
        "specs": {"load": specification_load, "dump": specification_dump},
    }


    def __init__(self,
                 base_url: Optional[str] = "",
                 keyjar: Optional[KeyJar] = None,
                 config: Optional[Union[dict, Configuration]] = None,
                 state: Optional[StateInterface] = None,
                 client_type: Optional[str] = None,
                 **kwargs):
        config = get_configuration(config)
        self.config = config
        if not client_type or client_type == "oidc":
            self.specs = OIDC_Specs()
        elif client_type == "oauth2":
            self.specs = OAUTH2_Specs()
        else:
            raise ValueError(f"Unknown client type: {client_type}")

        OidcContext.__init__(self, config, keyjar, entity_id=config.conf.get("client_id", ""))
        self.state = state or StateInterface()

        self.kid = {"sig": {}, "enc": {}}

        self.base_url = base_url or config.get("base_url", "")
        # Below so my IDE won't complain
        self.allow = {}
        self.args = {}
        self.add_on = {}
        self.iss_hash = ""
        self.issuer = ""
        self.httpc_params = {}
        self.callback = {}
        self.client_secret = ""
        self.client_secret_expires_at = 0
        self.provider_info = {}
        # self.post_logout_redirect_uri = ""
        # self.redirect_uris = []
        self.registration_response = {}
        self.requests_dir = ""

        _def_value = copy.deepcopy(DEFAULT_VALUE)

        for param in [
            "client_secret",
            "provider_info",
            "behaviour"
        ]:
            _val = config.conf.get(param, _def_value[param])
            self.set(param, _val)
            if param == "client_secret" and _val:
                self.keyjar.add_symmetric("", _val)

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

        self.specs.load_conf(config.conf)

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

    def get_sign_alg(self, typ):
        """

        :param typ: ['id_token', 'userinfo', 'request_object']
        :return:
        """

        try:
            return self.specs.behaviour[CLI_REG_MAP[typ]["sign"]]
        except KeyError:
            try:
                return self.provider_info[PROVIDER_INFO_MAP[typ]["sign"]]
            except (KeyError, TypeError):
                pass

        return None

    def get_enc_alg_enc(self, typ):
        """

        :param typ:
        :return:
        """

        res = {}
        for attr in ["enc", "alg"]:
            try:
                _alg = self.specs.behaviour[CLI_REG_MAP[typ][attr]]
            except KeyError:
                try:
                    _alg = self.provider_info[PROVIDER_INFO_MAP[typ][attr]]
                except KeyError:
                    _alg = None

            res[attr] = _alg

        return res

    def get(self, key, default=None):
        return getattr(self, key, default)

    def set(self, key, value):
        setattr(self, key, value)

    def get_client_id(self):
        return self.specs.get_metadata("client_id")
