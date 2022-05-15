"""
Implements a service context. A Service context is used to keep information that are
common between all the services that are used by OAuth2 client or OpenID Connect Relying Party.
"""
import copy
import os
from typing import Optional
from typing import Union

from cryptojwt.jwk.rsa import RSAKey
from cryptojwt.jwk.rsa import import_private_rsa_key_from_file
from cryptojwt.key_bundle import KeyBundle
from cryptojwt.key_jar import KeyJar
from cryptojwt.utils import as_bytes

from idpyoidc.client.configure import Configuration
from idpyoidc.context import OidcContext
from idpyoidc.util import rndstr
from .configure import get_configuration
from .service import Service
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
    "issuer": "",
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
            "metadata": None,
            "provider_info": None,
            "requests_dir": None,
            "registration_response": None,
            "state": StateInterface,
            'usage': None,
            "verify_args": None,
        }
    )

    metadata_attributes = {
        "application_type": "web",
        "contacts": None,
        "client_name": None,
        "client_id": None,
        "logo_uri": None,
        "client_uri": None,
        "policy_uri": None,
        "tos_uri": None,
        "jwks_uri": None,
        "jwks": None,
        "sector_identifier_uri": None,
        "grant_types": ["authorization_code", "implicit", "refresh_token"],
        "default_max_age": None,
        "id_token_signed_response_alg": "RS256",
        "id_token_encrypted_response_alg": None,
        "id_token_encrypted_response_enc": None,
        "initiate_login_uri": None,
        "subject_type": None,
        "default_acr_values": None,
        "require_auth_time": None,
        "redirect_uris": None,
        "request_object_signing_alg": None,
        "request_object_encryption_alg": None,
        "request_object_encryption_enc": None,
        "request_uris": None,
        "response_types": ["code"]
    }

    usage_rules = {
        "form_post": None,
        "jwks": None,
        "jwks_uri": None,
        "request_parameter": None,
        "request_uri": None,
        "scope": ["openid"],
        "verify_args": None,
    }

    callback_path = {
        "requests": "req",
        "code": "authz_cb",
        "implicit": "authz_im_cb",
        "form_post": "form"
    }

    callback_uris = ["redirect_uris"]

    def __init__(self,
                 base_url: Optional[str] = "",
                 keyjar: Optional[KeyJar] = None,
                 config: Optional[Union[dict, Configuration]] = None,
                 state: Optional[StateInterface] = None,
                 **kwargs):
        config = get_configuration(config)
        self.config = config
        self.metadata = {}
        self.usage = {}

        OidcContext.__init__(self, config, keyjar, entity_id=config.get("client_id", ""))
        self.state = state or StateInterface()

        self.kid = {"sig": {}, "enc": {}}

        self.base_url = base_url or config.get("base_url", "")
        # Below so my IDE won't complain
        self.allow = {}
        self.args = {}
        self.add_on = {}
        self.iss_hash = ""
        self.httpc_params = {}
        self.callback = {}
        self.client_secret = ""
        self.client_secret_expires_at = 0
        self.behaviour = {}
        self.provider_info = {}
        # self.post_logout_redirect_uri = ""
        # self.redirect_uris = []
        self.registration_response = {}
        self.requests_dir = ""

        _def_value = copy.deepcopy(DEFAULT_VALUE)

        for param in [
            "client_secret",
            "provider_info",
            "behaviour",
            "issuer",
        ]:
            _val = config.get(param, _def_value[param])
            self.set(param, _val)
            if param == "client_secret" and _val:
                self.keyjar.add_symmetric("", _val)

        if not self.issuer:
            self.issuer = self.provider_info.get("issuer", "")

        self.clock_skew = config.get("clock_skew", 15)

        _seed = config.get("hash_seed", rndstr(32))
        self.hash_seed = as_bytes(_seed)

        for key, val in kwargs.items():
            setattr(self, key, val)

        if "client_secret" in config.conf:
            self.keyjar.add_symmetric("", config.conf.get("client_secret"))

        for attr, val in config.conf.items():
            if attr in self.metadata_attributes:
                self.set_metadata(attr, val)

        for attr, val in config.conf.items():
            if attr in ["usage", "metadata"]:
                continue
            if attr in self.parameter:
                setattr(self, attr, val)

        if self.requests_dir:
            # make sure the path exists. If not, then create it.
            if not os.path.isdir(self.requests_dir):
                os.makedirs(self.requests_dir)

        # defaults is nothing else is given
        for key, val in self.metadata_attributes.items():
            if val and key not in self.metadata:
                self.set_metadata(key, val)

        for key, val in self.usage_rules.items():
            if val and key not in self.usage:
                self.set_usage(key, val)

        self.verify_usage_rules()

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
            return self.behaviour[CLI_REG_MAP[typ]["sign"]]
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
                _alg = self.behaviour[CLI_REG_MAP[typ][attr]]
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

    def get_metadata(self, key, default=None):
        if key in self.metadata:
            return self.metadata[key]
        else:
            return default

    def get_usage(self, key, default=None):
        if key in self.usage:
            return self.usage[key]
        else:
            return default

    def set_metadata(self, key, value):
        self.metadata[key] = value

    def set_usage(self, key, value):
        self.usage[key] = value

    def _callback_uris(self, base_url, hex):
        _red = {}
        for type in self.get_metadata("response_types", ["code"]):
            if "code" in type:
                _red['code'] = True
            elif type in ["id_token", "id_token token"]:
                _red['implicit'] = True

        if "form_post" in self.usage:
            _red["form_post"] = True

        callback_uri = {}
        for key in _red.keys():
            _uri = Service.get_uri(base_url, self.callback_path[key], hex)
            callback_uri[key] = _uri
        return  callback_uri

    def construct_redirect_uris(self, base_url, hex, callbacks):
        if not callbacks:
            callbacks = self._callback_uris(base_url, hex)

        if callbacks:
            self.set_metadata("redirect_uris", [v for k, v in callbacks.items()])

        self.callback = callbacks

    def construct_uris(self, base_url, hex):
        if "request_uri" in self.usage:
            if self.usage["request_uri"]:
                if self.requests_dir:
                    self.metadata["request_uris"] = [
                        Service.get_uri(base_url, self.requests_dir, hex)]
                else:
                    self.metadata["request_uris"] = [
                        Service.get_uri(base_url, self.callback_path["requests"], hex)]

    def verify_usage_rules(self):
        if self.get_usage("request_parameter") and self.get_usage("request_uri"):
            raise ValueError("You have to chose one of 'request_parameter' and 'request_uri'.")
        # default is jwks_uri
        if not self.get_usage("jwks") and not self.get_usage('jwks_uri'):
            self.set_usage('jwks_uri', True)