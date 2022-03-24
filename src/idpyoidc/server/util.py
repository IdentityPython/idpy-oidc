import base64
import hashlib
import json
import logging
import uuid
from urllib.parse import urlparse
from urllib.parse import urlunsplit

from cryptography.fernet import Fernet
from cryptojwt import as_unicode
from cryptojwt.utils import as_bytes

from idpyoidc.server.session.info import SessionInfo
from idpyoidc.util import importer

from .exception import OidcEndpointError

logger = logging.getLogger(__name__)

OAUTH2_NOCACHE_HEADERS = [("Pragma", "no-cache"), ("Cache-Control", "no-store")]


def build_endpoints(conf, server_get, issuer):
    """
    conf typically contains::

        'provider_config': {
            'path': '.well-known/openid-configuration',
            'class': ProviderConfiguration,
            'kwargs': {}
        },

    This function uses class and kwargs to instantiate a class instance with kwargs.

    :param conf:
    :param server_get: Callback function
    :param issuer:
    :return:
    """

    if issuer.endswith("/"):
        _url = issuer[:-1]
    else:
        _url = issuer

    endpoint = {}
    for name, spec in conf.items():
        kwargs = spec.get("kwargs", {})

        # class can be a string (class path) or a class reference
        if isinstance(spec["class"], str):
            _instance = importer(spec["class"])(server_get=server_get, **kwargs)
        else:
            _instance = spec["class"](server_get=server_get, **kwargs)

        try:
            _path = spec["path"]
        except KeyError:
            # Should there be a default ?
            raise

        _instance.endpoint_path = _path
        _instance.full_path = "{}/{}".format(_url, _path)

        # if _instance.endpoint_name:
        #     try:
        #         _instance.endpoint_info[_instance.endpoint_name] = _instance.full_path
        #     except TypeError:
        #         _instance.endpoint_info = {_instance.endpoint_name: _instance.full_path}

        endpoint[_instance.name] = _instance

    return endpoint


class JSONDictDB(object):
    def __init__(self, filename):
        with open(filename, "r") as f:
            self._db = json.load(f)

    def __getitem__(self, item):
        return self._db[item]

    def __contains__(self, item):
        return item in self._db


def lv_pack(*args):
    """
    Serializes using length:value format

    :param args: values
    :return: string
    """
    s = []
    for a in args:
        s.append("{}:{}".format(len(a), a))
    return "".join(s)


def lv_unpack(txt):
    """
    Deserializes a string of the length:value format

    :param txt: The input string
    :return: a list og values
    """
    txt = txt.strip()
    res = []
    while txt:
        l, v = txt.split(":", 1)
        res.append(v[: int(l)])
        txt = v[int(l):]
    return res


class Crypt(object):
    def __init__(self, password, mode=None):
        self.key = base64.urlsafe_b64encode(hashlib.sha256(password.encode("utf-8")).digest())
        self.core = Fernet(self.key)

    def encrypt(self, text):
        # Padding to block size of AES
        text = as_bytes(text)
        if len(text) % 16:
            text += b" " * (16 - len(text) % 16)
        return self.core.encrypt(as_bytes(text))

    def decrypt(self, ciphertext):
        dec_text = self.core.decrypt(ciphertext)
        dec_text = dec_text.rstrip(b" ")
        return as_unicode(dec_text)


def get_http_params(config):
    _verify_ssl = config.get("verify")
    if _verify_ssl is None:
        _verify_ssl = config.get("verify_ssl")

    if _verify_ssl in [True, False]:
        params = {"verify": _verify_ssl}
    else:
        params = {}

    _cert = config.get("client_cert")
    _key = config.get("client_key")
    if _cert:
        if _key:
            params["cert"] = (_cert, _key)
        else:
            params["cert"] = _cert
    elif _key:
        raise ValueError("Key without cert is no good")

    return params


def allow_refresh_token(endpoint_context):
    # Are there a refresh_token handler
    refresh_token_handler = endpoint_context.session_manager.token_handler.handler.get(
        "refresh_token")

    # Is refresh_token grant type supported
    _token_supported = False
    _cap = endpoint_context.conf.get("capabilities")
    if _cap:
        if "refresh_token" in _cap["grant_types_supported"]:
            # self.allow_refresh = kwargs.get("allow_refresh", True)
            _token_supported = True

    if refresh_token_handler and _token_supported:
        return True
    elif refresh_token_handler:
        logger.warning("Refresh Token handler available but grant type not supported")
    elif _token_supported:
        logger.error(
            "refresh_token grant type to be supported but no refresh_token handler available"
        )
        raise OidcEndpointError('Grant type "refresh_token" lacks support')

    return False


def execute(spec, **kwargs):
    extra_args = spec.get("kwargs", {})
    kwargs.update(extra_args)

    _class = spec.get("class")
    if _class:
        # class can be a string (class path) or a class reference
        if isinstance(_class, str):
            return importer(_class)(**kwargs)
        else:
            return _class(**kwargs)
    else:
        _function = spec.get("func")
        if _function:
            if isinstance(_function, str):
                _func = importer(_function)
            else:
                _func = _function
            return _func(**kwargs)
        else:
            return kwargs


# def sector_id_from_redirect_uris(uris):
#     if not uris:
#         return ""
#
#     _parts = urlparse(uris[0])
#     hostname = _parts.netloc
#     scheme = _parts.scheme
#     for uri in uris[1:]:
#         parsed = urlparse(uri)
#         if scheme != parsed.scheme or hostname != parsed.netloc:
#             raise ValueError(
#                 "All redirect_uris must have the same hostname in order to generate sector_id."
#             )
#
#     return urlunsplit((scheme, hostname, "", "", ""))


# def get_logout_id(endpoint_context, user_id, client_id):
#     _item = SessionInfo()
#     _item.user_id = user_id
#     _item.client_id = client_id
#
#     # Note that this session ID is not the session ID the session manager is using.
#     # It must be possible to map from one to the other.
#     logout_session_id = uuid.uuid4().hex
#     # Store the map
#     _mngr = endpoint_context.session_manager
#     _mngr.set([logout_session_id], _item)
#
#     return logout_session_id
