import json
import logging

from idpyoidc.util import importer
from .exception import OidcEndpointError

logger = logging.getLogger(__name__)

OAUTH2_NOCACHE_HEADERS = [("Pragma", "no-cache"), ("Cache-Control", "no-store")]


def build_endpoints(conf, upstream_get, issuer):
    """
    conf typically contains::

        'provider_config': {
            'path': '.well-known/openid-configuration',
            'class': ProviderConfiguration,
            'kwargs': {}
        },

    This function uses class and kwargs to instantiate a class instance with kwargs.

    :param conf:
    :param upstream_get: Callback function
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
            _instance = importer(spec["class"])(upstream_get=upstream_get, **kwargs)
        else:
            _instance = spec["class"](upstream_get=upstream_get, **kwargs)

        try:
            _path = spec["path"]
        except KeyError:
            # Should there be a default ?
            raise

        _instance.endpoint_path = _path
        _instance.full_path = "{}/{}".format(_url, _path)

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
        txt = v[int(l) :]
    return res


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


def allow_refresh_token(context):
    # Are there a refresh_token handler
    refresh_token_handler = context.session_manager.token_handler.handler.get("refresh_token")
    if refresh_token_handler is None:
        return False

    # Is refresh_token grant type supported
    _token_supported = False
    _supported = context.get_preference("grant_types_supported")
    if _supported:
        if "refresh_token" in _supported:
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
