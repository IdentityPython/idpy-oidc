import json
import logging
from typing import Optional

from cryptojwt import KeyBundle
from cryptojwt import KeyJar
from cryptojwt.key_issuer import KeyIssuer
from cryptojwt.key_jar import init_key_jar

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

        _path = spec.get("path", "")

        if _path:
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
        txt = v[int(l):]
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


def load_keyjar(dump):
    _args = {k: v for k, v in dump.items() if k not in ['issuers', 'spec2key']}
    keyjar = KeyJar(**_args)
    issuers = dump.get("issuers", {})
    for issuer_id, conf in issuers.items():
        _args = {k: v for k, v in conf.items() if k not in ['bundles', 'spec2key']}
        _iss = KeyIssuer(**_args)
        _bundles = []
        for bundle in conf.get("bundles", []):
            _args = {k: v for k, v in bundle.items() if k not in ['etag', 'ignore_errors_until', 'imp_jwks',
                                                                  'last_local', 'last_remote', 'last_updated', 'local',
                                                                  'remote', 'time_out']}
            _bundles.append(KeyBundle(**_args))
        _iss._bundles = _bundles
        keyjar._issuers[issuer_id] = _iss
    return keyjar


def get_key_conf(config, key_config=None, **kwargs):
    if key_config is None:
        key_config = kwargs.get("key_config", None)
        if key_config is None:
            key_config = config.get("key_conf", None)

    return key_config


def init_keyjar(config: Optional[dict] = None,
                keyjar: Optional[KeyJar] = None,
                key_config: Optional[dict] = None,
                issuer_id: Optional[str] = '',
                **kwargs) -> Optional[KeyJar]:
    """
    The keys in the keyjar can either be dynamically created every time the entity is started
    or it can dump them to a file which later can be read on startup.
    uri_path points to where the file shuld be.
    read_only defines if the file should be read only.
    If read_only == False the file is updated every time the entity is started.
    If read_only == True then no new keys are created. Only the ones in the file is accessible to the entity.

    :param config: Configuration dictionary
    :param keyjar: A KeyJar instance
    :param key_config: A key configuration
    :param issuer_id: The entity running this function and therefor the owner of all the keys
    :param kwargs: Extra key word arguments
    :return: A KeyJar instance
    """
    flag = False
    if keyjar is not None:
        if isinstance(keyjar, KeyJar):
            pass
        else:  # A dict
            keyjar = load_keyjar(keyjar)
    # key jar is unlikely to be in the configuration

    if keyjar is None:
        key_conf = get_key_conf(config, key_config, **kwargs)
        if key_conf is not None:
            _uri_path = key_conf.get("uri_path",'')
            _issuer_id = issuer_id or key_conf.get("issuer_id", '')
            if _uri_path:
                _read_only = key_conf.get('read_only', True)
                if _read_only:
                    keyjar = KeyJar()
                    keyjar.import_jwks_from_file(key_conf['uri_path'], issuer_id='')
                    if issuer_id:
                        keyjar.import_jwks(keyjar.export_jwks(private=True, issuer_id=''), issuer_id=_issuer_id)
            if not keyjar:
                flag = True
                _args = {k: v for k, v in key_conf.items() if k not in ['uri_path', 'issuer_id']}
                keyjar = init_key_jar(**_args)
                if _issuer_id:
                    keyjar.import_jwks(keyjar.export_jwks(private=True, issuer_id=''), issuer_id=_issuer_id)

                if _uri_path:
                    jwks = keyjar.export_jwks(private=True, issuer_id='')
                    with open(_uri_path, 'w') as _out:
                        _out.write(json.dumps(jwks))

    if keyjar is None:
        flag = True
        keyjar = KeyJar()

    if flag:
        _client_secret = config.get("client_secret", None)
        _client_id = config.get("client_id", None)
        if _client_id and _client_secret:
            keyjar.add_symmetric(issuer_id=_client_id, key=_client_secret, usage=['sig'])
            keyjar.add_symmetric(issuer_id='', key=_client_secret, usage=['sig'])

    return keyjar
