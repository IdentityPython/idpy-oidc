import importlib
import base64
import json
import time
import logging
import os
import secrets
import sys
from typing import Union
from urllib.parse import parse_qs
from urllib.parse import quote_plus
from urllib.parse import unquote_plus
from urllib.parse import urlsplit
from urllib.parse import urlunsplit

import yaml
from cryptojwt.utils import importer

logger = logging.getLogger(__name__)


def b2t(i):
    # 무조건 base64로 디코딩해서 보여줌
    return json.loads(base64.urlsafe_b64decode(i+'='*(4-len(i) % 4)).decode('utf-8'))

def check_token(token, context):
    '''
    base64 token decoding and validate
    '''
    if isinstance(token, str):
        _token = token.split(" ")[-1].split(".")
        try:
            payload = b2t(_token[1])
            client_id = payload['client_id'] or payload['aud'][0]
            is_registerd = context.cdb.get(client_id, False)
            is_active = int(payload['exp']) > time.time()
            return {'client_id': client_id, 'payload': payload, 'active': is_active and is_registerd, 'is_registerd': is_registerd}
        except:
            # TBD : 키를 찾아서 해독해봄..
            pass
    return {'active': False}


def rndstr(size=16):
    """
    Returns a string of random url safe characters

    :param size: The length of the string
    :return: string
    """
    return secrets.token_urlsafe(size)


def instantiate(cls, **kwargs):
    if isinstance(cls, str):
        return importer(cls)(**kwargs)
    else:
        return cls(**kwargs)


def sanitize(str):
    return str


def load_yaml_config(filename):
    """Load a YAML configuration file."""
    with open(filename, "rt", encoding="utf-8") as file:
        config_dict = yaml.safe_load(file)
    return config_dict


def load_config_file(filename):
    if filename.endswith(".yaml"):
        """Load configuration as YAML"""
        _cnf = load_yaml_config(filename)
    elif filename.endswith(".json"):
        _str = open(filename).read()
        _cnf = json.loads(_str)
    elif filename.endswith(".py"):
        head, tail = os.path.split(filename)
        tail = tail[:-3]
        sys.path.append(head)
        module = importlib.import_module(tail)
        _cnf = getattr(module, "CONFIG")
    else:
        raise ValueError("Unknown file type")

    return _cnf


def split_uri(uri: str) -> [str, Union[dict, None]]:
    """Removes fragment and separates the query part from the rest."""
    p = urlsplit(uri)

    if p.fragment:
        p = p._replace(fragment="")

    if p.query:
        o = p._replace(query="")
        base = urlunsplit(o)
        return [base, parse_qs(p.query)]
    else:
        base = urlunsplit(p)
        return [base, None]


# Converters


class QPKey:
    def serialize(self, str):
        return quote_plus(str)

    def deserialize(self, str):
        return unquote_plus(str)


class JSON:
    def serialize(self, str):
        return json.dumps(str)

    def deserialize(self, str):
        return json.loads(str)


class PassThru:
    def serialize(self, str):
        return str

    def deserialize(self, str):
        return str


def get_http_params(config):
    params = config.get("httpc_params", {})

    if "verify" not in params:
        _ver = config.get("verify")
        if _ver is None:
            _ver = config.get("verify_ssl", True)
        params["verify"] = _ver

    _cert = config.get("client_cert")
    _key = config.get("client_key")
    if _cert:
        if _key:
            params["cert"] = (_cert, _key)
        else:
            params["cert"] = _cert

    return params


def add_path(url, path):
    if url.endswith("/"):
        if path.startswith("/"):
            return "{}{}".format(url, path[1:])
        else:
            return "{}{}".format(url, path)
    else:
        if path.startswith("/"):
            return "{}{}".format(url, path)
        else:
            return "{}/{}".format(url, path)


def qualified_name(cls):
    """Does both classes and class instances

    :param cls: The item, class or class instance
    :return: fully qualified class name
    """

    try:
        return cls.__module__ + "." + cls.name
    except AttributeError:
        return cls.__module__ + "." + cls.__name__
