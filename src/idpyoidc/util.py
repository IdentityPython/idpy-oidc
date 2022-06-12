import importlib
import json
import logging
import os
import secrets
import sys
from typing import Optional
from typing import Union
from urllib.parse import parse_qs
from urllib.parse import quote_plus
from urllib.parse import unquote_plus
from urllib.parse import urlsplit
from urllib.parse import urlunsplit

from cryptojwt.utils import importer
import yaml

logger = logging.getLogger(__name__)


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


def claims_match(value: Union[str, int], claimspec: Optional[dict]) -> bool:
    """
    Implements matching according to section 5.5.1 of
    http://openid.net/specs/openid-connect-core-1_0.html
    The lack of value is not checked here.
    Also the text doesn't prohibit having both 'value' and 'values'.

    :param value: single value
    :param claimspec: None or dictionary with 'essential', 'value' or 'values'
        as key
    :return: Boolean
    """
    if value is None:
        return False

    if claimspec is None:  # match anything
        return True

    matched = False
    for key, val in claimspec.items():
        if key == "value":
            if value == val:
                matched = True
        elif key == "values":
            if value in val:
                matched = True
        elif key == "essential":
            # Whether it's essential or not doesn't change anything here
            continue

        if matched:
            break

    if matched is False:
        if list(claimspec.keys()) == ["essential"]:
            return True

    return matched
