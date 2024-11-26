import logging
import os
import warnings
from typing import Optional

from cryptojwt.exception import Invalid
from cryptojwt.key_jar import init_key_jar
from cryptojwt.utils import as_unicode

from idpyoidc.impexp import ImpExp
from idpyoidc.item import DLDict
from idpyoidc.util import importer

from . import DefaultToken
from . import Token
from . import UnknownToken
from .exception import TokenException

__author__ = "Roland Hedberg"

logger = logging.getLogger(__name__)


class TokenHandler(ImpExp):
    parameter = {"handler": DLDict, "handler_order": [""]}

    def __init__(
        self,
        access_token: Optional[Token] = None,
        authorization_code: Optional[Token] = None,
        refresh_token: Optional[Token] = None,
        id_token: Optional[Token] = None,
    ):
        ImpExp.__init__(self)
        self.handler = {"authorization_code": authorization_code, "access_token": access_token}

        self.handler_order = ["authorization_code", "access_token"]

        if refresh_token:
            self.handler["refresh_token"] = refresh_token
            self.handler_order.append("refresh_token")

        if id_token:
            self.handler["id_token"] = id_token
            self.handler_order.append("id_token")

    def __getitem__(self, typ):
        return self.handler[typ]

    def __contains__(self, item):
        return item in self.handler

    def info(self, item, order=None):
        _handler, item_info = self.get_handler(item, order)

        if _handler is None:
            logger.info("Unknown token format")
            raise UnknownToken(item)
        else:
            return item_info

    def sid(self, token, order=None):
        return self.info(token, order)["sid"]

    def token_class(self, token, order=None):
        return self.info(token, order)["token_class"]

    def get_handler(self, token, order=None):
        if order is None:
            order = self.handler_order

        for typ in order:
            try:
                res = self.handler[typ].info(token)
            except (KeyError, TokenException, Invalid, AttributeError):
                pass
            else:
                return self.handler[typ], res

        return None, None

    def keys(self):
        return self.handler.keys()


def init_token_handler(upstream_get, spec, token_class):
    _kwargs = spec.get("kwargs", {})

    _lt = spec.get("lifetime")
    if _lt:
        _kwargs["lifetime"] = _lt

    try:
        _cls = spec["class"]
    except KeyError:
        cls = DefaultToken
        _pw = spec.get("password")
        if _pw is not None:
            _kwargs["password"] = _pw
    else:
        cls = importer(_cls)

    if _kwargs is None:
        if cls != DefaultToken:
            warnings.warn(
                "Token initialisation arguments should be grouped under 'kwargs'.",
                DeprecationWarning,
                stacklevel=2,
            )
        _kwargs = spec

    return cls(token_class=token_class, upstream_get=upstream_get, **_kwargs)


def _add_passwd(keyjar, conf, kid):
    if keyjar:
        _keys = keyjar.get_encrypt_key(key_type="oct", kid=kid)
        if _keys:
            pw = as_unicode(_keys[0].k)
            if "kwargs" in conf:
                conf["kwargs"]["password"] = pw
            else:
                conf["password"] = pw


def is_defined(key_defs, kid):
    for _def in key_defs:
        if _def["kid"] == kid:
            return True

    return False


def default_token(spec):
    if "class" not in spec or spec["class"] in ["idpyoidc.server.token.DefaultToken", DefaultToken]:
        return True
    else:
        return False

def key_types(keys):
    return [k["kid"] for k in keys]


JWKS_FILE = "private/token_jwks.json"


def factory(
    upstream_get,
    code: Optional[dict] = None,
    token: Optional[dict] = None,
    refresh: Optional[dict] = None,
    id_token: Optional[dict] = None,
    jwks_file: Optional[str] = "",
    jwks_def: Optional[dict] = None,
    **kwargs
) -> TokenHandler:
    """
    Create a token handler

    :param code:
    :param token:
    :param refresh:
    :param jwks_file:
    :return: TokenHandler instance
    """

    token_class_map = {
        "code": "authorization_code",
        "token": "access_token",
        "refresh": "refresh_token",
        "idtoken": "id_token",
    }

    read_only = False
    cwd = upstream_get("attribute", "cwd")
    if jwks_def:
        if not jwks_file:
            jwks_file = jwks_def.get("private_path", os.path.join(cwd, JWKS_FILE))
        read_only = jwks_def.get("read_only", read_only)
        key_defs = jwks_def.get("key_defs", [])
    else:
        key_defs = None

    # if not jwks_file:
    #     jwks_file = os.path.join(cwd, JWKS_FILE)

    if key_defs or jwks_file:
        kj = init_key_jar(key_defs=key_defs, private_path=jwks_file, read_only=read_only)
    else:
        kj = None

    args = {}
    for cls, cnf, attr in [
        ("code", code, "authorization_code"),
        ("token", token, "access_token"),
        ("refresh", refresh, "refresh_token"),
    ]:
        if cnf is not None:  # else just default
            try:
                _key_types = key_types(
                    cnf["kwargs"]["crypt_conf"]["kwargs"]["keys"]["key_defs"])
            except KeyError:  # will fail on keys if it fails
                pass
            else:
                if "key" in _key_types and "password" in _key_types:
                    raise ValueError("You have to chose one of key or password")
                if "password" not in _key_types and "key" not in _key_types:
                    if kj:
                        _add_passwd(kj, cnf, cls)
            logger.debug(f"init_token_handler: {cls}")
            args[attr] = init_token_handler(upstream_get, cnf, token_class_map[cls])

    if id_token is not None:
        args["id_token"] = init_token_handler(upstream_get, id_token, token_class="")

    return TokenHandler(**args)
