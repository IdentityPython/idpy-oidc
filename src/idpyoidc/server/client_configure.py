import logging
from typing import Callable
from typing import Optional

from idpyoidc.message import OPTIONAL_LIST_OF_STRINGS
from idpyoidc.message.oidc import SINGLE_OPTIONAL_BOOLEAN
from idpyoidc.message.oidc import SINGLE_OPTIONAL_DICT
from idpyoidc.message.oidc import RegistrationResponse
from idpyoidc.server.session.token import TOKEN_MAP

logger = logging.getLogger(__name__)


class ClientConfiguration(RegistrationResponse):
    c_param = RegistrationResponse.c_param.copy()
    c_param.update(
        {
            "token_usage_rules": SINGLE_OPTIONAL_DICT,
            "token_exchange": SINGLE_OPTIONAL_DICT,
            "add_claims": SINGLE_OPTIONAL_DICT,
            "pkce_essential": SINGLE_OPTIONAL_BOOLEAN,
            "revoke_refresh_on_issue": SINGLE_OPTIONAL_BOOLEAN,
            "allowed_scopes": OPTIONAL_LIST_OF_STRINGS,
            "scopes_to_claims": SINGLE_OPTIONAL_DICT,
            #
            # These may be added dynamically at run time
            # "dpop_jkt": SINGLE_OPTIONAL_STRING,
            # "si_redirects": OPTIONAL_LIST_OF_STRINGS,
            # "sector_id": SINGLE_OPTIONAL_STRING,
            # "client_secret_expires_at": SINGLE_OPTIONAL_INT,
            # "registration_access_token": SINGLE_OPTIONAL_STRING
            # "auth_method": SINGLE_OPTIONAL_DICT,
        }
    )

    def verify(self, **kwargs):
        RegistrationResponse.verify(self, **kwargs)
        _server_get = kwargs.get("server_get")
        if _server_get:
            _endpoint_context = _server_get("endpoint_context")
        else:
            _endpoint_context = None

        if "add_claims" in self:
            if not set(self["add_claims"].keys()).issubset({"always", "by_scope"}):
                _diff = set(self["add_claims"].keys()).difference({"always", "by_scope"})
                logger.warning(f"Undefined add_claims parameter '{_diff}' used")

        if "token_usage_rules" in self:
            for _typ, _rule in self["token_usage_rules"].items():
                # The allowed rules are: expires_in, supports_minting, max_usage
                if _typ not in TOKEN_MAP.keys():
                    logger.warning(f"Undefined token type '{_typ}' used")

                if not set(_rule.keys()).issubset({"expires_in", "supports_minting", "max_usage"}):
                    _diff = set(_rule.keys()).difference(
                        {"expires_in", "supports_minting", "max_usage"}
                    )
                    logger.warning(f"Undefined token_usage_rules parameter '{_diff}' used")

                _supports = _rule.get("supports_minting")
                if _supports:
                    if not set(_supports).issubset(set(TOKEN_MAP.keys())):
                        _diff = set(_supports).difference(set(TOKEN_MAP.keys()))
                        logger.warning(f"Unknown supports_minting token '{_diff}' used")

        if "token_exchange" in self:
            pass


def verify_oidc_client_information(
    conf: dict, server_get: Optional[Callable] = None, **kwargs
) -> dict:
    res = {}
    for key, item in conf.items():
        _rr = ClientConfiguration(**item)
        _rr.verify(server_get=server_get, **kwargs)
        if _rr.extra():
            logger.info(f"Extras: {_rr.extra()}")
        res[key] = _rr

    return res
