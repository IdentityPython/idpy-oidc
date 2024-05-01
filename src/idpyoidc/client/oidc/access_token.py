import logging
from typing import Optional
from typing import Union

from idpyoidc.client.client_auth import get_client_authn_methods
from idpyoidc.client.exception import ParameterError
from idpyoidc.client.oauth2 import access_token
from idpyoidc.client.oidc import IDT2REG
from idpyoidc.message import Message
from idpyoidc.message import oidc
from idpyoidc.message.oidc import verified_claim_name
from idpyoidc.metadata import get_signing_algs
from idpyoidc.time_util import time_sans_frac

__author__ = "Roland Hedberg"

LOGGER = logging.getLogger(__name__)


class AccessToken(access_token.AccessToken):
    msg_type = oidc.AccessTokenRequest
    response_cls = oidc.AccessTokenResponse
    error_msg = oidc.ResponseMessage
    default_authn_method = "client_secret_basic"

    _include = {"grant_types_supported": ["authorization_code"]}

    _supports = {
        "token_endpoint_auth_methods_supported": get_client_authn_methods(),
        "token_endpoint_auth_signing_alg_values_supported": get_signing_algs(),
    }

    def __init__(self, upstream_get, conf: Optional[dict] = None):
        access_token.AccessToken.__init__(self, upstream_get, conf=conf)

    def gather_verify_arguments(
        self, response: Optional[Union[dict, Message]] = None, behaviour_args: Optional[dict] = None
    ):
        """
        Need to add some information before running verify()

        :return: dictionary with arguments to the verify call
        """
        _context = self.upstream_get("context")
        _entity = self.upstream_get("unit")

        _client_id = _entity.get_client_id()
        if not _client_id:
            _client_id = _context.get_client_id()

        kwargs = {
            "client_id": _client_id,
            "iss": _context.issuer,
            "keyjar": self.upstream_get("attribute", "keyjar"),
            "verify": True,
            "skew": _context.clock_skew,
        }

        _reg_resp = _context.registration_response
        if _reg_resp:
            for attr, param in IDT2REG.items():
                try:
                    kwargs[attr] = _reg_resp[param]
                except KeyError:
                    pass

        try:
            kwargs["allow_missing_kid"] = _context.allow["missing_kid"]
        except KeyError:
            pass

        _verify_args = _context.claims.get_usage("verify_args")
        if _verify_args:
            if _verify_args:
                kwargs.update(_verify_args)

        return kwargs

    def update_service_context(self, resp, key: Optional[str] = "", **kwargs):
        _cstate = self.upstream_get("context").cstate
        try:
            _idt = resp[verified_claim_name("id_token")]
        except KeyError:
            pass
        else:
            try:
                if _cstate.get_base_key(_idt["nonce"]) != key:
                    raise ParameterError('Someone has messed with "nonce"')
            except KeyError:
                raise ValueError("Invalid nonce value")

            _cstate.bind_key(_idt["sub"], key)

        if "expires_in" in resp:
            resp["__expires_at"] = time_sans_frac() + int(resp["expires_in"])

        _cstate.update(key, resp)
