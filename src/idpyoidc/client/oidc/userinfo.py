import logging
from typing import Optional
from typing import Union

from idpyoidc import verified_claim_name
from idpyoidc.client.oauth2.utils import get_state_parameter
from idpyoidc.client.service import Service
from idpyoidc.work_environment import get_encryption_algs
from idpyoidc.work_environment import get_encryption_encs
from idpyoidc.work_environment import get_signing_algs
from idpyoidc.exception import MissingSigningKey
from idpyoidc.message import Message
from idpyoidc.message import oidc

logger = logging.getLogger(__name__)

UI2REG = {
    "sigalg": "userinfo_signed_response_alg",
    "encalg": "userinfo_encrypted_response_alg",
    "encenc": "userinfo_encrypted_response_enc",
}


def carry_state(request_args=None, **kwargs):
    """
    Make sure post_construct_methods have access to state

    :param request_args:
    :param kwargs:
    :return: The value of the state parameter
    """
    return request_args, {"state": get_state_parameter(request_args, kwargs)}


class UserInfo(Service):
    msg_type = Message
    response_cls = oidc.OpenIDSchema
    error_msg = oidc.ResponseMessage
    endpoint_name = "userinfo_endpoint"
    synchronous = True
    service_name = "userinfo"
    default_authn_method = "bearer_header"
    http_method = "GET"

    _supports = {
        "userinfo_signing_alg_values_supported": get_signing_algs,
        "userinfo_encryption_alg_values_supported": get_encryption_algs,
        "userinfo_encryption_enc_values_supported": get_encryption_encs,
        "encrypt_userinfo_supported": None
    }

    def __init__(self, client_get, conf=None):
        Service.__init__(self, client_get, conf=conf)
        self.pre_construct = [self.oidc_pre_construct, carry_state]

    def oidc_pre_construct(self, request_args=None, **kwargs):
        if request_args is None:
            request_args = {}

        if "access_token" in request_args:
            pass
        else:
            request_args = self.client_get("service_context").cstate.get_set(
                kwargs["state"],
                claim=["access_token"]
            )

        return request_args, {}

    def post_parse_response(self, response, **kwargs):
        _context = self.client_get("service_context")
        _current = _context.cstate
        _args = _current.get_set(kwargs["state"], claim=[verified_claim_name("id_token")])

        try:
            _sub = _args[verified_claim_name("id_token")]["sub"]
        except KeyError:
            logger.warning("Can not verify value on sub")
        else:
            if response["sub"] != _sub:
                raise ValueError('Incorrect "sub" value')

        try:
            _csrc = response["_claim_sources"]
        except KeyError:
            pass
        else:
            for csrc, spec in _csrc.items():
                if "JWT" in spec:
                    try:
                        aggregated_claims = Message().from_jwt(
                            spec["JWT"].encode("utf-8"), keyjar=_context.keyjar
                        )
                    except MissingSigningKey as err:
                        logger.warning(
                            f"Error encountered while unpacking aggregated claims: {err}"
                        )
                    else:
                        claims = [
                            value for value, src in response["_claim_names"].items() if src == csrc
                        ]

                        for key in claims:
                            response[key] = aggregated_claims[key]

        # Extension point
        for meth in self.post_parse_process:
            response = meth(response, _current, kwargs["state"])

        _current.update(kwargs["state"], response)
        return response

    def gather_verify_arguments(
        self, response: Optional[Union[dict, Message]] = None, behaviour_args: Optional[dict] = None
    ):
        """
        Need to add some information before running verify()

        :return: dictionary with arguments to the verify call
        """
        _context = self.client_get("service_context")
        kwargs = {
            "client_id": _context.get_client_id(),
            "iss": _context.issuer,
            "keyjar": _context.keyjar,
            "verify": True,
            "skew": _context.clock_skew,
        }

        _reg_resp = _context.registration_response
        if _reg_resp:
            for attr, param in UI2REG.items():
                try:
                    kwargs[attr] = _reg_resp[param]
                except KeyError:
                    pass

        try:
            kwargs["allow_missing_kid"] = _context.allow["missing_kid"]
        except KeyError:
            pass

        return kwargs
