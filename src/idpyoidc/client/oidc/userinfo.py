import json
import logging
from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt.key_jar import KeyJar
import requests

from idpyoidc.client.oauth2.utils import get_state_parameter
from idpyoidc.client.oidc import FetchException
from idpyoidc.client.service import Service
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

    metadata_attributes = {
        "userinfo_signed_response_alg": None,
        "userinfo_encrypted_response_alg": None,
        "userinfo_encrypted_response_enc": None
    }

    def __init__(self, client_get, conf=None):
        Service.__init__(self, client_get, conf=conf)
        self.pre_construct = [self.oidc_pre_construct, carry_state]
        self.claim_sources_collect = collect_claim_sources

    def oidc_pre_construct(self, request_args=None, **kwargs):
        if request_args is None:
            request_args = {}

        if "access_token" in request_args:
            pass
        else:
            request_args = self.client_get("service_context").state.multiple_extend_request_args(
                request_args,
                kwargs["state"],
                ["access_token"],
                ["auth_response", "token_response", "refresh_token_response"],
            )

        return request_args, {}

    def post_parse_response(self, response, **kwargs):
        _context = self.client_get("service_context")
        _state_interface = _context.state
        _args = _state_interface.multiple_extend_request_args(
            {},
            kwargs["state"],
            ["id_token"],
            ["auth_response", "token_response", "refresh_token_response"],
        )

        try:
            _sub = _args["id_token"]["sub"]
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
            self.claim_sources_collect(_csrc, response, self.response_cls,
                                       _context.keyjar, httpc=None, **kwargs)

        # Extension point
        for meth in self.post_parse_process:
            response = meth(response, _state_interface, kwargs["state"])

        _state_interface.store_item(response, "user_info", kwargs["state"])
        return response

    def gather_verify_arguments(
            self, response: Optional[Union[dict, Message]] = None,
            behaviour_args: Optional[dict] = None
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


def _collect_claims_by_url(spec: Message,
                           httpc: type,
                           callback: Optional[Callable] = None):
    if "access_token" in spec:
        _bearer = "Bearer {}".format(spec["access_token"])
        http_args = {"headers": {"Authorization": _bearer}}
        _resp = httpc("GET", spec["endpoint"], **http_args)
    else:
        if callback:
            _bearer = "Bearer {}".format(callback(spec["endpoint"]))
            http_args = {"headers": {"Authorization": _bearer}}
            _resp = httpc("GET", spec["endpoint"], **http_args)
        else:
            _resp = httpc("GET", spec["endpoint"])

    if _resp.status_code == 200:
        _uinfo = json.loads(_resp.text)
    else:  # There shouldn't be any redirect
        raise FetchException(
            "HTTP error {}: {}".format(_resp.status_code, _resp.reason)
        )

    return _uinfo


def aggregate_claim(item: Message, ava: Message, claim_source: str):
    claims = [value for value, src in item["_claim_names"].items() if claim_source in src]
    for key in claims:
        if isinstance(item.c_param[key][0], list):
            _list = True
        else:
            _list = False

        if key in item:
            if _list:
                if isinstance(item[key], list):
                    item[key].append(ava[key])
                else:
                    item.set(key, [item[key], ava[key]])
            else:  # overwrite ??
                item.set(key, ava[key])
        else:
            if _list:
                if isinstance(ava[key], list):
                    item.set(key, ava[key])
                else:
                    item.set(key, [ava[key]])
            else:
                item.set(key, ava[key])
    return item


def collect_claim_sources(claim_sources: dict,
                          response: Message,
                          user_class: object,
                          keyjar: KeyJar,
                          httpc: Optional[Callable] = None,
                          **kwargs):
    """

    """
    if httpc is None:
        httpc = requests.request

    _aggregate = {}
    for csrc, spec in claim_sources.items():
        if "JWT" in spec:
            try:
                _ava = user_class().from_jwt(spec["JWT"].encode("utf-8"), keyjar=keyjar)
            except MissingSigningKey as err:
                logger.warning(
                    f"Error '{err}' encountered while unpacking claims from claims source")
            else:
                _ava.verify()
                response = aggregate_claim(response, ava=_ava, claim_source=csrc)
        elif "endpoint" in spec:
            _ava = user_class(**_collect_claims_by_url(spec, httpc))
            _ava.verify()
            response = aggregate_claim(response, ava=_ava, claim_source=csrc)
    return response
