import logging
from typing import Optional
from typing import Union

from idpyoidc.client.oauth2 import authorization
from idpyoidc.client.oauth2.utils import pre_construct_pick_redirect_uri
from idpyoidc.client.oidc import IDT2REG
from idpyoidc.client.oidc.utils import construct_request_uri
from idpyoidc.client.oidc.utils import request_object_encryption
from idpyoidc.exception import MissingRequiredAttribute
from idpyoidc.message import Message
from idpyoidc.message import oauth2
from idpyoidc.message import oidc
from idpyoidc.message.oidc import make_openid_request
from idpyoidc.message.oidc import verified_claim_name
from idpyoidc.time_util import time_sans_frac
from idpyoidc.time_util import utc_time_sans_frac
from idpyoidc.util import rndstr

__author__ = "Roland Hedberg"

LOGGER = logging.getLogger(__name__)


class Authorization(authorization.Authorization):
    msg_type = oidc.AuthorizationRequest
    response_cls = oidc.AuthorizationResponse
    error_msg = oidc.ResponseMessage

    usage_rules = {
    }

    def __init__(self, client_get, conf=None):
        authorization.Authorization.__init__(self, client_get, conf=conf)
        self.default_request_args = {"scope": ["openid"]}
        self.pre_construct = [
            self.set_state,
            pre_construct_pick_redirect_uri,
            self.oidc_pre_construct,
        ]
        self.post_construct = [self.oidc_post_construct]

    def set_state(self, request_args, **kwargs):
        try:
            _state = kwargs["state"]
        except KeyError:
            try:
                _state = request_args["state"]
            except KeyError:
                _state = ""

        _context = self.client_get("service_context")
        request_args["state"] = _context.state.create_state(_context.issuer, _state)
        return request_args, {}

    def update_service_context(self, resp, key="", **kwargs):
        _context = self.client_get("service_context")

        if "expires_in" in resp:
            resp["__expires_at"] = time_sans_frac() + int(resp["expires_in"])
        _context.state.store_item(resp.to_json(), "auth_response", key)

    def get_request_from_response(self, response):
        _context = self.client_get("service_context")
        return _context.state.get_item(
            oauth2.AuthorizationRequest, "auth_request", response["state"]
        )

    def post_parse_response(self, response, **kwargs):
        response = authorization.Authorization.post_parse_response(self, response, **kwargs)

        _idt = response.get(verified_claim_name("id_token"))
        if _idt:
            # If there is a verified ID Token then we have to do nonce
            # verification.
            _request = self.get_request_from_response(response)
            _req_nonce = _request.get("nonce")
            if _req_nonce:
                _id_token_nonce = _idt.get("nonce")
                if not _id_token_nonce:
                    raise MissingRequiredAttribute("nonce")
                elif _req_nonce != _id_token_nonce:
                    raise ValueError("Invalid nonce")
        return response

    def oidc_pre_construct(self, request_args=None, post_args=None, **kwargs):
        _context = self.client_get("service_context")
        _entity = self.client_get("entity")

        if request_args is None:
            request_args = {}

        try:
            _response_types = [request_args["response_type"]]
        except KeyError:
            _response_types = _context.specs.behaviour.get("response_types")
            if _response_types:
                request_args["response_type"] = _response_types[0]
            else:
                request_args["response_type"] = "code"

        # For OIDC 'openid' is required in scope
        if "scope" not in request_args:
            _scope = self.client_get("entity").get_usage_value("scope")
            if _scope:
                request_args["scope"] = _scope
            else:
                request_args["scope"] = "openid"
        elif "openid" not in request_args["scope"]:
            request_args["scope"].append("openid")

        # 'code' and/or 'id_token' in response_type means an ID Roken
        # will eventually be returnedm, hence the need for a nonce
        if "code" in _response_types or "id_token" in _response_types:
            if "nonce" not in request_args:
                request_args["nonce"] = rndstr(32)

        if post_args is None:
            post_args = {}

        for attr in ["request_object_signing_alg", "algorithm", "sig_kid"]:
            try:
                post_args[attr] = kwargs[attr]
            except KeyError:
                pass
            else:
                del kwargs[attr]

        if "request_method" in kwargs:
            if kwargs["request_method"] == "reference":
                post_args["request_param"] = "request_uri"
            else:
                post_args["request_param"] = "request"
            del kwargs["request_method"]
        else:
            if _entity.get_usage_value("request_uri"):
                post_args["request_param"] = "request_uri"
            elif _entity.get_usage_value("request_parameter"):
                post_args["request_param"] = "request"

        return request_args, post_args

    def get_request_object_signing_alg(self, **kwargs):
        alg = ""
        for arg in ["request_object_signing_alg", "algorithm"]:
            try:  # Trumps everything
                alg = kwargs[arg]
            except KeyError:
                pass
            else:
                break

        if not alg:
            _context = self.client_get("service_context")
            try:
                alg = _context.specs.behaviour["request_object_signing_alg"]
            except KeyError:  # Use default
                alg = "RS256"
        return alg

    def store_request_on_file(self, req, **kwargs):
        """
        Stores the request parameter in a file.
        :param req: The request
        :param kwargs: Extra keyword arguments
        :return: The URL the OP should use to access the file
        """
        _context = self.client_get("service_context")
        try:
            _webname = _context.registration_response["request_uris"][0]
            filename = _context.filename_from_webname(_webname)
        except KeyError:
            filename, _webname = construct_request_uri(**kwargs)

        fid = open(filename, mode="w")
        fid.write(req)
        fid.close()
        return _webname

    def construct_request_parameter(
            self, req, request_param, audience=None, expires_in=0, **kwargs
    ):
        """Construct a request parameter"""
        alg = self.get_request_object_signing_alg(**kwargs)
        kwargs["request_object_signing_alg"] = alg

        _context = self.client_get("service_context")
        if "keys" not in kwargs and alg and alg != "none":
            kwargs["keys"] = _context.keyjar

        if alg == "none":
            kwargs["keys"] = []

        _srv_cntx = _context

        # This is the issuer of the JWT, that is me !
        _issuer = kwargs.get("issuer")
        if _issuer is None:
            kwargs["issuer"] = _srv_cntx.get_client_id()

        if kwargs.get("recv") is None:
            try:
                kwargs["recv"] = _srv_cntx.provider_info["issuer"]
            except KeyError:
                kwargs["recv"] = _srv_cntx.issuer

        try:
            del kwargs["service"]
        except KeyError:
            pass

        if expires_in:
            req["exp"] = utc_time_sans_frac() + int(expires_in)

        _mor_args = {
            k: kwargs[k]
            for k in [
                "keys",
                "issuer",
                "request_object_signing_alg",
                "recv",
                "with_jti",
                "lifetime",
            ]
            if k in kwargs
        }

        _req = make_openid_request(req, **_mor_args)

        # Should the request be encrypted
        return request_object_encryption(_req, _context, **kwargs)

    def oidc_post_construct(self, req, **kwargs):
        """
        Modify the request arguments.

        :param req: The request
        :param kwargs: Extra keyword arguments
        :return: A possibly modified request.
        """
        _context = self.client_get("service_context")
        if "openid" in req["scope"]:
            _response_type = req["response_type"][0]
            if "id_token" in _response_type or "code" in _response_type:
                _context.state.store_nonce2state(req["nonce"], req["state"])

        if "offline_access" in req["scope"]:
            if "prompt" not in req:
                req["prompt"] = "consent"

        _context.state.store_item(req, "auth_request", req["state"])

        # Overrides what's in the configuration
        _request_param = kwargs.get("request_param")
        if _request_param:
            del kwargs["request_param"]
        else:
            if _context.specs.get_usage("request_uri"):
                _request_param = "request_uri"
            elif _context.specs.get_usage("request_parameter"):
                _request_param = "request"

        _req = None  # just a flag
        if _request_param == "request_uri":
            kwargs["base_path"] = _context.get("base_url") + "/" + "requests"
            kwargs["local_dir"] = _context.specs.get("requests_dir", "./requests")
            _req = self.construct_request_parameter(req, _request_param, **kwargs)
            req["request_uri"] = self.store_request_on_file(_req, **kwargs)
        elif _request_param == "request":
            _req = self.construct_request_parameter(req, _request_param)
            req["request"] = _req

        if _req:
            _leave = ["request", "request_uri"]
            _leave.extend(req.required_parameters())
            _keys = [k for k in req.keys() if k not in _leave]
            for k in _keys:
                del req[k]

        return req

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
            "iss": _context.issuer,
            "keyjar": _context.keyjar,
            "verify": True,
            "skew": _context.clock_skew,
        }

        _client_id = _context.get_client_id()
        if _client_id:
            kwargs["client_id"] = _client_id

        _reg_res = _context.registration_response
        if _reg_res:
            for attr, param in IDT2REG.items():
                try:
                    kwargs[attr] = _reg_res[param]
                except KeyError:
                    pass

        try:
            kwargs["allow_missing_kid"] = _context.allow["missing_kid"]
        except KeyError:
            pass

        _verify_args = _context.specs.behaviour.get("verify_args")
        if _verify_args:
            kwargs.update(_verify_args)

        return kwargs
