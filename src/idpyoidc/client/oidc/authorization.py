import logging
from typing import List
from typing import Optional
from typing import Union

from idpyoidc import metadata
from idpyoidc.client.oauth2 import authorization
from idpyoidc.client.oauth2.utils import pre_construct_pick_redirect_uri
from idpyoidc.client.oidc import IDT2REG
from idpyoidc.client.oidc.utils import construct_request_uri
from idpyoidc.client.oidc.utils import request_object_encryption
from idpyoidc.client.service_context import ServiceContext
from idpyoidc.client.util import implicit_response_types
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

    _supports = {
        "request_object_signing_alg_values_supported": metadata.get_signing_algs(),
        "request_object_encryption_alg_values_supported": metadata.get_encryption_algs(),
        "request_object_encryption_enc_values_supported": metadata.get_encryption_encs(),
        "response_types_supported": ["code", "id_token", "code id_token"],
        "request_parameter_supported": None,
        "request_uri_parameter_supported": None,
        "request_uris": None,
        "request_parameter": None,
        "encrypt_request_object_supported": False,
        "redirect_uris": None,
        "response_modes_supported": ["query", "fragment", "form_post"],
    }

    _callback_path = {
        "request_uris": ["req"],
        "redirect_uris": {  # based on response_mode
            "query": "authz_cb",
            "fragment": "authz_tok_cb",
            "form_post": "authz_cb_form",
        },
    }

    def __init__(self, upstream_get, conf=None, request_args: Optional[dict] = None):
        authorization.Authorization.__init__(self, upstream_get, conf=conf)
        self.default_request_args.update({"scope": ["openid"]})
        if request_args:
            self.default_request_args.update(request_args)
        self.pre_construct = [
            self.set_state,
            pre_construct_pick_redirect_uri,
            self.oidc_pre_construct,
        ]
        self.post_construct = [self.oidc_post_construct]
        if "scope" not in self.default_request_args:
            self.default_request_args["scope"] = ["openid"]

    def set_state(self, request_args, **kwargs):
        _context = self.upstream_get("context")
        try:
            _state = kwargs["state"]
        except KeyError:
            try:
                _state = request_args["state"]
            except KeyError:
                _state = _context.cstate.create_key()

        request_args["state"] = _state
        _context.cstate.set(_state, {"iss": _context.issuer})
        return request_args, {}

    def update_service_context(self, resp, key="", **kwargs):
        _context = self.upstream_get("context")

        if "expires_in" in resp:
            resp["__expires_at"] = time_sans_frac() + int(resp["expires_in"])
        _context.cstate.update(key, resp)

    def get_request_from_response(self, response):
        _context = self.upstream_get("context")
        return _context.cstate.get_set(response["state"], message=oauth2.AuthorizationRequest)

    def post_parse_response(self, response, **kwargs):
        response = authorization.Authorization.post_parse_response(self, response, **kwargs)

        _idt = response.get(verified_claim_name("id_token"))
        if _idt:
            # If there is a verified ID Token then we have to do nonce
            # verification.
            _req_nonce = (
                self.upstream_get("context")
                .cstate.get_set(response["state"], claim=["nonce"])
                .get("nonce")
            )
            if _req_nonce:
                _id_token_nonce = _idt.get("nonce")
                if not _id_token_nonce:
                    raise MissingRequiredAttribute("nonce")
                elif _req_nonce != _id_token_nonce:
                    raise ValueError("Invalid nonce")
        return response

    def oidc_pre_construct(self, request_args=None, post_args=None, **kwargs):
        _context = self.upstream_get("context")
        if request_args is None:
            request_args = {}

        try:
            _response_types = [request_args["response_type"]]
        except KeyError:
            _response_types = _context.get_usage("response_types")
            if _response_types:
                request_args["response_type"] = _response_types[0]
            else:
                _response_types = ["code"]
                request_args["response_type"] = "code"

        # For OIDC 'openid' is required in scope
        if "scope" not in request_args:
            _scope = _context.get_usage("scope")
            if _scope:
                request_args["scope"] = _scope
            else:
                _scope = _context.get_preference("scopes_supported")
                if _scope:
                    request_args["scope"] = _scope
                else:
                    request_args["scope"] = "openid"
        elif "openid" not in request_args["scope"]:
            request_args["scope"].append("openid")

        # 'code' and/or 'id_token' in response_type means an ID Roken
        # will eventually be returned, hence the need for a nonce
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
            if _context.get_usage("request_uri"):
                post_args["request_param"] = "request_uri"
            elif _context.get_usage("request_parameter"):
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
            _context = self.upstream_get("context")
            try:
                alg = _context.claims.get_usage("request_object_signing_alg")
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
        _context = self.upstream_get("context")
        _webname = _context.get_usage("request_uris")
        if _webname is None:
            filename, _webname = construct_request_uri(**kwargs)
        else:
            # webname should be a list
            _webname = _webname[0]
            filename = _context.filename_from_webname(_webname)

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

        _context = self.upstream_get("context")
        if "keys" not in kwargs and alg and alg != "none":
            kwargs["keys"] = self.upstream_get("attribute", "keyjar")

        if alg == "none":
            kwargs["keys"] = []

        # This is the issuer of the JWT, that is me !
        _issuer = kwargs.get("issuer")
        if _issuer is None:
            kwargs["issuer"] = _context.get_client_id()

        if kwargs.get("recv") is None:
            try:
                kwargs["recv"] = _context.provider_info["issuer"]
            except KeyError:
                kwargs["recv"] = _context.issuer

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

        _req_jwt = make_openid_request(req, **_mor_args)

        if "target" not in kwargs:
            kwargs["target"] = _context.provider_info.get("issuer", _context.issuer)

        # Should the request be encrypted
        _req_jwte = request_object_encryption(
            _req_jwt, _context, self.upstream_get("attribute", "keyjar"), **kwargs
        )
        return _req_jwte

    def oidc_post_construct(self, req, **kwargs):
        """
        Modify the request arguments.

        :param req: The request
        :param kwargs: Extra keyword arguments
        :return: A possibly modified request.
        """
        _context = self.upstream_get("context")
        if "openid" in req["scope"]:
            _response_type = req["response_type"][0]
            if "id_token" in _response_type or "code" in _response_type:
                _context.cstate.bind_key(req["nonce"], req["state"])

        if "offline_access" in req["scope"]:
            if "prompt" not in req:
                req["prompt"] = "consent"

        _context.cstate.update(req["state"], req)

        # Overrides what's in the configuration
        _request_param = kwargs.get("request_param")
        if _request_param:
            del kwargs["request_param"]
        else:
            if _context.get_usage("request_uri"):
                _request_param = "request_uri"
            elif _context.get_usage("request_parameter"):
                _request_param = "request"

        _req = None  # just a flag
        if _request_param == "request_uri":
            kwargs["base_path"] = _context.get("base_url") + "/" + "requests"
            kwargs["local_dir"] = _context.get_usage("requests_dir", "./requests")
            _req = self.construct_request_parameter(req, _request_param, **kwargs)
            req["request_uri"] = self.store_request_on_file(_req, **kwargs)
        elif _request_param == "request":
            _req = self.construct_request_parameter(req, _request_param, **kwargs)
            req["request"] = _req

        if _req:
            _leave = ["request", "request_uri"]
            _leave.extend(req.required_parameters())
            _keys = [k for k in req.keys() if k not in _leave]
            for k in _keys:
                del req[k]

        return req

    def gather_verify_arguments(
        self, response: Optional[Union[dict, Message]] = None, behaviour_args: Optional[dict] = None
    ):
        """
        Need to add some information before running verify()

        :return: dictionary with arguments to the verify call
        """
        _context = self.upstream_get("context")
        kwargs = {
            "iss": _context.issuer,
            "keyjar": self.upstream_get("attribute", "keyjar"),
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

        _allow = _context.allow.get("missing_kid")
        if _allow:
            kwargs["allow_missing_kid"] = _allow

        _verify_args = _context.get_usage("verify_args")
        if _verify_args:
            kwargs.update(_verify_args)

        return kwargs

    def _do_request_uris(self, base_url, hex, context, callback_uris):
        _uri_name = "request_uris"
        if context.get_preference("request_parameter") == _uri_name:
            if _uri_name not in callback_uris:
                callback_uris[_uri_name] = self.get_uri(
                    base_url, self._callback_path[_uri_name], hex
                )
        return callback_uris

    def _do_type(self, context, typ, response_types):
        if typ == "code" and "code" in response_types:
            if typ in context.get_preference("response_modes_supported"):
                return "query"
        elif typ == "implicit":
            if typ in context.get_preference("response_modes_supported"):
                if implicit_response_types(response_types):
                    return "fragment"
        elif typ == "form_post":
            if typ in context.get_preference("response_modes_supported"):
                return "form_post"
        return ""

    def construct_uris(
        self,
        base_url: str,
        hex: bytes,
        context: ServiceContext,
        targets: Optional[List[str]] = None,
        response_types: Optional[List[str]] = None,
    ):
        _callback_uris = context.get_preference("callback_uris", {})

        for uri_name in self._callback_path.keys():
            if uri_name == "redirect_uris":
                _callback_uris = self._do_redirect_uris(
                    base_url, hex, context, _callback_uris, response_types
                )
            elif uri_name == "request_uris":
                _callback_uris = self._do_request_uris(base_url, hex, context, _callback_uris)
            else:
                _callback_uris[uri_name] = self.get_uri(
                    base_url, self._callback_path[uri_name], hex
                )

        return _callback_uris
