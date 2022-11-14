import logging

from idpyoidc.client.entity import response_types_to_grant_types
from idpyoidc.client.service import Service
from idpyoidc.message import oidc
from idpyoidc.message.oauth2 import ResponseMessage

__author__ = "Roland Hedberg"

logger = logging.getLogger(__name__)


class Registration(Service):
    msg_type = oidc.RegistrationRequest
    response_cls = oidc.RegistrationResponse
    error_msg = ResponseMessage
    endpoint_name = "registration_endpoint"
    synchronous = True
    service_name = "registration"
    request_body_type = "json"
    http_method = "POST"

    usage_to_uri_map = {}
    callback_path = {}

    def __init__(self, client_get, conf=None):
        Service.__init__(self, client_get, conf=conf)
        self.pre_construct = [self.add_client_preference]
        self.post_construct = [self.oidc_post_construct]

    def add_client_preference(self, request_args=None, **kwargs):
        _work_condition = self.client_get("service_context")
        for prop, spec in self.msg_type.c_param.items():
            if prop in request_args:
                continue

            _val = _work_condition.get_preference(prop)
            if _val:
                if isinstance(_val, list):
                    if isinstance(spec[0], list):
                        request_args[prop] = _val
                    else:
                        request_args[prop] = _val[0]  # get the first one
                else:
                    request_args[prop] = _val
        return request_args, {}

    def oidc_post_construct(self, request_args=None, **kwargs):
        try:
            request_args["grant_types"] = response_types_to_grant_types(
                request_args["response_types"]
            )
        except KeyError:
            pass

        # If a Client can use jwks_uri, it MUST NOT use jwks.
        if "jwks_uri" in request_args and "jwks" in request_args:
            del request_args["jwks"]

        return request_args

    def update_service_context(self, resp, key="", **kwargs):
        if "token_endpoint_auth_method" not in resp:
            resp["token_endpoint_auth_method"] = "client_secret_basic"

        _context = self.client_get("service_context")
        _work_condition = _context.work_condition
        _keyjar = _context.keyjar

        _context.registration_response = resp
        _client_id = resp.get("client_id")
        if _client_id:
            _context.work_condition.set_usage_claim("client_id", _client_id)
            if _client_id not in _keyjar:
                _keyjar.import_jwks(_keyjar.export_jwks(True, ""), issuer_id=_client_id)
            _client_secret = resp.get("client_secret")
            if _client_secret:
                _work_condition.set_usage_claim("client_secret", _client_secret)
                # _context.client_secret = _client_secret
                _keyjar.add_symmetric("", _client_secret)
                _keyjar.add_symmetric(_client_id, _client_secret)
                try:
                    _work_condition.set_usage_claim("client_secret_expires_at",
                                                    resp["client_secret_expires_at"])
                except KeyError:
                    pass

        try:
            _work_condition.set_usage_claim("registration_access_token",
                                            resp["registration_access_token"])
        except KeyError:
            pass
