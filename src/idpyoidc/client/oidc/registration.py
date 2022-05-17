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
        self.pre_construct = [
            self.add_client_behaviour_preference,
            # add_redirect_uris,
        ]
        self.post_construct = [self.oidc_post_construct]

    def add_client_behaviour_preference(self, request_args=None, **kwargs):
        _context = self.client_get("service_context")
        for prop in self.msg_type.c_param.keys():
            if prop in request_args:
                continue

            try:
                request_args[prop] = _context.specs.behaviour[prop]
            except KeyError:
                _val = _context.specs.get_metadata(prop)
                if _val:
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
        _context.registration_response = resp
        _client_id = resp.get("client_id")
        if _client_id:
            _context.specs.set_metadata("client_id", _client_id)
            if _client_id not in _context.keyjar:
                _context.keyjar.import_jwks(
                    _context.keyjar.export_jwks(True, ""), issuer_id=_client_id
                )
            _client_secret = resp.get("client_secret")
            if _client_secret:
                _context.client_secret = _client_secret
                _context.keyjar.add_symmetric("", _client_secret)
                _context.keyjar.add_symmetric(_client_id, _client_secret)
                try:
                    _context.client_secret_expires_at = resp["client_secret_expires_at"]
                except KeyError:
                    pass

        try:
            _context.registration_access_token = resp["registration_access_token"]
        except KeyError:
            pass
