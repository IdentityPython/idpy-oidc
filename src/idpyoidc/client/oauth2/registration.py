import logging

from cryptojwt import KeyJar

from idpyoidc.client.entity import response_types_to_grant_types
from idpyoidc.client.service import Service
from idpyoidc.key_import import store_under_other_id
from idpyoidc.message import oauth2
from idpyoidc.message.oauth2 import ResponseMessage

__author__ = "Roland Hedberg"

from idpyoidc.util import get_client_keyjar

logger = logging.getLogger(__name__)


class Registration(Service):
    msg_type = oauth2.OauthClientMetadata
    response_cls = oauth2.OauthClientInformationResponse
    error_msg = ResponseMessage
    endpoint_name = "registration_endpoint"
    synchronous = True
    service_name = "registration"
    request_body_type = "json"
    http_method = "POST"

    callback_path = {}

    def __init__(self, upstream_get, conf=None):
        Service.__init__(self, upstream_get, conf=conf)
        self.pre_construct = [self.add_client_preference]
        self.post_construct = [self.oauth2_post_construct]

    def add_client_preference(self, context, request_args=None, **kwargs):
        _use = context.map_preferred_to_registered()
        for prop, spec in self.msg_type.c_param.items():
            if prop in request_args:
                continue

            _val = _use.get(prop)
            if _val:
                if isinstance(_val, list):
                    if isinstance(spec[0], list):
                        request_args[prop] = _val
                    else:
                        request_args[prop] = _val[0]  # get the first one
                else:
                    request_args[prop] = _val
        return request_args, {}

    def oauth2_post_construct(self, request_args=None, **kwargs):
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

    def update_service_context(self, context, resp, key="", **kwargs):
        context.map_preferred_to_registered(resp)

        context.registration_response = resp
        _client_id = context.get_usage("client_id")
        if _client_id:
            context.client_id = _client_id
            _keyjar = context.keyjar
            if _keyjar:
                if _client_id not in _keyjar:
                    _keyjar = store_under_other_id(_keyjar, "", _client_id, True)
            _client_secret = context.get_usage("client_secret")
            if _client_secret:
                if not _keyjar:
                    _entity = self.upstream_get("unit")
                    _keyjar = _entity.keyjar = KeyJar()

                context.client_secret = _client_secret
                _keyjar.add_symmetric("", _client_secret)
                _keyjar.add_symmetric(_client_id, _client_secret)
                try:
                    context.set_usage("client_secret_expires_at", resp["client_secret_expires_at"])
                except KeyError:
                    pass

        try:
            context.set_usage("registration_access_token", resp["registration_access_token"])
        except KeyError:
            pass

    def gather_request_args(self, context, **kwargs):
        """

        @param kwargs:
        @return:
        """
        req_args = context.claims.create_registration_request()
        if "request_args" in self.conf:
            req_args.update(self.conf["request_args"])

        req_args.update(kwargs)
        return req_args
