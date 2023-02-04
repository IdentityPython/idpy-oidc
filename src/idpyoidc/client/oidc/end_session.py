import logging

from idpyoidc.client.service import Service
from idpyoidc.message.oauth2 import Message
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.message.oidc import session
from idpyoidc.util import rndstr

__author__ = "Roland Hedberg"

logger = logging.getLogger(__name__)


class EndSession(Service):
    msg_type = session.EndSessionRequest
    response_cls = Message
    error_msg = ResponseMessage
    endpoint_name = "end_session_endpoint"
    synchronous = True
    service_name = "end_session"
    response_body_type = "html"

    _supports = {
        "post_logout_redirect_uris": None,
        'frontchannel_logout_supported': None,
        "frontchannel_logout_uri": None,
        "frontchannel_logout_session_required": None,
        'backchannel_logout_supported': None,
        "backchannel_logout_uri": None,
        "backchannel_logout_session_required": None
    }

    _callback_path = {
        "frontchannel_logout_uri": "fc_logout",
        "backchannel_logout_uri": "bc_logout",
        "post_logout_redirect_uris": ["session_logout"]
    }

    def __init__(self, upstream_get, conf=None):
        Service.__init__(self, upstream_get, conf=conf)
        self.pre_construct = [
            self.get_id_token_hint,
            self.add_post_logout_redirect_uri,
            self.add_state,
        ]

    def get_id_token_hint(self, request_args=None, **kwargs):
        """
        Add id_token_hint to request

        :param request_args:
        :param kwargs:
        :return:
        """

        _id_token = self.upstream_get("context").cstate.get_claim(kwargs["state"], claim='id_token')
        if _id_token:
            request_args["id_token_hint"] = _id_token

        return request_args, {}

    def add_post_logout_redirect_uri(self, request_args=None, **kwargs):
        if "post_logout_redirect_uri" not in request_args:
            _uri = self.upstream_get("context").get_usage("post_logout_redirect_uris")
            if _uri:
                if isinstance(_uri, str):
                    request_args["post_logout_redirect_uri"] = _uri
                else:  # assume list
                    request_args["post_logout_redirect_uri"] = _uri[0]

        return request_args, {}

    def add_state(self, request_args=None, **kwargs):
        if "state" not in request_args:
            request_args["state"] = rndstr(32)

        # As a side effect bind logout state to session state
        self.upstream_get("context").cstate.bind_key(request_args["state"], kwargs["state"])

        return request_args, {}
