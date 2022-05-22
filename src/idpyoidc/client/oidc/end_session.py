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

    metadata_attributes = {
        "post_logout_redirect_uris": None,
        "frontchannel_logout_uri": None,
        "frontchannel_logout_session_required": None,
        "backchannel_logout_uri": None,
        "backchannel_logout_session_required": None
    }

    usage_rules = {
        "frontchannel_logout": None,
        "backchannel_logout": None,
        "post_logout_redirects": None
    }

    callback_path = {
        "frontchannel_logout_uri": "fc_logout",
        "backchannel_logout_uri": "bc_logout",
        "post_logout_redirect_uris": "session_logout"
    }

    usage_to_uri_map = {
        "frontchannel_logout": "frontchannel_logout_uri",
        "backchannel_logout": "backchannel_logout_uri",
        "post_logout_redirect": "post_logout_redirect_uris"
    }

    callback_uris = [
        "frontchannel_logout_uri",
        "backchannel_logout_uri",
        "post_logout_redirect_uris"
    ]

    def __init__(self, client_get, conf=None):
        Service.__init__(self, client_get, conf=conf)
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
        request_args = self.client_get("service_context").state.multiple_extend_request_args(
            request_args,
            kwargs["state"],
            ["id_token"],
            ["auth_response", "token_response", "refresh_token_response"],
            orig=True,
        )

        try:
            request_args["id_token_hint"] = request_args["id_token"]
        except KeyError:
            pass
        else:
            del request_args["id_token"]

        return request_args, {}

    def add_post_logout_redirect_uri(self, request_args=None, **kwargs):
        if "post_logout_redirect_uri" not in request_args:
            _uri = self.metadata["post_logout_redirect_uris"]
            if isinstance(_uri, str):
                request_args["post_logout_redirect_uri"] = _uri
            else:  # assume list
                request_args["post_logout_redirect_uri"] = _uri[0]

        return request_args, {}

    def add_state(self, request_args=None, **kwargs):
        if "state" not in request_args:
            request_args["state"] = rndstr(32)

        # As a side effect bind logout state to session state
        self.client_get("service_context").state.store_logout_state2state(
            request_args["state"], kwargs["state"]
        )

        return request_args, {}
