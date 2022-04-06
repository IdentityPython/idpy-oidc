from typing import Optional
from uuid import uuid4

from cryptojwt.key_jar import KeyJar

from idpyoidc.impexp import ImpExp


class CIBAClient(ImpExp):
    parameter = {
        "context": {}
    }

    def __init__(
            self,
            keyjar: Optional[KeyJar] = None,
    ):
        ImpExp.__init__(self)
        self.keyjar = keyjar
        self.server = None
        self.client = None
        self.context = {}

    def create_authentication_request(self, scope, binding_message, login_hint):
        _service = self.client.client_get("service", "backchannel_authentication")

        client_notification_token = uuid4().hex

        request_args = {
            "scope": scope,
            "client_notification_token": client_notification_token,
            "binding_message": binding_message,
            "login_hint": login_hint
        }
        request = _service.get_request_parameters(request_args=request_args,
                                                  authn_method="private_key_jwt")

        self.context[client_notification_token] = {
            "authentication_request": request,
            "client_id": _service.client_get("service_context").issuer
        }
        return request

    def get_client_id_from_token(self, token):
        _context = self.context[token]
        return _context["client_id"]

    def do_client_notification(self, msg, http_info):
        _notification_endpoint = self.server.server_get("endpoint", "client_notification")
        _nreq = _notification_endpoint.parse_request(
            msg, http_info, get_client_id_from_token=self.get_client_id_from_token)
        _ninfo = _notification_endpoint.process_request(_nreq)


class CIBAServer(ImpExp):
    parameter = {
        "context": {}
    }

    def __init__(
            self,
            keyjar: Optional[KeyJar] = None,
    ):
        ImpExp.__init__(self)
        self.keyjar = keyjar
        self.server = None
        self.client = None
        self.context = {}
