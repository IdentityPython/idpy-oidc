from idpyoidc.message import Message
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.message.oidc import RegistrationResponse
from idpyoidc.server.endpoint import Endpoint
from idpyoidc.server.oidc.registration import comb_uri


class RegistrationRead(Endpoint):
    request_cls = Message
    response_cls = RegistrationResponse
    error_response = ResponseMessage
    request_format = "urlencoded"
    request_placement = "url"
    response_format = "json"
    name = "registration_read"

    def get_client_id_from_token(self, endpoint_context, token, request=None):
        if "client_id" in request:
            if (
                    request["client_id"]
                    == self.server_get("endpoint_context").registration_access_token[token]
            ):
                return request["client_id"]
        return ""

    def process_request(self, request=None, **kwargs):
        _cli_info = self.server_get("endpoint_context").cdb[request["client_id"]]
        args = {k: v for k, v in _cli_info.items() if k in RegistrationResponse.c_param}
        comb_uri(args)
        return {"response_args": RegistrationResponse(**args)}
