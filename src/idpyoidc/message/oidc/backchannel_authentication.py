from idpyoidc import verified_claim_name
from idpyoidc.exception import MissingRequiredAttribute
from idpyoidc.exception import ParameterError
from idpyoidc.message import OPTIONAL_LIST_OF_SP_SEP_STRINGS
from idpyoidc.message import OPTIONAL_LIST_OF_STRINGS
from idpyoidc.message import REQUIRED_LIST_OF_SP_SEP_STRINGS
from idpyoidc.message import REQUIRED_LIST_OF_STRINGS
from idpyoidc.message import SINGLE_OPTIONAL_INT
from idpyoidc.message import SINGLE_OPTIONAL_STRING
from idpyoidc.message import SINGLE_REQUIRED_INT
from idpyoidc.message import SINGLE_REQUIRED_STRING
from idpyoidc.message import Message
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.message.oidc import IdToken

JWT_ARGS = ["iss", "aud", "iat", "nbf", "jti", "exp"]


class AuthenticationRequest(Message):
    c_param = {
        "scope": OPTIONAL_LIST_OF_SP_SEP_STRINGS,
        "client_notification_token": SINGLE_OPTIONAL_STRING,
        "acr_values": OPTIONAL_LIST_OF_STRINGS,
        "login_hint_token": SINGLE_OPTIONAL_STRING,
        "id_token_hint": SINGLE_OPTIONAL_STRING,
        "login_hint": SINGLE_OPTIONAL_STRING,
        "binding_message": SINGLE_OPTIONAL_STRING,
        "user_code": SINGLE_OPTIONAL_STRING,
        "requested_expiry": SINGLE_OPTIONAL_INT,
        "request": SINGLE_OPTIONAL_STRING,
        # The ones below are part of client authentication information
        "client_id": SINGLE_OPTIONAL_STRING,
        "client_assertion_type": SINGLE_OPTIONAL_STRING,
        "client_assertion": SINGLE_OPTIONAL_STRING,
    }

    def verify(self, **kwargs):
        if "request" in self:
            _vc_name = verified_claim_name("request")
            if _vc_name in self:
                del self[_vc_name]

            # If request is present then none of the other authentication request parameters
            # is allowed apart from those connected to a client authentication method
            for c in self.c_param.keys():
                if c in ["client_id", "client_assertion_type", "client_assertion", "request"]:
                    continue
                if c in self:
                    raise ParameterError(f"'{c}' not allowed outside the request JWT.")

            args = {}
            for arg in ["keyjar", "opponent_id", "sender", "alg", "encalg", "encenc"]:
                try:
                    args[arg] = kwargs[arg]
                except KeyError:
                    pass

            _req = AuthenticationRequestJWT().from_jwt(str(self["request"]), **args)
            self.update({k: v for k, v in _req.items() if k not in JWT_ARGS})
            self[_vc_name] = _req

        if not self.has_none_or_one_of(["id_token_hint", "login_hint", "login_hint_token"]):
            raise ValueError("One and only one of the hints allowed")

        if "id_token_hint" in self:
            if isinstance(self["id_token_hint"], str):
                args = {}
                for arg in ["keyjar", "opponent_id", "sender", "alg", "encalg", "encenc"]:
                    try:
                        args[arg] = kwargs[arg]
                    except KeyError:
                        pass
                idt = IdToken().from_jwt(str(self["id_token_hint"]), **args)
                _vc_name = verified_claim_name("id_token_hint")
                self[_vc_name] = idt

        _mode = kwargs.get("mode")
        if _mode in ["ping", "push"]:
            if "client_notification_token" not in self:
                raise MissingRequiredAttribute(
                    "client_notification_token must be present in ping or push mode")


class AuthenticationRequestJWT(Message):
    c_param = {
        "iss": SINGLE_REQUIRED_STRING,
        "aud": REQUIRED_LIST_OF_STRINGS,  # Array of strings or string
        "exp": SINGLE_REQUIRED_INT,
        "nbf": SINGLE_REQUIRED_INT,
        "iat": SINGLE_REQUIRED_INT,
        "jti": SINGLE_REQUIRED_STRING,
        "scope": REQUIRED_LIST_OF_SP_SEP_STRINGS,
        "client_notification_token": SINGLE_OPTIONAL_STRING,
        "acr_values": OPTIONAL_LIST_OF_STRINGS,
        "login_hint_token": SINGLE_OPTIONAL_STRING,
        "id_token_hint": SINGLE_OPTIONAL_STRING,
        "login_hint": SINGLE_OPTIONAL_STRING,
        "binding_message": SINGLE_OPTIONAL_STRING,
        "user_code": SINGLE_OPTIONAL_STRING,
        "requested_expiry": SINGLE_OPTIONAL_INT,
    }

    def verify(self, **kwargs):
        def verify(self, **kwargs):
            _iss = kwargs.get("issuer")
            if _iss:
                if _iss not in self["aud"]:
                    raise ParameterError("Not among audience")

            _client_id = kwargs.get("client_id")
            if _client_id:
                if _client_id != self["iss"]:
                    raise ParameterError("Issuer mismatch")


class AuthenticationResponse(ResponseMessage):
    c_param = {
        "auth_req_id": SINGLE_REQUIRED_STRING,
        "expires_in": SINGLE_REQUIRED_INT,
        "interval": SINGLE_OPTIONAL_INT
    }
    c_default = {"interval": 5}


class TokenRequest(Message):
    c_param = {
        "grant_type": SINGLE_REQUIRED_STRING,
        "auth_req_id": SINGLE_REQUIRED_STRING,
        # The ones below are part of client authentication information
        "client_id": SINGLE_OPTIONAL_STRING,
        "client_assertion_type": SINGLE_OPTIONAL_STRING,
        "client_assertion": SINGLE_OPTIONAL_STRING,
    }


class NotificationRequest(Message):
    c_param = {
        "auth_req_id": SINGLE_REQUIRED_STRING
    }


class PushErrorPayload(Message):
    c_param = {
        "error": SINGLE_REQUIRED_STRING,
        "auth_req_id": SINGLE_REQUIRED_STRING,
        "error_description": SINGLE_OPTIONAL_STRING
    }
