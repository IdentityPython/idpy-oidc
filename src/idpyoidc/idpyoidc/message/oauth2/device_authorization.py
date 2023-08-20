from idpyoidc.exception import MissingRequiredAttribute
from idpyoidc.message import SINGLE_OPTIONAL_INT
from idpyoidc.message import SINGLE_OPTIONAL_STRING
from idpyoidc.message import SINGLE_REQUIRED_INT
from idpyoidc.message import SINGLE_REQUIRED_STRING
from idpyoidc.message import Message
from idpyoidc.message import oidc


class AuthorizationRequest(Message):
    c_param = {
        "client_id": SINGLE_REQUIRED_STRING,
        "scope": SINGLE_OPTIONAL_STRING,
    }


class AuthorizationResponse(Message):
    c_param = {
        "device_code": SINGLE_REQUIRED_STRING,
        "user_code": SINGLE_REQUIRED_STRING,
        "verification_uri": SINGLE_REQUIRED_STRING,
        "verification_uri_complete": SINGLE_OPTIONAL_STRING,
        "expires_in": SINGLE_REQUIRED_INT,
        "interval": SINGLE_OPTIONAL_INT,
    }


class AccessTokenRequest(oidc.AccessTokenRequest):
    def verify(self, **kwargs):
        super(AccessTokenRequest, self).verify(**kwargs)

        if "device_code" in self:
            # then both client_id and grant_type MUST be present
            for claim in ["grant_type", "client_id"]:
                if claim not in self:
                    raise MissingRequiredAttribute(claim)
