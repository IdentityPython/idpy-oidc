import inspect
import logging
import string
import sys

from idpyoidc import verified_claim_name
from idpyoidc.exception import MissingAttribute
from idpyoidc.exception import VerificationError
from idpyoidc.message import OPTIONAL_LIST_OF_SP_SEP_STRINGS
from idpyoidc.message import OPTIONAL_LIST_OF_STRINGS
from idpyoidc.message import REQUIRED_LIST_OF_SP_SEP_STRINGS
from idpyoidc.message import REQUIRED_LIST_OF_STRINGS
from idpyoidc.message import SINGLE_OPTIONAL_INT
from idpyoidc.message import SINGLE_OPTIONAL_JSON
from idpyoidc.message import SINGLE_OPTIONAL_STRING
from idpyoidc.message import SINGLE_REQUIRED_BOOLEAN
from idpyoidc.message import SINGLE_REQUIRED_INT
from idpyoidc.message import SINGLE_REQUIRED_STRING
from idpyoidc.message import Message

logger = logging.getLogger(__name__)


def is_error_message(msg):
    if "error" in msg:
        return True
    else:
        return False


error_chars = set(string.ascii_uppercase + string.ascii_lowercase + " " + "!")


class ResponseMessage(Message):
    """
    The basic error response
    """

    c_param = {
        "error": SINGLE_OPTIONAL_STRING,
        "error_description": SINGLE_OPTIONAL_STRING,
        "error_uri": SINGLE_OPTIONAL_STRING,
    }

    def verify(self, **kwargs):
        super(ResponseMessage, self).verify(**kwargs)
        if "error_description" in self:
            # Verify that the characters used are within the allow ranges
            # %x20-21 / %x23-5B / %x5D-7E
            if not all(x in error_chars for x in self["error_description"]):
                raise ValueError("Characters outside allowed set")
        return True


class AuthorizationErrorResponse(ResponseMessage):
    """
    Authorization error response.
    """

    c_param = ResponseMessage.c_param.copy()
    c_param.update({"state": SINGLE_OPTIONAL_STRING})
    c_allowed_values = ResponseMessage.c_allowed_values.copy()
    c_allowed_values.update(
        {
            "error": [
                "invalid_request",
                "unauthorized_client",
                "access_denied",
                "unsupported_response_type",
                "invalid_scope",
                "server_error",
                "temporarily_unavailable",
            ]
        }
    )


class TokenErrorResponse(ResponseMessage):
    """
    Error response from the token endpoint
    """

    c_allowed_values = {
        "error": [
            "invalid_request",
            "invalid_client",
            "invalid_grant",
            "unauthorized_client",
            "unsupported_grant_type",
            "invalid_scope",
        ]
    }


class AccessTokenRequest(Message):
    """
    An access token request
    """

    c_param = {
        "grant_type": SINGLE_REQUIRED_STRING,
        "code": SINGLE_REQUIRED_STRING,
        "redirect_uri": SINGLE_REQUIRED_STRING,
        "client_id": SINGLE_OPTIONAL_STRING,
        "client_secret": SINGLE_OPTIONAL_STRING,
        "state": SINGLE_OPTIONAL_STRING,
    }
    c_default = {"grant_type": "authorization_code"}


class AuthorizationRequest(Message):
    """
    An authorization request
    """

    c_param = {
        "response_type": REQUIRED_LIST_OF_SP_SEP_STRINGS,
        "client_id": SINGLE_REQUIRED_STRING,
        "scope": OPTIONAL_LIST_OF_SP_SEP_STRINGS,
        "redirect_uri": SINGLE_OPTIONAL_STRING,
        "state": SINGLE_OPTIONAL_STRING,
    }

    def merge(self, request_object, treatement="strict", whitelist=None):
        """
        How to combine parameter that appear in the request with parameters that
        appear in the request object.

        :param request: The original request
        :param request_object: The result of parsing the request/request_uri parameter
        :param treatement: How to do the merge strict/lax/whitelist
        :param whitelist: If whitelisted parameters from the request should be included in the
            result, this is the list to use.
        """

        if treatement == "strict":
            params = list(self.keys())
            # remove all parameters in request that does not appear in request_object
            for param in params:
                if param not in request_object:
                    del self[param]
        elif treatement == "lax":
            pass
        elif treatement == "whitelist" and whitelist:
            params = list(self.keys())
            for param in params:
                if param not in whitelist:
                    del self[param]

        self.update(request_object)


class AuthorizationResponse(ResponseMessage):
    """
    An authorization response.
    If *client_id* is returned in the response it will be checked against
    a client_id value provided when calling the verify method.
    The same with *iss* (issuer).
    """

    c_param = ResponseMessage.c_param.copy()
    c_param.update(
        {
            "code": SINGLE_REQUIRED_STRING,
            "state": SINGLE_OPTIONAL_STRING,
            "iss": SINGLE_OPTIONAL_STRING,
            "client_id": SINGLE_OPTIONAL_STRING,
        }
    )

    def verify(self, **kwargs):
        super(AuthorizationResponse, self).verify(**kwargs)

        if "client_id" in self:
            try:
                if self["client_id"] != kwargs["client_id"]:
                    raise VerificationError("client_id mismatch")
            except KeyError:
                logger.info("No client_id to verify against")
                pass
        if "iss" in self:
            try:
                # Issuer URL for the authorization server issuing the response.
                if self["iss"] != kwargs["iss"]:
                    raise VerificationError("Issuer mismatch")
            except KeyError:
                logger.info("No issuer set in the Client config")
                pass

        return True


class AccessTokenResponse(ResponseMessage):
    """
    Access token response
    """

    c_param = ResponseMessage.c_param.copy()
    c_param.update(
        {
            "access_token": SINGLE_REQUIRED_STRING,
            "token_type": SINGLE_REQUIRED_STRING,
            "expires_in": SINGLE_OPTIONAL_INT,
            "refresh_token": SINGLE_OPTIONAL_STRING,
            "scope": OPTIONAL_LIST_OF_SP_SEP_STRINGS,
            "state": SINGLE_OPTIONAL_STRING,
        }
    )


class NoneResponse(ResponseMessage):
    c_param = ResponseMessage.c_param.copy()
    c_param.update({"state": SINGLE_OPTIONAL_STRING})


class ROPCAccessTokenRequest(Message):
    """
    Resource Owner Password Credentials Grant flow access token request
    """

    c_param = {
        "grant_type": SINGLE_REQUIRED_STRING,
        "username": SINGLE_OPTIONAL_STRING,
        "password": SINGLE_OPTIONAL_STRING,
        "scope": OPTIONAL_LIST_OF_SP_SEP_STRINGS,
    }


class CCAccessTokenRequest(Message):
    """
    Client Credential grant flow access token request
    """

    c_param = {"grant_type": SINGLE_REQUIRED_STRING, "scope": OPTIONAL_LIST_OF_SP_SEP_STRINGS}
    c_default = {"grant_type": "client_credentials"}
    c_allowed_values = {"grant_type": ["client_credentials"]}


class RefreshAccessTokenRequest(Message):
    """
    Access token refresh request
    """

    c_param = {
        "grant_type": SINGLE_REQUIRED_STRING,
        "refresh_token": SINGLE_REQUIRED_STRING,
        "scope": OPTIONAL_LIST_OF_SP_SEP_STRINGS,
        "client_id": SINGLE_OPTIONAL_STRING,
        "client_secret": SINGLE_OPTIONAL_STRING,
    }
    c_default = {"grant_type": "refresh_token"}
    c_allowed_values = {"grant_type": ["refresh_token"]}


class ResourceRequest(Message):
    c_param = {"access_token": SINGLE_OPTIONAL_STRING}


class ASConfigurationResponse(Message):
    """
    Authorization Server configuration response
    """

    c_param = ResponseMessage.c_param.copy()
    c_param.update(
        {
            "issuer": SINGLE_REQUIRED_STRING,
            "authorization_endpoint": SINGLE_OPTIONAL_STRING,
            "token_endpoint": SINGLE_OPTIONAL_STRING,
            "jwks_uri": SINGLE_OPTIONAL_STRING,
            "registration_endpoint": SINGLE_OPTIONAL_STRING,
            "scopes_supported": OPTIONAL_LIST_OF_STRINGS,
            "response_types_supported": REQUIRED_LIST_OF_STRINGS,
            "response_modes_supported": OPTIONAL_LIST_OF_STRINGS,
            "grant_types_supported": REQUIRED_LIST_OF_STRINGS,
            "token_endpoint_auth_methods_supported": OPTIONAL_LIST_OF_STRINGS,
            "token_endpoint_auth_signing_alg_values_supported": OPTIONAL_LIST_OF_STRINGS,
            "service_documentation": SINGLE_OPTIONAL_STRING,
            "ui_locales_supported": OPTIONAL_LIST_OF_STRINGS,
            "op_policy_uri": SINGLE_OPTIONAL_STRING,
            "op_tos_uri": SINGLE_OPTIONAL_STRING,
            "revocation_endpoint": SINGLE_OPTIONAL_STRING,
            "introspection_endpoint": SINGLE_OPTIONAL_STRING,
        }
    )
    c_default = {"version": "3.0"}


# RFC 7662
class TokenIntrospectionRequest(Message):
    c_param = {
        "token": SINGLE_REQUIRED_STRING,
        "token_type_hint": SINGLE_OPTIONAL_STRING,
        # The ones below are part of authentication information
        "client_id": SINGLE_OPTIONAL_STRING,
        "client_assertion_type": SINGLE_OPTIONAL_STRING,
        "client_assertion": SINGLE_OPTIONAL_STRING,
    }


class TokenIntrospectionResponse(Message):
    c_param = {
        "active": SINGLE_REQUIRED_BOOLEAN,
        "scope": OPTIONAL_LIST_OF_SP_SEP_STRINGS,
        "client_id": SINGLE_OPTIONAL_STRING,
        "username": SINGLE_OPTIONAL_STRING,
        "token_type": SINGLE_OPTIONAL_STRING,
        "exp": SINGLE_OPTIONAL_INT,
        "iat": SINGLE_OPTIONAL_INT,
        "nbf": SINGLE_OPTIONAL_INT,
        "sub": SINGLE_OPTIONAL_STRING,
        "aud": OPTIONAL_LIST_OF_STRINGS,
        "iss": SINGLE_OPTIONAL_STRING,
        "jti": SINGLE_OPTIONAL_STRING,
    }


# RFC 8693
class TokenExchangeRequest(Message):
    c_param = {
        "grant_type": SINGLE_REQUIRED_STRING,
        "resource": OPTIONAL_LIST_OF_STRINGS,
        "audience": OPTIONAL_LIST_OF_STRINGS,
        "scope": OPTIONAL_LIST_OF_SP_SEP_STRINGS,
        "requested_token_type": SINGLE_OPTIONAL_STRING,
        "subject_token": SINGLE_REQUIRED_STRING,
        "subject_token_type": SINGLE_REQUIRED_STRING,
        "actor_token": SINGLE_OPTIONAL_STRING,
        "actor_token_type": SINGLE_OPTIONAL_STRING,
    }


class TokenExchangeResponse(Message):
    c_param = {
        "access_token": SINGLE_REQUIRED_STRING,
        "issued_token_type": SINGLE_REQUIRED_STRING,
        "token_type": SINGLE_REQUIRED_STRING,
        "expires_in": SINGLE_OPTIONAL_INT,
        "refresh_token": SINGLE_OPTIONAL_STRING,
        "scope": OPTIONAL_LIST_OF_SP_SEP_STRINGS,
    }


class JWTSecuredAuthorizationRequest(AuthorizationRequest):
    c_param = AuthorizationRequest.c_param.copy()
    c_param.update({"request": SINGLE_OPTIONAL_STRING, "request_uri": SINGLE_OPTIONAL_STRING})

    def verify(self, **kwargs):
        if "request" in self:
            _vc_name = verified_claim_name("request")
            if _vc_name in self:
                del self[_vc_name]

            args = {}
            for arg in ["keyjar", "opponent_id", "sender", "alg", "encalg", "encenc"]:
                try:
                    args[arg] = kwargs[arg]
                except KeyError:
                    pass

            _req = AuthorizationRequest().from_jwt(str(self["request"]), **args)
            self.merge(_req, "strict")
            self[_vc_name] = _req
        elif "request_uri" not in self:
            raise MissingAttribute("One of request or request_uri must be present")

        return True


class PushedAuthorizationRequest(AuthorizationRequest):
    c_param = AuthorizationRequest.c_param.copy()
    c_param.update({"request": SINGLE_OPTIONAL_STRING})

    def verify(self, **kwargs):
        if "request" in self:
            _vc_name = verified_claim_name("request")
            if _vc_name in self:
                del self[_vc_name]

            args = {}
            for arg in ["keyjar", "opponent_id", "sender", "alg", "encalg", "encenc"]:
                try:
                    args[arg] = kwargs[arg]
                except KeyError:
                    pass

            _req = AuthorizationRequest().from_jwt(str(self["request"]), **args)
            self.merge(_req, "lax")
            self[_vc_name] = _req

        return True


class SecurityEventToken(Message):
    c_param = {
        "iss": SINGLE_REQUIRED_STRING,
        "iat": SINGLE_REQUIRED_INT,
        "jti": SINGLE_REQUIRED_STRING,
        "aud": OPTIONAL_LIST_OF_STRINGS,
        "sub": SINGLE_OPTIONAL_STRING,
        "exp": SINGLE_OPTIONAL_INT,
        "events": SINGLE_OPTIONAL_JSON,
        "txt": SINGLE_OPTIONAL_STRING,
        "toe": SINGLE_OPTIONAL_INT,
    }


def factory(msgtype, **kwargs):
    """
    Factory method that can be used to easily instansiate a class instance

    :param msgtype: The name of the class
    :param kwargs: Keyword arguments
    :return: An instance of the class or None if the name doesn't match any
        known class.
    """
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj) and issubclass(obj, Message):
            try:
                if obj.__name__ == msgtype:
                    return obj(**kwargs)
            except AttributeError:
                pass
