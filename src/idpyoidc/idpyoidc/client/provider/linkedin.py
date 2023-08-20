from idpyoidc.client.oauth2 import access_token
from idpyoidc.client.oidc import userinfo
from idpyoidc.client.client_auth import get_client_authn_methods
from idpyoidc.message import Message
from idpyoidc.message import SINGLE_OPTIONAL_JSON
from idpyoidc.message import SINGLE_OPTIONAL_STRING
from idpyoidc.message import SINGLE_REQUIRED_INT
from idpyoidc.message import SINGLE_REQUIRED_STRING
from idpyoidc.message import oauth2
from idpyoidc.claims import get_signing_algs


class AccessTokenResponse(Message):
    """
    Access token response
    """

    c_param = {"access_token": SINGLE_REQUIRED_STRING, "expires_in": SINGLE_REQUIRED_INT}


class UserSchema(Message):
    c_param = {
        "firstName": SINGLE_OPTIONAL_STRING,
        "headline": SINGLE_OPTIONAL_STRING,
        "id": SINGLE_REQUIRED_STRING,
        "lastName": SINGLE_OPTIONAL_STRING,
        "siteStandardProfileRequest": SINGLE_OPTIONAL_JSON,
    }


class AccessToken(access_token.AccessToken):
    msg_type = oauth2.AccessTokenRequest
    response_cls = AccessTokenResponse
    error_msg = oauth2.TokenErrorResponse

    _supports = {
        "token_endpoint_auth_methods_supported": get_client_authn_methods,
        "token_endpoint_auth_signing_alg_values_supported": get_signing_algs,
    }


class UserInfo(userinfo.UserInfo):
    response_cls = UserSchema
