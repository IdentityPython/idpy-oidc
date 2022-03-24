from idpyoidc.client.oauth2 import access_token
from idpyoidc.client.oidc import userinfo
from idpyoidc.message import SINGLE_OPTIONAL_STRING
from idpyoidc.message import SINGLE_REQUIRED_STRING
from idpyoidc.message import Message
from idpyoidc.message import oauth2
from idpyoidc.message.oauth2 import ResponseMessage


class AccessTokenResponse(Message):
    """
    Access token response
    """
    c_param = {
        "access_token": SINGLE_REQUIRED_STRING,
        "token_type": SINGLE_REQUIRED_STRING,
        "scope": SINGLE_OPTIONAL_STRING
    }


class AccessToken(access_token.AccessToken):
    msg_type = oauth2.AccessTokenRequest
    response_cls = AccessTokenResponse
    error_msg = oauth2.TokenErrorResponse
    response_body_type = 'urlencoded'


class UserInfo(userinfo.UserInfo):
    response_cls = Message
    error_msg = ResponseMessage
    default_authn_method = ''
    http_method = 'GET'
