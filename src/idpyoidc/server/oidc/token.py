import logging

from idpyoidc import metadata
from idpyoidc.message import Message
from idpyoidc.message import oidc
from idpyoidc.message.oidc import TokenErrorResponse
from idpyoidc.server.oauth2 import token
from idpyoidc.server.oidc.backchannel_authentication import CIBATokenHelper
from idpyoidc.server.oidc.token_helper.access_token import AccessTokenHelper
from idpyoidc.server.oidc.token_helper.refresh_token import RefreshTokenHelper
from idpyoidc.server.oidc.token_helper.token_exchange import TokenExchangeHelper

logger = logging.getLogger(__name__)


class Token(token.Token):
    request_cls = Message
    response_cls = oidc.AccessTokenResponse
    error_cls = TokenErrorResponse
    request_format = "urlencoded"
    request_placement = "body"
    response_format = "json"
    response_placement = "body"
    endpoint_name = "token_endpoint"
    name = "token"
    default_capabilities = None

    helper_by_grant_type = {
        "authorization_code": AccessTokenHelper,
        "refresh_token": RefreshTokenHelper,
        "urn:openid:params:grant-type:ciba": CIBATokenHelper,
        "urn:ietf:params:oauth:grant-type:token-exchange": TokenExchangeHelper,
    }

    _supports = {
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
            "client_secret_basic",
            "client_secret_jwt",
            "private_key_jwt",
        ],
        "token_endpoint_auth_signing_alg_values_supported": metadata.get_signing_algs(),
        "grant_types_supported": list(helper_by_grant_type.keys()),
    }

    token_exchange_helper = TokenExchangeHelper
