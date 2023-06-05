import logging

from idpyoidc.server.oauth2.token_helper.token_exchange import \
    TokenExchangeHelper as OAuth2TokenExchangeHelper

logger = logging.getLogger(__name__)


class TokenExchangeHelper(OAuth2TokenExchangeHelper):
    token_types_mapping = {
        "urn:ietf:params:oauth:token-type:access_token": "access_token",
        "urn:ietf:params:oauth:token-type:refresh_token": "refresh_token",
        "urn:ietf:params:oauth:token-type:id_token": "id_token",
    }
