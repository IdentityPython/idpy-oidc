from idpyoidc.client.oauth2 import refresh_access_token
from idpyoidc.message import oidc


class RefreshAccessToken(refresh_access_token.RefreshAccessToken):
    msg_type = oidc.RefreshAccessTokenRequest
    response_cls = oidc.AccessTokenResponse
    error_msg = oidc.ResponseMessage

    def get_authn_method(self):
        _work_environment = self.superior_get("context").work_environment
        try:
            return _work_environment.get_usage("token_endpoint_auth_method")
        except KeyError:
            return self.default_authn_method
