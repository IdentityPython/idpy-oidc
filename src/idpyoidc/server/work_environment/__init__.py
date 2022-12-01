from idpyoidc.message.oidc import ProviderConfigurationResponse
from idpyoidc.server.client_authn import CLIENT_AUTHN_METHOD


def get_client_authn_methods():
    return list(CLIENT_AUTHN_METHOD.keys())


