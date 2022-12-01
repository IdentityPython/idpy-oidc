from idpyoidc.client.client_auth import CLIENT_AUTHN_METHOD


def get_client_authn_methods():
    return list(CLIENT_AUTHN_METHOD.keys())
