CLIENT_ID = 'client'

CLIENT_CONFIG = {
    "client_secret": "SUPERhemligtlösenord",
    "client_id": CLIENT_ID,
    "redirect_uris": ["https://example.com/cb"],
    "token_endpoint_auth_methods_supported": ["client_secret_post"],
    "response_types_supported": ["code"],
    "services": {
        "metadata": {"class": "idpyoidc.client.oauth2.server_metadata.ServerMetadata"},
        "authorization": {"class": "idpyoidc.client.oauth2.authorization.Authorization"},
        "access_token": {"class": "idpyoidc.client.oauth2.access_token.AccessToken"},
    }
}
