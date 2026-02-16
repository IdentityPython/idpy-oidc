CLIENT_ID = 'client'

CLIENT_CONFIG = {
    "client_secret": "SUPERhemligtlösenord",
    "client_id": CLIENT_ID,
    "redirect_uris": ["https://client.example.com/cb"],
    "token_endpoint_auth_methods_supported": ["client_secret_post"],
    "response_types_supported": ["code"],
    "allowed_scopes": ["foobar", "openid"],
    'base_url': 'https://client.example.com',
    "services": {
        "provider_info": {
            "class": "idpyoidc.client.oidc.provider_info_discovery.ProviderInfoDiscovery"},
        "authorization": {"class": "idpyoidc.client.oidc.authorization.Authorization"},
        "access_token": {"class": "idpyoidc.client.oidc.access_token.AccessToken"},
        'userinfo': {'class': "idpyoidc.client.oidc.userinfo.UserInfo"}
    }
}
