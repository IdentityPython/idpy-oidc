from cryptojwt.exception import IssuerNotFound
from cryptojwt.jwk.hmac import SYMKey

from idpyoidc import work_environment
from idpyoidc.client.client_auth import CLIENT_AUTHN_METHOD


def get_client_authn_methods():
    return list(CLIENT_AUTHN_METHOD.keys())


class WorkEnvironment(work_environment.WorkEnvironment):

    def get_base_url(self, configuration: dict):
        _base = configuration.get('base_url')
        if not _base:
            _base = configuration.get('client_id')

        return _base

    def get_id(self, configuration: dict):
        return self.get_preference('client_id')

    def add_extra_keys(self, keyjar, id):
        _secret = self.get_preference('client_secret')
        if _secret:
            keyjar.add_symmetric(issuer_id=id, key=_secret)
            keyjar.add_symmetric(issuer_id='', key=_secret)

    def get_jwks(self, keyjar):
        _jwks = None
        try:
            _own_keys = keyjar.get_issuer_keys('')
        except IssuerNotFound:
            pass
        else:
            if len(_own_keys) == 1 and isinstance(_own_keys[0], SYMKey):
                pass
            else:
                _jwks = keyjar.export_jwks()

        return _jwks
