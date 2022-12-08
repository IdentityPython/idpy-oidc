from cryptojwt.exception import IssuerNotFound
from cryptojwt.jwk.hmac import SYMKey

from idpyoidc import work_environment


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
            _new = SYMKey(key=_secret)
            try:
                _id_keys = keyjar.get_issuer_keys(id)
            except IssuerNotFound:
                keyjar.add_symmetric(issuer_id=id, key=_secret)
            else:
                if _new not in _id_keys:
                    keyjar.add_symmetric(issuer_id=id, key=_secret)

            try:
                _own_keys = keyjar.get_issuer_keys('')
            except IssuerNotFound:
                keyjar.add_symmetric(issuer_id='', key=_secret)
            else:
                if _new not in _own_keys:
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
