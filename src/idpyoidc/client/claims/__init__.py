from typing import Optional

from cryptojwt import KeyJar
from cryptojwt.exception import IssuerNotFound
from cryptojwt.jwk.hmac import SYMKey

from idpyoidc import claims
from idpyoidc.client.client_auth import CLIENT_AUTHN_METHOD


def get_client_authn_methods():
    return list(CLIENT_AUTHN_METHOD.keys())


class Claims(claims.Claims):
    def get_base_url(self, configuration: dict, entity_id: Optional[str] = ""):
        _base = configuration.get("base_url")
        if not _base:
            _base = configuration.get("client_id", configuration.get("entity_id"))

        return _base

    def get_id(self, configuration: dict):
        return self.get_preference("client_id")

    def _add_key_if_missing(self, keyjar, id, key):
        try:
            old_keys = keyjar.get_issuer_keys(id)
        except IssuerNotFound:
            old_keys = []

        _new_key = SYMKey(key=key)
        if _new_key not in old_keys:
            keyjar.add_symmetric(issuer_id=id, key=key)

    def add_extra_keys(self, keyjar, id):
        _secret = self.get_preference("client_secret")
        if _secret:
            if keyjar is None:
                keyjar = KeyJar()
            self._add_key_if_missing(keyjar, id, _secret)
            self._add_key_if_missing(keyjar, "", _secret)

    def get_jwks(self, keyjar):
        if keyjar is None:
            return None

        _jwks = None
        try:
            _own_keys = keyjar.get_issuer_keys("")
        except IssuerNotFound:
            pass
        else:
            # if only one key under the id == "", that key being a SYMKey I assume it's
            # and I have a client_secret then don't publish a JWKS
            if (
                len(_own_keys) == 1
                and isinstance(_own_keys[0], SYMKey)
                and self.prefer["client_secret"]
            ):
                pass
            else:
                _jwks = keyjar.export_jwks()

        return _jwks
