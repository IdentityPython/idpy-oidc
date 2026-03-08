from typing import Optional

from cryptojwt import KeyJar
from cryptojwt.exception import IssuerNotFound
from cryptojwt.jwk.hmac import SYMKey

from idpyoidc import claims
from idpyoidc.client.client_auth import CLIENT_AUTHN_METHOD


def get_client_authn_methods():
    return list(CLIENT_AUTHN_METHOD.keys())


class Claims(claims.Claims):
    _supports = {}

    def get_base_url(self, configuration: dict, entity_id: Optional[str] = ""):
        _base = configuration.get("base_url", None)
        if not _base:
            if entity_id:
                _base = entity_id
            else:
                _base = configuration.get("entity_id", configuration.get("client_id", ""))

        if not _base:
            raise ValueError("Missing client_id/entity_id/base_url in configuration")
        elif not _base.startswith("https://"):
            raise ValueError("Need client_id/entity_id to be a URL")

        return _base

    def get_id(self, configuration: dict):
        return self.get_preference("client_id", "")

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
        return keyjar
