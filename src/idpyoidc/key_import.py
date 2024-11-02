import json
from typing import List
from typing import Optional

from cryptojwt import JWK
from cryptojwt import KeyBundle
from cryptojwt import KeyJar
from cryptojwt.jwk.hmac import SYMKey
from cryptojwt.jwk.jwk import key_from_jwk_dict


def issuer_keys(keyjar: KeyJar, entity_id: str, format: Optional[str] = "jwk"):
    # sort of copying the functionality in KeyJar.get_issuer_keys()
    key_issuer = keyjar.return_issuer(entity_id)
    if format == "jwk":
        return [k.serialize() for k in key_issuer.all_keys()]
    else:
        return [k for k in key_issuer.all_keys()]


def import_jwks(keyjar: KeyJar, jwks: dict, entity_id: Optional[str] = "") -> KeyJar:
    keys = []
    jar = issuer_keys(keyjar, entity_id)
    for jwk in jwks["keys"]:
        if jwk not in jar:
            jar.append(jwk)
            key = key_from_jwk_dict(jwk)
            keys.append(key)
    if keys:
        keyjar.add_keys(entity_id, keys)
    return keyjar


def import_jwks_as_json(keyjar: KeyJar, jwks: str, entity_id: Optional[str] = "") -> KeyJar:
    return import_jwks(keyjar, json.loads(jwks), entity_id)


def import_jwks_from_file(keyjar: KeyJar, filename: str, entity_id) -> KeyJar:
    with open(filename) as jwks_file:
        keyjar = import_jwks_as_json(keyjar, jwks_file.read(), entity_id)
    return keyjar


def add_kb(keyjar: KeyJar, key_bundle: KeyBundle, entity_id: str) -> KeyJar:
    return import_jwks(keyjar, json.loads(key_bundle.jwks()), entity_id)


def add_symmetric(keyjar: KeyJar, key: str, entity_id: Optional[str] = "") -> KeyJar:
    jar = issuer_keys(keyjar, entity_id)
    _sym_key = SYMKey(key=key)

    jwk = _sym_key.serialize()
    if jwk not in jar:
        keyjar.add_symmetric(entity_id, key)
    return keyjar


def store_under_other_id(keyjar: KeyJar, fro: Optional[str] = "", to: Optional[str] = "",
                         private: Optional[bool] = False) -> KeyJar:
    if fro == to:
        return keyjar
    else:
        return import_jwks(keyjar, keyjar.export_jwks(private, fro), to)


def add_keys(keyjar:KeyJar, keys: List[JWK], entity_id) -> KeyJar:
    _keys = []
    jar = issuer_keys(keyjar, entity_id)
    for key in keys:
        jwk = key.serialize()
        if jwk not in jar:
            jar.append(jwk)
            _keys.append(key)
    if _keys:
        keyjar.add_keys(entity_id, _keys)
    return keyjar
