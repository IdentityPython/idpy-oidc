from typing import List

from cryptojwt import JWK
from cryptojwt import KeyJar


def keyjar_union(kj1, kj2):
    if kj2 is None:
        return kj1
    elif kj1 is None:
        return kj2

    _owners = set(kj1.owners())
    _owners.update(set(kj2.owners()))

    res = KeyJar()
    for owner in _owners:
        if owner in kj1:
            _keys = kj1.get_issuer_keys(owner)
            if owner in kj2:
                for k in kj2.get_issuer_keys(owner):
                    if k not in _keys:
                        _keys.append(k)
        else:
            _keys = kj2.get_issuer_keys(owner)
        res.add_keys(owner, _keys)
    return res


def keyjar_intersection(kj1, kj2):
    _owners = set(kj1.owners())
    _owners = _owners.intersection(set(kj2.owners()))

    res = KeyJar()
    if _owners is []:
        return res

    for owner in _owners:
        common_keys = []
        if owner in kj1:
            _keys = kj1.get_issuer_keys(owner)
            if owner in kj2:
                for k in kj2.get_issuer_keys(owner):
                    if k in _keys:
                        common_keys.append(k)
        if common_keys:
            res.add_keys(owner, common_keys)
    return res


def to_local_from_foreign(receiver, sender, issuer_id) -> List[JWK]:
    """
    Collects all keys that are stored as local (issuer_id='') and represents them as keys belonging to <issuer_id>

    :param kj1:
    :param kj2:
    :param issuer_id:
    :return:
    """
    keys_to_add = []

    if issuer_id in receiver:
        already_got = receiver.get_issuer_keys(issuer_id)
    else:
        already_got = []

    if '' in sender:
        for k in sender.get_issuer_keys(''):
            if k not in already_got:
                keys_to_add.append(k)

    return keys_to_add

