from functools import cmp_to_key
import logging

from cryptojwt.jwe import DEPRECATED
from cryptojwt.jwe import SUPPORTED
from cryptojwt.jws.jws import SIGNER_ALGS

logger = logging.getLogger(__name__)

SIGNING_ALGORITHM_SORT_ORDER = ["RS", "ES", "PS", "HS", "Ed"]


def alg_cmp(a, b):
    """ Should algorithm 'a' be sorted before (==1) algorithm 'b'"""
    if a == "none":
        if b != "none":
            return 1
        else:
            return 0
    elif b == "none":
        return -1

    _pos1 = SIGNING_ALGORITHM_SORT_ORDER.index(a[0:2])
    _pos2 = SIGNING_ALGORITHM_SORT_ORDER.index(b[0:2])
    if _pos1 == _pos2:
        if a[2:] < b[2:]:
            return 1
        elif a[2:] == b[2:]:
            return 0
        else:
            return -1
    elif _pos1 > _pos2:
        return 1
    else:
        return -1


def get_signing_algs():
    # Assumes Cryptojwt
    _algs = [name for name in list(SIGNER_ALGS.keys()) if
             name != "none" and name not in DEPRECATED["alg"]]
    return sorted(_algs, key=cmp_to_key(alg_cmp))


def get_encryption_algs():
    return SUPPORTED["alg"]


def get_encryption_encs():
    return SUPPORTED["enc"]


def array_or_singleton(claim_spec, values):
    if isinstance(claim_spec[0], list):
        if isinstance(values, list):
            return values
        else:
            return [values]
    else:
        if isinstance(values, list):
            return values[0]
        else:  # singleton
            return values
