from cryptojwt import KeyBundle
from cryptojwt.key_bundle import build_key_bundle
from cryptojwt.utils import qualified_name

from idpyoidc.item import DLDict

KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

KEYSPEC_2 = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
    {"type": "EC", "crv": "P-384", "use": ["sig"]},
]


def test_dl_dict():
    _dict = DLDict()
    _kb1 = build_key_bundle(key_conf=KEYSPEC)
    _dict["a"] = _kb1
    _kb2 = build_key_bundle(key_conf=KEYSPEC_2)
    _dict["b"] = _kb2

    dump = _dict.dump()

    _dict_copy = DLDict().load(dump)

    assert set(_dict_copy.keys()) == {"a", "b"}

    kb1_copy = _dict_copy["a"]
    assert len(kb1_copy.keys()) == 2
