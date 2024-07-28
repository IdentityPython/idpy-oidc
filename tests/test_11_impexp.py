from cryptojwt import KeyBundle
from cryptojwt.key_bundle import build_key_bundle

from idpyoidc.impexp import ImpExp
from idpyoidc.message.oauth2 import AuthorizationResponse
from idpyoidc.message.oidc import AuthorizationRequest

KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]


class ImpExpTest(ImpExp):
    parameter = {
        "string": "",
        "list": [],
        "dict": {},
        "message": AuthorizationRequest,
        "response_class": object,
        "key_bundle": KeyBundle,
        "bundles": [KeyBundle],
    }


def test_dump_load():
    b = ImpExpTest()
    b.string = "foo"
    b.list = ["a", "b", "c"]
    b.dict = {"a": 1, "b": 2}
    b.message = AuthorizationRequest(
        scope="openid",
        redirect_uri="https://example.com/cb",
        response_type="code",
        client_id="abcdefg",
    )
    b.response_class = AuthorizationResponse
    b.key_bundle = build_key_bundle(key_conf=KEYSPEC)
    b.bundles = [build_key_bundle(key_conf=KEYSPEC)]
    b.bundles.append(build_key_bundle(key_conf=KEYSPEC))

    dump = b.dump()

    b_copy = ImpExpTest().load(dump)
    assert b_copy
    assert b_copy.list == b.list
    assert b_copy.dict == b.dict
    # Message doesn't implement __eq__
    assert b_copy.message.__class__ == b.message.__class__
    assert b_copy.response_class == b.response_class
    # KeyBundle doesn't implement __eq__
    assert b_copy.key_bundle.keys() == b.key_bundle.keys()
    assert len(b_copy.bundles) == 2
    for kb in b_copy.bundles:
        assert isinstance(kb, KeyBundle)


def test_flush():
    b = ImpExpTest()
    b.string = "foo"
    b.list = ["a", "b", "c"]
    b.dict = {"a": 1, "b": 2}
    b.message = AuthorizationRequest(
        scope="openid",
        redirect_uri="https://example.com/cb",
        response_type="code",
        client_id="abcdefg",
    )
    b.response_class = AuthorizationResponse
    b.key_bundle = build_key_bundle(key_conf=KEYSPEC)
    b.bundles = [build_key_bundle(key_conf=KEYSPEC)]
    b.bundles.append(build_key_bundle(key_conf=KEYSPEC))

    dump = b.dump()

    b.flush()

    assert b.string == ""
    assert b.list == []
    assert b.dict == {}
    assert b.message is None
    assert b.response_class is None
    assert b.key_bundle is None
    assert b.bundles is None

    b.load(dump)

    assert b.string == "foo"
    assert b.list == ["a", "b", "c"]
    assert b.dict == {"a": 1, "b": 2}
    assert isinstance(b.message, AuthorizationRequest)
    assert b.response_class == AuthorizationResponse
    assert isinstance(b.key_bundle, KeyBundle)
    assert len(b.bundles) == 2
    for kb in b.bundles:
        assert isinstance(kb, KeyBundle)


def test_dict():
    b = ImpExpTest()
    b.string = "foo"
    b.list = ["a", "b", "c"]
    b.dict = {"a": 1, "b": 2}
    b.message = {
        "scope": "openid",
        "redirect_uri": "https://example.com/cb",
        "response_type": "code",
        "client_id": "abcdefg",
    }

    dump = b.dump()

    b.flush()

    b.load(dump)

    assert b.string == "foo"
    assert b.list == ["a", "b", "c"]
    assert b.dict == {"a": 1, "b": 2}
    assert isinstance(b.message, AuthorizationRequest)
