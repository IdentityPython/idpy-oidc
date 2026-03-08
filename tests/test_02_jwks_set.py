from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.rsa import RSAKey
from cryptojwt.key_jar import init_key_jar

from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.jwks_set import keyjar_intersection
from idpyoidc.jwks_set import keyjar_union
from idpyoidc.jwks_set import to_local_from_foreign


def test_jwks_set():
    keyjar_1 = init_key_jar(key_defs=DEFAULT_KEY_DEFS)
    keyjar_2 = init_key_jar(key_defs=DEFAULT_KEY_DEFS)

    res = keyjar_union(keyjar_1, keyjar_2)

    assert res.owners() == [""]
    assert len(res.get_signing_key(key_type="rsa")) == 2
    assert len(res.get_signing_key(key_type="ec")) == 2


def test_jwks_union2():
    keyjar_1 = init_key_jar(key_defs=DEFAULT_KEY_DEFS)
    keyjar_1.import_jwks(keyjar_1.export_jwks(issuer_id=""), "https://example.com")

    keyjar_2 = init_key_jar(key_defs=DEFAULT_KEY_DEFS)

    res = keyjar_union(keyjar_1, keyjar_2)

    assert res.owners() == ["", "https://example.com"]
    assert len(res.get_signing_key(key_type="rsa", issuer_id='')) == 2
    assert len(res.get_signing_key(key_type="ec", issuer_id='')) == 2
    assert len(res.get_signing_key(key_type="rsa", issuer_id='https://example.com')) == 1
    assert len(res.get_signing_key(key_type="ec", issuer_id='https://example.com')) == 1


def test_jwks_union3():
    keyjar_1 = init_key_jar(key_defs=DEFAULT_KEY_DEFS)
    keyjar_1.import_jwks(keyjar_1.export_jwks(issuer_id=""), "https://example.com")
    keyjar_1.add_symmetric(issuer_id="https://example.com", key="super.dumper.secret.key", usage=['sig', 'enc'])
    keyjar_1.add_symmetric(issuer_id="", key="super.dumper.secret.key", usage=['sig', 'enc'])

    keyjar_2 = init_key_jar(key_defs=DEFAULT_KEY_DEFS)

    res = keyjar_union(keyjar_1, keyjar_2)

    assert res.owners() == ["", "https://example.com"]
    assert len(res.get_signing_key(key_type="rsa", issuer_id='')) == 2
    assert len(res.get_signing_key(key_type="rsa", issuer_id='https://example.com')) == 1

    assert len(res.get_signing_key(key_type="ec", issuer_id='')) == 2
    assert len(res.get_signing_key(key_type="ec", issuer_id='https://example.com')) == 1

    assert len(res.get_signing_key(key_type="oct", issuer_id='')) == 1
    assert len(res.get_signing_key(key_type="oct", issuer_id='https://example.com')) == 1


def test_jwks_union4():
    keyjar_1 = init_key_jar(key_defs=DEFAULT_KEY_DEFS)
    keyjar_1.import_jwks(keyjar_1.export_jwks(issuer_id=""), "https://example.com")
    keyjar_1.add_symmetric(issuer_id="https://example.com", key="super.dumper.secret.key", usage=['sig', 'enc'])
    keyjar_1.add_symmetric(issuer_id="", key="super.dumper.secret.key", usage=['sig', 'enc'])

    keyjar_2 = init_key_jar(key_defs=DEFAULT_KEY_DEFS)
    keyjar_2.add_symmetric(issuer_id="https://example.com", key="super.dumper.secret.key", usage=['sig', 'enc'])

    res = keyjar_union(keyjar_1, keyjar_2)

    assert res.owners() == ["", "https://example.com"]
    assert len(res.get_signing_key(key_type="rsa", issuer_id='')) == 2
    assert len(res.get_signing_key(key_type="rsa", issuer_id='https://example.com')) == 1

    assert len(res.get_signing_key(key_type="ec", issuer_id='')) == 2
    assert len(res.get_signing_key(key_type="ec", issuer_id='https://example.com')) == 1

    assert len(res.get_signing_key(key_type="oct", issuer_id='')) == 1
    assert len(res.get_signing_key(key_type="oct", issuer_id='https://example.com')) == 1


def test_jwks_intersection():
    keyjar_1 = init_key_jar(key_defs=DEFAULT_KEY_DEFS)
    keyjar_2 = init_key_jar(key_defs=DEFAULT_KEY_DEFS)

    res = keyjar_intersection(keyjar_1, keyjar_2)

    assert res.owners() == []


def test_jwks_intersection2():
    keyjar_1 = init_key_jar(key_defs=DEFAULT_KEY_DEFS)
    keyjar_1.add_symmetric(issuer_id="https://example.com", key="super.dumper.secret.key", usage=['sig', 'enc'])
    keyjar_2 = init_key_jar(key_defs=DEFAULT_KEY_DEFS)
    keyjar_2.add_symmetric(issuer_id="https://example.com", key="super.dumper.secret.key", usage=['sig', 'enc'])

    res = keyjar_intersection(keyjar_1, keyjar_2)

    assert res.owners() == ["https://example.com"]
    assert len(res.get_signing_key(key_type="rsa", issuer_id='https://example.com')) == 0
    assert len(res.get_signing_key(key_type="ec", issuer_id='https://example.com')) == 0
    assert len(res.get_signing_key(key_type="oct", issuer_id='https://example.com')) == 1


def test_jwks_intersection3():
    keyjar_1 = init_key_jar(key_defs=DEFAULT_KEY_DEFS)
    keyjar_2 = init_key_jar(key_defs=DEFAULT_KEY_DEFS)

    keyjar_2.import_jwks(keyjar_1.export_jwks(issuer_id=""), "https://example.com")

    res = keyjar_intersection(keyjar_1, keyjar_2)

    assert len(res.get_signing_key(key_type="rsa", issuer_id='https://example.com')) == 0
    assert len(res.get_signing_key(key_type="ec", issuer_id='https://example.com')) == 0
    assert len(res.get_signing_key(key_type="oct", issuer_id='https://example.com')) == 0


def test_local_to_foreign():
    keyjar_1 = init_key_jar(key_defs=DEFAULT_KEY_DEFS)
    keyjar_2 = init_key_jar(key_defs=DEFAULT_KEY_DEFS)

    res = to_local_from_foreign(keyjar_1, keyjar_2, "https://example.com")
    assert len(res) == 2
    assert len([k for k in res if isinstance(k, RSAKey)]) == 1
    assert len([k for k in res if isinstance(k, ECKey)]) == 1

    assert len([k for k in res if k.has_private_key()]) == 2


def test_local_to_foreign2():
    keyjar_1 = init_key_jar(key_defs=DEFAULT_KEY_DEFS)
    keyjar_2 = init_key_jar(key_defs=DEFAULT_KEY_DEFS)

    res = to_local_from_foreign(keyjar_1, keyjar_2, "https://example.com")
    assert len(res) == 2
    for k in res:
        k.private_key = None

    # Added the missing keys
    keyjar_1.add_keys("https://example.com", res)

    # Should be no more to add
    res = to_local_from_foreign(keyjar_1, keyjar_2, "https://example.com")
    assert len(res) == 0
