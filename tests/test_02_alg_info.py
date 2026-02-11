# from idpyoidc.alg_info import is_subset
from idpyoidc.alg_info import alg_cmp
from idpyoidc.alg_info import array_or_singleton
from idpyoidc.message import OPTIONAL_ANY_LIST
from idpyoidc.message import SINGLE_OPTIONAL_ANY


def test_array_or_singleton_list():
    claim_spec = OPTIONAL_ANY_LIST
    res = array_or_singleton(claim_spec, ["foo", "bar", "baz"])
    assert res == ["foo", "bar", "baz"]
    res = array_or_singleton(claim_spec, "foo")
    assert res == ["foo"]


def test_array_or_singleton_single():
    claim_spec = SINGLE_OPTIONAL_ANY
    res = array_or_singleton(claim_spec, ["foo", "bar", "baz"])
    assert res == "foo"
    res = array_or_singleton(claim_spec, "foo")
    assert res == "foo"

def test_alg_cmp():
    # none should always be sorted last
    assert alg_cmp('RS256', 'none') == -1
    assert alg_cmp('none', 'RS256') == 1
    assert alg_cmp('none', 'none') == 0

    # There is a algorithm sorting order
    assert alg_cmp('RS256', 'RS256') == 0
    assert alg_cmp('RS256', 'HS256') == -1
    assert alg_cmp('RS256', 'ES256') == -1
    assert alg_cmp('HS256', 'ES256') == 1

    # longer keys preferred
    assert alg_cmp('RS256', 'RS384') == 1
