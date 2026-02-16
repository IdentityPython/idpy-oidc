from idpyoidc.claims import Claims
from idpyoidc.claims import claims_dump


def test_claims_dump():
    claims = Claims()
    _dump = claims_dump(claims, [])
    assert _dump != {}
    assert len(_dump.keys()) == 1
    assert list(_dump.keys())[0] == 'idpyoidc.claims.Claims'
    assert set(_dump['idpyoidc.claims.Claims'].keys()) == {'callback_path', 'prefer', 'use',
                                                           '_local'}

def test_dump_load():
    claims = Claims(prefer={}, callback_path={'':"callback"})
    _dump = claims_dump(claims, [])