import copy
import shutil

import pytest

from idpyoidc.context import OidcContext

KEYDEF = [
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["enc"]},
]

JWKS = {
    "keys": [
        {
            "n": "zkpUgEgXICI54blf6iWiD2RbMDCOO1jV0VSff1MFFnujM4othfMsad7H1kRo50YM5S"
            "_X9TdvrpdOfpz5aBaKFhT6Ziv0nhtcekq1eRl8mjBlvGKCE5XGk-0LFSDwvqgkJoFY"
            "Inq7bu0a4JEzKs5AyJY75YlGh879k1Uu2Sv3ZZOunfV1O1Orta-NvS-aG_jN5cstVb"
            "CGWE20H0vFVrJKNx0Zf-u-aA-syM4uX7wdWgQ-owoEMHge0GmGgzso2lwOYf_4znan"
            "LwEuO3p5aabEaFoKNR4K6GjQcjBcYmDEE4CtfRU9AEmhcD1kleiTB9TjPWkgDmT9MX"
            "sGxBHf3AKT5w",
            "e": "AQAB",
            "kty": "RSA",
            "kid": "rsa1",
        },
        {
            "k": "YTEyZjBlMDgxMGI4YWU4Y2JjZDFiYTFlZTBjYzljNDU3YWM0ZWNiNzhmNmFlYTNkNTY0NzMzYjE",
            "kty": "oct",
        },
    ]
}


def test_dump_load():
    c = OidcContext({})
    assert c.keyjar is not None
    mem = c.dump()
    c2 = OidcContext().load(mem)
    assert c2.keyjar is not None


class TestDumpLoad(object):
    @pytest.fixture(autouse=True)
    def setup(self):
        self.conf = {"issuer": "https://example.com"}

    def test_context_with_entity_id_no_keys(self):
        c = OidcContext(self.conf, entity_id="https://example.com")
        mem = c.dump()
        c2 = OidcContext().load(mem)
        assert c2.keyjar.owners() == []
        assert c2.issuer == "https://example.com"

    def test_context_with_entity_id_and_keys(self):
        conf = copy.deepcopy(self.conf)
        conf["keys"] = {"key_defs": KEYDEF}
        c = OidcContext(conf, entity_id="https://example.com")

        mem = c.dump()
        c2 = OidcContext().load(mem)
        assert set(c2.keyjar.owners()) == {"", "https://example.com"}

    def test_context_with_entity_id_and_jwks(self):
        conf = copy.deepcopy(self.conf)
        conf["jwks"] = JWKS
        c = OidcContext(conf, entity_id="https://example.com")

        mem = c.dump()
        c2 = OidcContext().load(mem)

        assert set(c2.keyjar.owners()) == {"", "https://example.com"}
        assert len(c2.keyjar.get("sig", "RSA")) == 1
        assert len(c2.keyjar.get("sig", "RSA", issuer_id="https://example.com")) == 1
        assert len(c2.keyjar.get("sig", "oct")) == 1
        assert len(c2.keyjar.get("sig", "oct", issuer_id="https://example.com")) == 1

    def test_context_restore(self):
        conf = copy.deepcopy(self.conf)
        conf["keys"] = {"key_defs": KEYDEF}

        c = OidcContext(conf, entity_id="https://example.com")
        mem = c.dump()
        c2 = OidcContext().load(mem)

        assert set(c2.keyjar.owners()) == {"", "https://example.com"}
        assert len(c2.keyjar.get("sig", "EC")) == 1
        assert len(c2.keyjar.get("enc", "EC")) == 1
        assert len(c.keyjar.get("sig", "RSA")) == 0
        assert len(c.keyjar.get("sig", "oct")) == 0
