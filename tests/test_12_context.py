from idpyoidc.context import OidcContext

ENTITY_ID = 'https://example.com'


class TestDumpLoad(object):
    def test_context_with_entity_id(self):
        c = OidcContext({}, entity_id=ENTITY_ID)
        mem = c.dump()
        c2 = OidcContext().load(mem)
        assert c2.entity_id == ENTITY_ID

    def test_context_with_entity_id_and_keys(self):
        c = OidcContext({"entity_id": ENTITY_ID})

        mem = c.dump()
        c2 = OidcContext().load(mem)
        assert c2.entity_id == ENTITY_ID
