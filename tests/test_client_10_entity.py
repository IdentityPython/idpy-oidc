import json
import os

import pytest
import responses

from idpyoidc.client.entity import Entity
from idpyoidc.util import keyjar_join

KEYSPEC = [{"type": "RSA", "use": ["sig"]}]


class TestClientInfo(object):

    @pytest.fixture(autouse=True)
    def create_client_info_instance(self):
        config = {
            "client_id": "client_id",
            "issuer": "issuer",
            "client_secret": "longenoughsupersecret",
            "base_url": "https://example.com",
            "requests_dir": "requests",
        }
        self.entity = Entity(config=config)

    def _keyjar(self, entity=None, issuer_id='', private=False):
        if entity is None:
            entity = self.entity
            context = self.entity.context
        else:
            context = entity.context

        return keyjar_join(entity.keyjar, context[''].keyjar, issuer_id=issuer_id, private=private)

    def test_import_keys_file(self):
        keyjar = self._keyjar()
        #
        assert len(keyjar.get_issuer_keys("")) == 1

        file_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "salesforce.key"))

        keyspec = {"file": {"rsa": [file_path]}}
        self.entity.import_keys(keyspec)

        keyjar = self._keyjar()
        # Now there should be 2 RSA keys
        assert len(keyjar.get_issuer_keys("")) == 2

    def test_import_keys_url(self):
        keyjar = self._keyjar()

        # Uses 2 variants of getting hold of the keyjar
        assert len(keyjar.get_issuer_keys("")) == 1

        with responses.RequestsMock() as rsps:
            _jwks_url = "https://foobar.com/jwks.json"
            rsps.add(
                "GET",
                _jwks_url,
                body=self.entity.get_attribute("keyjar").export_jwks_as_json(),
                status=200,
                adding_headers={"Content-Type": "application/json"},
            )
            keyspec = {"url": {"https://foobar.com": _jwks_url}}
            self.entity.import_keys(keyspec)
            keyjar = self._keyjar(issuer_id="https://foobar.com")

            # Now there should be one belonging to https://example.com
            assert (
                    len(keyjar.get_issuer_keys("https://foobar.com")) == 1
            )

    def test_dump_load_imported_keys_file_json(self):
        # Initial setup is no keys in self.entity and one key each for the
        # identities of the entity ['', 'client_id']
        # based on client_secret in self.entity.context[''].keyjar
        keyjar = self._keyjar()

        # Should only be one and that a symmetric key (client_secret) usable
        # for signing and encryption
        assert len(keyjar.get_issuer_keys("")) == 1

        file_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "salesforce.key"))

        keyspec = {"file": {"rsa": [file_path]}}
        self.entity.import_keys(keyspec)

        # entity now has one key, an RSA key just imported
        assert self.entity.keyjar.owners() == ['']
        assert len(self.entity.keyjar.key_summary('').split(',')) == 1

        # combine entity and context keys
        keyjar = self._keyjar()
        # one symmetric (client_secret) and one RSA
        assert len(keyjar.get_issuer_keys("")) == 2
        assert len(keyjar.get_signing_key(key_type="rsa", issuer_id="")) == 1
        assert len(keyjar.get_signing_key(key_type="oct", issuer_id="")) == 1

        assert set(self.entity.context[''].keyjar.owners()) == {'', 'client_id'}

        _entity_state = self.entity.dump()
        _jsc_state = json.dumps(_entity_state)
        _o_state = json.loads(_jsc_state)
        _entity = Entity().load(_o_state)

        assert set(_entity.keyjar.owners()) == {''}
        assert len(_entity.keyjar.key_summary('').split(',')) == 1
        assert len(_entity.keyjar.get_signing_key(key_type="rsa", issuer_id="")) == 1
        assert len(_entity.keyjar.get_signing_key(key_type="oct", issuer_id="")) == 0

        _cntx = _entity.context['']
        assert set(_cntx.keyjar.owners()) == {'client_id', ''}
        assert len(_cntx.keyjar.key_summary('').split(',')) == 1
        assert len(_cntx.keyjar.get_signing_key(key_type="oct", issuer_id="")) == 1
        assert len(_cntx.keyjar.get_signing_key(key_type="rsa", issuer_id="")) == 0
