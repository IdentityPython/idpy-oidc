import json
import os

import pytest
import responses

from idpyoidc.client.entity import Entity

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

    def test_import_keys_file(self):
        # Should only be one and that a symmetric key (client_secret) usable
        # for signing and encryption
        assert len(self.entity.keyjar.get_issuer_keys("")) == 1

        file_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "salesforce.key"))

        keyspec = {"file": {"rsa": [file_path]}}
        self.entity.import_keys(keyspec)

        # Now there should be 3, 2 RSA keys
        assert len(self.entity.keyjar.get_issuer_keys("")) == 2

    def test_import_keys_url(self):
        # Uses 2 variants of getting hold of the keyjar
        assert len(self.entity.keyjar.get_issuer_keys("")) == 1

        with responses.RequestsMock() as rsps:
            _jwks_url = "https://foobar.com/jwks.json"
            rsps.add(
                "GET",
                _jwks_url,
                body=self.entity.get_attribute('keyjar').export_jwks_as_json(),
                status=200,
                adding_headers={"Content-Type": "application/json"},
            )
            keyspec = {"url": {"https://foobar.com": _jwks_url}}
            self.entity.import_keys(keyspec)

            # Now there should be one belonging to https://example.com
            assert len(self.entity.get_attribute('keyjar').get_issuer_keys(
                "https://foobar.com")) == 1

    def test_import_keys_file_json(self):
        # Should only be one and that a symmetric key (client_secret) usable
        # for signing and encryption
        assert len(self.entity.keyjar.get_issuer_keys("")) == 1

        file_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "salesforce.key"))

        keyspec = {"file": {"rsa": [file_path]}}
        self.entity.import_keys(keyspec)

        _entity_state = self.entity.dump(exclude_attributes=["context"])
        _jsc_state = json.dumps(_entity_state)
        _o_state = json.loads(_jsc_state)
        _entity = Entity().load(_o_state)

        # Now there should be 2, the second a RSA key for signing
        assert len(_entity.keyjar.get_issuer_keys("")) == 2
