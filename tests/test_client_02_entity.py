import pytest

from idpyoidc.client.entity import Entity

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

MINI_CONFIG = {
    "base_url": "https://example.com/cli/",
    "key_conf": {"key_defs": KEYDEFS},
    "issuer": "https://op.example.com",
    "client_id": "Number5"
}


class TestEntity:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.entity = Entity(config=MINI_CONFIG,
                             services={"xyz": {"class": "idpyoidc.client.service.Service"}})

    def test_1(self):
        assert self.entity

    def test_get_service(self):
        _srv = self.entity.get_service("")
        assert _srv
        assert _srv.service_name == ""
        assert _srv.request_body_type == "urlencoded"

        _srv = self.entity.client_get("service", "")
        assert _srv.service_name == ""

    def test_get_service_unsupported(self):
        _srv = self.entity.get_service("foobar")
        assert _srv is None

    def test_get_client_id(self):
        assert self.entity.get_client_id() == "Number5"
        assert self.entity.client_get('client_id') == "Number5"

    def test_get_service_by_endpoint_name(self):
        _srv = self.entity.get_service("")
        _srv.endpoint_name = "flux_endpoint"
        _fsrv = self.entity.get_service_by_endpoint_name("flux_endpoint")
        assert _srv == _fsrv
        _fsrv2 = self.entity.client_get('service_by_endpoint_name', 'flux_endpoint')
        assert _fsrv == _fsrv2

    def test_get_service_context(self):
        _context = self.entity.get_service_context()
        assert _context