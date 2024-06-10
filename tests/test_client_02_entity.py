import pytest

from idpyoidc.client.client_auth import ClientAuthnMethod
from idpyoidc.client.entity import Entity
from idpyoidc.message.oidc import APPLICATION_TYPE_WEB

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

MINI_CONFIG = {
    "base_url": "https://example.com/cli/",
    "key_conf": {"key_defs": KEYDEFS},
    "issuer": "https://op.example.com",
    "client_id": "Number5",
}


class TestEntity:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.entity = Entity(
            config=MINI_CONFIG.copy(),
            services={"xyz": {"class": "idpyoidc.client.service.Service"}},
        )

    def test_1(self):
        assert self.entity

    def test_get_service(self):
        _srv = self.entity.get_service("")
        assert _srv
        assert _srv.service_name == ""
        assert _srv.request_body_type == "urlencoded"

    def test_get_service_unsupported(self):
        _srv = self.entity.get_service("foobar")
        assert _srv is None

    def test_get_client_id(self):
        assert self.entity.get_service_context().get_preference("client_id") == "Number5"
        assert self.entity.get_attribute("client_id") == "Number5"

    def test_get_service_by_endpoint_name(self):
        _srv = self.entity.get_service("")
        _srv.endpoint_name = "flux_endpoint"
        _fsrv = self.entity.get_service_by_endpoint_name("flux_endpoint")
        assert _srv == _fsrv

    def test_get_service_context(self):
        _context = self.entity.get_service_context()
        assert _context


RP_BASEURL = "https://example.com/rp"
KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]


def test_client_authn_default():
    config = {
        "application_type": APPLICATION_TYPE_WEB,
        "contacts": ["ops@example.org"],
        "redirect_uris": [f"{RP_BASEURL}/authz_cb"],
        "keys": {"key_defs": KEYSPEC, "read_only": True},
    }

    entity = Entity(config=config, client_type="oidc")

    assert entity.get_context().client_authn_methods == {}


def test_client_authn_by_names():
    config = {
        "application_type": APPLICATION_TYPE_WEB,
        "contacts": ["ops@example.org"],
        "redirect_uris": [f"{RP_BASEURL}/authz_cb"],
        "keys": {"key_defs": KEYSPEC, "read_only": True},
        "client_authn_methods": ["client_secret_basic", "client_secret_post"],
    }

    entity = Entity(config=config, client_type="oidc")

    assert set(entity.get_context().client_authn_methods.keys()) == {
        "client_secret_basic",
        "client_secret_post",
    }


class FooBar(ClientAuthnMethod):
    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def modify_request(self, request, service, **kwargs):
        request.update(self.kwargs)


def test_client_authn_full():
    config = {
        "application_type": APPLICATION_TYPE_WEB,
        "contacts": ["ops@example.org"],
        "redirect_uris": [f"{RP_BASEURL}/authz_cb"],
        "keys": {"key_defs": KEYSPEC, "read_only": True},
        "client_authn_methods": {
            "client_secret_basic": {},
            "client_secret_post": None,
            "home_brew": {"class": FooBar, "kwargs": {"one": "bar"}},
        },
    }

    entity = Entity(config=config, client_type="oidc")

    assert set(entity.get_context().client_authn_methods.keys()) == {
        "client_secret_basic",
        "client_secret_post",
        "home_brew",
    }


def test_service_specific():
    config = {
        "application_type": APPLICATION_TYPE_WEB,
        "contacts": ["ops@example.org"],
        "redirect_uris": [f"{RP_BASEURL}/authz_cb"],
        "keys": {"key_defs": KEYSPEC, "read_only": True},
        "client_authn_methods": ["client_secret_basic", "client_secret_post"],
    }

    entity = Entity(
        config=config,
        client_type="oidc",
        services={
            "xyz": {
                "class": "idpyoidc.client.service.Service",
                "kwargs": {"client_authn_methods": ["private_key_jwt"]},
            }
        },
    )

    # A specific does not change the general
    assert set(entity.get_context().client_authn_methods.keys()) == {
        "client_secret_basic",
        "client_secret_post",
    }

    assert set(entity.get_service("").client_authn_methods.keys()) == {"private_key_jwt"}


def test_service_specific2():
    config = {
        "application_type": APPLICATION_TYPE_WEB,
        "contacts": ["ops@example.org"],
        "redirect_uris": [f"{RP_BASEURL}/authz_cb"],
        "keys": {"key_defs": KEYSPEC, "read_only": True},
        "client_authn_methods": ["client_secret_basic", "client_secret_post"],
    }

    entity = Entity(
        config=config,
        client_type="oidc",
        services={
            "xyz": {
                "class": "idpyoidc.client.service.Service",
                "kwargs": {
                    "client_authn_methods": {
                        "home_brew": {"class": FooBar, "kwargs": {"one": "bar"}}
                    }
                },
            }
        },
    )

    # A specific does not change the general
    assert set(entity.get_context().client_authn_methods.keys()) == {
        "client_secret_basic",
        "client_secret_post",
    }

    assert set(entity.get_service("").client_authn_methods.keys()) == {"home_brew"}
