import pytest

from idpyoidc.client.client_auth import ClientAuthnMethod
from idpyoidc.client.entity import Entity
from idpyoidc.message.oidc import APPLICATION_TYPE_WEB
from idpyoidc.message.oidc import RegistrationResponse
from idpyoidc.util import use_default_keys

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

ISS = "https://op.example.com"

MINI_CONFIG = {
    "": {
        'base_url': "https://example.com",
    },
    "foo": {
        "base_url": "https://example.com/cli/",
        # "key_conf": {"key_defs": KEYDEFS},
        "issuer": ISS,
        "client_id": "Number5",
    }
}


class TestEntity:

    @pytest.fixture(autouse=True)
    def setup(self):
        key_conf = None
        if use_default_keys(None, key_conf, {}):
            key_conf = {"key_defs": KEYDEFS}

        self.entity = Entity(
            client_configs=MINI_CONFIG.copy(),
            services={"xyz": {"class": "idpyoidc.client.service.Service"}},
            key_conf=key_conf
        )

        self.context = self.entity.context[ISS]

    def test_1(self):
        assert self.entity

    def test_get_service(self):
        _srv = self.entity.get_service(self.context, "")
        assert _srv
        assert _srv.service_name == ""
        assert _srv.request_body_type == "urlencoded"

    def test_get_service_unsupported(self):
        _srv = self.entity.get_service(self.context, "foobar")
        assert _srv is None

    def test_get_client_id(self):
        assert self.context.client_id == "Number5"
        assert self.entity.get_attribute("client_id", ISS) == "Number5"

    def test_get_service_by_endpoint_name(self):
        _srv = self.context.get_service("")
        _srv.endpoint_name = "flux_endpoint"
        _fsrv = self.entity.get_service_by_endpoint_name(self.context, "flux_endpoint")
        assert _srv == _fsrv


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

    assert entity.context[""].client_authn_methods == {}


def test_client_authn_by_names():
    config = {
        "application_type": APPLICATION_TYPE_WEB,
        "contacts": ["ops@example.org"],
        "redirect_uris": [f"{RP_BASEURL}/authz_cb"],
        "keys": {"key_defs": KEYSPEC, "read_only": True},
        "client_authn_methods": ["client_secret_basic", "client_secret_post"],
    }

    entity = Entity(config=config, client_type="oidc")

    assert set(entity.context[""].client_authn_methods.keys()) == {
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

    assert set(entity.context[""].client_authn_methods.keys()) == {
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
    assert set(entity.context[""].client_authn_methods.keys()) == {
        "client_secret_basic",
        "client_secret_post",
    }

    context = entity.get_context("")
    assert set(entity.get_service(context, "").client_authn_methods.keys()) == {"private_key_jwt"}


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
    assert set(entity.context[""].client_authn_methods.keys()) == {
        "client_secret_basic",
        "client_secret_post",
    }
    context = entity.get_context("")
    assert set(entity.get_service(context, "").client_authn_methods.keys()) == {"home_brew"}


def test_context_duplication():
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
        metadata_class=RegistrationResponse,
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

    server_1_id = 'https://op.example.com'
    context_1 = entity.add_new_context(server_1_id)
    assert context_1

    assert set(context_1.client_authn_methods.keys()) == {'client_secret_post', 'client_secret_basic'}

    assert set(entity.context[""].client_authn_methods.keys()) == {
        "client_secret_basic",
        "client_secret_post",
    }

    assert set(context_1.get_service('').client_authn_methods.keys()) == {"home_brew"}

    server_2_id = 'https://foo_op.example.org'
    context_2 = entity.add_new_context(server_2_id)

    assert set(context_2.get_service(service_name='').client_authn_methods.keys()) == {"home_brew"}
