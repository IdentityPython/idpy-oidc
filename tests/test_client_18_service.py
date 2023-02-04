import pytest

from idpyoidc.client.entity import Entity
from idpyoidc.client.service import Service
from idpyoidc.message.oauth2 import SINGLE_OPTIONAL_INT
from idpyoidc.message.oauth2 import SINGLE_OPTIONAL_STRING
from idpyoidc.message.oauth2 import SINGLE_REQUIRED_STRING
from idpyoidc.message.oauth2 import Message


class DummyMessage(Message):
    c_param = {
        "req_str": SINGLE_REQUIRED_STRING,
        "opt_str": SINGLE_OPTIONAL_STRING,
        "opt_int": SINGLE_OPTIONAL_INT,
    }


class Response(object):
    def __init__(self, status_code, text, headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {"content-type": "text/plain"}


class DummyService(Service):
    msg_type = DummyMessage


class TestDummyService(object):
    @pytest.fixture(autouse=True)
    def create_service(self):
        config = {
            "issuer": "https://www.example.org/as",
            "client_id": "client_id",
            "client_secret": "a longesh password",
            "redirect_uris": ["https://example.com/cli/authz_cb"],
            "preference": {"response_types": ["code"]},
        }

        service = {"dummy": {"class": DummyService}}

        entity = Entity(config=config, services=service)
        self.service = DummyService(upstream_get=entity.unit_get, conf={})

    def test_construct(self):
        req_args = {"foo": "bar"}
        _req = self.service.construct(request_args=req_args)
        assert isinstance(_req, Message)
        assert list(_req.keys()) == ["foo"]

    def test_construct_service_context(self):
        req_args = {"foo": "bar", "req_str": "some string"}
        _req = self.service.construct(request_args=req_args)
        assert isinstance(_req, Message)
        assert set(_req.keys()) == {"foo", "req_str"}

    def test_get_request_parameters(self):
        req_args = {"foo": "bar", "req_str": "some string"}
        self.service.endpoint = "https://example.com/authorize"
        _info = self.service.get_request_parameters(request_args=req_args)
        assert set(_info.keys()) == {"url", "method", "request"}
        msg = DummyMessage().from_urlencoded(self.service.get_urlinfo(_info["url"]))

    def test_request_init(self):
        req_args = {"foo": "bar", "req_str": "some string"}
        self.service.endpoint = "https://example.com/authorize"
        _info = self.service.get_request_parameters(request_args=req_args)
        assert set(_info.keys()) == {"url", "method", "request"}
        msg = DummyMessage().from_urlencoded(self.service.get_urlinfo(_info["url"]))
        assert msg.to_dict() == {"foo": "bar", "req_str": "some string"}


# class TestRequest(object):
#     @pytest.fixture(autouse=True)
#     def create_service(self):
#         entity = Entity()
#         service_context = entity.get_service_context()
#         self.service = Service(service_context, client_authn_method=None)
#
#     def test_construct(self):
#         req_args = {'foo': 'bar'}
#         _req = self.service.construct(request_args=req_args)
#         assert isinstance(_req, Message)
#         assert list(_req.keys()) == ['foo']
