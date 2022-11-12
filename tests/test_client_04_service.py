import pytest

from idpyoidc.client.entity import Entity
from idpyoidc.message.oauth2 import AuthorizationResponse
from idpyoidc.message.oauth2 import Message


class Response(object):
    def __init__(self, status_code, text, headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {"content-type": "text/plain"}


KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

CLIENT_CONF = {
    "redirect_uris": ["https://example.com/cli/authz_cb"],
    "behaviour": {"response_types": ["code"]},
    "key_conf": {"key_defs": KEYDEFS},
}


class TestService:
    @pytest.fixture(autouse=True)
    def create_service(self):
        self.entity = Entity(
            config=CLIENT_CONF,
            services={
                "authz": {"class": "idpyoidc.client.oidc.authorization.Authorization"},
            }
        )

        self.service = self.entity.get_service("authorization")
        self.service_context = self.entity.get_service_context()

    def client_get(self, *args):
        if args[0] == "service_context":
            return self.service_context

    def test_1(self):
        assert self.service

    def test_gather_request_args(self):
        self.service.conf["request_args"] = {"response_type": "code"}
        args = self.service.gather_request_args(state="state")
        assert args == {"response_type": "code", "state": "state",
                        'redirect_uri': 'https://example.com/cli/authz_cb', 'scope': ['openid']}

        self.entity.set_metadata_claim("client_id", "client")
        args = self.service.gather_request_args(state="state")
        assert args == {"client_id": "client", "response_type": "code", "state": "state",
                        'redirect_uri': 'https://example.com/cli/authz_cb', 'scope': ['openid']}

        self.service.default_request_args = {"scope": ["openid"]}
        args = self.service.gather_request_args(state="state")
        assert args == {
            "client_id": "client",
            "response_type": "code",
            "scope": ["openid"],
            "state": "state",
            'redirect_uri': 'https://example.com/cli/authz_cb',
        }

        self.entity.set_metadata_claim("redirect_uris", ["https://rp.example.com"])
        args = self.service.gather_request_args(state="state")
        assert args == {
            "client_id": "client",
            "redirect_uri": "https://rp.example.com",
            "response_type": "code",
            "scope": ["openid"],
            "state": "state",
        }

    def test_parse_response_urlencoded(self):
        resp1 = AuthorizationResponse(code="auth_grant", state="state").to_urlencoded()
        self.service.response_body_type = "urlencoded"
        self.service.response_cls = AuthorizationResponse
        self.service_context.issuer = "https://op.example.com/"
        self.service_context.client_id = "client"
        arg = self.service.parse_response(resp1)
        assert isinstance(arg, AuthorizationResponse)
        assert arg.to_dict() == {"code": "auth_grant", "state": "state"}

    def test_parse_response_json(self):
        self.service.response_body_type = "json"
        self.service.response_cls = AuthorizationResponse
        self.service_context.issuer = "https://op.example.com/"
        self.service_context.client_id = "client"

        _sign_key = self.service_context.keyjar.get_signing_key()
        resp1 = AuthorizationResponse(code="auth_grant", state="state").to_json()
        arg = self.service.parse_response(resp1)
        assert isinstance(arg, AuthorizationResponse)
        assert arg.to_dict() == {"code": "auth_grant", "state": "state"}

    def test_parse_response_jwt(self):
        self.service.response_body_type = "jwt"
        self.service.response_cls = AuthorizationResponse
        self.service_context.issuer = "https://op.example.com/"
        self.service_context.client_id = "client"

        _sign_key = self.service_context.keyjar.get_signing_key()
        resp1 = AuthorizationResponse(code="auth_grant", state="state").to_jwt(
            key=_sign_key, algorithm="RS256"
        )
        arg = self.service.parse_response(resp1)
        assert isinstance(arg, AuthorizationResponse)
        assert arg.to_dict() == {"code": "auth_grant", "state": "state"}

    def test_parse_response_err(self):
        self.service.response_body_type = "urlencoded"
        self.service.response_cls = AuthorizationResponse
        self.service_context.issuer = "https://op.example.com/"
        self.service_context.client_id = "client"

        _sign_key = self.service_context.keyjar.get_signing_key()
        resp1 = AuthorizationResponse(code="auth_grant", state="state").to_jwt(
            key=_sign_key, algorithm="RS256"
        )
        with pytest.raises(ValueError):
            arg = self.service.parse_response(resp1)


class TestAuthorization(object):
    @pytest.fixture(autouse=True)
    def create_service(self):
        self.entity = Entity(
            config=CLIENT_CONF, services={"base": {"class": "idpyoidc.client.service.Service"}}
        )
        self.service = self.entity.get_service("")

    def test_construct(self):
        req_args = {"foo": "bar"}
        _req = self.service.construct(request_args=req_args, state="state")
        assert isinstance(_req, Message)
        assert set(_req.keys()) == {"foo"}

    def test_get_request_parameters(self):
        req_args = {"response_type": "code"}
        self.service.endpoint = "https://example.com/authorize"
        _info = self.service.get_request_parameters(request_args=req_args, state="state")
        assert set(_info.keys()) == {"url", "method", "request"}
        msg = Message().from_urlencoded(self.service.get_urlinfo(_info["url"]))
        assert msg.to_dict() == {"response_type": "code"}

    def test_request_init(self):
        req_args = {"response_type": "code", "state": "state"}
        self.service.endpoint = "https://example.com/authorize"
        _info = self.service.get_request_parameters(request_args=req_args)
        assert set(_info.keys()) == {"url", "method", "request"}
        msg = Message().from_urlencoded(self.service.get_urlinfo(_info["url"]))
        assert msg.to_dict() == {"response_type": "code", "state": "state"}

    def test_response(self):
        _state = "today"
        req_args = {"response_type": "code", "state": _state}
        self.service.endpoint = "https://example.com/authorize"
        _info = self.service.get_request_parameters(request_args=req_args)
        assert set(_info.keys()) == {"url", "method", "request"}
        msg = Message().from_urlencoded(self.service.get_urlinfo(_info["url"]))
        self.service.client_get("service_context").state.store_item(msg, "request", _state)

        resp1 = AuthorizationResponse(code="auth_grant", state=_state)
        response = self.service.parse_response(resp1.to_urlencoded(), "urlencoded", state=_state)
        self.service.update_service_context(response, key=_state)
        assert self.service.client_get("service_context").state.get_state(_state)
