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
    "preference": {"response_types_supported": ["code"]},
    "key_conf": {"key_defs": KEYDEFS},
    "client_id": "CLIENT",
    "base_url": "https://example.com/cli",
}


class TestService:
    @pytest.fixture(autouse=True)
    def create_service(self):
        self.entity = Entity(
            config=CLIENT_CONF.copy(),
            services={"authz": {"class": "idpyoidc.client.oidc.authorization.Authorization"}},
            client_type="oidc",
            jwks_uri="https://example.com/cli/jwks.json",
        )

        self.service = self.entity.get_service("authorization")
        self.service_context = self.entity.get_service_context()
        self.service_context.map_supported_to_preferred()

    def upstream_get(self, *args):
        if args[0] == "context":
            return self.service_context
        elif args[0] == "attribute" and args[1] == "keyjar":
            return self.upstream_get("attribute", "keyjar")

    def test_1(self):
        assert self.service

    def test_use(self):
        use = self.service_context.map_preferred_to_registered()

        assert set(use.keys()) == {
            "application_type",
            "callback_uris",
            "client_id",
            "default_max_age",
            "encrypt_request_object_supported",
            "id_token_signed_response_alg",
            "jwks",
            "redirect_uris",
            "request_object_signing_alg",
            'request_parameter_supported',
            "response_modes",
            "response_types",
            "scope",
            "subject_type",
        }

    def test_gather_request_args(self):
        self.service.conf["request_args"] = {"response_type": "code"}
        args = self.service.gather_request_args(state="state")
        assert args == {
            "response_type": "code",
            "state": "state",
            "client_id": "CLIENT",
            "redirect_uri": "https://example.com/cli/authz_cb",
            "scope": ["openid"],
        }

        self.service_context.set_usage("client_id", "client")
        args = self.service.gather_request_args(state="state")
        assert args == {
            "client_id": "client",
            "response_type": "code",
            "state": "state",
            "redirect_uri": "https://example.com/cli/authz_cb",
            "scope": ["openid"],
        }

        self.service_context.set_usage("scope", ["openid", "foo"])
        args = self.service.gather_request_args(state="state")
        assert args == {
            "client_id": "client",
            "response_type": "code",
            "scope": ["openid", "foo"],
            "state": "state",
            "redirect_uri": "https://example.com/cli/authz_cb",
        }

        self.service_context.set_usage("redirect_uri", "https://rp.example.com")
        args = self.service.gather_request_args(state="state")
        assert args == {
            "client_id": "client",
            "redirect_uri": "https://rp.example.com",
            "response_type": "code",
            "scope": ["openid", "foo"],
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

        _sign_key = self.service.upstream_get("attribute", "keyjar").get_signing_key()
        resp1 = AuthorizationResponse(code="auth_grant", state="state").to_json()
        arg = self.service.parse_response(resp1)
        assert isinstance(arg, AuthorizationResponse)
        assert arg.to_dict() == {"code": "auth_grant", "state": "state"}

    def test_parse_response_jwt(self):
        self.service.response_body_type = "jwt"
        self.service.response_cls = AuthorizationResponse
        self.service_context.issuer = "https://op.example.com/"
        self.service_context.client_id = "client"

        _sign_key = self.service.upstream_get("attribute", "keyjar").get_signing_key()
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

        _sign_key = self.service.upstream_get("attribute", "keyjar").get_signing_key()
        resp1 = AuthorizationResponse(code="auth_grant", state="state").to_jwt(
            key=_sign_key, algorithm="RS256"
        )
        with pytest.raises(ValueError):
            arg = self.service.parse_response(resp1)


class TestAuthorization(object):
    @pytest.fixture(autouse=True)
    def create_service(self):
        self.entity = Entity(
            config=CLIENT_CONF.copy(),
            services={"base": {"class": "idpyoidc.client.service.Service"}},
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
        self.service.upstream_get("service_context").cstate.set(_state, msg)

        resp1 = AuthorizationResponse(code="auth_grant", state=_state)
        response = self.service.parse_response(resp1.to_urlencoded(), "urlencoded", state=_state)
        self.service.update_service_context(response, key=_state)
        assert self.service.upstream_get("service_context").cstate.get(_state)
