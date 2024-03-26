import os

from cryptojwt.exception import UnsupportedAlgorithm
from cryptojwt.jws import jws
from cryptojwt.jws.utils import left_hash
from cryptojwt.jwt import JWT
from cryptojwt.key_jar import build_keyjar
from cryptojwt.key_jar import init_key_jar
import pytest
import responses

from idpyoidc.client.defaults import DEFAULT_OIDC_SERVICES
from idpyoidc.client.entity import Entity
from idpyoidc.client.exception import ParameterError
from idpyoidc.client.oidc.registration import response_types_to_grant_types
from idpyoidc.exception import MissingRequiredAttribute
from idpyoidc.message.oidc import AccessTokenRequest
from idpyoidc.message.oidc import AccessTokenResponse
from idpyoidc.message.oidc import AuthorizationRequest
from idpyoidc.message.oidc import AuthorizationResponse
from idpyoidc.message.oidc import IdToken
from idpyoidc.message.oidc import Message
from idpyoidc.message.oidc import OpenIDSchema
from idpyoidc.message.oidc import RegistrationRequest
from idpyoidc.message.oidc import verified_claim_name
from idpyoidc.message.oidc.session import CheckIDRequest
from idpyoidc.message.oidc.session import CheckSessionRequest
from idpyoidc.message.oidc.session import EndSessionRequest


class Response(object):
    def __init__(self, status_code, text, headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {"content-type": "text/plain"}


KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

_dirname = os.path.dirname(os.path.abspath(__file__))

ISS = "https://example.com"

ISS_KEY = init_key_jar(
    public_path="{}/pub_iss.jwks".format(_dirname),
    private_path="{}/priv_iss.jwks".format(_dirname),
    key_defs=KEYSPEC,
    issuer_id=ISS,
    read_only=False,
)

ISS_KEY.import_jwks_as_json(open("{}/pub_client.jwks".format(_dirname)).read(), "client_id")


def make_keyjar():
    _keyjar = init_key_jar(
        public_path="{}/pub_client.jwks".format(_dirname),
        private_path="{}/priv_client.jwks".format(_dirname),
        key_defs=KEYSPEC,
        issuer_id="client_id",
        read_only=False,
    )
    _keyjar.import_jwks(_keyjar.export_jwks(private=True, issuer_id="client_id"), issuer_id="")
    _keyjar.import_jwks_as_json(open("{}/pub_iss.jwks".format(_dirname)).read(), ISS)
    return _keyjar


class TestAuthorization(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        client_config = {
            "client_id": "client_id",
            "client_secret": "a longesh password",
            "callback_uris": {
                "redirect_uris": {  # different flows
                    "query": ["https://example.com/cli/authz_cb"],
                    "fragment": ["https://example.com/cli/imp_cb"],
                    "form_post": ["https://example.com/cli/form"],
                }
            },
            "response_types_supported": ["code", "token"],
        }
        entity = Entity(
            services=DEFAULT_OIDC_SERVICES,
            keyjar=make_keyjar(),
            config=client_config,
            client_type="oidc",
        )
        _context = entity.get_context()
        _context.issuer = "https://example.com"
        _context.map_supported_to_preferred()
        _context.map_preferred_to_registered()
        self.context = _context
        self.service = entity.get_service("authorization")

    def test_construct(self):
        req_args = {"foo": "bar", "response_type": "code", "state": "state"}
        _req = self.service.construct(request_args=req_args)
        assert isinstance(_req, AuthorizationRequest)
        assert set(_req.keys()) == {
            "redirect_uri",
            "foo",
            "client_id",
            "response_type",
            "scope",
            "state",
            "nonce",
        }

    def test_construct_missing_openid_scope(self):
        req_args = {"foo": "bar", "response_type": "code", "state": "state", "scope": ["email"]}
        _req = self.service.construct(request_args=req_args)
        assert isinstance(_req, AuthorizationRequest)
        assert set(_req.keys()) == {
            "redirect_uri",
            "foo",
            "client_id",
            "response_type",
            "scope",
            "state",
            "nonce",
        }
        assert _req["scope"] == ["email", "openid"]

    def test_construct_token(self):
        req_args = {"foo": "bar", "response_type": "token", "state": "state"}
        _req = self.service.construct(request_args=req_args)
        assert isinstance(_req, AuthorizationRequest)
        assert set(_req.keys()) == {
            "redirect_uri",
            "foo",
            "client_id",
            "response_type",
            "scope",
            "state",
        }

    def test_construct_token_nonce(self):
        req_args = {"foo": "bar", "response_type": "token", "nonce": "nonce", "state": "state"}
        _req = self.service.construct(request_args=req_args)
        assert isinstance(_req, AuthorizationRequest)
        assert set(_req.keys()) == {
            "redirect_uri",
            "foo",
            "client_id",
            "response_type",
            "scope",
            "state",
            "nonce",
        }
        assert _req["nonce"] == "nonce"

    def test_get_request_parameters(self):
        req_args = {"response_type": "code", "state": "state"}
        self.service.endpoint = "https://example.com/authorize"
        _info = self.service.get_request_parameters(request_args=req_args)
        assert set(_info.keys()) == {"url", "method", "request"}
        msg = AuthorizationRequest().from_urlencoded(self.service.get_urlinfo(_info["url"]))
        assert set(msg.keys()) == {
            "response_type",
            "state",
            "client_id",
            "nonce",
            "redirect_uri",
            "scope",
        }

    def test_request_init(self):
        req_args = {"response_type": "code", "state": "state"}
        self.service.endpoint = "https://example.com/authorize"
        _info = self.service.get_request_parameters(request_args=req_args)
        assert set(_info.keys()) == {"url", "method", "request"}
        msg = AuthorizationRequest().from_urlencoded(self.service.get_urlinfo(_info["url"]))
        assert set(msg.keys()) == {
            "client_id",
            "scope",
            "response_type",
            "state",
            "redirect_uri",
            "nonce",
        }

    def test_request_init_request_method(self):
        req_args = {"response_type": "code", "state": "state"}
        self.service.endpoint = "https://example.com/authorize"
        self.context.set_usage("request_object_encryption_alg", None)
        _info = self.service.get_request_parameters(request_args=req_args, request_method="value")
        assert set(_info.keys()) == {"url", "method", "request"}
        msg = AuthorizationRequest().from_urlencoded(self.service.get_urlinfo(_info["url"]))
        assert set(msg.to_dict()) == {
            "client_id",
            "redirect_uri",
            "request",
            "response_type",
            "scope",
        }
        _jws = jws.factory(msg["request"])
        assert _jws
        _resp = _jws.verify_compact(
            msg["request"], keys=ISS_KEY.get_signing_key(key_type="RSA", issuer_id="client_id")
        )
        assert _resp
        assert set(_resp.keys()) == {
            "response_type",
            "client_id",
            "scope",
            "redirect_uri",
            "state",
            "nonce",
            "iss",
            "aud",
            "iat",
        }

    def test_request_param(self):
        req_args = {"response_type": "code", "state": "state"}
        self.service.endpoint = "https://example.com/authorize"

        assert os.path.isfile(os.path.join(_dirname, "request123456.jwt"))

        _context = self.service.upstream_get("context")
        _context.set_usage("redirect_uris", ["https://example.com/cb"])
        _context.set_usage("request_uris", ["https://example.com/request123456.jwt"])
        _context.base_url = "https://example.com/"
        # _context.set_usage('request_object_encryption_alg', None)
        _info = self.service.get_request_parameters(
            request_args=req_args, request_method="reference"
        )

        assert set(_info.keys()) == {"url", "method", "request"}

    def test_update_service_context_no_idtoken(self):
        req_args = {"response_type": "code", "state": "state"}
        self.service.endpoint = "https://example.com/authorize"
        _info = self.service.get_request_parameters(request_args=req_args)
        resp = AuthorizationResponse(state="state", code="code")
        self.service.update_service_context(resp, "state")

    def test_update_service_context_with_idtoken(self):
        req_args = {"response_type": "code", "state": "state", "nonce": "nonce"}
        self.service.endpoint = "https://example.com/authorize"
        _info = self.service.get_request_parameters(request_args=req_args)
        # Build an ID Token
        idt = JWT(key_jar=ISS_KEY, iss=ISS, lifetime=3600)
        payload = {"sub": "123456789", "aud": ["client_id"], "nonce": "nonce"}
        # have to calculate c_hash
        alg = "RS256"
        halg = "HS%s" % alg[-3:]
        payload["c_hash"] = left_hash("code", halg)

        _idt = idt.pack(payload)
        resp = AuthorizationResponse(state="state", code="code", id_token=_idt)
        resp = self.service.parse_response(resp.to_urlencoded())
        self.service.update_service_context(resp, "state")

    def test_update_service_context_with_idtoken_wrong_nonce(self):
        req_args = {"response_type": "code", "state": "state", "nonce": "nonce"}
        self.service.endpoint = "https://example.com/authorize"
        _info = self.service.get_request_parameters(request_args=req_args)
        # Build an ID Token
        idt = JWT(ISS_KEY, iss=ISS, lifetime=3600)
        payload = {"sub": "123456789", "aud": ["client_id"], "nonce": "noice"}
        # have to calculate c_hash
        alg = "RS256"
        halg = "HS%s" % alg[-3:]
        payload["c_hash"] = left_hash("code", halg)

        _idt = idt.pack(payload)
        resp = AuthorizationResponse(state="state", code="code", id_token=_idt)
        with pytest.raises(ValueError):
            self.service.parse_response(resp.to_urlencoded())

    def test_update_service_context_with_idtoken_missing_nonce(self):
        req_args = {"response_type": "code", "state": "state", "nonce": "nonce"}
        self.service.endpoint = "https://example.com/authorize"
        self.service.get_request_parameters(request_args=req_args)
        # Build an ID Token
        idt = JWT(ISS_KEY, iss=ISS, lifetime=3600)
        payload = {"sub": "123456789", "aud": ["client_id"]}
        # have to calculate c_hash
        alg = "RS256"
        halg = "HS%s" % alg[-3:]
        payload["c_hash"] = left_hash("code", halg)

        _idt = idt.pack(payload)
        resp = AuthorizationResponse(state="state", code="code", id_token=_idt)
        with pytest.raises(MissingRequiredAttribute):
            self.service.parse_response(resp.to_urlencoded())

    @pytest.mark.parametrize("allow_sign_alg_none", [True, False])
    def test_allow_unsigned_idtoken(self, allow_sign_alg_none):
        req_args = {"response_type": "code", "state": "state", "nonce": "nonce"}
        self.service.endpoint = "https://example.com/authorize"
        self.service.get_request_parameters(request_args=req_args)
        # Build an ID Token
        idt = JWT(ISS_KEY, iss=ISS, lifetime=3600, sign_alg="none")
        payload = {"sub": "123456789", "aud": ["client_id"], "nonce": req_args["nonce"]}
        _idt = idt.pack(payload)
        self.service.upstream_get("context").claims.set_usage(
            "verify_args", {"allow_sign_alg_none": allow_sign_alg_none}
        )
        resp = AuthorizationResponse(state="state", code="code", id_token=_idt)
        if allow_sign_alg_none:
            self.service.parse_response(resp.to_urlencoded())
        else:
            with pytest.raises(UnsupportedAlgorithm):
                self.service.parse_response(resp.to_urlencoded())


class TestAuthorizationCallback(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        client_config = {
            "client_id": "client_id",
            "client_secret": "a longesh password",
            "callback_uris": {
                "redirect_uris": {
                    "query": ["https://example.com/cli/authz_cb"],
                    "fragment": ["https://example.com/cli/authz_im_cb"],
                    "form_post": ["https://example.com/cli/authz_fp_cb"],
                },
            },
        }
        entity = Entity(
            keyjar=make_keyjar(),
            config=client_config,
            services=DEFAULT_OIDC_SERVICES,
            client_type="oidc",
        )
        _context = entity.get_context()
        _context.issuer = "https://example.com"
        _context.map_supported_to_preferred()
        _context.map_preferred_to_registered()

        self.service = entity.get_service("authorization")

    def test_construct_code(self):
        req_args = {"foo": "bar", "response_type": "code", "state": "state"}
        _req = self.service.construct(request_args=req_args)
        assert isinstance(_req, AuthorizationRequest)
        assert set(_req.keys()) == {
            "redirect_uri",
            "foo",
            "client_id",
            "response_type",
            "scope",
            "state",
            "nonce",
        }
        assert _req["redirect_uri"] == "https://example.com/cli/authz_cb"

    def test_construct_implicit(self):
        req_args = {
            "foo": "bar",
            "response_type": "id_token token",
            "state": "state",
            "nonce": "nonce",
        }
        _req = self.service.construct(request_args=req_args)
        assert isinstance(_req, AuthorizationRequest)
        assert set(_req.keys()) == {
            "redirect_uri",
            "foo",
            "client_id",
            "response_type",
            "scope",
            "state",
            "nonce",
        }
        assert _req["redirect_uri"] == "https://example.com/cli/authz_im_cb"

    def test_construct_form_post(self):
        req_args = {
            "foo": "bar",
            "response_type": "code id_token token",
            "state": "state",
            "response_mode": "form_post",
            "nonce": "nonce",
        }
        _req = self.service.construct(request_args=req_args)
        assert isinstance(_req, AuthorizationRequest)
        assert set(_req.keys()) == {
            "redirect_uri",
            "foo",
            "client_id",
            "response_type",
            "scope",
            "state",
            "nonce",
            "response_mode",
        }
        assert _req["redirect_uri"] == "https://example.com/cli/authz_fp_cb"


class TestAccessTokenRequest(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        client_config = {
            "client_id": "client_id",
            "client_secret": "a longesh password",
            "redirect_uris": ["https://example.com/cli/authz_cb"],
            "client_authn_methods": ["client_secret_basic"],
        }
        entity = Entity(keyjar=make_keyjar(), config=client_config, services=DEFAULT_OIDC_SERVICES)
        _context = entity.get_context()
        _context.issuer = "https://example.com"
        _context.provider_info = {"token_endpoint": f"{_context.issuer}/token"}
        self.service = entity.get_service("accesstoken")

        # add some history
        auth_request = AuthorizationRequest(
            redirect_uri="https://example.com/cli/authz_cb", state="state", response_type="code"
        )

        _current = entity.get_context().cstate
        _current.update("state", auth_request)

        auth_response = AuthorizationResponse(code="access_code")
        _current.update("state", auth_response)

    def test_construct(self):
        req_args = {"foo": "bar"}

        _req = self.service.construct(request_args=req_args, state="state")
        assert isinstance(_req, AccessTokenRequest)
        assert set(_req.keys()) == {
            "client_id",
            "foo",
            "grant_type",
            "client_secret",
            "code",
            "state",
            "redirect_uri",
        }

    def test_get_request_parameters(self):
        req_args = {"redirect_uri": "https://example.com/cli/authz_cb", "code": "access_code"}
        self.service.endpoint = "https://example.com/authorize"
        _info = self.service.get_request_parameters(
            request_args=req_args, state="state", authn_method="client_secret_basic"
        )
        assert set(_info.keys()) == {"body", "url", "headers", "method", "request"}
        assert _info["url"] == "https://example.com/authorize"
        msg = AccessTokenRequest().from_urlencoded(self.service.get_urlinfo(_info["body"]))
        assert msg.to_dict() == {
            "client_id": "client_id",
            "code": "access_code",
            "grant_type": "authorization_code",
            "state": "state",
            "redirect_uri": "https://example.com/cli/authz_cb",
        }

    def test_request_init(self):
        req_args = {"redirect_uri": "https://example.com/cli/authz_cb", "code": "access_code"}
        self.service.endpoint = "https://example.com/authorize"

        _info = self.service.get_request_parameters(request_args=req_args, state="state")
        assert set(_info.keys()) == {"body", "url", "headers", "method", "request"}
        assert _info["url"] == "https://example.com/authorize"
        msg = AccessTokenRequest().from_urlencoded(self.service.get_urlinfo(_info["body"]))
        assert set(msg.keys()) == {"redirect_uri", "grant_type", "state", "code", "client_id"}

    def test_id_token_nonce_match(self):
        _cstate = self.service.upstream_get("context").cstate
        _cstate.bind_key("nonce", "state")
        resp = AccessTokenResponse()
        resp[verified_claim_name("id_token")] = {"nonce": "nonce"}
        _cstate.bind_key("nonce2", "state2")
        with pytest.raises(ParameterError):
            self.service.update_service_context(resp, key="state2")


class TestProviderInfo(object):
    @pytest.fixture(autouse=True)
    def create_service(self):
        self._iss = ISS
        client_config = {
            "client_id": "client_id",
            "client_secret": "a longesh password",
            "redirect_uris": ["https://example.com/cli/authz_cb"],
            "issuer": self._iss,
            "application_name": "rphandler",
            "application_type": "web",
            "contacts": ["ops@example.org"],
            "preference": {
                "scope": ["openid", "profile", "email", "address", "phone"],
                "response_types_supported": ["code"],
                "request_object_signing_alg_values_supported": ["ES256"],
                "encrypt_id_token_supported": False,  # default
                "token_endpoint_auth_methods_supported": ["private_key_jwt"],
                "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
                "userinfo_signing_alg_values_supported": ["ES256"],
                "post_logout_redirect_uris": ["https://rp.example.com/post"],
                "backchannel_logout_uri": "https://rp.example.com/back",
                "backchannel_logout_session_required": True,
            },
            "services": {
                "web_finger": {"class": "idpyoidc.client.oidc.webfinger.WebFinger"},
                "discovery": {
                    "class": "idpyoidc.client.oidc.provider_info_discovery.ProviderInfoDiscovery"
                },
                "registration": {
                    "class": "idpyoidc.client.oidc.registration.Registration",
                    "kwargs": {},
                },
                "authorization": {
                    "class": "idpyoidc.client.oidc.authorization.Authorization",
                    "kwargs": {},
                },
                "accesstoken": {
                    "class": "idpyoidc.client.oidc.access_token.AccessToken",
                    "kwargs": {},
                },
                "userinfo": {"class": "idpyoidc.client.oidc.userinfo.UserInfo", "kwargs": {}},
                "end_session": {
                    "class": "idpyoidc.client.oidc.end_session.EndSession",
                    "kwargs": {},
                },
            },
        }
        entity = Entity(keyjar=make_keyjar(), config=client_config, client_type="oidc")
        entity.get_context().issuer = "https://example.com"
        self.service = entity.get_service("provider_info")

    def test_construct(self):
        _req = self.service.construct()
        assert isinstance(_req, Message)
        assert len(_req) == 0

    def test_get_request_parameters(self):
        _info = self.service.get_request_parameters()
        assert set(_info.keys()) == {"url", "method"}
        assert _info["url"] == "{}/.well-known/openid-configuration".format(self._iss)

    def test_post_parse(self):
        OP_BASEURL = ISS

        provider_info_response = {
            "version": "3.0",
            "token_endpoint_auth_methods_supported": [
                "client_secret_post",
                "client_secret_basic",
                "client_secret_jwt",
                "private_key_jwt",
            ],
            "claims_parameter_supported": True,
            "request_parameter_supported": True,
            "request_uri_parameter_supported": True,
            # "require_request_uri_registration": True,
            "grant_types_supported": [
                "authorization_code",
                "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "refresh_token",
            ],
            "response_types_supported": [
                "code",
                "id_token",
                "id_token token",
                "code id_token",
                "code token",
                "code id_token token",
            ],
            "response_modes_supported": ["query", "fragment", "form_post"],
            "subject_types_supported": ["public", "pairwise"],
            "claim_types_supported": ["normal", "aggregated", "distributed"],
            "claims_supported": [
                "birthdate",
                "address",
                "nickname",
                "picture",
                "website",
                "email",
                "gender",
                "sub",
                "phone_number_verified",
                "given_name",
                "profile",
                "phone_number",
                "updated_at",
                "middle_name",
                "name",
                "locale",
                "email_verified",
                "preferred_username",
                "zoneinfo",
                "family_name",
            ],
            "scopes_supported": [
                "openid",
                "profile",
                "email",
                "address",
                "phone",
                "offline_access",
            ],
            "userinfo_signing_alg_values_supported": [
                "RS256",
                "RS384",
                "RS512",
                "ES256",
                "ES384",
                "ES512",
                "HS256",
                "HS384",
                "HS512",
                "PS256",
                "PS384",
                "PS512",
                "none",
            ],
            "id_token_signing_alg_values_supported": [
                "RS256",
                "RS384",
                "RS512",
                "ES256",
                "ES384",
                "ES512",
                "HS256",
                "HS384",
                "HS512",
                "PS256",
                "PS384",
                "PS512",
                "none",
            ],
            "request_object_signing_alg_values_supported": [
                "RS256",
                "RS384",
                "RS512",
                "ES256",
                "ES384",
                "ES512",
                "HS256",
                "HS384",
                "HS512",
                "PS256",
                "PS384",
                "PS512",
                "none",
            ],
            "token_endpoint_auth_signing_alg_values_supported": [
                "RS256",
                "RS384",
                "RS512",
                "ES256",
                "ES384",
                "ES512",
                "HS256",
                "HS384",
                "HS512",
                "PS256",
                "PS384",
                "PS512",
            ],
            "userinfo_encryption_alg_values_supported": [
                "RSA1_5",
                "RSA-OAEP",
                "RSA-OAEP-256",
                "A128KW",
                "A192KW",
                "A256KW",
                "ECDH-ES",
                "ECDH-ES+A128KW",
                "ECDH-ES+A192KW",
                "ECDH-ES+A256KW",
            ],
            "id_token_encryption_alg_values_supported": [
                "RSA1_5",
                "RSA-OAEP",
                "RSA-OAEP-256",
                "A128KW",
                "A192KW",
                "A256KW",
                "ECDH-ES",
                "ECDH-ES+A128KW",
                "ECDH-ES+A192KW",
                "ECDH-ES+A256KW",
            ],
            "request_object_encryption_alg_values_supported": [
                "RSA1_5",
                "RSA-OAEP",
                "RSA-OAEP-256",
                "A128KW",
                "A192KW",
                "A256KW",
                "ECDH-ES",
                "ECDH-ES+A128KW",
                "ECDH-ES+A192KW",
                "ECDH-ES+A256KW",
            ],
            "userinfo_encryption_enc_values_supported": [
                "A128CBC-HS256",
                "A192CBC-HS384",
                "A256CBC-HS512",
                "A128GCM",
                "A192GCM",
                "A256GCM",
            ],
            "id_token_encryption_enc_values_supported": [
                "A128CBC-HS256",
                "A192CBC-HS384",
                "A256CBC-HS512",
                "A128GCM",
                "A192GCM",
                "A256GCM",
            ],
            "request_object_encryption_enc_values_supported": [
                "A128CBC-HS256",
                "A192CBC-HS384",
                "A256CBC-HS512",
                "A128GCM",
                "A192GCM",
                "A256GCM",
            ],
            "acr_values_supported": ["PASSWORD"],
            "issuer": OP_BASEURL,
            "jwks_uri": "{}/static/jwks_tE2iLbOAqXhe8bqh.json".format(OP_BASEURL),
            "authorization_endpoint": "{}/authorization".format(OP_BASEURL),
            "token_endpoint": "{}/token".format(OP_BASEURL),
            "userinfo_endpoint": "{}/userinfo".format(OP_BASEURL),
            "registration_endpoint": "{}/registration".format(OP_BASEURL),
            "end_session_endpoint": "{}/end_session".format(OP_BASEURL),
        }
        _context = self.service.upstream_get("context")
        # assert _context.claims.use == {}
        resp = self.service.post_parse_response(provider_info_response)

        iss_jwks = ISS_KEY.export_jwks_as_json(issuer_id=ISS)
        with responses.RequestsMock() as rsps:
            rsps.add("GET", resp["jwks_uri"], body=iss_jwks, status=200)

            self.service.update_service_context(resp, "")

        # static client registration
        _context.map_preferred_to_registered()

        use_copy = self.service.upstream_get("context").claims.use.copy()
        # jwks content will change dynamically between runs
        assert "jwks" in use_copy
        del use_copy["jwks"]
        del use_copy["callback_uris"]

        assert use_copy == {
            "application_type": "web",
            "backchannel_logout_session_required": True,
            "backchannel_logout_uri": "https://rp.example.com/back",
            "client_id": "client_id",
            "client_secret": "a longesh password",
            "contacts": ["ops@example.org"],
            "default_max_age": 86400,
            "encrypt_id_token_supported": False,
            "encrypt_request_object_supported": False,
            "encrypt_userinfo_supported": False,
            "grant_types": ["authorization_code"],
            "id_token_signed_response_alg": "RS256",
            "post_logout_redirect_uris": ["https://rp.example.com/post"],
            "redirect_uris": ["https://example.com/cli/authz_cb"],
            "request_object_signing_alg": "ES256",
            "response_modes": ["query", "fragment", "form_post"],
            "response_types": ["code"],
            "scope": ["openid"],
            "subject_type": "public",
            "token_endpoint_auth_method": "private_key_jwt",
            "token_endpoint_auth_signing_alg": "ES256",
            "userinfo_signed_response_alg": "ES256",
        }

    def test_post_parse_2(self):
        OP_BASEURL = ISS

        provider_info_response = {
            "version": "3.0",
            "token_endpoint_auth_methods_supported": [
                "client_secret_post",
                "client_secret_basic",
                "client_secret_jwt",
                "private_key_jwt",
            ],
            "issuer": OP_BASEURL,
            "jwks_uri": "{}/static/jwks_tE2iLbOAqXhe8bqh.json".format(OP_BASEURL),
            "authorization_endpoint": "{}/authorization".format(OP_BASEURL),
            "token_endpoint": "{}/token".format(OP_BASEURL),
            "userinfo_endpoint": "{}/userinfo".format(OP_BASEURL),
            "registration_endpoint": "{}/registration".format(OP_BASEURL),
            "end_session_endpoint": "{}/end_session".format(OP_BASEURL),
        }
        _context = self.service.upstream_get("context")
        assert set(_context.claims.use.keys()) == {
            'application_type',
            'backchannel_logout_session_required',
            'backchannel_logout_uri',
            'callback_uris',
            'client_id',
            'client_secret',
            'contacts',
            'default_max_age',
            'encrypt_id_token_supported',
            'encrypt_request_object_supported',
            'encrypt_userinfo_supported',
            'grant_types',
            'id_token_signed_response_alg',
            'jwks',
            'post_logout_redirect_uris',
            'redirect_uris',
            'request_object_signing_alg',
            'response_modes',
            'response_types',
            'scope',
            'subject_type',
            'token_endpoint_auth_method',
            'token_endpoint_auth_signing_alg',
            'userinfo_signed_response_alg'}
        resp = self.service.post_parse_response(provider_info_response)

        iss_jwks = ISS_KEY.export_jwks_as_json(issuer_id=ISS)
        with responses.RequestsMock() as rsps:
            rsps.add("GET", resp["jwks_uri"], body=iss_jwks, status=200)

            self.service.update_service_context(resp, "")

        # static client registration
        _context.map_preferred_to_registered()

        use_copy = self.service.upstream_get("context").claims.use.copy()
        # jwks content will change dynamically between runs
        assert "jwks" in use_copy
        del use_copy["jwks"]
        del use_copy["callback_uris"]

        assert use_copy == {
            "application_type": "web",
            "backchannel_logout_session_required": True,
            "backchannel_logout_uri": "https://rp.example.com/back",
            "client_id": "client_id",
            "client_secret": "a longesh password",
            "contacts": ["ops@example.org"],
            "default_max_age": 86400,
            "encrypt_id_token_supported": False,
            "encrypt_request_object_supported": False,
            "encrypt_userinfo_supported": False,
            "grant_types": ["authorization_code"],
            "id_token_signed_response_alg": "RS256",
            "post_logout_redirect_uris": ["https://rp.example.com/post"],
            "redirect_uris": ["https://example.com/cli/authz_cb"],
            "request_object_signing_alg": "ES256",
            "response_modes": ["query", "fragment", "form_post"],
            "response_types": ["code"],
            "scope": ["openid"],
            "subject_type": "public",
            "token_endpoint_auth_method": "private_key_jwt",
            "token_endpoint_auth_signing_alg": "ES256",
            "userinfo_signed_response_alg": "ES256",
        }


def test_response_types_to_grant_types():
    req_args = ["code"]
    assert set(response_types_to_grant_types(req_args)) == {"authorization_code"}
    req_args = ["code", "code id_token"]
    assert set(response_types_to_grant_types(req_args)) == {"authorization_code", "implicit"}
    req_args = ["code", "id_token code", "code token id_token"]
    assert set(response_types_to_grant_types(req_args)) == {"authorization_code", "implicit"}


def create_jws(val):
    lifetime = 3600

    idts = IdToken(**val)

    return idts.to_jwt(
        key=ISS_KEY.get_signing_key("ec", issuer_id=ISS), algorithm="ES256", lifetime=lifetime
    )


class TestRegistration(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self._iss = ISS
        client_config = {
            "redirect_uris": ["https://example.com/cli/authz_cb"],
            "issuer": self._iss,
            "requests_dir": "requests",
            "base_url": "https://example.com/cli/",
        }
        entity = Entity(
            keyjar=make_keyjar(),
            config=client_config,
            services=DEFAULT_OIDC_SERVICES,
            client_type="oidc",
        )
        entity.get_context().issuer = "https://example.com"
        entity.get_context().map_supported_to_preferred()
        self.service = entity.get_service("registration")

    def test_construct(self):
        _req = self.service.construct()
        assert isinstance(_req, RegistrationRequest)
        assert set(_req.keys()) == {
            "application_type",
            "default_max_age",
            "grant_types",
            "id_token_signed_response_alg",
            "jwks",
            "redirect_uris",
            "request_object_signing_alg",
            "response_modes",
            "response_types",
            "subject_type",
            "token_endpoint_auth_method",
            "token_endpoint_auth_signing_alg",
            "userinfo_signed_response_alg",
        }

    def test_config_with_post_logout(self):
        self.service.upstream_get("context").claims.set_preference(
            "post_logout_redirect_uri", "https://example.com/post_logout"
        )

        _req = self.service.construct()
        assert isinstance(_req, RegistrationRequest)
        assert set(_req.keys()) == {
            "application_type",
            "default_max_age",
            "grant_types",
            "id_token_signed_response_alg",
            "jwks",
            "post_logout_redirect_uri",
            "redirect_uris",
            "request_object_signing_alg",
            "response_modes",
            "response_types",
            "subject_type",
            "token_endpoint_auth_method",
            "token_endpoint_auth_signing_alg",
            "userinfo_signed_response_alg",
        }
        assert "post_logout_redirect_uri" in _req.keys()


def test_config_with_required_request_uri():
    client_config = {
        "client_id": "client_id",
        "client_secret": "a longesh password",
        "redirect_uris": ["https://example.com/cli/authz_cb"],
        "issuer": ISS,
        "requests_dir": "requests",
        "request_parameter": "request_uri",
        "request_uris": ["https://example.com/cli/requests"],
        "base_url": "https://example.com/cli",
    }
    entity = Entity(
        keyjar=make_keyjar(),
        config=client_config,
        services=DEFAULT_OIDC_SERVICES,
        client_type="oidc",
    )
    entity.get_context().issuer = "https://example.com"

    pi_service = entity.get_service("provider_info")
    pi_service.match_preferences({"require_request_uri_registration": True})

    reg_service = entity.get_service("registration")
    _req = reg_service.construct()
    assert isinstance(_req, RegistrationRequest)
    assert set(_req.keys()) == {
        "application_type",
        "response_modes",
        "response_types",
        "jwks",
        "redirect_uris",
        "grant_types",
        "id_token_signed_response_alg",
        "request_uris",
        "default_max_age",
        "request_object_signing_alg",
        "subject_type",
        "token_endpoint_auth_method",
        "token_endpoint_auth_signing_alg",
        "userinfo_signed_response_alg",
    }


def test_config_logout_uri():
    client_config = {
        "client_id": "client_id",
        "client_secret": "a longesh password",
        "redirect_uris": ["https://example.com/cli/authz_cb"],
        "issuer": ISS,
        "requests_dir": "requests",
        "request_uris": ["https://example.com/cli/requests"],
        "base_url": "https://example.com/cli/",
        "preference": {
            "request_parameter": "request_uri",
            "request_object_signing_alg": "ES256",
            "token_endpoint_auth_method": "private_key_jwt",
            "token_endpoint_auth_signing_alg": "ES256",
            "userinfo_signed_response_alg": "ES256",
            "post_logout_redirect_uri": "https://rp.example.com/post",
            "backchannel_logout_uri": "https://rp.example.com/back",
            "backchannel_logout_session_required": True,
            "backchannel_logout_supported": True,
        },
    }
    entity = Entity(
        keyjar=make_keyjar(),
        config=client_config,
        services=DEFAULT_OIDC_SERVICES,
        client_type="oidc",
    )
    _context = entity.get_context()
    _context.issuer = "https://example.com"

    pi_service = entity.get_service("provider_info")
    _pi = {"require_request_uri_registration": True, "backchannel_logout_supported": True}
    pi_service.match_preferences(_pi)

    reg_service = entity.get_service("registration")
    _req = reg_service.construct()
    assert isinstance(_req, RegistrationRequest)
    assert set(_req.keys()) == {
        "application_type",
        "default_max_age",
        "grant_types",
        "id_token_signed_response_alg",
        "jwks",
        "redirect_uris",
        "request_object_signing_alg",
        "request_uris",
        "response_modes",
        "response_types",
        "subject_type",
        "token_endpoint_auth_method",
        "token_endpoint_auth_signing_alg",
        "userinfo_signed_response_alg",
    }


class TestUserInfo(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self._iss = ISS
        client_config = {
            "client_id": "client_id",
            "client_secret": "a longesh password",
            "redirect_uris": ["https://example.com/cli/authz_cb"],
            "issuer": self._iss,
            "requests_dir": "requests",
            "base_url": "https://example.com/cli/",
        }
        entity = Entity(
            keyjar=make_keyjar(),
            config=client_config,
            services=DEFAULT_OIDC_SERVICES,
            client_type="oidc",
        )
        entity.get_context().issuer = "https://example.com"
        self.service = entity.get_service("userinfo")

        entity.get_context().claims.use = {
            "userinfo_signed_response_alg": "RS256",
            "userinfo_encrypted_response_alg": "RSA-OAEP",
            "userinfo_encrypted_response_enc": "A256GCM",
        }

        _cstate = self.service.upstream_get("context").cstate
        # Add history
        auth_response = AuthorizationResponse(code="access_code")
        _cstate.update("abcde", auth_response)

        idtval = {"nonce": "KUEYfRM2VzKDaaKD", "sub": "diana", "iss": ISS, "aud": "client_id"}
        idt = create_jws(idtval)

        ver_idt = IdToken().from_jwt(idt, make_keyjar())

        token_response = AccessTokenResponse(
            access_token="access_token", id_token=idt, __verified_id_token=ver_idt
        )
        _cstate.update("abcde", token_response)

    def test_construct(self):
        _req = self.service.construct(state="abcde")
        assert isinstance(_req, Message)
        assert len(_req) == 1
        assert "access_token" in _req

    def test_unpack_simple_response(self):
        resp = OpenIDSchema(sub="diana", given_name="Diana", family_name="krall")
        _resp = self.service.parse_response(resp.to_json(), state="abcde")
        assert _resp

    def test_unpack_aggregated_response(self):
        claims = {
            "address": {
                "street_address": "1234 Hollywood Blvd.",
                "locality": "Los Angeles",
                "region": "CA",
                "postal_code": "90210",
                "country": "US",
            },
            "phone_number": "+1 (555) 123-4567",
        }

        srv = JWT(ISS_KEY, iss=ISS, sign_alg="ES256")
        _jwt = srv.pack(payload=claims)

        resp = OpenIDSchema(
            sub="diana",
            given_name="Diana",
            family_name="krall",
            _claim_names={"address": "src1", "phone_number": "src1"},
            _claim_sources={"src1": {"JWT": _jwt}},
        )

        _resp = self.service.parse_response(resp.to_json(), state="abcde")
        _resp = self.service.post_parse_response(_resp, state="abcde")
        assert set(_resp.keys()) == {
            "sub",
            "given_name",
            "family_name",
            "_claim_names",
            "_claim_sources",
            "address",
            "phone_number",
        }

    def test_unpack_aggregated_response_missing_keys(self):
        claims = {
            "address": {
                "street_address": "1234 Hollywood Blvd.",
                "locality": "Los Angeles",
                "region": "CA",
                "postal_code": "90210",
                "country": "US",
            },
            "phone_number": "+1 (555) 123-4567",
        }

        _keyjar = build_keyjar(KEYSPEC)

        srv = JWT(_keyjar, iss=ISS, sign_alg="ES256")
        _jwt = srv.pack(payload=claims)

        resp = OpenIDSchema(
            sub="diana",
            given_name="Diana",
            family_name="krall",
            _claim_names={"address": "src1", "phone_number": "src1"},
            _claim_sources={"src1": {"JWT": _jwt}},
        )

        _resp = self.service.parse_response(resp.to_json(), state="abcde")
        assert _resp

    def test_unpack_signed_response(self):
        resp = OpenIDSchema(sub="diana", given_name="Diana", family_name="krall", iss=ISS)
        sk = ISS_KEY.get_signing_key("rsa", issuer_id=ISS)
        alg = self.service.upstream_get("context").get_sign_alg("userinfo")
        _resp = self.service.parse_response(
            resp.to_jwt(sk, algorithm=alg), state="abcde", sformat="jwt"
        )
        assert _resp

    def test_unpack_encrypted_response(self):
        # Add encryption key
        _kj = build_keyjar([{"type": "RSA", "use": ["enc"]}], issuer_id="")
        # Own key jar gets the private key
        self.service.upstream_get("attribute", "keyjar").import_jwks(
            _kj.export_jwks(private=True), issuer_id="client_id"
        )
        # opponent gets the public key
        ISS_KEY.import_jwks(_kj.export_jwks(), issuer_id="client_id")

        resp = OpenIDSchema(
            sub="diana", given_name="Diana", family_name="krall", iss=ISS, aud="client_id"
        )
        enckey = ISS_KEY.get_encrypt_key("rsa", issuer_id="client_id")
        algspec = self.service.upstream_get("context").get_enc_alg_enc(self.service.service_name)

        enc_resp = resp.to_jwe(enckey, **algspec)
        _resp = self.service.parse_response(enc_resp, state="abcde", sformat="jwe")
        assert _resp


class TestCheckSession(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self._iss = ISS
        client_config = {
            "client_id": "client_id",
            "client_secret": "a longesh password",
            "redirect_uris": ["https://example.com/cli/authz_cb"],
            "issuer": self._iss,
            "requests_dir": "requests",
            "base_url": "https://example.com/cli/",
        }
        services = {"checksession": {"class": "idpyoidc.client.oidc.check_session.CheckSession"}}
        entity = Entity(keyjar=make_keyjar(), config=client_config, services=services)
        entity.get_context().issuer = "https://example.com"
        self.service = entity.get_service("check_session")

    def test_construct(self):
        _cstate = self.service.upstream_get("service_context").cstate
        _cstate.update("abcde", {"id_token": "a.signed.jwt"})
        _req = self.service.construct(state="abcde")
        assert isinstance(_req, CheckSessionRequest)
        assert len(_req) == 1
        assert "id_token" in _req
        assert _req["id_token"] == "a.signed.jwt"


class TestCheckID(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self._iss = ISS
        client_config = {
            "client_id": "client_id",
            "client_secret": "a longesh password",
            "redirect_uris": ["https://example.com/cli/authz_cb"],
            "issuer": self._iss,
            "requests_dir": "requests",
            "base_url": "https://example.com/cli/",
        }
        services = {"checksession": {"class": "idpyoidc.client.oidc.check_id.CheckID"}}
        entity = Entity(keyjar=make_keyjar(), config=client_config, services=services)
        entity.get_context().issuer = "https://example.com"
        self.service = entity.get_service("check_id")

    def test_construct(self):
        _cstate = self.service.upstream_get("service_context").cstate
        _cstate.set("abcde", {"id_token": "a.signed.jwt"})
        _req = self.service.construct(state="abcde")
        assert isinstance(_req, CheckIDRequest)
        assert len(_req) == 1
        assert "id_token" in _req
        assert _req["id_token"] == "a.signed.jwt"


class TestEndSession(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self._iss = ISS
        client_config = {
            "client_id": "client_id",
            "client_secret": "a longesh password",
            "redirect_uris": ["https://example.com/cli/authz_cb"],
            "issuer": self._iss,
            "requests_dir": "requests",
            "base_url": "https://example.com/cli/",
            "post_logout_redirect_uris": ["https://example.com/post_logout"],
        }
        services = {"checksession": {"class": "idpyoidc.client.oidc.end_session.EndSession"}}
        entity = Entity(keyjar=make_keyjar(), config=client_config, services=services)
        _context = entity.get_context()
        _context.issuer = "https://example.com"
        _context.map_supported_to_preferred()
        _context.map_preferred_to_registered()
        self.service = entity.get_service("end_session")

    def test_construct(self):
        self.service.upstream_get("service_context").cstate.update(
            "abcde", {"id_token": "a.signed.jwt"}
        )
        _req = self.service.construct(state="abcde")
        assert isinstance(_req, EndSessionRequest)
        assert len(_req) == 3
        assert set(_req.keys()) == {"state", "id_token_hint", "post_logout_redirect_uri"}


def test_authz_service_conf():
    client_config = {
        "client_id": "client_id",
        "client_secret": "a longesh password",
        "redirect_uris": ["https://example.com/cli/authz_cb"],
        "response_types": ["code", "id_token"],
    }

    services = {
        "authz": {
            "class": "idpyoidc.client.oidc.authorization.Authorization",
            "kwargs": {
                "request_args": {
                    "claims": {
                        "id_token": {
                            "auth_time": {"essential": True},
                            "acr": {"values": ["urn:mace:incommon:iap:silver"]},
                        }
                    }
                }
            },
        }
    }
    entity = Entity(
        keyjar=make_keyjar(), config=client_config, services=services, client_type="oidc"
    )
    _context = entity.get_context()
    _context.issuer = "https://example.com"
    _context.map_supported_to_preferred()
    _context.map_preferred_to_registered()
    service = entity.get_service("authorization")

    req = service.construct()
    assert set(req.keys()) == {
        "claims",
        "client_id",
        "nonce",
        "redirect_uri",
        "response_type",
        "scope",
        "state",
    }

    assert set(req["claims"].keys()) == {"id_token"}


def test_jwks_uri_conf():
    client_config = {
        "client_secret": "a longesh password",
        "issuer": ISS,
        "client_id": "client_id",
        "jwks_uri": "https://example.com/jwks/jwks.json",
        "redirect_uris": ["https://example.com/cli/authz_cb"],
        "id_token_signed_response_alg": "RS384",
        "userinfo_signed_response_alg": "RS384",
    }
    entity = Entity(
        keyjar=make_keyjar(),
        config=client_config,
        services=DEFAULT_OIDC_SERVICES,
        client_type="oidc",
    )
    _context = entity.get_context()
    _context.issuer = "https://example.com"
    _context.map_supported_to_preferred()
    _context.map_preferred_to_registered()

    assert _context.get_usage("jwks_uri")


def test_jwks_uri_arg():
    client_config = {
        "client_secret": "a longesh password",
        "issuer": ISS,
        "client_id": "client_id",
        "redirect_uris": ["https://example.com/cli/authz_cb"],
        "jwks_uri": "https://example.com/jwks/jwks.json",
        "preference": {
            "id_token_signed_response_alg": "RS384",
            "userinfo_signed_response_alg": "RS384",
        },
    }
    entity = Entity(
        keyjar=make_keyjar(),
        config=client_config,
        services=DEFAULT_OIDC_SERVICES,
        client_type="oidc",
    )
    _context = entity.get_context()
    _context.issuer = "https://example.com"
    _context.map_supported_to_preferred()
    _context.map_preferred_to_registered()

    assert _context.get_usage("jwks_uri")
