import base64
import os

import pytest
from cryptojwt.exception import MissingKey
from cryptojwt.jws.jws import factory
from cryptojwt.jws.jws import JWS
from cryptojwt.jwt import JWT
from cryptojwt.key_bundle import KeyBundle
from cryptojwt.key_jar import init_key_jar
from cryptojwt.key_jar import KeyJar

from idpyoidc.claims import Claims
from idpyoidc.client.client_auth import assertion_jwt
from idpyoidc.client.client_auth import AuthnFailure
from idpyoidc.client.client_auth import bearer_auth
from idpyoidc.client.client_auth import BearerBody
from idpyoidc.client.client_auth import BearerHeader
from idpyoidc.client.client_auth import ClientSecretBasic
from idpyoidc.client.client_auth import ClientSecretJWT
from idpyoidc.client.client_auth import ClientSecretPost
from idpyoidc.client.client_auth import PrivateKeyJWT
from idpyoidc.client.client_auth import valid_service_context
from idpyoidc.client.entity import Entity
from idpyoidc.defaults import JWT_BEARER
from idpyoidc.key_import import add_kb
from idpyoidc.key_import import import_jwks
from idpyoidc.message import Message
from idpyoidc.message.oauth2 import AccessTokenRequest
from idpyoidc.message.oauth2 import AccessTokenResponse
from idpyoidc.message.oauth2 import AuthorizationRequest
from idpyoidc.message.oauth2 import AuthorizationResponse
from idpyoidc.message.oauth2 import CCAccessTokenRequest
from idpyoidc.message.oauth2 import ResourceRequest

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
CLIENT_ID = "A"

KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

CLIENT_CONF = {
    "issuer": "https://example.com/as",
    # "redirect_uris": ["https://example.com/cli/authz_cb"],
    "client_secret": "white boarding pass",
    "client_id": CLIENT_ID,
    "key_conf": {"key_defs": KEYSPEC},
}

KEY_CONF = {
    "key_defs": [
        {"type": "RSA", "key": "", "use": ["sig"]},
        {"type": "EC", "crv": "P-256", "use": ["sig"]},
    ],
    "read_only": False,
}


def _eq(l1, l2):
    return set(l1) == set(l2)


@pytest.fixture
def entity():
    keyjar = init_key_jar(**KEY_CONF)
    _entity = Entity(
        config=CLIENT_CONF,
        services={
            "base": {"class": "idpyoidc.client.service.Service"},
            "accesstoken": {"class": "idpyoidc.client.oidc.access_token.AccessToken", "kwargs": {}},
        },
        keyjar=keyjar,
        client_type="oidc",
    )
    # The following two lines is necessary since they replace provider info collection and
    # client registration.
    _entity.get_service_context().map_supported_to_preferred()
    _entity.get_service_context().map_preferred_to_registered()
    return _entity


def test_quote():
    csb = ClientSecretBasic()
    http_args = csb.construct(
        Message(),
        password="MKEM/A7Pkn7JuU0LAcxyHVKvwdczsugaPU0BieLb4CbQAgQj+ypcanFOCb0/FA5h",
        user="796d8fae-a42f-4e4f-ab25-d6205b6d4fa2",
    )

    assert (
            http_args["headers"]["Authorization"] == "Basic "
                                                     "Nzk2ZDhmYWUtYTQyZi00ZTRmLWFiMjUtZDYyMDViNmQ0ZmEyOk1LRU0vQTdQa243SnVVMExBY3h5SFZLdndkY3pzdWdhUFUwQmllTGI0Q2JRQWdRait5cGNhbkZPQ2IwL0ZBNWg="
    )


class TestClientSecretBasic(object):

    def test_construct(self, entity):
        _service = entity.get_service("")
        request = _service.construct(
            request_args={"redirect_uri": "http://example.com", "state": "ABCDE"}
        )

        csb = ClientSecretBasic()
        http_args = csb.construct(request, _service)

        _authz = http_args["headers"]["Authorization"]
        assert _authz.startswith("Basic ")
        _token = _authz.split(" ", 1)[1]
        assert base64.urlsafe_b64decode(_token) == b"A:white boarding pass"

    def test_does_not_remove_padding(self):
        request = AccessTokenRequest(code="foo", redirect_uri="http://example.com")

        csb = ClientSecretBasic()
        http_args = csb.construct(request, user="ab", password="c")

        assert http_args["headers"]["Authorization"].endswith("==")

    def test_construct_cc(self):
        """CC == Client Credentials, the 4th OAuth2 flow"""
        request = CCAccessTokenRequest(grant_type="client_credentials")

        csb = ClientSecretBasic()
        http_args = csb.construct(request, user="service1", password="secret")

        assert http_args["headers"]["Authorization"].startswith("Basic ")


class TestBearerHeader(object):

    def test_construct(self, entity):
        request = ResourceRequest(access_token="Sesame")
        bh = BearerHeader()
        http_args = bh.construct(request, service=entity.get_service(""))

        assert http_args == {"headers": {"Authorization": "Bearer Sesame"}}

    def test_construct_with_http_args(self, entity):
        request = ResourceRequest(access_token="Sesame")
        bh = BearerHeader()
        # Any HTTP args should just be passed on
        http_args = bh.construct(request, service=entity.get_service(""), http_args={"foo": "bar"})

        assert _eq(http_args.keys(), ["foo", "headers"])
        assert http_args["headers"] == {"Authorization": "Bearer Sesame"}

    def test_construct_with_headers_in_http_args(self, entity):
        request = ResourceRequest(access_token="Sesame")

        bh = BearerHeader()
        http_args = bh.construct(
            request,
            service=entity.get_service(""),
            http_args={"headers": {"x-foo": "bar"}},
        )

        assert _eq(http_args.keys(), ["headers"])
        assert _eq(http_args["headers"].keys(), ["Authorization", "x-foo"])
        assert http_args["headers"]["Authorization"] == "Bearer Sesame"

    def test_construct_with_resource_request(self, entity):
        bh = BearerHeader()
        request = ResourceRequest(access_token="Sesame")

        http_args = bh.construct(request, service=entity.get_service(""))

        assert "access_token" not in request
        assert http_args == {"headers": {"Authorization": "Bearer Sesame"}}

    def test_construct_with_token(self, entity):
        _service = entity.get_service("")
        srv_cntx = _service.upstream_get("context")
        _state = srv_cntx.cstate.create_key()
        srv_cntx.cstate.set(_state, {"iss": "Issuer"})
        req = AuthorizationRequest(
            state=_state, response_type="code", redirect_uri="https://example.com", scope=["openid"]
        )
        srv_cntx.cstate.update(_state, req)

        # Add a state and bind a code to it
        resp1 = AuthorizationResponse(code="auth_grant", state=_state)
        response = _service.parse_response(resp1.to_urlencoded(), "urlencoded")
        _service.update_service_context(response, key=_state)

        # based on state find the code and then get an access token
        resp2 = AccessTokenResponse(
            access_token="token1", token_type="Bearer", expires_in=0, state=_state
        )

        response = _service.parse_response(resp2.to_urlencoded(), "urlencoded")
        _service.upstream_get("service_context").cstate.update(_state, response)

        # and finally use the access token, bound to a state, to
        # construct the authorization header
        http_args = BearerHeader().construct(ResourceRequest(), _service, key=_state)
        assert http_args == {"headers": {"Authorization": "Bearer token1"}}


class TestBearerBody(object):

    def test_construct(self, entity):
        _token_service = entity.get_service("")
        request = ResourceRequest(access_token="Sesame")
        http_args = BearerBody().construct(request, service=_token_service)

        assert request["access_token"] == "Sesame"
        assert http_args is None

    def test_construct_with_state(self, entity):
        _auth_service = entity.get_service("accesstoken")
        _cntx = _auth_service.upstream_get("context")
        _key = _cntx.cstate.create_key()
        _cntx.cstate.set(_key, {"iss": "Issuer"})

        resp = AuthorizationResponse(code="code", state=_key)
        _cntx.cstate.update(_key, resp)

        atr = AccessTokenResponse(
            access_token="2YotnFZFEjr1zCsicMWpAA",
            token_type="example",
            refresh_token="tGzv3JOkF0XG5Qx2TlKWIA",
            example_parameter="example_value",
            scope=["inner", "outer"],
        )
        _cntx.cstate.update(_key, atr)

        request = ResourceRequest()
        http_args = BearerBody().construct(request, service=_auth_service, key=_key)
        assert request["access_token"] == "2YotnFZFEjr1zCsicMWpAA"
        assert http_args is None

    def test_construct_with_request(self, entity):
        authz_service = entity.get_service("")
        _cntx = authz_service.upstream_get("context")

        _key = _cntx.cstate.create_key()
        _cntx.cstate.set(_key, {"iss": "Issuer"})
        resp1 = AuthorizationResponse(code="auth_grant", state=_key)
        response = authz_service.parse_response(resp1.to_urlencoded(), "urlencoded")
        authz_service.update_service_context(response, key=_key)

        resp2 = AccessTokenResponse(
            access_token="token1", token_type="Bearer", expires_in=0, state=_key
        )
        _service2 = entity.get_service("")
        response = _service2.parse_response(resp2.to_urlencoded(), "urlencoded")
        _service2.upstream_get("service_context").cstate.update(_key, response)

        request = ResourceRequest()
        BearerBody().construct(request, service=authz_service, key=_key)

        assert "access_token" in request
        assert request["access_token"] == "token1"


class TestClientSecretPost(object):

    def test_construct(self, entity):
        _token_service = entity.get_service("")
        request = _token_service.construct(
            request_args={"redirect_uri": "http://example.com", "state": "ABCDE"}
        )
        csp = ClientSecretPost()
        http_args = csp.construct(request, service=_token_service)

        assert request["client_id"] == "A"
        assert request["client_secret"] == "white boarding pass"
        assert http_args is None

        request = AccessTokenRequest(code="foo", redirect_uri="http://example.com")
        http_args = csp.construct(request, service=_token_service, client_secret="another")
        assert request["client_id"] == "A"
        assert request["client_secret"] == "another"
        assert http_args is None

    def test_modify_1(self, entity):
        token_service = entity.get_service("")
        request = token_service.construct(
            request_args={"redirect_uri": "http://example.com", "state": "ABCDE"}
        )
        csp = ClientSecretPost()
        http_args = csp.construct(request, service=token_service)
        assert "client_secret" in request

    def test_modify_2(self, entity):
        _service = entity.get_service("")
        request = _service.construct(
            request_args={"redirect_uri": "http://example.com", "state": "ABCDE"}
        )
        csp = ClientSecretPost()
        _service.upstream_get("context").set_usage("client_secret", "")
        # this will fail
        with pytest.raises(AuthnFailure):
            http_args = csp.construct(request, service=_service)


class TestPrivateKeyJWT(object):

    def test_construct(self, entity):
        token_service = entity.get_service("")
        kb_rsa = KeyBundle(
            source="file://{}".format(os.path.join(BASE_PATH, "data/keys/rsa.key")),
            fileformat="der",
        )

        for key in kb_rsa:
            key.add_kid()

        _context = token_service.upstream_get("context")
        _keyjar = token_service.upstream_get("attribute", "keyjar")
        _keyjar.add_kb("", kb_rsa)
        _context.provider_info = {
            "issuer": "https://example.com/",
            "token_endpoint": "https://example.com/token",
        }
        _context.registration_response = {"token_endpoint_auth_signing_alg": "RS256"}
        token_service.endpoint = "https://example.com/token"

        request = AccessTokenRequest()
        pkj = PrivateKeyJWT()
        http_args = pkj.construct(request, service=token_service, authn_endpoint="token_endpoint")
        assert http_args == {}
        cas = request["client_assertion"]

        # Receiver
        _kj = KeyJar()
        _kj = import_jwks(_kj, _keyjar.export_jwks(), _context.get_client_id())
        _kj = add_kb(_kj, kb_rsa, _context.get_client_id())
        jso = JWT(key_jar=_kj).unpack(cas)
        assert _eq(jso.keys(), ["aud", "iss", "sub", "jti", "exp", "iat"])
        # assert _jwt.headers == {'alg': 'RS256'}
        assert jso["aud"] == [_context.provider_info["token_endpoint"]]

    def test_construct_client_assertion(self, entity):
        token_service = entity.get_service("")

        kb_rsa = KeyBundle(
            source="file://{}".format(os.path.join(BASE_PATH, "data/keys/rsa.key")),
            fileformat="der",
        )

        request = AccessTokenRequest()
        pkj = PrivateKeyJWT()
        _ca = assertion_jwt(
            token_service.upstream_get("context").get_client_id(),
            kb_rsa.get("RSA"),
            "https://example.com/token",
            "RS256",
        )
        http_args = pkj.construct(request, client_assertion=_ca)
        assert http_args == {}
        assert request["client_assertion"] == _ca
        assert request["client_assertion_type"] == JWT_BEARER


class TestClientSecretJWT_TE(object):

    def test_client_secret_jwt(self, entity):
        _service_context = entity.get_context()
        _service_context.token_endpoint = "https://example.com/token"

        _service_context.provider_info = {
            "issuer": "https://example.com/",
            "token_endpoint": "https://example.com/token",
        }

        # This is not the default
        _service_context.set_usage("token_endpoint_auth_signing_alg", "HS256")

        csj = ClientSecretJWT()
        request = AccessTokenRequest()

        csj.construct(request, service=entity.get_service(""), authn_endpoint="token_endpoint")
        assert request["client_assertion_type"] == JWT_BEARER
        assert "client_assertion" in request
        cas = request["client_assertion"]

        _kj = KeyJar()
        _kj.add_symmetric(
            _service_context.get_client_id(), _service_context.get_usage("client_secret"), ["sig"]
        )
        jso = JWT(key_jar=_kj, sign_alg="HS256").unpack(cas)
        assert _eq(jso.keys(), ["aud", "iss", "sub", "exp", "iat", "jti"])

        _rj = JWS(alg="HS256")
        info = _rj.verify_compact(
            cas, _kj.get_signing_key(issuer_id=_service_context.get_client_id())
        )

        assert _eq(info.keys(), ["aud", "iss", "sub", "jti", "exp", "iat"])
        assert info["aud"] == [_service_context.provider_info["token_endpoint"]]

    def test_get_key_by_kid(self, entity):
        _service_context = entity.get_context()
        _service_context.token_endpoint = "https://example.com/token"

        _service_context.provider_info = {
            "issuer": "https://example.com/",
            "token_endpoint": "https://example.com/token",
        }

        _service_context.set_usage("token_endpoint_auth_signing_alg", "HS256")

        csj = ClientSecretJWT()
        request = AccessTokenRequest()

        # get a kid for a symmetric key
        kid = ""
        for _key in entity.get_attribute("keyjar").get_issuer_keys(""):
            if _key.kty == "oct":
                kid = _key.kid
                break

        # token_service = entity.get_service("")
        token_service = entity.get_service("accesstoken")
        csj.construct(request, service=token_service, authn_endpoint="token_endpoint", kid=kid)
        assert "client_assertion" in request

    def test_get_key_by_kid_fail(self, entity):
        token_service = entity.get_service("")
        _service_context = token_service.upstream_get("context")
        _service_context.token_endpoint = "https://example.com/token"

        _service_context.provider_info = {
            "issuer": "https://example.com/",
            "token_endpoint": "https://example.com/token",
        }

        _service_context.set_usage("token_endpoint_auth_signing_alg", "HS256")

        csj = ClientSecretJWT()
        request = AccessTokenRequest()

        # get a kid
        kid = "abcdefgh"
        with pytest.raises(MissingKey):
            csj.construct(request, service=token_service, authn_endpoint="token_endpoint", kid=kid)

    def test_get_audience_and_algorithm_default_alg(self, entity):
        _service_context = entity.get_context()
        _service_context.token_endpoint = "https://example.com/token"

        _service_context.provider_info = {
            "issuer": "https://example.com/",
            "token_endpoint": "https://example.com/token",
        }

        # This is the default so this line is unnecessary
        # _service_context.set_usage("token_endpoint_auth_signing_alg", "RS256")

        csj = ClientSecretJWT()
        request = AccessTokenRequest()

        # No preference -> default == RS256
        _service_context.registration_response = {}

        token_service = entity.get_service("")

        # Since I have an RSA key this doesn't fail
        csj.construct(request, service=token_service, authn_endpoint="token_endpoint")

        _rsa_key = entity.keyjar.get(key_use="sig", key_type="rsa", issuer_id="")[0]
        _jws = factory(request["client_assertion"])
        assert _jws.jwt.headers["alg"] == "RS256"
        _rsa_key = entity.keyjar.get_signing_key(key_type="RSA")[0]
        assert _jws.jwt.headers["kid"] == _rsa_key.kid

        # By client preferences
        request = AccessTokenRequest()
        _service_context.set_usage("token_endpoint_auth_signing_alg", "RS512")
        csj.construct(request, service=token_service, authn_endpoint="token_endpoint")

        _jws = factory(request["client_assertion"])
        assert _jws.jwt.headers["alg"] == "RS512"
        assert _jws.jwt.headers["kid"] == _rsa_key.kid

        # Use provider information is everything else fails
        request = AccessTokenRequest()
        _service_context.claims = Claims()
        _service_context.provider_info["token_endpoint_auth_signing_alg_values_supported"] = [
            "ES256",
            "RS256",
        ]
        csj.construct(request, service=token_service, authn_endpoint="token_endpoint")

        _ec_key = entity.keyjar.get(key_use="sig", key_type="ec", issuer_id="")[0]
        _jws = factory(request["client_assertion"])
        # Should be ES256 since I have a key for ES256
        assert _jws.jwt.headers["alg"] == "ES256"
        _ec_key = entity.keyjar.get_signing_key(key_type="EC")[0]
        assert _jws.jwt.headers["kid"] == _ec_key.kid


class TestClientSecretJWT_UI(object):

    def test_client_secret_jwt(self, entity):
        access_token_service = entity.get_service("")

        _service_context = access_token_service.upstream_get("context")
        _service_context.token_endpoint = "https://example.com/token"
        _service_context.provider_info = {
            "issuer": "https://example.com/",
            "token_endpoint": "https://example.com/token",
        }

        csj = ClientSecretJWT()
        request = AccessTokenRequest()

        csj.construct(
            request, service=access_token_service, algorithm="HS256", authn_endpoint="userinfo"
        )
        assert request["client_assertion_type"] == JWT_BEARER
        assert "client_assertion" in request
        cas = request["client_assertion"]

        _kj = KeyJar()
        _kj.add_symmetric(
            _service_context.get_client_id(),
            _service_context.get_usage("client_secret"),
            usage=["sig"],
        )
        jso = JWT(key_jar=_kj, sign_alg="HS256").unpack(cas)
        assert _eq(jso.keys(), ["aud", "iss", "sub", "jti", "exp", "iat"])

        _rj = JWS(alg="HS256")
        info = _rj.verify_compact(
            cas, _kj.get_signing_key(issuer_id=_service_context.get_client_id())
        )

        assert _eq(info.keys(), ["aud", "iss", "sub", "jti", "exp", "iat"])
        assert info["aud"] == [_service_context.provider_info["issuer"]]


class TestValidClientInfo(object):

    def test_valid_service_context(self, entity):
        _service_context = entity.get_context()

        _now = 123456  # At some time
        # Expiration time missing or 0, client_secret never expires
        # service_context.client_secret_expires_at
        assert valid_service_context(_service_context, _now)
        assert valid_service_context(_service_context, _now)
        # Expired secret
        _service_context.client_secret_expires_at = 1
        assert valid_service_context(_service_context, _now) is not True

        _service_context.client_secret_expires_at = 123455
        assert valid_service_context(_service_context, _now) is not True

        # Valid secret
        _service_context.client_secret_expires_at = 123460
        assert valid_service_context(_service_context, _now)


def test_bearer_auth():
    request = ResourceRequest(access_token="12345678")
    authn = ""
    assert bearer_auth(request, authn) == "12345678"

    request = ResourceRequest()
    authn = "Bearer abcdefghijklm"
    assert bearer_auth(request, authn) == "abcdefghijklm"

    request = ResourceRequest()
    authn = ""
    with pytest.raises(ValueError):
        bearer_auth(request, authn)
