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


class TestClientSecretBasic(object):

    @pytest.fixture(autouse=True)
    def entity(self):
        keyjar = init_key_jar(**KEY_CONF)
        self.entity = Entity(
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
        self.entity.context[''].map_supported_to_preferred()
        self.entity.context[''].map_preferred_to_registered()
        self.context = self.entity.context['']

    def test_quote(self):
        csb = ClientSecretBasic()
        http_args = csb.construct(
            self.entity.get_context(''),
            Message(),
            password="MKEM/A7Pkn7JuU0LAcxyHVKvwdczsugaPU0BieLb4CbQAgQj+ypcanFOCb0/FA5h",
            user="796d8fae-a42f-4e4f-ab25-d6205b6d4fa2",
        )

        assert (
                http_args["headers"]["Authorization"] == "Basic "
                                                         'Nzk2ZDhmYWUtYTQyZi00ZTRmLWFiMjUtZDYyMDViNmQ0ZmEyOk1LRU0lMkZBN1BrbjdKdVUwTEFjeHlIVkt2d2RjenN1Z2FQVTBCaWVMYjRDYlFBZ1FqJTJCeXBjYW5GT0NiMCUyRkZBNWg='
        )

    def test_construct(self):
        _service = self.entity.get_service(self.context, "")
        request = _service.construct(
            self.context,
            request_args={"redirect_uri": "http://example.com", "state": "ABCDE"}
        )

        csb = ClientSecretBasic()
        http_args = csb.construct(self.context, request, _service)

        _authz = http_args["headers"]["Authorization"]
        assert _authz.startswith("Basic ")
        _token = _authz.split(" ", 1)[1]
        assert base64.urlsafe_b64decode(_token) == b'A:white+boarding+pass'

    def test_does_not_remove_padding(self):
        request = AccessTokenRequest(code="foo", redirect_uri="http://example.com")

        csb = ClientSecretBasic()
        http_args = csb.construct(self.context, request, user="ab", password="c")

        assert http_args["headers"]["Authorization"].endswith("==")

    def test_construct_cc(self):
        """CC == Client Credentials, the 4th OAuth2 flow"""
        request = CCAccessTokenRequest(grant_type="client_credentials")

        csb = ClientSecretBasic()
        http_args = csb.construct(self.context, request, user="service1", password="secret")

        assert http_args["headers"]["Authorization"].startswith("Basic ")

    def test_http_id(self):
        request = AccessTokenRequest(code="foo", redirect_uri="http://example.com")

        csb = ClientSecretBasic()
        http_args = csb.construct(self.context, request, user="https://entity.example.org", password="client_secret")

        _authz = http_args["headers"]["Authorization"]
        assert _authz.startswith("Basic ")
        _token = _authz.split(" ", 1)[1]
        assert base64.urlsafe_b64decode(_token) == b'https%3A%2F%2Fentity.example.org:client_secret'


class TestBearerHeader(object):

    @pytest.fixture(autouse=True)
    def entity(self):
        keyjar = init_key_jar(**KEY_CONF)
        self.entity = Entity(
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
        self.entity.context[''].map_supported_to_preferred()
        self.entity.context[''].map_preferred_to_registered()
        self.context = self.entity.context['']

    def test_construct(self):
        request = ResourceRequest(access_token="Sesame")
        bh = BearerHeader()
        http_args = bh.construct(self.context, request, service=self.entity.get_service(self.context, ""))

        assert http_args == {"headers": {"Authorization": "Bearer Sesame"}}

    def test_construct_with_http_args(self):
        request = ResourceRequest(access_token="Sesame")
        bh = BearerHeader()
        # Any HTTP args should just be passed on
        http_args = bh.construct(self.context, request, service=self.entity.get_service(self.context, ""),
                                 http_args={"foo": "bar"})

        assert _eq(http_args.keys(), ["foo", "headers"])
        assert http_args["headers"] == {"Authorization": "Bearer Sesame"}

    def test_construct_with_headers_in_http_args(self):
        request = ResourceRequest(access_token="Sesame")

        bh = BearerHeader()
        http_args = bh.construct(
            self.context,
            request,
            service=self.entity.get_service(self.context, ""),
            http_args={"headers": {"x-foo": "bar"}},
        )

        assert _eq(http_args.keys(), ["headers"])
        assert _eq(http_args["headers"].keys(), ["Authorization", "x-foo"])
        assert http_args["headers"]["Authorization"] == "Bearer Sesame"

    def test_construct_with_resource_request(self):
        bh = BearerHeader()
        request = ResourceRequest(access_token="Sesame")

        http_args = bh.construct(self.context, request, service=self.entity.get_service(self.context, ""))

        assert "access_token" not in request
        assert http_args == {"headers": {"Authorization": "Bearer Sesame"}}

    def test_construct_with_token(self):
        _service = self.entity.get_service(self.context, "")
        _state = self.context.cstate.create_key()
        self.context.cstate.set(_state, {"iss": "Issuer"})
        req = AuthorizationRequest(
            state=_state, response_type="code", redirect_uri="https://example.com", scope=["openid"]
        )
        self.context.cstate.update(_state, req)

        # Add a state and bind a code to it
        resp1 = AuthorizationResponse(code="auth_grant", state=_state)
        response = _service.parse_response(self.context, resp1.to_urlencoded(), "urlencoded")
        _service.update_service_context(self.context, response, key=_state)

        # based on state find the code and then get an access token
        resp2 = AccessTokenResponse(
            access_token="token1", token_type="Bearer", expires_in=0, state=_state
        )

        response = _service.parse_response(self.context, resp2.to_urlencoded(), "urlencoded")
        _service.upstream_get("context").cstate.update(_state, response)

        # and finally use the access token, bound to a state, to
        # construct the authorization header
        http_args = BearerHeader().construct(self.context, ResourceRequest(), _service, key=_state)
        assert http_args == {"headers": {"Authorization": "Bearer token1"}}


class TestBearerBody(object):

    @pytest.fixture(autouse=True)
    def entity(self):
        keyjar = init_key_jar(**KEY_CONF)
        self.entity = Entity(
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
        self.entity.context[''].map_supported_to_preferred()
        self.entity.context[''].map_preferred_to_registered()
        self.context = self.entity.context['']

    def test_construct(self):
        _token_service = self.entity.get_service(self.context, "")
        request = ResourceRequest(access_token="Sesame")
        http_args = BearerBody().construct(self.context, request, service=_token_service)

        assert request["access_token"] == "Sesame"
        assert http_args is None

    def test_construct_with_state(self):
        _auth_service = self.entity.get_service(self.context, "accesstoken")
        _key = self.context.cstate.create_key()
        self.context.cstate.set(_key, {"iss": "Issuer"})

        resp = AuthorizationResponse(code="code", state=_key)
        self.context.cstate.update(_key, resp)

        atr = AccessTokenResponse(
            access_token="2YotnFZFEjr1zCsicMWpAA",
            token_type="example",
            refresh_token="tGzv3JOkF0XG5Qx2TlKWIA",
            example_parameter="example_value",
            scope=["inner", "outer"],
        )
        self.context.cstate.update(_key, atr)

        request = ResourceRequest()
        http_args = BearerBody().construct(self.context, request, service=_auth_service, key=_key)
        assert request["access_token"] == "2YotnFZFEjr1zCsicMWpAA"
        assert http_args is None

    def test_construct_with_request(self):
        authz_service = self.entity.get_service(self.context, "")
        self.context = authz_service.upstream_get("context")

        _key = self.context.cstate.create_key()
        self.context.cstate.set(_key, {"iss": "Issuer"})
        resp1 = AuthorizationResponse(code="auth_grant", state=_key)
        response = authz_service.parse_response(self.context, resp1.to_urlencoded(), "urlencoded")
        authz_service.update_service_context(self.context, response, key=_key)

        resp2 = AccessTokenResponse(
            access_token="token1", token_type="Bearer", expires_in=0, state=_key
        )
        _service2 = self.entity.get_service(self.context, "")
        response = _service2.parse_response(self.context, resp2.to_urlencoded(), "urlencoded")
        _service2.upstream_get("context").cstate.update(_key, response)

        request = ResourceRequest()
        BearerBody().construct(self.context, request, service=authz_service, key=_key)

        assert "access_token" in request
        assert request["access_token"] == "token1"


class TestClientSecretPost(object):

    @pytest.fixture(autouse=True)
    def entity(self):
        keyjar = init_key_jar(**KEY_CONF)
        self.entity = Entity(
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
        self.entity.context[''].map_supported_to_preferred()
        self.entity.context[''].map_preferred_to_registered()
        self.context = self.entity.context['']

    def test_construct(self):
        _token_service = self.entity.get_service(self.context, "")
        request = _token_service.construct(
            self.context, request_args={"redirect_uri": "http://example.com", "state": "ABCDE"}
        )
        csp = ClientSecretPost()
        http_args = csp.construct(self.context, request, service=_token_service)

        assert request["client_id"] == "A"
        assert request["client_secret"] == "white boarding pass"
        assert http_args is None

        request = AccessTokenRequest(code="foo", redirect_uri="http://example.com")
        http_args = csp.construct(self.context, request, service=_token_service, client_secret="another")
        assert request["client_id"] == "A"
        assert request["client_secret"] == "another"
        assert http_args is None

    def test_modify_1(self):
        token_service = self.entity.get_service(self.context, "")
        request = token_service.construct(
            self.context, request_args={"redirect_uri": "http://example.com", "state": "ABCDE"}
        )
        csp = ClientSecretPost()
        http_args = csp.construct(self.context, request, service=token_service)
        assert "client_secret" in request

    def test_modify_2(self):
        _service = self.entity.get_service(self.context, "")
        request = _service.construct(
            self.context, request_args={"redirect_uri": "http://example.com", "state": "ABCDE"}
        )
        csp = ClientSecretPost()
        self.context.set_usage("client_secret", "")
        # this will fail
        with pytest.raises(AuthnFailure):
            http_args = csp.construct(self.context, request, service=_service)


class TestPrivateKeyJWT(object):

    @pytest.fixture(autouse=True)
    def entity(self):
        keyjar = init_key_jar(**KEY_CONF)
        self.entity = Entity(
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
        self.entity.context[''].map_supported_to_preferred()
        self.entity.context[''].map_preferred_to_registered()
        self.context = self.entity.context['']

    def test_construct(self):
        token_service = self.entity.get_service(self.context, "")
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
        http_args = pkj.construct(self.context, request, service=token_service, authn_endpoint="token_endpoint")
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

    def test_construct_client_assertion(self):
        token_service = self.entity.get_service(self.context, "")

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
        http_args = pkj.construct(self.context, request, client_assertion=_ca)
        assert http_args == {}
        assert request["client_assertion"] == _ca
        assert request["client_assertion_type"] == JWT_BEARER


class TestClientSecretJWTTE(object):

    @pytest.fixture(autouse=True)
    def entity(self):
        keyjar = init_key_jar(**KEY_CONF)
        self.entity = Entity(
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
        self.entity.context[''].map_supported_to_preferred()
        self.entity.context[''].map_preferred_to_registered()
        self.context = self.entity.context['']

    def test_client_secret_jwt(self):
        self.context.token_endpoint = "https://example.com/token"

        self.context.provider_info = {
            "issuer": "https://example.com/",
            "token_endpoint": "https://example.com/token",
        }

        # This is not the default
        self.context.set_usage("token_endpoint_auth_signing_alg", "HS256")

        csj = ClientSecretJWT()
        request = AccessTokenRequest()

        csj.construct(self.context, request, service=self.entity.get_service(self.context, ""),
                      authn_endpoint="token_endpoint")
        assert request["client_assertion_type"] == JWT_BEARER
        assert "client_assertion" in request
        cas = request["client_assertion"]

        _kj = KeyJar()
        _kj.add_symmetric(
            self.context.get_client_id(), self.context.get_usage("client_secret"), ["sig"]
        )
        jso = JWT(key_jar=_kj, sign_alg="HS256").unpack(cas)
        assert _eq(jso.keys(), ["aud", "iss", "sub", "exp", "iat", "jti"])

        _rj = JWS(alg="HS256")
        info = _rj.verify_compact(
            cas, _kj.get_signing_key(issuer_id=self.context.get_client_id())
        )

        assert _eq(info.keys(), ["aud", "iss", "sub", "jti", "exp", "iat"])
        assert info["aud"] == [self.context.provider_info["token_endpoint"]]

    def test_get_key_by_kid(self):
        self.context = self.entity.get_context()
        self.context.token_endpoint = "https://example.com/token"

        self.context.provider_info = {
            "issuer": "https://example.com/",
            "token_endpoint": "https://example.com/token",
        }

        self.context.set_usage("token_endpoint_auth_signing_alg", "HS256")

        csj = ClientSecretJWT()
        request = AccessTokenRequest()

        # get a kid for a symmetric key
        kid = ""
        for _key in self.entity.get_attribute("keyjar").get_issuer_keys(""):
            if _key.kty == "oct":
                kid = _key.kid
                break

        # token_service = self.entity.get_service("")
        token_service = self.entity.get_service(self.context, "accesstoken")
        csj.construct(self.context, request, service=token_service, authn_endpoint="token_endpoint", kid=kid)
        assert "client_assertion" in request

    def test_get_key_by_kid_fail(self):
        token_service = self.entity.get_service(self.context, "")
        self.context = token_service.upstream_get("context")
        self.context.token_endpoint = "https://example.com/token"

        self.context.provider_info = {
            "issuer": "https://example.com/",
            "token_endpoint": "https://example.com/token",
        }

        self.context.set_usage("token_endpoint_auth_signing_alg", "HS256")

        csj = ClientSecretJWT()
        request = AccessTokenRequest()

        # get a kid
        kid = "abcdefgh"
        with pytest.raises(MissingKey):
            csj.construct(self.context, request, service=token_service, authn_endpoint="token_endpoint", kid=kid)

    def test_get_audience_and_algorithm_default_alg(self):
        self.context = self.entity.get_context()
        self.context.token_endpoint = "https://example.com/token"

        self.context.provider_info = {
            "issuer": "https://example.com/",
            "token_endpoint": "https://example.com/token",
        }

        # This is the default so this line is unnecessary
        # self.context.set_usage("token_endpoint_auth_signing_alg", "RS256")

        csj = ClientSecretJWT()
        request = AccessTokenRequest()

        # No preference -> default == RS256
        self.context.registration_response = {}

        token_service = self.entity.get_service(self.context, "")

        # Since I have an RSA key this doesn't fail
        csj.construct(self.context, request, service=token_service, authn_endpoint="token_endpoint")

        _rsa_key = self.entity.keyjar.get(key_use="sig", key_type="rsa", issuer_id="")[0]
        _jws = factory(request["client_assertion"])
        assert _jws.jwt.headers["alg"] == "RS256"
        _rsa_key = self.entity.keyjar.get_signing_key(key_type="RSA")[0]
        assert _jws.jwt.headers["kid"] == _rsa_key.kid

        # By client preferences
        request = AccessTokenRequest()
        self.context.set_usage("token_endpoint_auth_signing_alg", "RS512")
        csj.construct(self.context, request, service=token_service, authn_endpoint="token_endpoint")

        _jws = factory(request["client_assertion"])
        assert _jws.jwt.headers["alg"] == "RS512"
        assert _jws.jwt.headers["kid"] == _rsa_key.kid

        # Use provider information is everything else fails
        request = AccessTokenRequest()
        self.context.claims = Claims()
        self.context.provider_info["token_endpoint_auth_signing_alg_values_supported"] = [
            "ES256",
            "RS256",
        ]
        csj.construct(self.context, request, service=token_service, authn_endpoint="token_endpoint")

        _ec_key = self.entity.keyjar.get(key_use="sig", key_type="ec", issuer_id="")[0]
        _jws = factory(request["client_assertion"])
        # Should be ES256 since I have a key for ES256
        assert _jws.jwt.headers["alg"] == "ES256"
        _ec_key = self.entity.keyjar.get_signing_key(key_type="EC")[0]
        assert _jws.jwt.headers["kid"] == _ec_key.kid


class TestClientSecretJWT_UI(object):

    @pytest.fixture(autouse=True)
    def entity(self):
        keyjar = init_key_jar(**KEY_CONF)
        self.entity = Entity(
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
        self.entity.context[''].map_supported_to_preferred()
        self.entity.context[''].map_preferred_to_registered()
        self.context = self.entity.context['']

    def test_client_secret_jwt(self):
        access_token_service = self.entity.get_service(self.context, "")

        self.context = access_token_service.upstream_get("context")
        self.context.token_endpoint = "https://example.com/token"
        self.context.provider_info = {
            "issuer": "https://example.com/",
            "token_endpoint": "https://example.com/token",
        }

        csj = ClientSecretJWT()
        request = AccessTokenRequest()

        csj.construct(
            self.context, request, service=access_token_service, algorithm="HS256", authn_endpoint="userinfo"
        )
        assert request["client_assertion_type"] == JWT_BEARER
        assert "client_assertion" in request
        cas = request["client_assertion"]

        _kj = KeyJar()
        _kj.add_symmetric(
            self.context.get_client_id(),
            self.context.get_usage("client_secret"),
            usage=["sig"],
        )
        jso = JWT(key_jar=_kj, sign_alg="HS256").unpack(cas)
        assert _eq(jso.keys(), ["aud", "iss", "sub", "jti", "exp", "iat"])

        _rj = JWS(alg="HS256")
        info = _rj.verify_compact(
            cas, _kj.get_signing_key(issuer_id=self.context.get_client_id())
        )

        assert _eq(info.keys(), ["aud", "iss", "sub", "jti", "exp", "iat"])
        assert info["aud"] == [self.context.provider_info["issuer"]]


class TestValidClientInfo(object):

    @pytest.fixture(autouse=True)
    def entity(self):
        keyjar = init_key_jar(**KEY_CONF)
        self.entity = Entity(
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
        self.entity.context[''].map_supported_to_preferred()
        self.entity.context[''].map_preferred_to_registered()
        self.context = self.entity.context['']

    def test_valid_service_context(self):
        _now = 123456  # At some time
        # Expiration time missing or 0, client_secret never expires
        # service_context.client_secret_expires_at
        assert valid_service_context(self.context, _now)
        assert valid_service_context(self.context, _now)
        # Expired secret
        self.context.client_secret_expires_at = 1
        assert valid_service_context(self.context, _now) is not True

        self.context.client_secret_expires_at = 123455
        assert valid_service_context(self.context, _now) is not True

        # Valid secret
        self.context.client_secret_expires_at = 123460
        assert valid_service_context(self.context, _now)


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
