# pylint: disable=no-self-use,missing-docstring
import json
from urllib.parse import parse_qs
from urllib.parse import urlparse

import pytest
from cryptojwt.key_jar import build_keyjar

from idpyoidc import verified_claim_name
from idpyoidc.exception import MissingRequiredAttribute
from idpyoidc.message import DecodeError
from idpyoidc.message import json_deserializer
from idpyoidc.message import json_serializer
from idpyoidc.message import sp_sep_list_deserializer
from idpyoidc.message.oauth2 import AccessTokenRequest
from idpyoidc.message.oauth2 import AccessTokenResponse
from idpyoidc.message.oauth2 import AuthorizationErrorResponse
from idpyoidc.message.oauth2 import AuthorizationRequest
from idpyoidc.message.oauth2 import AuthorizationResponse
from idpyoidc.message.oauth2 import CCAccessTokenRequest
from idpyoidc.message.oauth2 import JWTSecuredAuthorizationRequest
from idpyoidc.message.oauth2 import RefreshAccessTokenRequest
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.message.oauth2 import ROPCAccessTokenRequest
from idpyoidc.message.oauth2 import TokenErrorResponse
from idpyoidc.message.oauth2 import TokenExchangeRequest
from idpyoidc.message.oauth2 import TokenExchangeResponse
from idpyoidc.message.oauth2 import factory
from idpyoidc.message.oauth2 import is_error_message

__author__ = "Roland Hedberg"

keys = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "RSA", "use": ["enc"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["enc"]},
]

keym = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "RSA", "use": ["sig"]},
    {"type": "RSA", "use": ["sig"]},
]

KEYJAR = build_keyjar(keys)
KEYJAR.import_jwks(KEYJAR.export_jwks(private=True), "issuer")

IKEYJAR = build_keyjar(keys)
IKEYJAR.import_jwks(IKEYJAR.export_jwks(private=True), "issuer")
del IKEYJAR[""]


def url_compare(url1, url2):
    url1 = urlparse(url1)
    url2 = urlparse(url2)

    if url1.scheme != url2.scheme:
        return False
    if url1.netloc != url2.netloc:
        return False
    if url1.path != url2.path:
        return False
    if not query_string_compare(url1.query, url2.query):
        return False
    if not query_string_compare(url1.fragment, url2.fragment):
        return False

    return True


def query_string_compare(query_str1, query_str2):
    return parse_qs(query_str1) == parse_qs(query_str2)


def _eq(l1, l2):
    return set(l1) == set(l2)


def test_sp_sep_list_deserializer():
    vals = sp_sep_list_deserializer("foo bar zen")
    assert len(vals) == 3
    assert _eq(vals, ["foo", "bar", "zen"])

    vals = sp_sep_list_deserializer(["foo bar zen"])
    assert len(vals) == 3
    assert _eq(vals, ["foo", "bar", "zen"])


def test_json_serializer():
    val = json_serializer({"foo": ["bar", "stool"]})
    val_obj = json.loads(val)
    assert val_obj == {"foo": ["bar", "stool"]}


def test_json_deserializer():
    _dict = {"foo": ["bar", "stool"]}
    val = json_serializer(_dict)

    sdict = json_deserializer(val)
    assert _dict == sdict


class TestAuthorizationRequest(object):
    def test_authz_req_urlencoded(self):
        ar = AuthorizationRequest(response_type=["code"], client_id="foobar")
        ue = ar.to_urlencoded()
        assert query_string_compare(ue, "response_type=code&client_id=foobar")

    def test_urlencoded_with_redirect_uri(self):
        ar = AuthorizationRequest(
            response_type=["code"],
            client_id="foobar",
            redirect_uri="http://foobar.example.com/oaclient",
            state="cold",
        )

        ue = ar.to_urlencoded()
        assert query_string_compare(
            ue,
            "state=cold&redirect_uri=http%3A%2F%2Ffoobar.example.com"
            "%2Foaclient&"
            "response_type=code&client_id=foobar",
        )

    def test_urlencoded_resp_type_token(self):
        ar = AuthorizationRequest(
            response_type=["token"],
            client_id="s6BhdRkqt3",
            redirect_uri="https://client.example.com/cb",
            state="xyz",
        )

        ue = ar.to_urlencoded()
        assert query_string_compare(
            ue,
            "state=xyz&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb"
            "&response_type=token&"
            "client_id=s6BhdRkqt3",
        )

    def test_deserialize_urlencoded(self):
        ar = AuthorizationRequest(response_type=["code"], client_id="foobar")
        urlencoded = ar.to_urlencoded()
        ar2 = AuthorizationRequest().deserialize(urlencoded, "urlencoded")

        assert ar == ar2

    def test_urlencoded_with_scope(self):
        ar = AuthorizationRequest(
            response_type=["code"],
            client_id="foobar",
            redirect_uri="http://foobar.example.com/oaclient",
            scope=["foo", "bar"],
            state="cold",
        )

        ue = ar.to_urlencoded()
        assert query_string_compare(
            ue,
            "scope=foo+bar&state=cold&redirect_uri=http%3A%2F%2Ffoobar"
            ".example.com%2Foaclient&"
            "response_type=code&client_id=foobar",
        )

    def test_deserialize_urlencoded_multiple_params(self):
        ar = AuthorizationRequest(
            response_type=["code"],
            client_id="foobar",
            redirect_uri="http://foobar.example.com/oaclient",
            scope=["foo", "bar"],
            state="cold",
        )
        urlencoded = ar.to_urlencoded()
        ar2 = AuthorizationRequest().deserialize(urlencoded, "urlencoded")

        assert ar == ar2

    def test_urlencoded_missing_required(self):
        ar = AuthorizationRequest(response_type=["code"])
        with pytest.raises(MissingRequiredAttribute):
            ar.verify()

    def test_urlencoded_invalid_scope(self):
        args = {
            "response_type": [10],
            "client_id": "foobar",
            "redirect_uri": "http://foobar.example.com/oaclient",
            "scope": ["foo", "bar"],
            "state": "cold",
        }

        with pytest.raises(DecodeError):
            AuthorizationRequest(**args)

    def test_urlencoded_deserialize_state(self):
        txt = (
            "scope=foo+bar&state=-11&redirect_uri=http%3A%2F%2Ffoobar"
            ".example.com%2Foaclient&response_type=code&"
            "client_id=foobar"
        )

        ar = AuthorizationRequest().deserialize(txt, "urlencoded")
        assert ar["state"] == "-11"

    def test_urlencoded_deserialize_response_type(self):
        txt = (
            "scope=openid&state=id-6a3fc96caa7fd5cb1c7d00ed66937134&"
            "redirect_uri=http%3A%2F%2Flocalhost%3A8087authz&response_type"
            "=code&client_id=a1b2c3"
        )

        ar = AuthorizationRequest().deserialize(txt, "urlencoded")
        assert ar["scope"] == ["openid"]
        assert ar["response_type"] == ["code"]

    def test_req_json_serialize(self):
        ar = AuthorizationRequest(response_type=["code"], client_id="foobar")

        js_obj = json.loads(ar.serialize(method="json"))
        expected_js_obj = {"response_type": "code", "client_id": "foobar"}
        assert js_obj == expected_js_obj

    def test_json_multiple_params(self):
        ar = AuthorizationRequest(
            response_type=["code"],
            client_id="foobar",
            redirect_uri="http://foobar.example.com/oaclient",
            state="cold",
        )

        ue_obj = json.loads(ar.serialize(method="json"))
        expected_ue_obj = {
            "response_type": "code",
            "state": "cold",
            "redirect_uri": "http://foobar.example.com/oaclient",
            "client_id": "foobar",
        }
        assert ue_obj == expected_ue_obj

    def test_json_resp_type_token(self):
        ar = AuthorizationRequest(
            response_type=["token"],
            client_id="s6BhdRkqt3",
            redirect_uri="https://client.example.com/cb",
            state="xyz",
        )

        ue_obj = json.loads(ar.serialize(method="json"))
        expected_ue_obj = {
            "state": "xyz",
            "redirect_uri": "https://client.example.com/cb",
            "response_type": "token",
            "client_id": "s6BhdRkqt3",
        }
        assert ue_obj == expected_ue_obj

    def test_json_serialize_deserialize(self):
        ar = AuthorizationRequest(response_type=["code"], client_id="foobar")
        jtxt = ar.serialize(method="json")
        ar2 = AuthorizationRequest().deserialize(jtxt, "json")

        assert ar == ar2

    def test_verify(self):
        query = (
            "redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fauthz"
            "&response_type=code&client_id=0123456789"
        )
        ar = AuthorizationRequest().deserialize(query, "urlencoded")
        assert ar.verify()

    def test_load_dict(self):
        bib = {
            "scope": ["openid"],
            "state": "id-6da9ca0cc23959f5f33e8becd9b08cae",
            "redirect_uri": "http://localhost:8087authz",
            "response_type": ["code"],
            "client_id": "a1b2c3",
        }

        arq = AuthorizationRequest(**bib)

        assert arq["scope"] == bib["scope"]
        assert arq["response_type"] == bib["response_type"]
        assert arq["redirect_uri"] == bib["redirect_uri"]
        assert arq["state"] == bib["state"]
        assert arq["client_id"] == bib["client_id"]

    def test_json_serizalize_deserialize_multiple_params(self):
        argv = {
            "scope": ["openid"],
            "state": "id-b0be8bb64118c3ec5f70093a1174b039",
            "redirect_uri": "http://localhost:8087authz",
            "response_type": ["code"],
            "client_id": "a1b2c3",
        }

        arq = AuthorizationRequest(**argv)
        jstr = arq.serialize(method="json")
        jarq = AuthorizationRequest().deserialize(jstr, "json")

        assert jarq["scope"] == ["openid"]
        assert jarq["response_type"] == ["code"]
        assert jarq["redirect_uri"] == "http://localhost:8087authz"
        assert jarq["state"] == "id-b0be8bb64118c3ec5f70093a1174b039"
        assert jarq["client_id"] == "a1b2c3"

    def test_multiple_response_types_urlencoded(self):
        ar = AuthorizationRequest(response_type=["code", "token"], client_id="foobar")

        ue = ar.to_urlencoded()
        ue_splits = ue.split("&")
        expected_ue_splits = "response_type=code+token&client_id=foobar".split("&")
        assert _eq(ue_splits, expected_ue_splits)

        are = AuthorizationRequest().deserialize(ue, "urlencoded")
        assert _eq(are.keys(), ["response_type", "client_id"])
        assert _eq(are["response_type"], ["code", "token"])

    def test_multiple_scopes_urlencoded(self):
        ar = AuthorizationRequest(
            response_type=["code", "token"], client_id="foobar", scope=["openid", "foxtrot"]
        )
        ue = ar.to_urlencoded()
        ue_splits = ue.split("&")
        expected_ue_splits = (
            "scope=openid+foxtrot&response_type=code+token" "&client_id=foobar".split("&")
        )
        assert _eq(ue_splits, expected_ue_splits)

        are = AuthorizationRequest().deserialize(ue, "urlencoded")
        assert _eq(are.keys(), ["response_type", "client_id", "scope"])
        assert _eq(are["response_type"], ["code", "token"])
        assert _eq(are["scope"], ["openid", "foxtrot"])

    def test_multiple_response_types_json(self):
        ar = AuthorizationRequest(response_type=["code", "token"], client_id="foobar")
        ue = ar.to_json()
        ue_obj = json.loads(ue)
        expected_ue_obj = {"response_type": "code token", "client_id": "foobar"}
        assert ue_obj == expected_ue_obj

        are = AuthorizationRequest().deserialize(ue, "json")
        assert _eq(are.keys(), ["response_type", "client_id"])
        assert _eq(are["response_type"], ["code", "token"])

    def test_multiple_scopes_json(self):
        ar = AuthorizationRequest(
            response_type=["code", "token"], client_id="foobar", scope=["openid", "foxtrot"]
        )
        ue = ar.to_json()
        ue_obj = json.loads(ue)
        expected_ue_obj = {
            "scope": "openid foxtrot",
            "response_type": "code token",
            "client_id": "foobar",
        }
        assert ue_obj == expected_ue_obj

        are = AuthorizationRequest().deserialize(ue, "json")
        assert _eq(are.keys(), ["response_type", "client_id", "scope"])
        assert _eq(are["response_type"], ["code", "token"])
        assert _eq(are["scope"], ["openid", "foxtrot"])


class TestMerge:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.req_obj = {
            "scope": ["openid", "fox"],
            "state": "id-b0be8bb64118c3ec5f70093a1174b039",
            "redirect_uri": "http://localhost:8087authz",
            "response_type": ["code id_token"],
            "response_mode": "form_post",
            "client_id": "a1b2c3",
        }

        self.req_obj = AuthorizationRequest(
            scope=["openid"],
            state="id-b0be8bb64118c3ec5f70093a1174b039",
            redirect_uri="http://localhost:8087authz",
            response_type=["code"],
            client_id="a1b2c3",
        )

    def test_merge_strict(self):
        _areq = AuthorizationRequest(**self.req_obj)
        # Some modifications
        _areq["scope"] = ["openid", "fox"]
        _areq["response_mode"] = "form_post"

        _areq.merge(self.req_obj)  # strict is default
        assert "response_mode" not in _areq
        assert _areq["scope"] == ["openid"]

    def test_merge_lax(self):
        _areq = AuthorizationRequest(**self.req_obj)
        # Some modifications
        _areq["scope"] = ["openid", "fox"]
        _areq["response_mode"] = "form_post"
        _areq.merge(self.req_obj, treatement="lax")
        assert _areq
        assert "response_mode" in _areq
        assert _areq["scope"] == ["openid"]

    def test_merge_whitelist(self):
        _areq = AuthorizationRequest(**self.req_obj)
        # Some modifications
        _areq["scope"] = ["openid", "fox"]
        _areq["response_mode"] = "form_post"
        _areq["extra"] = "lopp"
        _areq.merge(self.req_obj, treatement="whitelist", whitelist=["extra"])
        assert "response_mode" not in _areq
        assert _areq["scope"] == ["openid"]
        assert "extra" in _areq


class TestAuthorizationErrorResponse(object):
    def test_init(self):
        aer = AuthorizationErrorResponse(error="access_denied", state="xyz")
        assert aer["error"] == "access_denied"
        assert aer["state"] == "xyz"

    def test_extra_params(self):
        aer = AuthorizationErrorResponse(
            error="access_denied", error_description="brewers has a " "four game series", foo="bar"
        )
        assert aer["error"] == "access_denied"
        assert aer["error_description"] == "brewers has a four game series"
        assert aer["foo"] == "bar"


class TestTokenErrorResponse(object):
    def test_init(self):
        ter = TokenErrorResponse(error="access_denied", state="xyz")

        assert ter["error"] == "access_denied"
        assert ter["state"] == "xyz"

    def test_extra_params(self):
        ter = TokenErrorResponse(
            error="access_denied", error_description="brewers has a four game " "series", foo="bar"
        )

        assert ter["error"] == "access_denied"
        assert ter["error_description"] == "brewers has a four game series"
        assert ter["foo"] == "bar"


class TestAccessTokenResponse(object):
    def test_json_serialize(self):
        at = AccessTokenResponse(access_token="SlAV32hkKG", token_type="Bearer", expires_in=3600)

        atj = at.serialize(method="json")
        atj_obj = json.loads(atj)
        expected_atj_obj = {
            "token_type": "Bearer",
            "access_token": "SlAV32hkKG",
            "expires_in": 3600,
        }
        assert atj_obj == expected_atj_obj

    def test_multiple_scope(self):
        atr = AccessTokenResponse(
            access_token="2YotnFZFEjr1zCsicMWpAA",
            token_type="example",
            expires_in=3600,
            refresh_token="tGzv3JOkF0XG5Qx2TlKWIA",
            example_parameter="example_value",
            scope=["inner", "outer"],
        )

        assert _eq(atr["scope"], ["inner", "outer"])

        uec = atr.to_urlencoded()
        assert "inner+outer" in uec

    def test_to_urlencoded_extended_omit(self):
        atr = AccessTokenResponse(
            access_token="2YotnFZFEjr1zCsicMWpAA",
            token_type="example",
            expires_in=3600,
            refresh_token="tGzv3JOkF0XG5Qx2TlKWIA",
            example_parameter="example_value",
            scope=["inner", "outer"],
            extra=["local", "external"],
            level=3,
        )

        uec = atr.to_urlencoded()
        assert query_string_compare(
            uec,
            "scope=inner+outer&level=3&expires_in=3600&token_type=example"
            "&extra=local&"
            "extra=external&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA&"
            "access_token=2YotnFZFEjr1zCsicMWpAA&example_parameter"
            "=example_value",
        )

        del atr["extra"]
        ouec = atr.to_urlencoded()
        assert query_string_compare(
            ouec,
            "access_token=2YotnFZFEjr1zCsicMWpAA&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA&"
            "level=3&example_parameter=example_value&token_type=example"
            "&expires_in=3600&"
            "scope=inner+outer",
        )
        assert len(uec) == (len(ouec) + len("extra=local") + len("extra=external") + 2)

        atr2 = AccessTokenResponse().deserialize(uec, "urlencoded")
        assert _eq(
            atr2.keys(),
            [
                "access_token",
                "expires_in",
                "token_type",
                "scope",
                "refresh_token",
                "level",
                "example_parameter",
                "extra",
            ],
        )

        atr3 = AccessTokenResponse().deserialize(ouec, "urlencoded")
        assert _eq(
            atr3.keys(),
            [
                "access_token",
                "expires_in",
                "token_type",
                "scope",
                "refresh_token",
                "level",
                "example_parameter",
            ],
        )


class TestAccessTokenRequest(object):
    def test_extra(self):
        atr = AccessTokenRequest(
            grant_type="authorization_code",
            code="SplxlOBeZQQYbYS6WxSbIA",
            redirect_uri="https://client.example.com/cb",
            extra="foo",
        )

        query = atr.to_urlencoded()
        assert query_string_compare(
            query,
            "code=SplxlOBeZQQYbYS6WxSbIA&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&"
            "grant_type=authorization_code&extra=foo",
        )

        atr2 = AccessTokenRequest().deserialize(query, "urlencoded")
        assert atr == atr2


class TestAuthorizationResponse(object):
    def test_init(self):
        atr = AuthorizationResponse(code="SplxlOBeZQQYbYS6WxSbIA", state="Fun_state", extra="foo")

        assert atr["code"] == "SplxlOBeZQQYbYS6WxSbIA"
        assert atr["state"] == "Fun_state"
        assert atr["extra"] == "foo"


class TestROPCAccessTokenRequest(object):
    def test_init(self):
        ropc = ROPCAccessTokenRequest(grant_type="password", username="johndoe", password="A3ddj3w")

        assert ropc["grant_type"] == "password"
        assert ropc["username"] == "johndoe"
        assert ropc["password"] == "A3ddj3w"


class TestCCAccessTokenRequest(object):
    def test_init(self):
        cc = CCAccessTokenRequest(scope="/foo")
        assert cc["grant_type"] == "client_credentials"
        assert cc["scope"] == ["/foo"]


class TestRefreshAccessTokenRequest(object):
    def test_init(self):
        ratr = RefreshAccessTokenRequest(refresh_token="ababababab", client_id="Client_id")
        assert ratr["grant_type"] == "refresh_token"
        assert ratr["refresh_token"] == "ababababab"
        assert ratr["client_id"] == "Client_id"

        assert ratr.verify()


class TestTokenExchangeRequest(object):
    def test_init(self):
        request = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token="ababababab",
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
        )
        assert request["grant_type"] == "urn:ietf:params:oauth:grant-type:token-exchange"
        assert request["subject_token"] == "ababababab"
        assert request["subject_token_type"] == "urn:ietf:params:oauth:token-type:access_token"

        assert request.verify()


class TestTokenExchangeResponse(object):
    def test_init(self):
        response = TokenExchangeResponse(
            access_token="bababababa",
            issued_token_type="urn:ietf:params:oauth:token-type:access_token",
            token_type="Bearer",
            expires_in=60,
        )
        assert response["issued_token_type"] == "urn:ietf:params:oauth:token-type:access_token"
        assert response["access_token"] == "bababababa"
        assert response["token_type"] == "Bearer"
        assert response["expires_in"] == 60

        assert response.verify()


class TestResponseMessage_error(object):
    def test_error_message(self):
        err = ResponseMessage(
            error="invalid_request",
            error_description="Something was missing",
            error_uri="http://example.com/error_message.html",
        )

        ue_str = err.to_urlencoded()
        del err["error_uri"]
        ueo_str = err.to_urlencoded()

        assert ue_str != ueo_str
        assert "error_message" not in ueo_str
        assert "error_message" in ue_str
        assert is_error_message(err)

    def test_auth_error_message(self):
        resp = AuthorizationResponse(
            error="invalid_request", error_description="Something was missing"
        )
        assert is_error_message(resp)


def test_factory():
    dr = factory("ResponseMessage", error="some_error")
    assert isinstance(dr, ResponseMessage)
    assert list(dr.keys()) == ["error"]


def test_factory_auth_response():
    ar = factory("AuthorizationResponse", client_id="client1", iss="Issuer", code="1234567")
    assert isinstance(ar, AuthorizationResponse)
    assert ar.verify(client_id="client1", iss="Issuer")


def test_set_default():
    ar = AccessTokenRequest(set_defaults=False)
    assert list(ar.keys()) == []
    ar.set_defaults()
    assert "grant_type" in ar


class TestJWTSecuredAuthorizationRequest:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.auth_req = {
            "response_type": ["code"],
            "client_id": "foobar",
            "redirect_uri": "http://foobar.example.com/oaclient",
            "state": "cold",
        }

    def test_1(self):
        _req = JWTSecuredAuthorizationRequest(**self.auth_req)
        _keys = KEYJAR.get_signing_key()
        _req["request"] = _req.to_jwt(key=_keys, algorithm="RS256")
        assert _req.verify(keyjar=KEYJAR)
        assert verified_claim_name("request") in _req
