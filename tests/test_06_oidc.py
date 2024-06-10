# -*- coding: utf-8 -*-
import json
import os
import sys
import time
from urllib.parse import parse_qs
from urllib.parse import urlencode

import pytest
from cryptojwt.exception import BadSignature
from cryptojwt.exception import UnsupportedAlgorithm
from cryptojwt.jws.exception import SignerAlgError
from cryptojwt.jws.utils import left_hash
from cryptojwt.jwt import JWT
from cryptojwt.key_bundle import KeyBundle
from cryptojwt.key_jar import KeyJar

from idpyoidc import proper_path
from idpyoidc import time_util
from idpyoidc.exception import MessageException
from idpyoidc.exception import MissingRequiredAttribute
from idpyoidc.exception import NotAllowedValue
from idpyoidc.exception import OidcMsgError
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.message.oauth2 import ROPCAccessTokenRequest
from idpyoidc.message.oidc import JRD
from idpyoidc.message.oidc import AccessTokenRequest
from idpyoidc.message.oidc import AccessTokenResponse
from idpyoidc.message.oidc import AddressClaim
from idpyoidc.message.oidc import APPLICATION_TYPE_WEB
from idpyoidc.message.oidc import AtHashError
from idpyoidc.message.oidc import AuthnToken
from idpyoidc.message.oidc import AuthorizationErrorResponse
from idpyoidc.message.oidc import AuthorizationRequest
from idpyoidc.message.oidc import AuthorizationResponse
from idpyoidc.message.oidc import CHashError
from idpyoidc.message.oidc import Claims
from idpyoidc.message.oidc import DiscoveryRequest
from idpyoidc.message.oidc import EXPError
from idpyoidc.message.oidc import IATError
from idpyoidc.message.oidc import IdToken
from idpyoidc.message.oidc import Link
from idpyoidc.message.oidc import OpenIDSchema
from idpyoidc.message.oidc import ProviderConfigurationResponse
from idpyoidc.message.oidc import RegistrationRequest
from idpyoidc.message.oidc import RegistrationResponse
from idpyoidc.message.oidc import address_deser
from idpyoidc.message.oidc import claims_deser
from idpyoidc.message.oidc import claims_match
from idpyoidc.message.oidc import claims_ser
from idpyoidc.message.oidc import dict_deser
from idpyoidc.message.oidc import factory
from idpyoidc.message.oidc import link_deser
from idpyoidc.message.oidc import link_ser
from idpyoidc.message.oidc import make_openid_request
from idpyoidc.message.oidc import msg_ser
from idpyoidc.message.oidc import msg_ser_json
from idpyoidc.message.oidc import registration_request_deser
from idpyoidc.message.oidc import verified_claim_name
from idpyoidc.message.oidc import verify_id_token
from idpyoidc.time_util import utc_time_sans_frac

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

__author__ = "Roland Hedberg"

CLIENT_ID = "client_1"
IDTOKEN = IdToken(
    iss="http://oic.example.org/",
    sub="sub",
    aud=CLIENT_ID,
    exp=utc_time_sans_frac() + 300,
    nonce="N0nce",
    iat=time.time(),
)
KC_SYM_S = KeyBundle(
    {"kty": "oct", "key": "abcdefghijklmnop".encode("utf-8"), "use": "sig", "alg": "HS256"}
)


def query_string_compare(query_str1, query_str2):
    return parse_qs(query_str1) == parse_qs(query_str2)


def _eq(l1, l2):
    return set(l1) == set(l2)


def test_openidschema():
    inp = '{"middle_name":null, "updated_at":"20170328081544", "sub":"abc"}'
    ois = OpenIDSchema().from_json(inp)
    assert ois.verify() is False


@pytest.mark.parametrize(
    "json_param",
    [
        '{"middle_name":"fo", "updated_at":"20170328081544Z", "sub":"abc"}',
        '{"middle_name":true, "updated_at":"20170328081544", "sub":"abc"}',
        '{"middle_name":"fo", "updated_at":false, "sub":"abc"}',
        '{"middle_name":"fo", "updated_at":"20170328081544Z", "sub":true}',
    ],
)
def test_openidschema_from_json(json_param):
    with pytest.raises(ValueError):
        OpenIDSchema().from_json(json_param)


@pytest.mark.parametrize(
    "json_param",
    [
        '{"email_verified":false, "email":"foo@example.com", "sub":"abc"}',
        '{"email_verified":true, "email":"foo@example.com", "sub":"abc"}',
        '{"phone_number_verified":false, "phone_number":"+1 555 200000", ' '"sub":"abc"}',
        '{"phone_number_verified":true, "phone_number":"+1 555 20000", ' '"sub":"abc"}',
    ],
)
def test_claim_booleans(json_param):
    assert OpenIDSchema().from_json(json_param)


@pytest.mark.parametrize(
    "json_param",
    [
        '{"email_verified":"Not", "email":"foo@example.com", "sub":"abc"}',
        '{"email_verified":"Sure", "email":"foo@example.com", "sub":"abc"}',
        '{"phone_number_verified":"Not", "phone_number":"+1 555 200000", ' '"sub":"abc"}',
        '{"phone_number_verified":"Sure", "phone_number":"+1 555 20000", ' '"sub":"abc"}',
    ],
)
def test_claim_not_booleans(json_param):
    with pytest.raises(ValueError):
        OpenIDSchema().from_json(json_param)


def test_claims_deser():
    _dic = {
        "userinfo": {
            "given_name": {"essential": True},
            "nickname": None,
            "email": {"essential": True},
            "email_verified": {"essential": True},
            "picture": None,
            "http://example.info/claims/groups": None,
        },
        "id_token": {
            "auth_time": {"essential": True},
            "acr": {"values": ["urn:mace:incommon:iap:silver"]},
        },
    }

    claims = claims_deser(json.dumps(_dic), sformat="json")
    assert _eq(claims.keys(), ["userinfo", "id_token"])


def test_claims_deser_dict():
    pre = Claims(
        name={"essential": True},
        nickname=None,
        email={"essential": True},
        email_verified={"essential": True},
        picture=None,
    )

    claims = claims_deser(pre.to_json(), sformat="json")
    assert _eq(claims.keys(), ["name", "nickname", "email", "email_verified", "picture"])

    claims = claims_deser(pre.to_dict(), sformat="dict")
    assert _eq(claims.keys(), ["name", "nickname", "email", "email_verified", "picture"])


def test_address_deser():
    pre = AddressClaim(street_address="Kasamark 114", locality="Umea", country="Sweden")

    adc = address_deser(pre.to_json(), sformat="json")
    assert _eq(adc.keys(), ["street_address", "locality", "country"])

    adc = address_deser(pre.to_dict(), sformat="json")
    assert _eq(adc.keys(), ["street_address", "locality", "country"])


def test_msg_ser_json():
    pre = AddressClaim(street_address="Kasamark 114", locality="Umea", country="Sweden")

    ser = msg_ser_json(pre, "json")

    adc = address_deser(ser, "json")
    assert _eq(adc.keys(), ["street_address", "locality", "country"])


def test_msg_ser_json_from_dict():
    ser = msg_ser_json(
        {"street_address": "Kasamark 114", "locality": "Umea", "country": "Sweden"}, "json"
    )

    adc = address_deser(ser, "json")
    assert _eq(adc.keys(), ["street_address", "locality", "country"])


def test_msg_ser_json_to_dict():
    pre = AddressClaim(street_address="Kasamark 114", locality="Umea", country="Sweden")

    ser = msg_ser_json(pre, "dict")

    adc = address_deser(ser, "dict")
    assert _eq(adc.keys(), ["street_address", "locality", "country"])


def test_msg_ser_dict_to_dict():
    pre = {"street_address": "Kasamark 114", "locality": "Umea", "country": "Sweden"}

    ser = msg_ser_json(pre, "dict")
    adc = address_deser(ser, "dict")
    assert _eq(adc.keys(), ["street_address", "locality", "country"])


def test_msg_ser_urlencoded():
    pre = AddressClaim(street_address="Kasamark 114", locality="Umea", country="Sweden")

    ser = msg_ser(pre.to_dict(), "urlencoded")

    adc = address_deser(ser, "urlencoded")
    assert _eq(adc.keys(), ["street_address", "locality", "country"])


def test_msg_ser_dict():
    pre = AddressClaim(street_address="Kasamark 114", locality="Umea", country="Sweden")

    ser = msg_ser(pre.to_dict(), "dict")

    adc = address_deser(ser, "dict")
    assert _eq(adc.keys(), ["street_address", "locality", "country"])


def test_msg_ser_from_dict():
    pre = {"street_address": "Kasamark 114", "locality": "Umea", "country": "Sweden"}

    ser = msg_ser(pre, "dict")

    adc = address_deser(ser, "dict")
    assert _eq(adc.keys(), ["street_address", "locality", "country"])


def test_claims_ser_json():
    claims = Claims(
        name={"essential": True},
        nickname=None,
        email={"essential": True},
        email_verified={"essential": True},
        picture=None,
    )
    claims = claims_deser(claims_ser(claims, "json"), sformat="json")
    assert _eq(claims.keys(), ["name", "nickname", "email", "email_verified", "picture"])


def test_claims_ser_from_dict_to_json():
    claims = claims_ser(
        {
            "name": {"essential": True},
            "nickname": None,
            "email": {"essential": True},
            "email_verified": {"essential": True},
            "picture": None,
        },
        sformat="json",
    )
    cl = Claims().from_json(claims)
    assert _eq(cl.keys(), ["name", "nickname", "email", "email_verified", "picture"])


def test_claims_ser_from_dict_to_urlencoded():
    claims = claims_ser(
        {
            "name": {"essential": True},
            "nickname": None,
            "email": {"essential": True},
            "email_verified": {"essential": True},
            "picture": None,
        },
        sformat="urlencoded",
    )
    cl = Claims().from_urlencoded(claims)
    assert _eq(cl.keys(), ["name", "nickname", "email", "email_verified", "picture"])


def test_claims_ser_from_dict_to_dict():
    claims = claims_ser(
        {
            "name": {"essential": True},
            "nickname": None,
            "email": {"essential": True},
            "email_verified": {"essential": True},
            "picture": None,
        },
        sformat="dict",
    )
    cl = Claims(**claims)
    assert _eq(cl.keys(), ["name", "nickname", "email", "email_verified", "picture"])


def test_claims_ser_from_dict_to_foo():
    with pytest.raises(OidcMsgError):
        _ = claims_ser(
            {
                "name": {"essential": True},
                "nickname": None,
                "email": {"essential": True},
                "email_verified": {"essential": True},
                "picture": None,
            },
            sformat="foo",
        )


def test_claims_ser_wrong_type():
    with pytest.raises(MessageException):
        _ = claims_ser(
            json.dumps(
                {
                    "name": {"essential": True},
                    "nickname": None,
                    "email": {"essential": True},
                    "email_verified": {"essential": True},
                    "picture": None,
                }
            ),
            sformat="dict",
        )


def test_discovery_request():
    request = {"rel": "http://openid.net/specs/connect/1.0/issuer", "resource": "diana@localhost"}

    req = DiscoveryRequest().from_json(json.dumps(request))
    assert set(req.keys()) == {"rel", "resource"}


def test_discovery_response():
    link = Link(href="https://example.com/op", rel="http://openid.net/specs/connect/1.0/issuer")

    resp = JRD(subject="diana@localhost", links=[link])

    assert set(resp.keys()) == {"subject", "links"}


def test_link_ser1():
    link = Link(href="https://example.com/op", rel="http://openid.net/specs/connect/1.0/issuer")
    _js = link_ser(link, "json")
    _lnk = json.loads(_js)
    assert set(_lnk.keys()) == {"href", "rel"}


def test_link_ser_dict():
    info = {"href": "https://example.com/op", "rel": "http://openid.net/specs/connect/1.0/issuer"}
    _js = link_ser(info, "json")
    _lnk = json.loads(_js)
    assert set(_lnk.keys()) == {"href", "rel"}

    _ue = link_ser(info, "urlencoded")
    assert _ue
    res = parse_qs(_ue)
    assert set(res.keys()) == {"href", "rel"}


class TestProviderConfigurationResponse(object):
    def test_deserialize(self):
        resp = {
            "authorization_endpoint": "https://server.example.com/connect/authorize",
            "issuer": "https://server.example.com",
            "token_endpoint": "https://server.example.com/connect/token",
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "private_key_jwt"],
            "userinfo_endpoint": "https://server.example.com/connect/user",
            "check_id_endpoint": "https://server.example.com/connect/check_id",
            "refresh_session_endpoint": "https://server.example.com/connect/refresh_session",
            "end_session_endpoint": "https://server.example.com/connect/end_session",
            "jwk_url": "https://server.example.com/jwk.json",
            "registration_endpoint": "https://server.example.com/connect/register",
            "scopes_supported": ["openid", "profile", "email", "address", "phone"],
            "response_types_supported": ["code", "code id_token", "token id_token"],
            "acrs_supported": ["1", "2", "http://id.incommon.org/assurance/bronze"],
            "user_id_types_supported": ["public", "pairwise"],
            "userinfo_algs_supported": ["HS256", "RS256", "A128CBC", "A128KW", "RSA1_5"],
            "id_token_algs_supported": ["HS256", "RS256", "A128CBC", "A128KW", "RSA1_5"],
            "request_object_algs_supported": ["HS256", "RS256", "A128CBC", "A128KW", "RSA1_5"],
        }

        pcr = ProviderConfigurationResponse().deserialize(json.dumps(resp), "json")

        # Missing subject_types_supported
        with pytest.raises(MissingRequiredAttribute):
            assert pcr.verify()

        assert _eq(pcr["user_id_types_supported"], ["public", "pairwise"])
        assert _eq(pcr["acrs_supported"], ["1", "2", "http://id.incommon.org/assurance/bronze"])

    def test_example_response(self):
        resp = {
            "version": "3.0",
            "issuer": "https://server.example.com",
            "authorization_endpoint": "https://server.example.com/connect/authorize",
            "token_endpoint": "https://server.example.com/connect/token",
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "private_key_jwt"],
            "token_endpoint_alg_values_supported": ["RS256", "ES256"],
            "userinfo_endpoint": "https://server.example.com/connect/userinfo",
            "check_session_iframe": "https://server.example.com/connect/check_session",
            "end_session_endpoint": "https://server.example.com/connect/end_session",
            "jwks_uri": "https://server.example.com/jwks.json",
            "registration_endpoint": "https://server.example.com/connect/register",
            "scopes_supported": [
                "openid",
                "profile",
                "email",
                "address",
                "phone",
                "offline_access",
            ],
            "response_types_supported": ["code", "code id_token", "id_token", "token id_token"],
            "acr_values_supported": [
                "urn:mace:incommon:iap:silver",
                "urn:mace:incommon:iap:bronze",
            ],
            "subject_types_supported": ["public", "pairwise"],
            "userinfo_signing_alg_values_supported": ["RS256", "ES256", "HS256"],
            "userinfo_encryption_alg_values_supported": ["RSA1_5", "A128KW"],
            "userinfo_encryption_enc_values_supported": ["A128CBC+HS256", "A128GCM"],
            "id_token_signing_alg_values_supported": ["RS256", "ES256", "HS256"],
            "id_token_encryption_alg_values_supported": ["RSA1_5", "A128KW"],
            "id_token_encryption_enc_values_supported": ["A128CBC+HS256", "A128GCM"],
            "request_object_signing_alg_values_supported": ["none", "RS256", "ES256"],
            "display_values_supported": ["page", "popup"],
            "claim_types_supported": ["normal", "distributed"],
            "claims_supported": [
                "sub",
                "iss",
                "auth_time",
                "acr",
                "name",
                "given_name",
                "family_name",
                "nickname",
                "profile",
                "picture",
                "website",
                "email",
                "email_verified",
                "locale",
                "zoneinfo",
                "http://example.info/claims/groups",
            ],
            "claims_parameter_supported": True,
            "service_documentation": "http://server.example.com/connect/service_documentation.html",
            "ui_locales_supported": ["en-US", "en-GB", "en-CA", "fr-FR", "fr-CA"],
        }

        pcr = ProviderConfigurationResponse().deserialize(json.dumps(resp), "json")
        assert pcr.verify()
        rk = list(resp.keys())
        # parameters with default value if missing
        rk.extend(
            [
                "grant_types_supported",
                "request_parameter_supported",
                "request_uri_parameter_supported",
                "require_request_uri_registration",
            ]
        )
        assert sorted(rk) == sorted(list(pcr.keys()))

    @pytest.mark.parametrize(
        "required_param",
        [
            "issuer",
            "authorization_endpoint",
            "jwks_uri",
            "response_types_supported",
            "subject_types_supported",
            "id_token_signing_alg_values_supported",
        ],
    )
    def test_required_parameters(self, required_param):
        provider_config = {
            "issuer": "https://server.example.com",
            "authorization_endpoint": "https://server.example.com/connect/authorize",
            "jwks_uri": "https://server.example.com/jwks.json",
            "response_types_supported": ["code", "code id_token", "id_token", "token id_token"],
            "subject_types_supported": ["public", "pairwise"],
            "id_token_signing_alg_values_supported": ["RS256", "ES256", "HS256"],
        }

        del provider_config[required_param]
        with pytest.raises(MissingRequiredAttribute):
            ProviderConfigurationResponse(**provider_config).verify()

    def test_token_endpoint_is_not_required_for_implicit_flow_only(self):
        provider_config = {
            "issuer": "https://server.example.com",
            "authorization_endpoint": "https://server.example.com/connect/authorize",
            "jwks_uri": "https://server.example.com/jwks.json",
            "response_types_supported": ["id_token", "token id_token"],
            "subject_types_supported": ["public", "pairwise"],
            "id_token_signing_alg_values_supported": ["RS256", "ES256", "HS256"],
        }

        # should not raise an exception
        assert ProviderConfigurationResponse(**provider_config).verify()

    def test_token_endpoint_is_required_for_other_than_implicit_flow_only(self):
        provider_config = {
            "issuer": "https://server.example.com",
            "authorization_endpoint": "https://server.example.com/connect/authorize",
            "jwks_uri": "https://server.example.com/jwks.json",
            "response_types_supported": ["code", "id_token"],
            "subject_types_supported": ["public", "pairwise"],
            "id_token_signing_alg_values_supported": ["RS256", "ES256", "HS256"],
        }

        with pytest.raises(MissingRequiredAttribute):
            ProviderConfigurationResponse(**provider_config).verify()


class TestRegistrationRequest(object):
    def test_deserialize(self):
        msg = {
            "application_type": APPLICATION_TYPE_WEB,
            "redirect_uris": [
                "https://client.example.org/callback",
                "https://client.example.org/callback2",
            ],
            "client_name": "My Example",
            "client_name#ja-Jpan-JP": "クライアント名",
            "logo_uri": "https://client.example.org/logo.png",
            "subject_type": "pairwise",
            "sector_identifier_uri": "https://other.example.net/file_of_redirect_uris.json",
            "token_endpoint_auth_method": "client_secret_basic",
            "jwks_uri": "https://client.example.org/my_public_keys.jwks",
            "userinfo_encrypted_response_alg": "RSA1_5",
            "userinfo_encrypted_response_enc": "A128CBC+HS256",
            "contacts": ["ve7jtb@example.org", "mary@example.org"],
            "request_uris": [
                "https://client.example.org/rf.txt" "#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA"
            ],
        }

        reg = RegistrationRequest().deserialize(json.dumps(msg), "json")
        assert reg.verify()
        assert _eq(list(msg.keys()) + ["response_types"], reg.keys())

    def test_registration_request(self):
        req = RegistrationRequest(
            operation="register",
            default_max_age=10,
            require_auth_time=True,
            default_acr="foo",
            application_type=APPLICATION_TYPE_WEB,
            redirect_uris=["https://example.com/authz_cb"],
        )
        assert req.verify()
        js = req.to_json()
        js_obj = json.loads(js)
        expected_js_obj = {
            "redirect_uris": ["https://example.com/authz_cb"],
            "application_type": APPLICATION_TYPE_WEB,
            "default_acr": "foo",
            "require_auth_time": True,
            "operation": "register",
            "default_max_age": 10,
            "response_types": ["code"],
        }
        assert js_obj == expected_js_obj

        flattened_list_dict = {
            k: v[0] if isinstance(v, list) else v for k, v in expected_js_obj.items()
        }
        assert query_string_compare(req.to_urlencoded(), urlencode(flattened_list_dict))

    @pytest.mark.parametrize(
        "enc_param",
        [
            "request_object_encryption_enc",
            "id_token_encrypted_response_enc",
            "userinfo_encrypted_response_enc",
        ],
    )
    def test_registration_request_with_coupled_encryption_params(self, enc_param):
        registration_params = {
            "redirect_uris": ["https://example.com/authz_cb"],
            enc_param: "RS256",
        }
        registration_req = RegistrationRequest(**registration_params)
        with pytest.raises(MissingRequiredAttribute):
            registration_req.verify()

    def test_deser(self):
        req = RegistrationRequest(
            operation="register",
            default_max_age=10,
            require_auth_time=True,
            default_acr="foo",
            application_type=APPLICATION_TYPE_WEB,
            redirect_uris=["https://example.com/authz_cb"],
        )
        ser_req = req.serialize("urlencoded")
        deser_req = registration_request_deser(ser_req)
        assert set(deser_req.keys()) == {
            "operation",
            "default_max_age",
            "require_auth_time",
            "default_acr",
            "application_type",
            "redirect_uris",
            "response_types",
        }

    def test_deser_dict(self):
        req = {
            "operation": "register",
            "default_max_age": 10,
            "require_auth_time": True,
            "default_acr": "foo",
            "application_type": APPLICATION_TYPE_WEB,
            "redirect_uris": ["https://example.com/authz_cb"],
        }

        deser_req = registration_request_deser(req, "dict")
        assert set(deser_req.keys()) == {
            "operation",
            "default_max_age",
            "require_auth_time",
            "default_acr",
            "application_type",
            "redirect_uris",
            "response_types",
        }

    def test_deser_dict_json(self):
        req = {
            "operation": "register",
            "default_max_age": 10,
            "require_auth_time": True,
            "default_acr": "foo",
            "application_type": APPLICATION_TYPE_WEB,
            "redirect_uris": ["https://example.com/authz_cb"],
        }

        deser_req = registration_request_deser(req, "json")
        assert set(deser_req.keys()) == {
            "operation",
            "default_max_age",
            "require_auth_time",
            "default_acr",
            "application_type",
            "redirect_uris",
            "response_types",
        }


class TestRegistrationResponse(object):
    def test_deserialize(self):
        msg = {
            "client_id": "s6BhdRkqt3",
            "client_secret": "ZJYCqe3GGRvdrudKyZS0XhGv_Z45DuKhCUk0gBR1vZk",
            "client_secret_expires_at": 1577858400,
            "registration_access_token": "this.is.an.access.token.value.ffx83",
            "registration_client_uri": "https://server.example.com/connect/register?client_id"
            "=s6BhdRkqt3",
            "token_endpoint_auth_method": "client_secret_basic",
            "application_type": APPLICATION_TYPE_WEB,
            "redirect_uris": [
                "https://client.example.org/callback",
                "https://client.example.org/callback2",
            ],
            "client_name": "My Example",
            "client_name#ja-Jpan-JP": "クライアント名",
            "logo_uri": "https://client.example.org/logo.png",
            "subject_type": "pairwise",
            "sector_identifier_uri": "https://other.example.net/file_of_redirect_uris.json",
            "jwks_uri": "https://client.example.org/my_public_keys.jwks",
            "userinfo_encrypted_response_alg": "RSA1_5",
            "userinfo_encrypted_response_enc": "A128CBC+HS256",
            "contacts": ["ve7jtb@example.org", "mary@example.org"],
            "request_uris": [
                "https://client.example.org/rf.txt" "#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA"
            ],
        }

        resp = RegistrationResponse().deserialize(json.dumps(msg), "json")
        assert resp.verify()
        assert _eq(msg.keys(), resp.keys())


class TestAuthorizationRequest(object):
    def test_deserialize(self):
        query = (
            "response_type=token%20id_token&client_id=0acf77d4-b486-4c99"
            "-bd76-074ed6a64ddf&redirect_uri=https%3A%2F%2Fclient.example"
            ".com%2Fcb&scope=openid%20profile&state=af0ifjsldkj&nonce=n"
            "-0S6_WzA2Mj"
        )

        req = AuthorizationRequest().deserialize(query, "urlencoded")

        assert _eq(
            req.keys(), ["nonce", "state", "redirect_uri", "response_type", "client_id", "scope"]
        )

        assert req["response_type"] == ["token", "id_token"]
        assert req["scope"] == ["openid", "profile"]

    def test_verify_no_scopes(self):
        args = {
            "client_id": "foobar",
            "redirect_uri": "http://foobar.example.com/oaclient",
            "response_type": "code",
        }
        ar = AuthorizationRequest(**args)
        with pytest.raises(MissingRequiredAttribute):
            ar.verify()

    def test_verify_nonce(self):
        args = {
            "client_id": "foobar",
            "redirect_uri": "http://foobar.example.com/oaclient",
            "response_type": ["code", "id_token"],
            "scope": "openid",
        }
        ar = AuthorizationRequest(**args)
        with pytest.raises(MissingRequiredAttribute):
            ar.verify()

        ar["nonce"] = "abcdefgh"
        assert ar.verify()

        with pytest.raises(ValueError):
            assert ar.verify(nonce="12345678")

    def test_claims(self):
        args = {
            "client_id": "foobar",
            "redirect_uri": "http://foobar.example.com/oaclient",
            "response_type": "code",
            "scope": "openid",
            "claims": {
                "userinfo": {
                    "given_name": {"essential": True},
                    "nickname": None,
                    "email": {"essential": True},
                    "email_verified": {"essential": True},
                    "picture": None,
                    "http://example.info/claims/groups": None,
                },
                "id_token": {
                    "auth_time": {"essential": True},
                    "acr": {"values": ["urn:mace:incommon:iap:silver"]},
                },
            },
        }
        ar = AuthorizationRequest(**args)
        assert ar.verify()

        ar_url = ar.to_urlencoded()
        ar2 = AuthorizationRequest().from_urlencoded(ar_url)
        assert ar2.verify()

        ar_json = ar.to_json()
        ar3 = AuthorizationRequest().from_json(ar_json)
        assert ar3.verify()

    def test_request(self):
        args = {
            "client_id": "foobar",
            "redirect_uri": "http://foobar.example.com/oaclient",
            "response_type": "code",
            "scope": "openid",
            "nonce": "some value",
            "extra": "attribute",
        }
        ar = AuthorizationRequest(**args)
        keyjar = KeyJar()
        keyjar.add_symmetric("", "SomeTestPassword")
        keyjar.add_symmetric("foobar", "SomeTestPassword")
        _signed_jwt = make_openid_request(ar, keyjar, "foobar", "HS256", "barfoo")
        ar["request"] = _signed_jwt
        del ar["nonce"]
        del ar["extra"]
        ar["scope"] = ["openid", "email"]
        res = ar.verify(keyjar=keyjar)
        assert res
        assert "extra" in ar
        assert "nonce" in ar
        assert ar["scope"] == ["openid"]


class TestAccessTokenResponse(object):
    def test_ok_idtoken(self):
        idval = {
            "nonce": "KUEYfRM2VzKDaaKD",
            "sub": "EndUserSubject",
            "iss": "https://alpha.cloud.nds.rub.de",
            "aud": "TestClient",
        }
        idts = IdToken(**idval)
        keyjar = KeyJar()
        keyjar.add_symmetric("", "SomeTestPassword")
        keyjar.add_symmetric("https://alpha.cloud.nds.rub.de", "SomeTestPassword")
        _signed_jwt = idts.to_jwt(
            key=keyjar.get_signing_key("oct"), algorithm="HS256", lifetime=300
        )

        _info = {
            "access_token": "accessTok",
            "id_token": _signed_jwt,
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        at = AccessTokenResponse(**_info)
        assert at.verify(keyjar=keyjar)

    def test_faulty_idtoken(self):
        idval = {
            "nonce": "KUEYfRM2VzKDaaKD",
            "sub": "EndUserSubject",
            "iss": "https://alpha.cloud.nds.rub.de",
            "aud": "TestClient",
        }
        idts = IdToken(**idval)
        keyjar = KeyJar()
        keyjar.add_symmetric("", "SomeTestPassword")
        keyjar.add_symmetric("https://alpha.cloud.nds.rub.de", "SomeTestPassword")
        _signed_jwt = idts.to_jwt(
            key=keyjar.get_signing_key("oct"), algorithm="HS256", lifetime=300
        )
        # Mess with the signed id_token
        p = _signed_jwt.split(".")
        p[2] = "aaa"
        _faulty_signed_jwt = ".".join(p)

        _info = {
            "access_token": "accessTok",
            "id_token": _faulty_signed_jwt,
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        at = AccessTokenResponse(**_info)
        with pytest.raises(BadSignature):
            at.verify(keyjar=keyjar)

    def test_wrong_alg(self):
        idval = {
            "nonce": "KUEYfRM2VzKDaaKD",
            "sub": "EndUserSubject",
            "iss": "https://alpha.cloud.nds.rub.de",
            "aud": "TestClient",
        }
        idts = IdToken(**idval)
        keyjar = KeyJar()
        keyjar.add_symmetric("", "SomeTestPassword")
        keyjar.add_symmetric("https://alpha.cloud.nds.rub.de", "SomeTestPassword")
        _signed_jwt = idts.to_jwt(
            key=keyjar.get_signing_key("oct"), algorithm="HS256", lifetime=300
        )

        _info = {
            "access_token": "accessTok",
            "id_token": _signed_jwt,
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        at = AccessTokenResponse(**_info)
        with pytest.raises(SignerAlgError):
            at.verify(keyjar=keyjar, sigalg="HS512")


def test_at_hash():
    lifetime = 3600
    _token = {"access_token": "accessTok"}
    idval = {
        "nonce": "KUEYfRM2VzKDaaKD",
        "sub": "EndUserSubject",
        "iss": "https://alpha.cloud.nds.rub.de",
        "aud": "TestClient",
    }
    idval.update(_token)

    idts = IdToken(**idval)
    keyjar = KeyJar()
    keyjar.add_symmetric("", "SomeTestPassword")
    keyjar.add_symmetric("https://alpha.cloud.nds.rub.de", "SomeTestPassword")
    _signed_jwt = idts.to_jwt(
        key=keyjar.get_signing_key("oct"), algorithm="HS256", lifetime=lifetime
    )

    _info = {"id_token": _signed_jwt, "token_type": "Bearer", "expires_in": lifetime}
    _info.update(_token)

    at = AuthorizationResponse(**_info)
    assert at.verify(keyjar=keyjar, sigalg="HS256")
    assert "at_hash" in at[verified_claim_name("id_token")]


def test_c_hash():
    lifetime = 3600
    _token = {"code": "grant"}

    idval = {
        "nonce": "KUEYfRM2VzKDaaKD",
        "sub": "EndUserSubject",
        "iss": "https://alpha.cloud.nds.rub.de",
        "aud": "TestClient",
    }
    idval.update(_token)

    idts = IdToken(**idval)
    keyjar = KeyJar()
    keyjar.add_symmetric("", "SomeTestPassword")
    keyjar.add_symmetric("https://alpha.cloud.nds.rub.de", "SomeTestPassword")
    _signed_jwt = idts.to_jwt(
        key=keyjar.get_signing_key("oct"), algorithm="HS256", lifetime=lifetime
    )

    _info = {"id_token": _signed_jwt, "token_type": "Bearer", "expires_in": lifetime}
    _info.update(_token)

    at = AuthorizationResponse(**_info)
    r = at.verify(keyjar=keyjar, sigalg="HS256")
    assert "c_hash" in at[verified_claim_name("id_token")]


def test_missing_c_hash():
    lifetime = 3600
    _token = {"code": "grant"}

    idval = {
        "nonce": "KUEYfRM2VzKDaaKD",
        "sub": "EndUserSubject",
        "iss": "https://alpha.cloud.nds.rub.de",
        "aud": "TestClient",
    }
    # idval.update(_token)

    idts = IdToken(**idval)
    keyjar = KeyJar()
    keyjar.add_symmetric("", "SomeTestPassword")
    keyjar.add_symmetric("https://alpha.cloud.nds.rub.de", "SomeTestPassword")

    _signed_jwt = idts.to_jwt(
        key=keyjar.get_signing_key("oct"), algorithm="HS256", lifetime=lifetime
    )

    _info = {"id_token": _signed_jwt, "token_type": "Bearer", "expires_in": lifetime}
    _info.update(_token)

    at = AuthorizationResponse(**_info)
    with pytest.raises(MissingRequiredAttribute):
        at.verify(keyjar=keyjar, sigalg="HS256")


def test_id_token():
    _now = time_util.utc_time_sans_frac()

    idt = IdToken(
        **{
            "sub": "553df2bcf909104751cfd8b2",
            "aud": ["5542958437706128204e0000", "554295ce3770612820620000"],
            "auth_time": 1441364872,
            "azp": "554295ce3770612820620000",
            "at_hash": "L4Ign7TCAD_EppRbHAuCyw",
            "iat": _now,
            "exp": _now + 3600,
            "iss": "https://sso.qa.7pass.ctf.prosiebensat1.com",
        }
    )

    idt.verify()


def test_id_token_expired():
    _now = time_util.utc_time_sans_frac()

    idt = IdToken(
        **{
            "sub": "553df2bcf909104751cfd8b2",
            "aud": ["5542958437706128204e0000", "554295ce3770612820620000"],
            "auth_time": 1441364872,
            "azp": "554295ce3770612820620000",
            "at_hash": "L4Ign7TCAD_EppRbHAuCyw",
            "iat": _now - 200,
            "exp": _now - 100,
            "iss": "https://sso.qa.7pass.ctf.prosiebensat1.com",
        }
    )

    with pytest.raises(EXPError):
        idt.verify()


def test_id_token_iat_in_the_future():
    _now = time_util.utc_time_sans_frac()

    idt = IdToken(
        **{
            "sub": "553df2bcf909104751cfd8b2",
            "aud": ["5542958437706128204e0000", "554295ce3770612820620000"],
            "auth_time": 1441364872,
            "azp": "554295ce3770612820620000",
            "at_hash": "L4Ign7TCAD_EppRbHAuCyw",
            "iat": _now + 600,
            "exp": _now + 1200,
            "iss": "https://sso.qa.7pass.ctf.prosiebensat1.com",
        }
    )

    with pytest.raises(IATError):
        idt.verify()


def test_id_token_exp_before_iat():
    _now = time_util.utc_time_sans_frac()

    idt = IdToken(
        **{
            "sub": "553df2bcf909104751cfd8b2",
            "aud": ["5542958437706128204e0000", "554295ce3770612820620000"],
            "auth_time": 1441364872,
            "azp": "554295ce3770612820620000",
            "at_hash": "L4Ign7TCAD_EppRbHAuCyw",
            "iat": _now + 50,
            "exp": _now,
            "iss": "https://sso.qa.7pass.ctf.prosiebensat1.com",
        }
    )

    with pytest.raises(IATError):
        idt.verify(skew=100)


class TestAccessTokenRequest(object):
    def test_example(self):
        _txt = (
            "grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA"
            "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb"
        )
        atr = AccessTokenRequest().from_urlencoded(_txt)
        assert atr.verify()


class TestAuthnToken(object):
    def test_example(self):
        at = AuthnToken(
            iss="https://example.com",
            sub="https://example,org",
            aud=["https://example.org/token"],  # Array of strings or string
            jti="abcdefghijkl",
            exp=utc_time_sans_frac() + 3600,
        )
        assert at.verify()


class TestAuthorizationErrorResponse(object):
    def test_allowed_err(self):
        aer = AuthorizationErrorResponse(error="interaction_required")
        assert aer.verify()

    def test_not_allowed_err(self):
        aer = AuthorizationErrorResponse(error="other_error")
        with pytest.raises(NotAllowedValue):
            assert aer.verify()


@pytest.mark.parametrize("bdate", ["1971-11-23", "0000-11-23", "1971"])
def test_birthdate(bdate):
    uinfo = OpenIDSchema(birthdate=bdate, sub="jarvis")
    uinfo.verify()


def test_factory():
    dr = factory(
        "DiscoveryRequest",
        resource="local@domain",
        rel="http://openid.net/specs/connect/1.0/issuer",
    )
    assert isinstance(dr, DiscoveryRequest)
    assert set(dr.keys()) == {"resource", "rel"}


def test_factory_chain():
    dr = factory("ResponseMessage", error="some_error")
    assert isinstance(dr, ResponseMessage)
    assert list(dr.keys()) == ["error"]


def test_dict_deser():
    _info = {"foo": "bar"}

    # supposed to output JSON
    _jinfo = dict_deser(_info, "dict")
    assert _jinfo == json.dumps(_info)

    _jinfo2 = dict_deser(_jinfo, "dict")
    assert _jinfo == _jinfo2

    with pytest.raises(ValueError):
        _ = dict_deser(_info, "foo")


def test_claims_match():
    assert claims_match(["val"], None)
    assert claims_match("val", {"value": "val"})
    assert claims_match("val", {"value": "other"}) is False
    assert claims_match("val", {"values": ["val", "other"]})
    assert claims_match("val", {"value": "val", "essential": True})
    assert claims_match("val", {"value": "other", "essential": True}) is False
    assert claims_match("val", {"essential": True})


def test_factory_2():
    inst = factory("ROPCAccessTokenRequest", username="me", password="text", scope="mar")
    assert isinstance(inst, ROPCAccessTokenRequest)


def test_link_deser():
    link = Link(href="https://example.com/op", rel="http://openid.net/specs/connect/1.0/issuer")

    jl = link_ser(link, "json")
    l2 = link_deser([jl], "json")
    assert isinstance(l2[0], Link)


def test_link_deser_dict():
    link = Link(href="https://example.com/op", rel="http://openid.net/specs/connect/1.0/issuer")

    l2 = link_deser([link.to_dict()], "json")
    assert isinstance(l2[0], Link)


def test_proper_path():
    p = proper_path("foo/bar")
    assert p == "./foo/bar/"

    p = proper_path("/foo/bar")
    assert p == "./foo/bar/"

    p = proper_path("./foo/bar")
    assert p == "./foo/bar/"

    p = proper_path("../foo/bar")
    assert p == "./foo/bar/"


def test_verify_id_token():
    idt = IdToken(
        **{
            "sub": "553df2bcf909104751cfd8b2",
            "aud": ["5542958437706128204e0000", "554295ce3770612820620000"],
            "auth_time": 1441364872,
            "azp": "554295ce3770612820620000",
        }
    )

    kj = KeyJar()
    kj.add_symmetric("", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"])
    kj.add_symmetric(
        "https://sso.qa.7pass.ctf.prosiebensat1.com", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"]
    )
    packer = JWT(
        kj, sign_alg="HS256", iss="https://sso.qa.7pass.ctf.prosiebensat1.com", lifetime=3600
    )
    _jws = packer.pack(payload=idt.to_dict())
    msg = AuthorizationResponse(id_token=_jws)
    vidt = verify_id_token(
        msg,
        keyjar=kj,
        iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
        client_id="554295ce3770612820620000",
    )
    assert vidt


def test_verify_id_token_wrong_issuer():
    idt = IdToken(
        **{
            "sub": "553df2bcf909104751cfd8b2",
            "aud": ["5542958437706128204e0000", "554295ce3770612820620000"],
            "auth_time": 1441364872,
            "azp": "554295ce3770612820620000",
        }
    )

    kj = KeyJar()
    kj.add_symmetric("", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"])
    kj.add_symmetric(
        "https://sso.qa.7pass.ctf.prosiebensat1.com", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"]
    )
    packer = JWT(kj, sign_alg="HS256", iss="https://example.com/as", lifetime=3600)
    _jws = packer.pack(payload=idt.to_dict())
    msg = AuthorizationResponse(id_token=_jws)
    with pytest.raises(ValueError):
        verify_id_token(
            msg,
            keyjar=kj,
            iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
            client_id="554295ce3770612820620000",
        )


def test_verify_id_token_wrong_aud():
    idt = IdToken(
        **{
            "sub": "553df2bcf909104751cfd8b2",
            "aud": ["5542958437706128204e0000", "554295ce3770612820620000"],
            "auth_time": 1441364872,
            "azp": "554295ce3770612820620000",
        }
    )

    kj = KeyJar()
    kj.add_symmetric("", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"])
    kj.add_symmetric(
        "https://sso.qa.7pass.ctf.prosiebensat1.com", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"]
    )
    packer = JWT(kj, sign_alg="HS256", iss="https://example.com/as", lifetime=3600)
    _jws = packer.pack(payload=idt.to_dict())
    msg = AuthorizationResponse(id_token=_jws)
    with pytest.raises(ValueError):
        verify_id_token(
            msg,
            keyjar=kj,
            iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
            client_id="aaaaaaaaaaaaaaaaaaaa",
        )


def test_verify_id_token_mismatch_aud_azp():
    idt = IdToken(
        **{
            "sub": "553df2bcf909104751cfd8b2",
            "aud": ["5542958437706128204e0000", "554295ce3770612820620000"],
            "auth_time": 1441364872,
            "azp": "aaaaaaaaaaaaaaaaaaaa",
        }
    )

    kj = KeyJar()
    kj.add_symmetric("", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"])
    kj.add_symmetric(
        "https://sso.qa.7pass.ctf.prosiebensat1.com", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"]
    )
    packer = JWT(kj, sign_alg="HS256", iss="https://example.com/as", lifetime=3600)
    _jws = packer.pack(payload=idt.to_dict())
    msg = AuthorizationResponse(id_token=_jws)
    with pytest.raises(ValueError):
        verify_id_token(
            msg,
            keyjar=kj,
            iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
            client_id="aaaaaaaaaaaaaaaaaaaa",
        )


def test_verify_id_token_c_hash():
    code = "AccessCode1"
    lhsh = left_hash(code)

    idt = IdToken(
        **{
            "sub": "553df2bcf909104751cfd8b2",
            "aud": ["5542958437706128204e0000", "554295ce3770612820620000"],
            "auth_time": 1441364872,
            "azp": "554295ce3770612820620000",
            "c_hash": lhsh,
        }
    )

    kj = KeyJar()
    kj.add_symmetric("", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"])
    kj.add_symmetric(
        "https://sso.qa.7pass.ctf.prosiebensat1.com", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"]
    )
    packer = JWT(
        kj, sign_alg="HS256", iss="https://sso.qa.7pass.ctf.prosiebensat1.com", lifetime=3600
    )
    _jws = packer.pack(payload=idt.to_dict())
    msg = AuthorizationResponse(code=code, id_token=_jws)
    verify_id_token(
        msg,
        check_hash=True,
        keyjar=kj,
        iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
        client_id="554295ce3770612820620000",
    )


def test_verify_id_token_c_hash_fail():
    code = "AccessCode1"
    lhsh = left_hash(code)

    idt = IdToken(
        **{
            "sub": "553df2bcf909104751cfd8b2",
            "aud": ["5542958437706128204e0000", "554295ce3770612820620000"],
            "auth_time": 1441364872,
            "azp": "554295ce3770612820620000",
            "c_hash": lhsh,
        }
    )

    kj = KeyJar()
    kj.add_symmetric("", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"])
    kj.add_symmetric(
        "https://sso.qa.7pass.ctf.prosiebensat1.com", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"]
    )
    packer = JWT(
        kj, sign_alg="HS256", iss="https://sso.qa.7pass.ctf.prosiebensat1.com", lifetime=3600
    )
    _jws = packer.pack(payload=idt.to_dict())
    msg = AuthorizationResponse(code="AccessCode289", id_token=_jws)
    with pytest.raises(CHashError):
        verify_id_token(
            msg,
            check_hash=True,
            keyjar=kj,
            iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
            client_id="554295ce3770612820620000",
        )


def test_verify_id_token_at_hash():
    token = "AccessTokenWhichCouldBeASignedJWT"
    lhsh = left_hash(token)

    idt = IdToken(
        **{
            "sub": "553df2bcf909104751cfd8b2",
            "aud": ["5542958437706128204e0000", "554295ce3770612820620000"],
            "auth_time": 1441364872,
            "azp": "554295ce3770612820620000",
            "at_hash": lhsh,
        }
    )

    kj = KeyJar()
    kj.add_symmetric("", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"])
    kj.add_symmetric(
        "https://sso.qa.7pass.ctf.prosiebensat1.com", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"]
    )
    packer = JWT(
        kj, sign_alg="HS256", iss="https://sso.qa.7pass.ctf.prosiebensat1.com", lifetime=3600
    )
    _jws = packer.pack(payload=idt.to_dict())
    msg = AuthorizationResponse(access_token=token, id_token=_jws)
    verify_id_token(
        msg,
        check_hash=True,
        keyjar=kj,
        iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
        client_id="554295ce3770612820620000",
    )


def test_verify_id_token_at_hash_fail():
    token = "AccessTokenWhichCouldBeASignedJWT"
    token2 = "ACompletelyOtherAccessToken"
    lhsh = left_hash(token)

    idt = IdToken(
        **{
            "sub": "553df2bcf909104751cfd8b2",
            "aud": ["5542958437706128204e0000", "554295ce3770612820620000"],
            "auth_time": 1441364872,
            "azp": "554295ce3770612820620000",
            "at_hash": lhsh,
        }
    )

    kj = KeyJar()
    kj.add_symmetric("", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"])
    kj.add_symmetric(
        "https://sso.qa.7pass.ctf.prosiebensat1.com", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"]
    )
    packer = JWT(
        kj, sign_alg="HS256", iss="https://sso.qa.7pass.ctf.prosiebensat1.com", lifetime=3600
    )
    _jws = packer.pack(payload=idt.to_dict())
    msg = AuthorizationResponse(access_token=token2, id_token=_jws)
    with pytest.raises(AtHashError):
        verify_id_token(
            msg,
            check_hash=True,
            keyjar=kj,
            iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
            client_id="554295ce3770612820620000",
        )


def test_verify_id_token_missing_at_hash():
    token = "AccessTokenWhichCouldBeASignedJWT"

    idt = IdToken(
        **{
            "sub": "553df2bcf909104751cfd8b2",
            "aud": ["5542958437706128204e0000", "554295ce3770612820620000"],
            "auth_time": 1441364872,
            "azp": "554295ce3770612820620000",
        }
    )

    kj = KeyJar()
    kj.add_symmetric("", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"])
    kj.add_symmetric(
        "https://sso.qa.7pass.ctf.prosiebensat1.com", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"]
    )
    packer = JWT(
        kj, sign_alg="HS256", iss="https://sso.qa.7pass.ctf.prosiebensat1.com", lifetime=3600
    )
    _jws = packer.pack(payload=idt.to_dict())
    msg = AuthorizationResponse(access_token=token, id_token=_jws)
    with pytest.raises(MissingRequiredAttribute):
        verify_id_token(
            msg,
            check_hash=True,
            keyjar=kj,
            iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
            client_id="554295ce3770612820620000",
        )


def test_verify_id_token_missing_c_hash():
    code = "AccessCode1"

    idt = IdToken(
        **{
            "sub": "553df2bcf909104751cfd8b2",
            "aud": ["5542958437706128204e0000", "554295ce3770612820620000"],
            "auth_time": 1441364872,
            "azp": "554295ce3770612820620000",
        }
    )

    kj = KeyJar()
    kj.add_symmetric("", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"])
    kj.add_symmetric(
        "https://sso.qa.7pass.ctf.prosiebensat1.com", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"]
    )
    packer = JWT(
        kj, sign_alg="HS256", iss="https://sso.qa.7pass.ctf.prosiebensat1.com", lifetime=3600
    )
    _jws = packer.pack(payload=idt.to_dict())
    msg = AuthorizationResponse(code=code, id_token=_jws)
    with pytest.raises(MissingRequiredAttribute):
        verify_id_token(
            msg,
            check_hash=True,
            keyjar=kj,
            iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
            client_id="554295ce3770612820620000",
        )


def test_verify_id_token_at_hash_and_chash():
    token = "AccessTokenWhichCouldBeASignedJWT"
    at_hash = left_hash(token)
    code = "AccessCode1"
    c_hash = left_hash(code)

    idt = IdToken(
        **{
            "sub": "553df2bcf909104751cfd8b2",
            "aud": ["5542958437706128204e0000", "554295ce3770612820620000"],
            "auth_time": 1441364872,
            "azp": "554295ce3770612820620000",
            "at_hash": at_hash,
            "c_hash": c_hash,
        }
    )

    kj = KeyJar()
    kj.add_symmetric("", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"])
    kj.add_symmetric(
        "https://sso.qa.7pass.ctf.prosiebensat1.com", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"]
    )
    packer = JWT(
        kj, sign_alg="HS256", iss="https://sso.qa.7pass.ctf.prosiebensat1.com", lifetime=3600
    )
    _jws = packer.pack(payload=idt.to_dict())
    msg = AuthorizationResponse(access_token=token, id_token=_jws, code=code)
    verify_id_token(
        msg,
        check_hash=True,
        keyjar=kj,
        iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
        client_id="554295ce3770612820620000",
    )


def test_verify_id_token_missing_iss():
    idt = IdToken(
        **{
            "sub": "553df2bcf909104751cfd8b2",
            "aud": ["5542958437706128204e0000", "554295ce3770612820620000"],
            "auth_time": 1441364872,
            "azp": "554295ce3770612820620000",
        }
    )

    kj = KeyJar()
    kj.add_symmetric("", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"])
    kj.add_symmetric(
        "https://sso.qa.7pass.ctf.prosiebensat1.com", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"]
    )
    packer = JWT(kj, sign_alg="HS256", lifetime=3600)
    _jws = packer.pack(payload=idt.to_dict())
    msg = AuthorizationResponse(id_token=_jws)
    with pytest.raises(MissingRequiredAttribute):
        verify_id_token(
            msg,
            check_hash=True,
            keyjar=kj,
            iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
            client_id="554295ce3770612820620000",
        )


def test_verify_id_token_iss_not_in_keyjar():
    idt = IdToken(
        **{
            "sub": "553df2bcf909104751cfd8b2",
            "aud": ["5542958437706128204e0000", "554295ce3770612820620000"],
            "auth_time": 1441364872,
            "azp": "554295ce3770612820620000",
        }
    )

    kj = KeyJar()
    kj.add_symmetric("", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"])
    kj.add_symmetric(
        "https://sso.qa.7pass.ctf.prosiebensat1.com", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"]
    )
    packer = JWT(kj, sign_alg="HS256", lifetime=3600, iss="https://example.com/op")
    _jws = packer.pack(payload=idt.to_dict())
    msg = AuthorizationResponse(id_token=_jws)
    with pytest.raises(ValueError):
        verify_id_token(
            msg,
            check_hash=True,
            keyjar=kj,
            iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
            client_id="554295ce3770612820620000",
        )


def test_wrong_sign_alg():
    idt = IdToken(
        **{
            "sub": "553df2bcf909104751cfd8b2",
            "aud": ["5542958437706128204e0000", "554295ce3770612820620000"],
            "auth_time": 1441364872,
            "azp": "554295ce3770612820620000",
        }
    )

    kj = KeyJar()
    kj.add_symmetric("", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"])
    kj.add_symmetric("554295ce3770612820620000", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"])
    packer = JWT(kj, sign_alg="HS256", lifetime=3600, iss="https://example.com/op")
    _jws = packer.pack(payload=idt.to_dict())
    msg = AuthorizationResponse(id_token=_jws)
    with pytest.raises(UnsupportedAlgorithm):
        verify_id_token(
            msg,
            check_hash=True,
            keyjar=kj,
            iss="https://example.com/op",
            client_id="554295ce3770612820620000",
            allowed_sign_alg="RS256",
        )


def test_correct_sign_alg():
    idt = IdToken(
        **{
            "sub": "553df2bcf909104751cfd8b2",
            "aud": ["5542958437706128204e0000", "554295ce3770612820620000"],
            "auth_time": 1441364872,
            "azp": "554295ce3770612820620000",
        }
    )

    kj = KeyJar()
    kj.add_symmetric("", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"])
    kj.add_symmetric("https://example.com/op", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"])
    kj.add_symmetric("554295ce3770612820620000", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"])
    packer = JWT(kj, sign_alg="HS256", lifetime=3600, iss="https://example.com/op")
    _jws = packer.pack(payload=idt.to_dict())
    msg = AuthorizationResponse(id_token=_jws)
    assert verify_id_token(
        msg,
        check_hash=True,
        keyjar=kj,
        iss="https://example.com/op",
        client_id="554295ce3770612820620000",
        allowed_sign_alg="HS256",
    )


def test_ID_Token_space_in_id():
    idt = IdToken(
        **{
            "at_hash": "buCCujNN632UIV8-VbKhgw",
            "sub": "user-subject-1234531",
            "aud": "client_ifCttPphtLxtPWd20602 ^.+/",
            "iss": "https://www.certification.openid.net/test/a/idpy/",
            "exp": 1632495959,
            "nonce": "B88En9UpdHkQZMQXK9U3KHzV",
            "iat": 1632495659,
        }
    )

    assert idt["aud"] == ["client_ifCttPphtLxtPWd20602 ^.+/"]

    idt = IdToken(
        **{
            "at_hash": "rgMbiR-Dj11dQjxhCyLkOw",
            "sub": "user-subject-1234531",
            "aud": "client_dVCwIQuSKklinFP70742;#__$",
            "iss": "https://www.certification.openid.net/test/a/idpy/",
            "exp": 1632639462,
            "nonce": "hUT3RhSooxC9CilrD8al6bGx",
            "iat": 1632639162,
        }
    )

    assert idt["aud"] == ["client_dVCwIQuSKklinFP70742;#__$"]
