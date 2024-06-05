from typing import Callable

import pytest
from cryptojwt.utils import importer

from idpyoidc.client.claims.oidc import Claims as OIDC_Claims
from idpyoidc.client.claims.transform import create_registration_request
from idpyoidc.client.claims.transform import preferred_to_registered
from idpyoidc.client.claims.transform import supported_to_preferred
from idpyoidc.message.oidc import APPLICATION_TYPE_WEB
from idpyoidc.message.oidc import ProviderConfigurationResponse
from idpyoidc.message.oidc import RegistrationRequest


class TestTransform:
    @pytest.fixture(autouse=True)
    def setup(self):
        supported = OIDC_Claims._supports.copy()
        for service in [
            "idpyoidc.client.oidc.access_token.AccessToken",
            "idpyoidc.client.oidc.authorization.Authorization",
            "idpyoidc.client.oidc.backchannel_authentication.BackChannelAuthentication",
            "idpyoidc.client.oidc.backchannel_authentication.ClientNotification",
            "idpyoidc.client.oidc.check_id.CheckID",
            "idpyoidc.client.oidc.check_session.CheckSession",
            "idpyoidc.client.oidc.end_session.EndSession",
            "idpyoidc.client.oidc.provider_info_discovery.ProviderInfoDiscovery",
            "idpyoidc.client.oidc.read_registration.RegistrationRead",
            "idpyoidc.client.oidc.refresh_access_token.RefreshAccessToken",
            "idpyoidc.client.oidc.registration.Registration",
            "idpyoidc.client.oidc.userinfo.UserInfo",
            "idpyoidc.client.oidc.webfinger.WebFinger",
        ]:
            cls = importer(service)
            supported.update(cls._supports)

        for key, val in supported.items():
            if isinstance(val, Callable):
                supported[key] = val()
        # NOTE! Not checking rules
        self.supported = supported

    def test_supported(self):
        # These are all the available configuration parameters
        assert set(self.supported.keys()) == {
            "acr_values_supported",
            "application_type",
            "backchannel_logout_session_required",
            "backchannel_logout_supported",
            "backchannel_logout_uri",
            "callback_uris",
            "client_id",
            "client_name",
            "client_secret",
            "client_uri",
            "contacts",
            "default_max_age",
            "encrypt_id_token_supported",
            "encrypt_request_object_supported",
            "encrypt_userinfo_supported",
            "frontchannel_logout_session_required",
            "frontchannel_logout_supported",
            "frontchannel_logout_uri",
            "id_token_encryption_alg_values_supported",
            "id_token_encryption_enc_values_supported",
            "id_token_signing_alg_values_supported",
            "initiate_login_uri",
            "jwks",
            "jwks_uri",
            "logo_uri",
            "policy_uri",
            "post_logout_redirect_uris",
            "redirect_uris",
            "request_object_encryption_alg_values_supported",
            "request_object_encryption_enc_values_supported",
            "request_object_signing_alg_values_supported",
            "request_parameter",
            "request_parameter_supported",
            "request_uri_parameter_supported",
            "request_uris",
            "requests_dir",
            "require_auth_time",
            "response_modes_supported",
            "response_types_supported",
            "scopes_supported",
            "sector_identifier_uri",
            "subject_types_supported",
            # 'token_endpoint_auth_method',
            "token_endpoint_auth_methods_supported",
            "token_endpoint_auth_signing_alg_values_supported",
            "tos_uri",
            "userinfo_encryption_alg_values_supported",
            "userinfo_encryption_enc_values_supported",
            "userinfo_signing_alg_values_supported",
        }

    def test_oidc_setup(self):
        # This is OP specified stuff
        assert set(ProviderConfigurationResponse.c_param.keys()).difference(
            set(self.supported)
        ) == {
            "authorization_endpoint",
            "check_session_iframe",
            "claim_types_supported",
            "claims_locales_supported",
            "claims_parameter_supported",
            "claims_supported",
            "display_values_supported",
            "end_session_endpoint",
            "error",
            "error_description",
            "error_uri",
            "grant_types_supported",
            "issuer",
            "op_policy_uri",
            "op_tos_uri",
            "registration_endpoint",
            "require_request_uri_registration",
            "service_documentation",
            "token_endpoint",
            "ui_locales_supported",
            "userinfo_endpoint",
            "code_challenge_methods_supported",
        }

        # parameters that are not mapped against what the OP's provider info says
        assert set(self.supported).difference(
            set(ProviderConfigurationResponse.c_param.keys())
        ) == {
            "application_type",
            "backchannel_logout_uri",
            "callback_uris",
            "client_id",
            "client_name",
            "client_secret",
            "client_uri",
            "contacts",
            "default_max_age",
            "encrypt_id_token_supported",
            "encrypt_request_object_supported",
            "encrypt_userinfo_supported",
            "frontchannel_logout_uri",
            "initiate_login_uri",
            "jwks",
            "logo_uri",
            "policy_uri",
            "post_logout_redirect_uris",
            "redirect_uris",
            "request_parameter",
            "request_uris",
            "requests_dir",
            "require_auth_time",
            "sector_identifier_uri",
            "tos_uri",
        }

        claims = OIDC_Claims()
        # No input from the IDP so info is absent
        claims.prefer = supported_to_preferred(
            supported=self.supported, preference=claims.prefer, base_url="https://example.com"
        )

        # These are the claims that has default values. A default value may be an empty list.
        # This is the case for claims like id_token_encryption_enc_values_supported.
        assert set(claims.prefer.keys()) == {
            "application_type",
            "default_max_age",
            "encrypt_request_object_supported",
            "encrypt_userinfo_supported",
            "id_token_encryption_alg_values_supported",
            "id_token_encryption_enc_values_supported",
            "id_token_signing_alg_values_supported",
            "request_object_encryption_alg_values_supported",
            "request_object_encryption_enc_values_supported",
            "request_object_signing_alg_values_supported",
            "response_modes_supported",
            "response_types_supported",
            "scopes_supported",
            "subject_types_supported",
            "token_endpoint_auth_methods_supported",
            "token_endpoint_auth_signing_alg_values_supported",
            "userinfo_encryption_alg_values_supported",
            "userinfo_encryption_enc_values_supported",
            "userinfo_signing_alg_values_supported",
        }

        # To verify that I have all the necessary claims to do client registration
        reg_claim = []
        for key, spec in OIDC_Claims.registration_request.c_param.items():
            _pref_key = OIDC_Claims.register2preferred.get(key, key)
            if _pref_key in self.supported:
                reg_claim.append(key)

        assert set(RegistrationRequest.c_param.keys()).difference(set(reg_claim)) == {
            "post_logout_redirect_uri",
            "grant_types",
            "response_modes",  # Extra item
        }

        # Which ones are list -> singletons

        l_to_s = []
        non_oidc = []
        for key, pref_key in OIDC_Claims.register2preferred.items():
            spec = RegistrationRequest.c_param.get(key)
            if spec is None:
                non_oidc.append(pref_key)
            elif isinstance(spec[0], list):
                l_to_s.append(key)

        assert set(non_oidc) == {"scopes_supported"}
        assert set(l_to_s) == {"response_types", "grant_types", "default_acr_values"}

    def test_provider_info(self):
        OP_BASEURL = "https://example.com"
        provider_info_response = {
            "version": "3.0",
            "token_endpoint_auth_methods_supported": [
                "client_secret_post",
                "client_secret_basic",
                "client_secret_jwt",
                "private_key_jwt",
            ],
            "issuer": OP_BASEURL,
            "jwks_uri": f"{OP_BASEURL}/static/jwks_tE2iLbOAqXhe8bqh.json",
            "authorization_endpoint": f"{OP_BASEURL}/authorization",
            "token_endpoint": f"{OP_BASEURL}/token",
            "userinfo_endpoint": f"{OP_BASEURL}/userinfo",
            "registration_endpoint": f"{OP_BASEURL}/registration",
            "end_session_endpoint": f"{OP_BASEURL}/end_session",
            # below are a set which the RP has default values but the OP overwrites
            "scopes_supported": ["openid", "fee", "faa", "foo", "fum"],
            "response_types_supported": ["code", "id_token", "code id_token"],
            "response_modes_supported": ["query", "form_post", "new_fangled"],
            # this does not have a default value
            "acr_values_supported": ["mfa"],
        }

        claims = OIDC_Claims()
        claims.prefer = supported_to_preferred(
            supported=self.supported,
            preference=claims.prefer,
            base_url="https://example.com",
            info=provider_info_response,
        )

        # These are the claims that has default values
        assert set(claims.prefer.keys()) == {
            "application_type",
            "default_max_age",
            "encrypt_request_object_supported",
            "encrypt_userinfo_supported",
            "id_token_encryption_alg_values_supported",
            "id_token_encryption_enc_values_supported",
            "id_token_signing_alg_values_supported",
            "request_object_encryption_alg_values_supported",
            "request_object_encryption_enc_values_supported",
            "request_object_signing_alg_values_supported",
            "response_modes_supported",
            "response_types_supported",
            "scopes_supported",
            "subject_types_supported",
            "token_endpoint_auth_methods_supported",
            "token_endpoint_auth_signing_alg_values_supported",
            "userinfo_encryption_alg_values_supported",
            "userinfo_encryption_enc_values_supported",
            "userinfo_signing_alg_values_supported",
        }

        # least common denominator
        # The RP supports less than the OP
        assert claims.get_preference("scopes_supported") == ["openid"]
        assert claims.get_preference("response_modes_supported") == ["query", "form_post"]
        # The OP supports less than the RP
        assert claims.get_preference("response_types_supported") == [
            "code",
            "id_token",
            "code id_token",
        ]


class TestTransform2:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.claims = OIDC_Claims()
        supported = self.claims._supports.copy()
        for service in [
            "idpyoidc.client.oidc.access_token.AccessToken",
            "idpyoidc.client.oidc.authorization.Authorization",
            "idpyoidc.client.oidc.backchannel_authentication.BackChannelAuthentication",
            "idpyoidc.client.oidc.backchannel_authentication.ClientNotification",
            "idpyoidc.client.oidc.check_id.CheckID",
            "idpyoidc.client.oidc.check_session.CheckSession",
            "idpyoidc.client.oidc.end_session.EndSession",
            "idpyoidc.client.oidc.provider_info_discovery.ProviderInfoDiscovery",
            "idpyoidc.client.oidc.read_registration.RegistrationRead",
            "idpyoidc.client.oidc.refresh_access_token.RefreshAccessToken",
            "idpyoidc.client.oidc.registration.Registration",
            "idpyoidc.client.oidc.userinfo.UserInfo",
            "idpyoidc.client.oidc.webfinger.WebFinger",
        ]:
            cls = importer(service)
            supported.update(cls._supports)

        for key, val in supported.items():
            if isinstance(val, Callable):
                supported[key] = val()

        self.supported = supported
        preference = {
            "application_type": APPLICATION_TYPE_WEB,
            "redirect_uris": [
                "https://client.example.org/callback",
                "https://client.example.org/callback2",
            ],
            "client_name": "My Example",
            # "client_name#ja-Jpan-JP": "クライアント名",
            "logo_uri": "https://client.example.org/logo.png",
            "contacts": ["ve7jtb@example.org", "mary@example.org"],
        }

        self.claims.load_conf(preference, self.supported)

    def test_registration_response(self):
        OP_BASEURL = "https://example.com"
        provider_info_response = {
            "version": "3.0",
            "token_endpoint_auth_methods_supported": [
                "client_secret_post",
                "client_secret_basic",
                "client_secret_jwt",
                "private_key_jwt",
            ],
            "issuer": OP_BASEURL,
            "jwks_uri": f"{OP_BASEURL}/static/jwks_tE2iLbOAqXhe8bqh.json",
            "authorization_endpoint": f"{OP_BASEURL}/authorization",
            "token_endpoint": f"{OP_BASEURL}/token",
            "userinfo_endpoint": f"{OP_BASEURL}/userinfo",
            "registration_endpoint": f"{OP_BASEURL}/registration",
            "end_session_endpoint": f"{OP_BASEURL}/end_session",
            # below are a set which the RP has default values but the OP overwrites
            "scopes_supported": ["openid", "fee", "faa", "foo", "fum"],
            "response_types_supported": ["code", "id_token", "code id_token"],
            "response_modes_supported": ["query", "form_post", "new_fangled"],
            # this does not have a default value
            "acr_values_supported": ["mfa"],
        }

        self.claims.prefer = supported_to_preferred(
            supported=self.supported,
            preference=self.claims.prefer,
            base_url="https://example.com",
            info=provider_info_response,
        )

        registration_request = create_registration_request(
            prefers=self.claims.prefer, supported=self.supported
        )

        assert set(registration_request.keys()) == {
            "application_type",
            "client_name",
            "contacts",
            "default_max_age",
            "id_token_signed_response_alg",
            "logo_uri",
            "redirect_uris",
            "request_object_signing_alg",
            "response_types",
            "response_modes",  # non-standard
            "subject_type",
            "token_endpoint_auth_method",
            "token_endpoint_auth_signing_alg",
            "userinfo_signed_response_alg",
        }

        assert registration_request["subject_type"] == "public"

        registration_response = {
            "application_type": APPLICATION_TYPE_WEB,
            "redirect_uris": [
                "https://client.example.org/callback",
                "https://client.example.org/callback2",
            ],
            "client_name": "My Example",
            "logo_uri": "https://client.example.org/logo.png",
            "subject_type": "pairwise",
            "sector_identifier_uri": "https://other.example.net/file_of_redirect_uris.json",
            "token_endpoint_auth_method": "client_secret_basic",
            "jwks_uri": "https://client.example.org/my_public_keys.jwks",
            "userinfo_encrypted_response_alg": "RSA1_5",
            "userinfo_encrypted_response_enc": "A128CBC-HS256",
            "contacts": ["ve7jtb@example.org", "mary@example.org"],
            "request_uris": [
                "https://client.example.org/rf.txt#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA"
            ],
        }

        to_use = preferred_to_registered(
            supported=self.supported,
            prefers=self.claims.prefer,
            registration_response=registration_response,
        )

        assert set(to_use.keys()) == {
            "application_type",
            "client_name",
            "contacts",
            "default_max_age",
            "encrypt_request_object_supported",
            "encrypt_userinfo_supported",
            "id_token_signed_response_alg",
            "jwks_uri",
            "logo_uri",
            "redirect_uris",
            "request_object_signing_alg",
            "request_uris",
            "response_types",
            "response_modes",  # non-standard
            "scope",
            "sector_identifier_uri",
            "subject_type",
            "token_endpoint_auth_method",
            "token_endpoint_auth_signing_alg",
            "userinfo_encrypted_response_alg",
            "userinfo_encrypted_response_enc",
            "userinfo_signed_response_alg",
        }

        assert to_use["subject_type"] == "pairwise"
