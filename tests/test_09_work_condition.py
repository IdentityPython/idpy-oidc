from typing import Callable

import pytest as pytest
from cryptojwt.utils import importer

from idpyoidc.client.claims.oidc import Claims
from idpyoidc.client.claims.transform import create_registration_request
from idpyoidc.client.claims.transform import preferred_to_registered
from idpyoidc.client.claims.transform import supported_to_preferred

KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]


class TestWorkEnvironment:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.claims = Claims()
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

    def test_load_conf(self):
        # Only symmetric key
        client_conf = {
            "application_type": "web",
            "redirect_uris": [
                "https://client.example.org/callback",
                "https://client.example.org/callback2",
            ],
            "client_name": "My Example",
            "client_id": "client_id",
            "client_secret": "a longesh password",
            "logo_uri": "https://client.example.org/logo.png",
            "contacts": ["ve7jtb@example.org", "mary@example.org"],
        }

        self.claims.load_conf(client_conf, self.supported)
        assert self.claims.get_preference("jwks") is None
        assert self.claims.get_preference("jwks_uri") is None

    def test_load_jwks(self):
        # Symmetric and asymmetric keys published as JWKS
        client_conf = {
            "application_type": "web",
            "base_url": "https://client.example.org/",
            "redirect_uris": [
                "https://client.example.org/callback",
                "https://client.example.org/callback2",
            ],
            "client_name": "My Example",
            "client_id": "client_id",
            "keys": {"key_defs": KEYSPEC, "read_only": True},
            "client_secret": "a longesh password",
            "logo_uri": "https://client.example.org/logo.png",
            "contacts": ["ve7jtb@example.org", "mary@example.org"],
        }

        self.claims.load_conf(client_conf, self.supported)
        assert self.claims.get_preference("jwks") is not None
        assert self.claims.get_preference("jwks_uri") is None

    def test_load_jwks_uri1(self):
        # Symmetric and asymmetric keys published through a jwks_uri
        client_conf = {
            "application_type": "web",
            "base_url": "https://client.example.org/",
            "redirect_uris": [
                "https://client.example.org/callback",
                "https://client.example.org/callback2",
            ],
            "client_name": "My Example",
            "keys": {"uri_path": "static/jwks.json", "key_defs": KEYSPEC, "read_only": True},
            "logo_uri": "https://client.example.org/logo.png",
            "contacts": ["ve7jtb@example.org", "mary@example.org"],
        }

        self.claims.load_conf(client_conf, self.supported)
        assert self.claims.get_preference("jwks") is None
        assert (
            self.claims.get_preference("jwks_uri")
            == f"{client_conf['base_url']}{client_conf['keys']['uri_path']}"
        )

    def test_load_jwks_uri2(self):
        # Symmetric and asymmetric keys published through a jwks_uri
        client_conf = {
            "application_type": "web",
            "base_url": "https://client.example.org/",
            "redirect_uris": [
                "https://client.example.org/callback",
                "https://client.example.org/callback2",
            ],
            "client_name": "My Example",
            "keys": {"key_defs": KEYSPEC, "read_only": True},
            "jwks_uri": "https://client.example.org/keys/jwks.json",
            "logo_uri": "https://client.example.org/logo.png",
            "contacts": ["ve7jtb@example.org", "mary@example.org"],
        }

        self.claims.load_conf(client_conf, self.supported)
        assert self.claims.get_preference("jwks") is None
        assert self.claims.get_preference("jwks_uri") == client_conf["jwks_uri"]

    def test_registration_response(self):
        client_conf = {
            "application_type": "web",
            "base_url": "https://client.example.org/",
            "redirect_uris": [
                "https://client.example.org/callback",
                "https://client.example.org/callback2",
            ],
            "client_name": "My Example",
            "client_id": "client_id",
            "keys": {"key_defs": KEYSPEC, "read_only": True},
            "client_secret": "a longesh password",
            "logo_uri": "https://client.example.org/logo.png",
            "contacts": ["ve7jtb@example.org", "mary@example.org"],
        }

        self.claims.load_conf(client_conf, self.supported)

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

        pref = self.claims.prefer = supported_to_preferred(
            supported=self.supported,
            preference=self.claims.prefer,
            base_url="https://example.com",
            info=provider_info_response,
        )

        registration_request = create_registration_request(self.claims.prefer, self.supported)

        assert set(registration_request.keys()) == {
            "application_type",
            "client_name",
            "contacts",
            "default_max_age",
            "id_token_signed_response_alg",
            "jwks",
            "logo_uri",
            "redirect_uris",
            "request_object_signing_alg",
            "response_modes",  # non-standard
            "response_types",
            "subject_type",
            "token_endpoint_auth_method",
            "token_endpoint_auth_signing_alg",
            "userinfo_signed_response_alg",
        }

        assert registration_request["subject_type"] == "public"

        registration_response = {
            "application_type": "web",
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
            prefers=self.claims.prefer,
            supported=self.supported,
            registration_response=registration_response,
        )

        assert set(to_use.keys()) == {
            "application_type",
            "client_id",
            "client_name",
            "client_secret",
            "contacts",
            "default_max_age",
            "encrypt_request_object_supported",
            "encrypt_userinfo_supported",
            "id_token_signed_response_alg",
            "jwks",
            "jwks_uri",
            "logo_uri",
            "redirect_uris",
            "request_object_signing_alg",
            "request_uris",
            "response_modes",
            "response_types",
            "scope",
            "sector_identifier_uri",
            "subject_type",
            "token_endpoint_auth_method",
            "token_endpoint_auth_signing_alg",
            "userinfo_encrypted_response_alg",
            "userinfo_encrypted_response_enc",
            "userinfo_signed_response_alg",
        }

        # Not what I asked for but something I can handle
        assert to_use["subject_type"] == "pairwise"

    def test_registration_response_consistence(self):
        client_conf = {
            "application_type": "web",
            "base_url": "https://client.example.org/",
            "redirect_uris": [
                "https://client.example.org/callback",
                "https://client.example.org/callback2",
            ],
            "client_name": "My Example",
            "client_id": "client_id",
            "keys": {"key_defs": KEYSPEC, "read_only": True},
            "client_secret": "a longesh password",
            "logo_uri": "https://client.example.org/logo.png",
            "contacts": ["ve7jtb@example.org", "mary@example.org"],
        }

        self.claims.load_conf(client_conf, self.supported)

        self.claims.prefer = supported_to_preferred(
            supported=self.supported,
            preference=self.claims.prefer,
            base_url="https://example.com",
        )
        to_use_1 = preferred_to_registered(
            prefers=self.claims.prefer,
            supported=self.supported,
        )

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

        pref = self.claims.prefer = supported_to_preferred(
            supported=self.supported,
            preference=self.claims.prefer,
            base_url="https://example.com",
            info=provider_info_response,
        )

        registration_request = create_registration_request(self.claims.prefer, self.supported)

        assert set(registration_request.keys()) == {
            "application_type",
            "client_name",
            "contacts",
            "default_max_age",
            "id_token_signed_response_alg",
            "jwks",
            "logo_uri",
            "redirect_uris",
            "request_object_signing_alg",
            "response_modes",  # non-standard
            "response_types",
            "subject_type",
            "token_endpoint_auth_method",
            "token_endpoint_auth_signing_alg",
            "userinfo_signed_response_alg",
        }

        assert registration_request["subject_type"] == "public"

        registration_response = {
            "application_type": "web",
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

        to_use_2 = preferred_to_registered(
            prefers=self.claims.prefer,
            supported=self.supported,
            registration_response=registration_response,
        )

        assert set(to_use_2.keys()) == {
            "application_type",
            "client_id",
            "client_name",
            "client_secret",
            "contacts",
            "default_max_age",
            "encrypt_request_object_supported",
            "encrypt_userinfo_supported",
            "id_token_signed_response_alg",
            "jwks",
            "jwks_uri",
            "logo_uri",
            "redirect_uris",
            "request_object_signing_alg",
            "request_uris",
            "response_modes",
            "response_types",
            "scope",
            "sector_identifier_uri",
            "subject_type",
            "token_endpoint_auth_method",
            "token_endpoint_auth_signing_alg",
            "userinfo_encrypted_response_alg",
            "userinfo_encrypted_response_enc",
            "userinfo_signed_response_alg",
        }

        # Not what I asked for but something I can handle
        assert to_use_2["subject_type"] == "pairwise"
