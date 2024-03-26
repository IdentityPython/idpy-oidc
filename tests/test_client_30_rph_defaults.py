from urllib.parse import parse_qs
from urllib.parse import urlparse

from cryptojwt.key_jar import build_keyjar
import pytest
import responses

from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.client.rp_handler import RPHandler
from idpyoidc.message.oidc import ProviderConfigurationResponse
from idpyoidc.message.oidc import RegistrationResponse

BASE_URL = "https://example.com"


class TestRPHandler(object):
    @pytest.fixture(autouse=True)
    def rphandler_setup(self):
        self.rph = RPHandler(BASE_URL)

    def test_pick_config(self):
        cnf = self.rph.pick_config("")
        assert cnf

    def test_init_client(self):
        client = self.rph.init_client("")
        assert set(client.get_services().keys()) == {
            "registration",
            "provider_info",
            "authorization",
            "accesstoken",
            "userinfo",
            "refresh_token",
        }

        _context = client.get_context()

        assert set(_context.claims.prefer.keys()) == {
            'application_type',
            'callback_uris',
            'default_max_age',
            'encrypt_request_object_supported',
            'encrypt_userinfo_supported',
            'grant_types_supported',
            'id_token_encryption_alg_values_supported',
            'id_token_encryption_enc_values_supported',
            'id_token_signing_alg_values_supported',
            'jwks_uri',
            'redirect_uris',
            'request_object_encryption_alg_values_supported',
            'request_object_encryption_enc_values_supported',
            'request_object_signing_alg_values_supported',
            'response_modes_supported',
            'response_types_supported',
            'scopes_supported',
            'subject_types_supported',
            'token_endpoint_auth_methods_supported',
            'token_endpoint_auth_signing_alg_values_supported',
            'userinfo_encryption_alg_values_supported',
            'userinfo_encryption_enc_values_supported',
            'userinfo_signing_alg_values_supported'}

        _keyjar = client.get_attribute("keyjar")
        assert list(_keyjar.owners()) == ["", BASE_URL]
        keys = _keyjar.get_issuer_keys("")
        assert len(keys) == 2

        assert _context.base_url == BASE_URL

    def test_begin(self):
        ISS_ID = "https://op.example.org"
        OP_KEYS = build_keyjar(DEFAULT_KEY_DEFS)
        # The 4 steps of client_setup
        client = self.rph.init_client(ISS_ID)
        with responses.RequestsMock() as rsps:
            request_uri = "{}/.well-known/openid-configuration".format(ISS_ID)
            _jws = ProviderConfigurationResponse(
                issuer=ISS_ID,
                authorization_endpoint="{}/authorization".format(ISS_ID),
                jwks_uri="{}/jwks.json".format(ISS_ID),
                response_types_supported=["code", "id_token", "id_token token"],
                subject_types_supported=["public"],
                id_token_signing_alg_values_supported=["RS256", "ES256"],
                token_endpoint="{}/token".format(ISS_ID),
                registration_endpoint="{}/register".format(ISS_ID),
            ).to_json()
            rsps.add("GET", request_uri, body=_jws, status=200)

            rsps.add(
                "GET", "{}/jwks.json".format(ISS_ID), body=OP_KEYS.export_jwks_as_json(), status=200
            )

            issuer = self.rph.do_provider_info(client)

        _context = client.get_context()

        # Calculating request so I can build a reasonable response
        _req = client.get_service("registration").construct_request()

        with responses.RequestsMock() as rsps:
            request_uri = _context.get("provider_info")["registration_endpoint"]
            _jws = RegistrationResponse(
                client_id="client uno", client_secret="VerySecretAndLongEnough", **_req.to_dict()
            ).to_json()
            rsps.add("POST", request_uri, body=_jws, status=200)
            self.rph.do_client_registration(client, ISS_ID)

        self.rph.issuer2rp[issuer] = client

        assert set(_context.claims.use.keys()) == {
            "application_type",
            "callback_uris",
            "client_id",
            "client_secret",
            "default_max_age",
            "encrypt_request_object_supported",
            "grant_types",
            "id_token_signed_response_alg",
            "jwks_uri",
            "redirect_uris",
            "request_object_signing_alg",
            "response_modes",
            "response_types",
            "scope",
            "subject_type",
            "token_endpoint_auth_method",
            "token_endpoint_auth_signing_alg",
        }
        assert _context.get_client_id() == "client uno"
        assert _context.get_usage("client_secret") == "VerySecretAndLongEnough"
        assert _context.get("issuer") == ISS_ID

        url = self.rph.init_authorization(client)
        p = urlparse(url)
        assert p.hostname == "op.example.org"
        assert p.path == "/authorization"
        qs = parse_qs(p.query)
        # PKCE stuff
        assert "code_challenge" in qs
        assert qs["code_challenge_method"] == ["S256"]

    def test_begin_2(self):
        ISS_ID = "https://op.example.org"
        OP_KEYS = build_keyjar(DEFAULT_KEY_DEFS)
        # The 4 steps of client_setup
        client = self.rph.init_client(ISS_ID)
        with responses.RequestsMock() as rsps:
            request_uri = "{}/.well-known/openid-configuration".format(ISS_ID)
            _jws = ProviderConfigurationResponse(
                issuer=ISS_ID,
                authorization_endpoint="{}/authorization".format(ISS_ID),
                jwks_uri="{}/jwks.json".format(ISS_ID),
                response_types_supported=["code", "id_token", "id_token token"],
                subject_types_supported=["public"],
                id_token_signing_alg_values_supported=["RS256", "ES256"],
                token_endpoint="{}/token".format(ISS_ID),
                registration_endpoint="{}/register".format(ISS_ID),
            ).to_json()
            rsps.add("GET", request_uri, body=_jws, status=200)

            rsps.add(
                "GET", "{}/jwks.json".format(ISS_ID), body=OP_KEYS.export_jwks_as_json(), status=200
            )

            issuer = self.rph.do_provider_info(client)

        _context = client.get_context()
        # Calculating request so I can build a reasonable response
        # Publishing a JWKS instead of a JWKS_URI
        _context.jwks_uri = ""
        _context.jwks = client.keyjar.export_jwks()

        _req = client.get_service("registration").construct_request()

        with responses.RequestsMock() as rsps:
            request_uri = _context.get("provider_info")["registration_endpoint"]
            _jws = RegistrationResponse(
                client_id="client uno", client_secret="VerySecretAndLongEnough", **_req.to_dict()
            ).to_json()
            rsps.add("POST", request_uri, body=_jws, status=200)
            self.rph.do_client_registration(client, ISS_ID)

        assert "jwks_uri" in _context.get("registration_response")
