from urllib.parse import parse_qs
from urllib.parse import urlsplit

import pytest
import responses
from cryptojwt.key_jar import build_keyjar

from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.client.defaults import OIDCONF_PATTERN
from idpyoidc.client.oauth2.stand_alone_client import StandAloneClient
from idpyoidc.message.oidc import ProviderConfigurationResponse
from idpyoidc.message.oidc import RegistrationResponse

ISSUER = "https://op.example.com"

STATIC_CONFIG = {
    "base_url": "https://example.com/cli/",
    "client_id": "Number5",
    "client_type": "oidc",
    "client_secret": "asdflkjh0987654321",
    "provider_info": {
        "issuer": ISSUER,
        "authorization_endpoint": "https://op.example.com/authn",
        "token_endpoint": "https://op.example.com/token",
        "userinfo_endpoint": "https://op.example.com/user",
    }
}


def get_state_from_url(url):
    p = urlsplit(url)
    qs = parse_qs(p.query)
    return qs['state'][0]


class TestStandAloneClientOIDCStatic(object):

    @pytest.fixture(autouse=True)
    def client_setup(self):
        self.client = StandAloneClient(config=STATIC_CONFIG)

    def test_get_services(self):
        assert set(self.client.get_services().keys()) == {'provider_info', 'registration',
                                                          'authorization', 'accesstoken',
                                                          'refresh_token', 'userinfo'}

    def test_do_provider_info(self):
        issuer = self.client.do_provider_info()
        assert issuer == STATIC_CONFIG['provider_info']['issuer']
        assert self.client.context.get('issuer') == issuer

    def test_client_registration(self):
        self.client.do_provider_info()
        self.client.do_client_registration()
        assert self.client.context.get_usage('client_id') == STATIC_CONFIG['client_id']

    def test_init_authorization(self):
        self.client.do_provider_info()
        self.client.do_client_registration()
        url = self.client.init_authorization()
        assert url
        p = urlsplit(url)
        qs = parse_qs(p.query)
        assert qs['client_id'][0] == STATIC_CONFIG['client_id']
        assert qs['response_type'][0] == 'code'

    def test_response_type_id_token(self):
        self.client.do_provider_info()
        self.client.do_client_registration()

        # Explicitly set
        url = self.client.init_authorization(req_args={'response_type': 'id_token'})

        assert url
        p = urlsplit(url)
        qs = parse_qs(p.query)
        assert qs['client_id'][0] == STATIC_CONFIG['client_id']
        assert qs['response_type'][0] == 'id_token'


def test_response_mode():
    conf = STATIC_CONFIG.copy()
    conf.update({
        "response_modes_supported": ['code','form_post'],
        'separate_form_post_cb': True
    })
    client = StandAloneClient(config=conf)
    client.do_provider_info()
    client.do_client_registration()

    # Explicitly set
    url = client.init_authorization(req_args={'response_mode': 'form_post'})

    assert url
    p = urlsplit(url)
    qs = parse_qs(p.query)
    assert 'authz_cb_form' in qs['redirect_uri'][0]
    assert qs['client_id'][0] == STATIC_CONFIG['client_id']
    assert qs['response_type'][0] == 'code'
    assert qs['response_mode'][0] == 'form_post'

def test_response_mode_not_separate():
    conf = STATIC_CONFIG.copy()
    conf.update({
        "response_modes_supported": ['code','form_post'],
        'separate_form_post_cb': False
    })
    client = StandAloneClient(config=conf)
    client.do_provider_info()
    client.do_client_registration()

    # Explicitly set
    url = client.init_authorization(req_args={'response_mode': 'form_post'})

    assert url
    p = urlsplit(url)
    qs = parse_qs(p.query)
    assert 'authz_cb_form' not in qs['redirect_uri'][0]
    assert qs['client_id'][0] == STATIC_CONFIG['client_id']
    assert qs['response_type'][0] == 'code'
    assert qs['response_mode'][0] == 'form_post'


SEMI_DYN_CONFIG = {
    "base_url": "https://example.com/cli/",
    "client_id": "Number5",
    "client_secret": "asdflkjh0987654321",
    "client_type": "oidc",
    "provider_info": {
        "issuer": "https://op.example.com"
    }
}

PROVIDER_INFO = ProviderConfigurationResponse(
    issuer=ISSUER,
    authorization_endpoint="https://op.example.com/authn",
    token_endpoint="https://op.example.com/token",
    userinfo_endpoint="https://op.example.com/user",
    registration_endpoint="https://op.example.com/register",
    jwks_uri="https://op.example.com/keys/jwks.json",
    response_types_supported=["code"],
    subject_types_supported=['public'],
    id_token_signing_alg_values_supported=['RS256']
)

OP_KEYS = build_keyjar(DEFAULT_KEY_DEFS)


class TestStandAloneClientOIDCDynProviderInfo(object):

    @pytest.fixture(autouse=True)
    def client_setup(self):
        self.client = StandAloneClient(config=SEMI_DYN_CONFIG)

    def test_do_provider_info(self):
        with responses.RequestsMock() as rsps:
            rsps.add(
                "GET",
                OIDCONF_PATTERN.format(SEMI_DYN_CONFIG['provider_info']['issuer']),
                body=PROVIDER_INFO.to_json(),
                adding_headers={"Content-Type": "application/json"},
                status=200,
            )
            rsps.add(
                "GET",
                PROVIDER_INFO['jwks_uri'],
                body=OP_KEYS.export_jwks_as_json(),
                adding_headers={"Content-Type": "application/json"},
                status=200,
            )
            issuer = self.client.do_provider_info()

        assert issuer == SEMI_DYN_CONFIG['provider_info']['issuer']
        assert self.client.context.get('issuer') == issuer


DYN_CONFIG = {
    "base_url": "https://rp.example.com",
    "redirect_uris": ["https://rp.example.com/cb"],
    "key_conf": {"key_defs": DEFAULT_KEY_DEFS},
    "client_type": "oidc",
    "provider_info": {
        "issuer": "https://op.example.com"
    }
}


class TestStandAloneClientOIDCDyn(object):

    @pytest.fixture(autouse=True)
    def client_setup(self):
        self.client = StandAloneClient(config=DYN_CONFIG)

    def test_do_provider_info(self):
        with responses.RequestsMock() as rsps:
            rsps.add(
                "GET",
                OIDCONF_PATTERN.format(SEMI_DYN_CONFIG['provider_info']['issuer']),
                body=PROVIDER_INFO.to_json(),
                adding_headers={"Content-Type": "application/json"},
                status=200,
            )
            rsps.add(
                "GET",
                PROVIDER_INFO['jwks_uri'],
                body=OP_KEYS.export_jwks_as_json(),
                adding_headers={"Content-Type": "application/json"},
                status=200,
            )
            issuer = self.client.do_provider_info()

        assert issuer == DYN_CONFIG['provider_info']['issuer']
        assert self.client.context.get('issuer') == issuer

        registration_response = RegistrationResponse(
            client_id="client_1",
            client_secret="a0b1c2d3e4f5g6h7i8j9",
            redirect_uris=["https://rp.example.com/cb"]
        )
        with responses.RequestsMock() as rsps:
            # registration response
            rsps.add(
                "POST",
                PROVIDER_INFO['registration_endpoint'],
                body=registration_response.to_json(),
                adding_headers={"Content-Type": "application/json"},
                status=200,
            )

            self.client.do_client_registration()

        assert self.client.context.get_usage('client_id') == 'client_1'
