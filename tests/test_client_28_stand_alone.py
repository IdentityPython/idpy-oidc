from urllib.parse import parse_qs
from urllib.parse import urlsplit

import pytest
import responses
from cryptojwt.key_jar import build_keyjar

from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.client.defaults import DEFAULT_OIDC_SERVICES
from idpyoidc.client.defaults import OIDCONF_PATTERN
from idpyoidc.client.exception import Unsupported
from idpyoidc.client.oauth2.stand_alone_client import StandAloneClient
from idpyoidc.exception import VerificationError
from idpyoidc.message.oidc import AccessTokenResponse
from idpyoidc.message.oidc import AuthorizationResponse
from idpyoidc.message.oidc import IdToken
from idpyoidc.message.oidc import OpenIDSchema
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
        "response_modes_supported": ['query', 'form_post'],
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


def test_response_mode_not_separate_endpoint():
    conf = STATIC_CONFIG.copy()
    conf.update({
        "response_modes_supported": ['query', 'form_post'],
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
    assert 'authz_cb' in qs['redirect_uri'][0]
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


def test_request_type_mode_1():
    config = STATIC_CONFIG.copy()
    config.update({
        "response_modes_supported": ['query', 'form_post'],
        "response_types_supported": ['code', 'code idtoken']
    })
    client = StandAloneClient(config=config)
    client.do_provider_info()
    client.do_client_registration()

    # Explicitly set
    url = client.init_authorization()

    assert url
    p = urlsplit(url)
    qs = parse_qs(p.query)
    assert 'authz_cb' in qs['redirect_uri'][0]
    assert qs['client_id'][0] == STATIC_CONFIG['client_id']
    assert qs['response_type'][0] == 'code'

    assert 'response_mode' not in qs


def test_request_type_mode_2():
    config = STATIC_CONFIG.copy()
    config.update({
        "response_modes_supported": ['form_post'],
        "response_types_supported": ['code', 'code id_token']
    })
    client = StandAloneClient(config=config)
    client.do_provider_info()
    client.do_client_registration()

    # Explicitly set
    url = client.init_authorization()

    assert url
    p = urlsplit(url)
    qs = parse_qs(p.query)
    assert 'authz_cb' in qs['redirect_uri'][0]
    assert qs['client_id'][0] == STATIC_CONFIG['client_id']
    assert qs['response_type'][0] == 'code'
    assert qs['response_mode'][0] == 'form_post'


def test_request_type_mode_3():
    config = STATIC_CONFIG.copy()
    config.update({
        "response_modes_supported": ['form_post'],
        "response_types_supported": ['id_token code']
    })
    client = StandAloneClient(config=config)
    client.do_provider_info()
    client.do_client_registration()

    # Explicitly set
    url = client.init_authorization()

    assert url
    p = urlsplit(url)
    qs = parse_qs(p.query)
    assert 'authz_cb' in qs['redirect_uri'][0]
    assert qs['client_id'][0] == STATIC_CONFIG['client_id']
    assert qs['response_type'][0] == 'id_token code'
    assert qs['response_mode'][0] == 'form_post'


def test_request_type_mode_4():
    config = STATIC_CONFIG.copy()
    config.update({
        "response_modes_supported": ['query'],
        "response_types_supported": ['id_token code']
    })
    client = StandAloneClient(config=config)
    client.do_provider_info()
    client.do_client_registration()

    # Explicitly set
    with pytest.raises(Unsupported):
        client.init_authorization()


class TestFinalizeAuth(object):

    @pytest.fixture(autouse=True)
    def client_setup(self):
        self.client = StandAloneClient(config=STATIC_CONFIG)
        self.client.do_provider_info()
        self.client.do_client_registration()

    def test_one(self):
        url = self.client.init_authorization()

        _state = get_state_from_url(url)
        _response = AuthorizationResponse(
            code=24 * 'x',
            state=_state,
            iss=self.client.context.issuer,
            client_id=self.client.context.get_client_id()
        )
        _auth_response = self.client.finalize_auth(_response.to_dict())
        assert _auth_response

    def test_imposter(self):
        url = self.client.init_authorization()

        _state = get_state_from_url(url)
        _response = AuthorizationResponse(
            code=24 * 'x',
            state=_state,
            iss="https://fake.example.com",
            client_id=self.client.context.get_client_id()
        )

        with pytest.raises(VerificationError):
            self.client.finalize_auth(_response.to_dict())

    def test_wrong_state(self):
        url = self.client.init_authorization()

        _state = get_state_from_url(url)
        _response = AuthorizationResponse(
            code=24 * 'x',
            state="_state",
            iss=self.client.context.issuer,
            client_id=self.client.context.get_client_id()
        )

        with pytest.raises(KeyError):
            self.client.finalize_auth(_response.to_dict())


ISSUER_KEYS = build_keyjar(DEFAULT_KEY_DEFS, issuer_id=ISSUER)
SUBJECT_NAME = "Subject"
_services = DEFAULT_OIDC_SERVICES.copy()
_services["end_session"] = {'class': "idpyoidc.client.oidc.end_session.EndSession"}

EXTENDED_STATIC_CONFIG = {
    "base_url": "https://example.com/cli/",
    "client_id": "Number5",
    "client_type": "oidc",
    "client_secret": "asdflkjh0987654321",
    "post_logout_redirect_uri": "https://example.com/cli/logout",
    "services": _services,
    "provider_info": {
        "issuer": ISSUER,
        "authorization_endpoint": "https://op.example.com/authn",
        "token_endpoint": "https://op.example.com/token",
        "userinfo_endpoint": "https://op.example.com/user",
        "end_session_endpoint": "https://op.example.com/end_session"
    }
}


class TestPostAuthn(object):

    @pytest.fixture(autouse=True)
    def client_setup(self):
        self.client = StandAloneClient(config=EXTENDED_STATIC_CONFIG)
        self.client.do_provider_info()
        self.client.do_client_registration()
        url = self.client.init_authorization()

        self.state = get_state_from_url(url)
        _response = AuthorizationResponse(
            code=24 * 'x',
            state=self.state,
            iss=self.client.context.issuer,
            client_id=self.client.context.get_client_id()
        )
        self.client.finalize_auth(_response.to_dict())

    def _create_id_token(self, subject):
        _context = self.client.get_context()
        _session = self.client.get_session_information(self.state)
        _nonce = _session["nonce"]
        _iss = _session["iss"]
        _aud = _context.get_client_id()
        idval = {"nonce": _nonce, "sub": subject, "iss": _iss, "aud": _aud}

        _keyjar = _context.upstream_get("attribute", "keyjar")
        _keyjar.import_jwks(ISSUER_KEYS.export_jwks(issuer_id=ISSUER), ISSUER)

        idts = IdToken(**idval)
        return idts.to_jwt(
            key=ISSUER_KEYS.get_signing_key("rsa", issuer_id=ISSUER),
            algorithm="RS256",
            lifetime=300,
        )

    def test_get_access_token(self):
        with responses.RequestsMock() as rsps:
            token_response = AccessTokenResponse(
                access_token='access_token',
                token_type='Bearer'
            )
            rsps.add(
                "POST",
                STATIC_CONFIG['provider_info']['token_endpoint'],
                body=token_response.to_json(),
                adding_headers={"Content-Type": "application/json"},
                status=200,
            )

            response = self.client.get_tokens(self.state)
        assert isinstance(response, AccessTokenResponse)
        assert 'access_token' in response

    def test_get_access_and_id_token(self):
        with responses.RequestsMock() as rsps:
            token_response = AccessTokenResponse(
                access_token='access_token',
                token_type='Bearer',
                id_token=self._create_id_token('Subject')
            )
            rsps.add(
                "POST",
                STATIC_CONFIG['provider_info']['token_endpoint'],
                body=token_response.to_json(),
                adding_headers={"Content-Type": "application/json"},
                status=200,
            )

            response = self.client.get_access_and_id_token(state=self.state)

        assert response
        assert set(response.keys()) == {'access_token', 'id_token'}
        assert response['access_token'] == "access_token"
        assert response['id_token']['iss'] == ISSUER

    def test_userinfo(self):
        with responses.RequestsMock() as rsps:
            token_response = AccessTokenResponse(
                access_token='access_token',
                token_type='Bearer'
            )
            rsps.add(
                "POST",
                STATIC_CONFIG['provider_info']['token_endpoint'],
                body=token_response.to_json(),
                adding_headers={"Content-Type": "application/json"},
                status=200,
            )

            self.client.get_tokens(self.state)

        with responses.RequestsMock() as rsps:
            _response = OpenIDSchema(
                sub=SUBJECT_NAME,
                email='subject@example.com'
            )
            rsps.add(
                "GET",
                STATIC_CONFIG['provider_info']['userinfo_endpoint'],
                body=_response.to_json(),
                adding_headers={"Content-Type": "application/json"},
                status=200,
            )

            response = self.client.get_user_info(self.state)
        assert response

    def test_finalize_1(self):
        _auth_response = AuthorizationResponse(
            code=24 * 'x',
            state=self.state,
            iss=self.client.context.issuer,
            client_id=self.client.context.get_client_id()
        )

        with responses.RequestsMock() as rsps:
            token_response = AccessTokenResponse(
                access_token='access_token',
                token_type='Bearer'
            )
            rsps.add(
                "POST",
                STATIC_CONFIG['provider_info']['token_endpoint'],
                body=token_response.to_json(),
                adding_headers={"Content-Type": "application/json"},
                status=200,
            )
            _response = OpenIDSchema(
                sub=SUBJECT_NAME,
                email='subject@example.com'
            )
            rsps.add(
                "GET",
                STATIC_CONFIG['provider_info']['userinfo_endpoint'],
                body=_response.to_json(),
                adding_headers={"Content-Type": "application/json"},
                status=200,
            )

            response = self.client.finalize(_auth_response.to_dict())
        assert response
        assert set(response.keys()) == {'userinfo', 'state', 'token', 'id_token',
                                        'session_state', 'issuer'}
        assert response['token'] == 'access_token'
        assert response['id_token'] is None
        assert response['userinfo']['sub'] == SUBJECT_NAME
        assert response['issuer'] == ISSUER

    def test_finalize_2(self):
        _auth_response = AuthorizationResponse(
            code=24 * 'x',
            state=self.state,
            iss=self.client.context.issuer,
            client_id=self.client.context.get_client_id()
        )

        with responses.RequestsMock() as rsps:
            token_response = AccessTokenResponse(
                access_token='access_token',
                expires_in=300,
                token_type='Bearer',
                id_token=self._create_id_token(SUBJECT_NAME)
            )
            rsps.add(
                "POST",
                STATIC_CONFIG['provider_info']['token_endpoint'],
                body=token_response.to_json(),
                adding_headers={"Content-Type": "application/json"},
                status=200,
            )
            _response = OpenIDSchema(
                sub=SUBJECT_NAME,
                email='subject@example.com'
            )
            rsps.add(
                "GET",
                STATIC_CONFIG['provider_info']['userinfo_endpoint'],
                body=_response.to_json(),
                adding_headers={"Content-Type": "application/json"},
                status=200,
            )

            response = self.client.finalize(_auth_response.to_dict())
        assert response
        assert set(response.keys()) == {'userinfo', 'state', 'token', 'id_token',
                                        'session_state', 'issuer'}
        assert response['token'] == 'access_token'
        assert response['id_token'] is not None
        assert response['userinfo']['sub'] == SUBJECT_NAME
        assert response['issuer'] == ISSUER

        assert self.client.has_active_authentication(self.state)

        token, eat = self.client.get_valid_access_token(self.state)
        assert token == "access_token"
        assert eat > 0
        logout_info = self.client.logout(self.state, "https://example.com/cli/logout")
        assert set(logout_info.keys()) == {'method', 'request', 'url'}
        assert set(logout_info['request'].keys()) == {'post_logout_redirect_uri', 'id_token_hint',
                                                      'state'}
