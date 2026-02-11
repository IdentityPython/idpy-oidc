import json
import os
from urllib.parse import parse_qs
from urllib.parse import urlparse
from urllib.parse import urlsplit

import pytest
import responses
from cryptojwt.key_jar import init_key_jar
from cryptojwt.utils import b64e

from idpyoidc.client.entity import Entity
from idpyoidc.client.oidc.rp import RP
from idpyoidc.key_import import import_jwks
from idpyoidc.message.oidc import AccessTokenResponse
from idpyoidc.message.oidc import APPLICATION_TYPE_WEB
from idpyoidc.message.oidc import AuthorizationResponse
from idpyoidc.message.oidc import IdToken
from idpyoidc.message.oidc import RegistrationRequest
from idpyoidc.util import full_keyjar_join
from idpyoidc.util import get_asymetric_keys_from_keyjar_chain
from idpyoidc.util import get_keyjar_chain

BASE_URL = "https://example.com/rp"

PREF = {
    "application_type": APPLICATION_TYPE_WEB,
    "contacts": ["ops@example.com"],
    "response_types_supported": [
        "code",
        "id_token",
        "code id_token",
    ],
    "token_endpoint_auth_methods_supported": ["client_secret_basic"],
    "scopes_supported": ["openid", "profile", "email", "address", "phone"],
    "verify_args": {"allow_sign_alg_none": True},
}

# CONFIG = {
#     "services": {
#         "web_finger": {"class": "idpyoidc.client.oidc.webfinger.WebFinger"},
#         "discovery": {
#             "class": "idpyoidc.client.oidc.provider_info_discovery.ProviderInfoDiscovery"
#         },
#         "registration": {"class": "idpyoidc.client.oidc.registration.Registration"},
#         "authorization": {"class": "idpyoidc.client.oidc.authorization.Authorization"},
#         "access_token": {"class": "idpyoidc.client.oidc.access_token.AccessToken"},
#         "refresh_access_token": {
#             "class": "idpyoidc.client.oidc.refresh_access_token" ".RefreshAccessToken"
#         },
#         "userinfo": {"class": "idpyoidc.client.oidc.userinfo.UserInfo"},
#     }
# }

LINKEDIN = "https://www.linkedin.com/oauth/v2/"
FACEBOOK = "https://www.facebook.com/v2.11/dialog/oauth"
GITHUB = "https://github.com/login/oauth/authorize"

CLIENT_CONFIGS = {
    "": {
        "preference": PREF,
        "redirect_uris": None,
        "base_url": BASE_URL,
        "request_parameter": "request_uris",
        "client_type": "oidc",
    },
    "linkedin": {
        "issuer": LINKEDIN,
        "client_id": "LinkedIN",
        "client_secret": b64e(b"yyyyyyyyyyyyyyyyyyyy"),
        "redirect_uris": ["{}/authz_cb/linkedin".format(BASE_URL)],
        "preference": {
            "response_types_supported": ["code"],
            "scopes_supported": ["r_basicprofile", "r_emailaddress"],
            "token_endpoint_auth_methods_supported": ["client_secret_post"],
        },
        "provider_info": {
            "authorization_endpoint": "https://www.linkedin.com/oauth/v2/authorization",
            "token_endpoint": "https://www.linkedin.com/oauth/v2/accessToken",
            "userinfo_endpoint": "https://api.linkedin.com/v1/people/~?format=json",
        },
        "userinfo_request_method": "GET",
        "supported_services": {
            "authorization": {"class": "idpyoidc.client.oidc.authorization.Authorization"},
            "access_token": {"class": "idpyoidc.client.provider.linkedin.AccessToken"},
            "userinfo": {"class": "idpyoidc.client.provider.linkedin.UserInfo"},
        },
    },
    "facebook": {
        "issuer": FACEBOOK,
        "client_id": "Facebook",
        "client_secret": b64e(b"dddddddddddddd"),
        "preference": {
            "response_types_supported": ["code"],
            "scopes_supported": ["email", "public_profile"],
            "token_endpoint_auth_methods_supported": [],
        },
        "redirect_uris": ["{}/authz_cb/facebook".format(BASE_URL)],
        "provider_info": {
            "authorization_endpoint": "https://www.facebook.com/v2.11/dialog/oauth",
            "token_endpoint": "https://graph.facebook.com/v2.11/oauth/access_token",
            "userinfo_endpoint": "https://graph.facebook.com/me",
        },
        "services": {
            "authorization": {"class": "idpyoidc.client.oidc.authorization.Authorization"},
            "access_token": {
                "class": "idpyoidc.client.oidc.access_token.AccessToken",
                "kwargs": {"conf": {"default_authn_method": ""}},
            },
            "userinfo": {
                "class": "idpyoidc.client.oidc.userinfo.UserInfo",
                "kwargs": {"conf": {"default_authn_method": ""}},
            },
        },
    },
    "github": {
        "issuer": GITHUB,
        "client_id": "GitHub",
        "client_secret": "aaaaaaaaaaaaaaaaaaaa",
        "client_type": "oidc",
        "redirect_uris": ["{}/authz_cb/github".format(BASE_URL)],
        "preference": {
            "response_types_supported": ["code"],
            "scopes_supported": ["user", "public_repo", "openid"],
            "token_endpoint_auth_methods_supported": [],
            "verify_args": {"allow_sign_alg_none": True},
        },
        "provider_info": {
            "authorization_endpoint": "https://github.com/login/oauth/authorize",
            "token_endpoint": "https://github.com/login/oauth/access_token",
            "userinfo_endpoint": "https://api.github.com/user",
        },
        "services": {
            "authorization": {
                "class": "idpyoidc.client.oidc.authorization.Authorization",
            },
            "access_token": {"class": "idpyoidc.client.oidc.access_token.AccessToken"},
            "userinfo": {"class": "idpyoidc.client.oidc.userinfo.UserInfo"},
            "refresh_access_token": {
                "class": "idpyoidc.client.oidc.refresh_access_token.RefreshAccessToken"
            },
        },
    }
}

KEYDEFS = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

_dirname = os.path.dirname(os.path.abspath(__file__))


CLI_KEYCONF = {
    "public_path": "{}/pub_client.jwks".format(_dirname),
    'private_path': "{}/priv_client.jwks".format(_dirname),
    'key_defs': KEYDEFS,
}

LINKEDIN_KEYJAR = init_key_jar(
    public_path="{}/pub_linkedin.jwks".format(_dirname),
    private_path="{}/priv_linkedin.jwks".format(_dirname),
    key_defs=KEYDEFS,
    issuer_id=CLIENT_CONFIGS["linkedin"]["issuer"],
)

FACEBOOK_KEYJAR = init_key_jar(
    public_path="{}/pub_facebook.jwks".format(_dirname),
    private_path="{}/priv_facebook.jwks".format(_dirname),
    key_defs=KEYDEFS,
    issuer_id=CLIENT_CONFIGS["facebook"]["issuer"],
)

GITHUB_KEYJAR = init_key_jar(
    public_path="{}/pub_github.jwks".format(_dirname),
    private_path="{}/priv_github.jwks".format(_dirname),
    key_defs=KEYDEFS,
    issuer_id=CLIENT_CONFIGS["github"]["issuer"],
)


def get_state_from_url(url):
    p = urlsplit(url)
    qp = parse_qs(p.query)
    return qp["state"][0]


def iss_id(iss):
    return CLIENT_CONFIGS[iss]["issuer"]


CONFIG = {
    "redirect_uris": [f"{BASE_URL}/authz_cb"],
    "public_path": f"{BASE_URL}/pub_client.jwks",
    'private_path': f"{BASE_URL}/priv_client.jwks",
    'key_defs': KEYDEFS,
}


class TestClient(object):

    @pytest.fixture(autouse=True)
    def client_setup(self):
        self.rp = RP(
            config=CONFIG,
            client_configs=CLIENT_CONFIGS, key_conf=CLI_KEYCONF, module_dirs=["oidc"], base_url=BASE_URL,
            entity_id=BASE_URL,
            metadata_class=RegistrationRequest,
        )

    def test_pick_config(self):
        context = self.rp.get_context_by_client_id("Facebook")
        assert context.server_entity_id == FACEBOOK

        context = self.rp.get_context_by_client_id("LinkedIN")
        assert context.issuer == LINKEDIN

        context = self.rp.get_context_by_client_id("GitHub")
        assert context.issuer == GITHUB

        context = self.rp.get_context_by_client_id("")
        assert context.issuer == ""

    def test_init_client(self):
        _context = self.rp.get_context_by_client_id('GitHub')

        assert set(self.rp.get_services(_context).keys()) == {'authorization', 'userinfo',
                                                              'refresh_token', 'accesstoken'}

        # Neither provider info discovery not client registration has been done
        # So only preferences so far.
        assert _context.get_preference("client_id") == "GitHub"
        assert _context.get_preference("client_secret") == "aaaaaaaaaaaaaaaaaaaa"
        assert _context.issuer == "https://github.com/login/oauth/authorize"

        assert _context.get("provider_info") is not None
        assert set(_context.get("provider_info").keys()) == {
            "authorization_endpoint",
            "token_endpoint",
            "userinfo_endpoint",
        }

        _pref = [k for k, v in _context.prefers().items() if v]
        assert set(_pref) == {'application_type',
                              'callback_uris',
                              'client_id',
                              'client_secret',
                              'default_max_age',
                              'grant_types_supported',
                              'id_token_signing_alg_values_supported',
                              'redirect_uris',
                              'request_object_signing_alg_values_supported',
                              'request_parameter_supported',
                              'response_modes_supported',
                              'response_types_supported',
                              'scopes_supported',
                              'subject_types_supported',
                              'token_endpoint_auth_signing_alg_values_supported',
                              'userinfo_signing_alg_values_supported'}

        _github_id = _context.client_id

        key_chain = get_keyjar_chain(_context)
        keys = get_asymetric_keys_from_keyjar_chain(key_chain, key_usages=["sig"])
        assert len(keys) == 2  # one EC and one RSA

        assert _context.base_url == BASE_URL

    def test_do_provider_info(self):
        _context = self.rp.get_context_by_client_id('GitHub')
        issuer = _context.issuer
        assert issuer == GITHUB

        # Make sure the service endpoints are set

        for service_type in ["authorization", "accesstoken", "userinfo"]:
            _srv = _context.get_service(service_type)
            _endp = _context.provider_info[_srv.endpoint_name]
            assert _srv.endpoint == _endp

    def test_do_client_registration(self):
        _context = self.rp.get_context_by_client_id('GitHub')

        self.rp.do_client_registration(_context)

        # only 2 things should have happened

        assert _context.get_preference("callback_uris").get("post_logout_redirect_uris") is None

    def test_create_callbacks(self):
        _context = self.rp.add_new_context("https://op.example.com/")
        # _srv = _context.get_service("registration")
        cb = _context.get_preference("callback_uris")

        assert set(cb.keys()) == {"request_uris", "redirect_uris"}
        assert set(cb["redirect_uris"].keys()) == {"query", "fragment", "form_post"}

        assert cb["redirect_uris"]["query"] == [f"https://example.com/authz_cb"]

    def test_begin(self):
        url = self.rp.begin(GITHUB)

        part = urlsplit(url)
        assert part.scheme == "https"
        assert part.netloc == "github.com"
        assert part.path == "/login/oauth/authorize"
        query = parse_qs(part.query)

        assert set(query.keys()) == {'client_id',
                                     'code_challenge',
                                     'code_challenge_method',
                                     'nonce',
                                     'redirect_uri',
                                     'response_type',
                                     'scope',
                                     'state'}

        # nonce and state are created on the fly so can't check for those
        # that all values are lists is a parse_qs artifact.
        assert query["client_id"] == ["GitHub"]
        assert query["redirect_uri"] == ['https://example.com/rp/authz_cb/github']
        assert query["response_type"] == ["code"]
        assert set(query["scope"][0].split(" ")) == {"openid", "user", "public_repo"}

    def test_get_client_from_session_key(self):
        url = self.rp.begin(issuer_id=LINKEDIN)
        _state = get_state_from_url(url)
        issuer = self.rp.state2issuer(state=_state)
        _context = self.rp.issuer2context(issuer)
        _session = self.rp.get_session_information(_context, _state)

    def test_finalize_auth(self):
        url = self.rp.begin(issuer_id=LINKEDIN)
        _state = get_state_from_url(url)
        _context = self.rp.issuer2context(LINKEDIN)
        _session = self.rp.get_session_information(_context, _state)

        auth_response = AuthorizationResponse(code="access_code", state=_state)
        resp = self.rp.finalize_auth(auth_response.to_dict())
        assert set(resp.keys()) == {"state", "code"}

        _state = _context.cstate.get(_state)
        assert set(_state.keys()) == {'client_id',
                                      'code',
                                      'code_challenge',
                                      'code_challenge_method',
                                      'code_verifier',
                                      'iss',
                                      'nonce',
                                      'redirect_uri',
                                      'response_type',
                                      'scope',
                                      'state'}

    def test_get_client_authn_method(self):
        url = self.rp.begin(issuer_id=GITHUB)
        _state = get_state_from_url(url)
        _g_context = self.rp.issuer2context(GITHUB)
        _session = self.rp.get_session_information(_g_context, _state)
        authn_method = self.rp.get_client_authn_method(_g_context, "token_endpoint")
        assert authn_method == ""

        url = self.rp.begin(issuer_id=LINKEDIN)
        _state = get_state_from_url(url)
        _l_context = self.rp.issuer2context(LINKEDIN)
        _session = self.rp.get_session_information(_l_context, _state)
        authn_method = self.rp.get_client_authn_method(_l_context, "token_endpoint")
        assert authn_method == "client_secret_post"

    def test_get_tokens(self):
        url = self.rp.begin(GITHUB)
        _state = get_state_from_url(url)
        _context = self.rp.issuer2context(GITHUB)
        _session = self.rp.get_session_information(_context, _state)

        _github_id = iss_id("github")
        _keyjar = self.rp.context[_github_id].keyjar
        # Import github keys into context's keyjar.This so it can verify the signature later
        _keyjar.import_jwks(GITHUB_KEYJAR.export_jwks(issuer_id=_github_id), _github_id)

        _nonce = _session["nonce"]
        _iss = _session["iss"]
        _aud = _context.get_client_id()
        idval = {"nonce": _nonce, "sub": "EndUserSubject", "iss": _iss, "aud": _aud}

        idts = IdToken(**idval)
        # _keyjar = full_keyjar_join(self.rp.context[_github_id].keyjar, self.rp.keyjar, private=True)
        # The entity signing the IdToken is the server (_iss). Signing with its own key.
        _signed_jwt = idts.to_jwt(
            key=GITHUB_KEYJAR.get_signing_key(issuer_id=_github_id), algorithm="RS256",
            lifetime=300
        )

        _info = {
            "access_token": "accessTok",
            "id_token": _signed_jwt,
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        at = AccessTokenResponse(**_info)
        _url = "https://github.com/token"
        with responses.RequestsMock() as rsps:
            rsps.add(
                "POST",
                _url,
                body=at.to_json(),
                adding_headers={"Content-Type": "application/json"},
                status=200,
            )
            self.rp.get_service(_context, "accesstoken").endpoint = _url

            auth_response = AuthorizationResponse(code="access_code", state=_state)
            resp = self.rp.finalize_auth(auth_response.to_dict())

            resp = self.rp.get_tokens(_context, _state)
            assert set(resp.keys()) == {
                "access_token",
                "expires_in",
                "id_token",
                "token_type",
                "__verified_id_token",
                "__expires_at",
            }

            _curr = _context.cstate.get(_state)
            assert set(_curr.keys()) == {'__expires_at',
                                         '__verified_id_token',
                                         'access_token',
                                         'client_id',
                                         'code',
                                         'code_challenge',
                                         'code_challenge_method',
                                         'code_verifier',
                                         'expires_in',
                                         'id_token',
                                         'iss',
                                         'nonce',
                                         'redirect_uri',
                                         'response_type',
                                         'scope',
                                         'state',
                                         'token_type'}

    def test_access_and_id_token(self):
        url = self.rp.begin(issuer_id=GITHUB)
        _state = get_state_from_url(url)
        _context = self.rp.issuer2context(GITHUB)

        _session = self.rp.get_session_information(_context, _state)
        _nonce = _session["nonce"]
        _iss = _session["iss"]
        _aud = _context.get_client_id()
        idval = {"nonce": _nonce, "sub": "EndUserSubject", "iss": _iss, "aud": _aud}

        _github_id = iss_id("github")
        _keyjar = self.rp.context[_github_id].keyjar
        _keyjar.import_jwks(GITHUB_KEYJAR.export_jwks(issuer_id=_github_id), _github_id)

        idts = IdToken(**idval)
        _signed_jwt = idts.to_jwt(
            key=GITHUB_KEYJAR.get_signing_key("rsa", issuer_id=_github_id),
            algorithm="RS256",
            lifetime=300,
        )

        _info = {
            "access_token": "accessTok",
            "id_token": _signed_jwt,
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        at = AccessTokenResponse(**_info)
        _url = "https://github.com/token"
        with responses.RequestsMock() as rsps:
            rsps.add(
                "POST",
                _url,
                body=at.to_json(),
                adding_headers={"Content-Type": "application/json"},
                status=200,
            )
            _context.get_service("accesstoken").endpoint = _url

            _response = AuthorizationResponse(code="access_code", state=_state)
            auth_response = self.rp.finalize_auth(_response.to_dict())
            resp = self.rp.get_access_and_id_token(_context, auth_response)
            assert resp["access_token"] == "accessTok"
            assert isinstance(resp["id_token"], IdToken)

    def test_access_and_id_token_by_reference(self):
        url = self.rp.begin(issuer_id=GITHUB)
        _state = get_state_from_url(url)
        _context = self.rp.issuer2context(GITHUB)

        _session = self.rp.get_session_information(_context, _state)

        _nonce = _session["nonce"]
        _iss = _session["iss"]
        _aud = _context.get_client_id()
        idval = {"nonce": _nonce, "sub": "EndUserSubject", "iss": _iss, "aud": _aud}

        _github_id = iss_id("github")
        _keyjar = self.rp.context[_github_id].keyjar
        _keyjar.import_jwks(GITHUB_KEYJAR.export_jwks(issuer_id=_github_id), _github_id)

        idts = IdToken(**idval)
        _signed_jwt = idts.to_jwt(
            key=GITHUB_KEYJAR.get_signing_key("rsa", issuer_id=_github_id),
            algorithm="RS256",
            lifetime=300,
        )

        _info = {
            "access_token": "accessTok",
            "id_token": _signed_jwt,
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        at = AccessTokenResponse(**_info)
        _url = "https://github.com/token"
        with responses.RequestsMock() as rsps:
            rsps.add(
                "POST",
                _url,
                body=at.to_json(),
                adding_headers={"Content-Type": "application/json"},
                status=200,
            )
            _context.get_service("accesstoken").endpoint = _url

            _response = AuthorizationResponse(code="access_code", state=_state)
            _ = self.rp.finalize_auth(_response.to_dict())
            resp = self.rp.get_access_and_id_token(_context, state=_state)
            assert resp["access_token"] == "accessTok"
            assert isinstance(resp["id_token"], IdToken)

    def test_get_user_info(self):
        url = self.rp.begin(issuer_id=GITHUB)
        _state = get_state_from_url(url)
        _context = self.rp.issuer2context(GITHUB)

        _session = self.rp.get_session_information(_context, _state)

        _nonce = _session["nonce"]
        _iss = _session["iss"]
        _aud = _context.get_client_id()
        idval = {"nonce": _nonce, "sub": "EndUserSubject", "iss": _iss, "aud": _aud}

        _github_id = iss_id("github")
        _keyjar = self.rp.context[_github_id].keyjar
        _keyjar.import_jwks(GITHUB_KEYJAR.export_jwks(issuer_id=_github_id), _github_id)

        idts = IdToken(**idval)
        _signed_jwt = idts.to_jwt(
            key=GITHUB_KEYJAR.get_signing_key("rsa", issuer_id=_github_id),
            algorithm="RS256",
            lifetime=300,
        )

        _info = {
            "access_token": "accessTok",
            "id_token": _signed_jwt,
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        at = AccessTokenResponse(**_info)
        _url = "https://github.com/token"
        with responses.RequestsMock() as rsps:
            rsps.add(
                "POST",
                _url,
                body=at.to_json(),
                adding_headers={"Content-Type": "application/json"},
                status=200,
            )
            _context.get_service("accesstoken").endpoint = _url

            _response = AuthorizationResponse(code="access_code", state=_state)
            auth_response = self.rp.finalize_auth(_response.to_dict())

            token_resp = self.rp.get_access_and_id_token(_context, auth_response)

        _url = "https://github.com/user_info"
        with responses.RequestsMock() as rsps:
            rsps.add(
                "GET",
                _url,
                body='{"sub":"EndUserSubject"}',
                adding_headers={"Content-Type": "application/json"},
                status=200,
            )
            _context.get_service("userinfo").endpoint = _url

            userinfo_resp = self.rp.get_user_info(_context, _state, token_resp["access_token"])
            assert userinfo_resp

    def test_userinfo_in_id_token(self):
        url = self.rp.begin(issuer_id=GITHUB)
        _state = get_state_from_url(url)
        _context = self.rp.issuer2context(GITHUB)

        _session = self.rp.get_session_information(_context, _state)

        _nonce = _session["nonce"]
        _iss = _session["iss"]
        _aud = _context.get_client_id()
        idval = {
            "nonce": _nonce,
            "sub": "EndUserSubject",
            "iss": _iss,
            "aud": _aud,
            "given_name": "Diana",
            "family_name": "Krall",
            "occupation": "Jazz pianist",
        }

        idts = IdToken(**idval)

        userinfo = self.rp.userinfo_in_id_token(idts)
        assert set(userinfo.keys()) == {"sub", "family_name", "given_name", "occupation"}


def test_get_provider_specific_service():
    srv_desc = {"access_token": {"class": "idpyoidc.client.provider.github.AccessToken"}}
    entity = Entity(services=srv_desc, config={})
    assert entity.get_service(entity.context[''], "accesstoken").response_body_type == "urlencoded"


class TestRPHandlerTier2(object):

    @pytest.fixture(autouse=True)
    def rphandler_setup(self):
        self.rp = RP(
            config=CONFIG,
            client_configs=CLIENT_CONFIGS, key_conf=CLI_KEYCONF, module_dirs=["oidc"], base_url=BASE_URL,
            entity_id=BASE_URL
        )

        url = self.rp.begin(issuer_id=GITHUB)
        _state = get_state_from_url(url)
        self.context = self.rp.issuer2context(GITHUB)

        _session = self.rp.get_session_information(self.context, _state)

        _nonce = _session["nonce"]
        _iss = _session["iss"]
        _aud = self.context.get_client_id()
        idval = {"nonce": _nonce, "sub": "EndUserSubject", "iss": _iss, "aud": _aud}

        _github_id = iss_id("github")
        _keyjar = self.rp.context[_github_id].keyjar
        _keyjar.import_jwks(GITHUB_KEYJAR.export_jwks(issuer_id=_github_id), _github_id)

        idts = IdToken(**idval)
        _signed_jwt = idts.to_jwt(
            key=GITHUB_KEYJAR.get_signing_key("rsa", issuer_id=_github_id),
            algorithm="RS256",
            lifetime=300,
        )

        _info = {
            "access_token": "accessTok",
            "id_token": _signed_jwt,
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "refreshing",
        }

        at = AccessTokenResponse(**_info)
        _url = "https://github.com/token"
        with responses.RequestsMock() as rsps:
            rsps.add(
                "POST",
                _url,
                body=at.to_json(),
                adding_headers={"Content-Type": "application/json"},
                status=200,
            )

            self.context.get_service("accesstoken").endpoint = _url

            _response = AuthorizationResponse(code="access_code", state=_state)
            auth_response = self.rp.finalize_auth(_response.to_dict())

            token_resp = self.rp.get_access_and_id_token(self.context, auth_response)

        _url = "https://github.com/token"
        with responses.RequestsMock() as rsps:
            rsps.add(
                "GET",
                _url,
                body='{"sub":"EndUserSubject"}',
                adding_headers={"Content-Type": "application/json"},
                status=200,
            )

            self.context.get_service("userinfo").endpoint = _url
            self.rp.get_user_info(self.context, _state, token_resp["access_token"])
            self.state = _state

    def test_init_authorization(self):
        _session = self.rp.get_session_information(self.context, self.state)

        _url = self.rp.init_authorization(self.context, req_args={"scope": ["openid", "email"]})
        part = urlsplit(_url)
        _qp = parse_qs(part.query)
        assert _qp["scope"] == ["openid email"]

    def test_refresh_access_token(self):
        _session = self.rp.get_session_information(self.context, self.state)

        _info = {"access_token": "2nd_accessTok", "token_type": "Bearer", "expires_in": 3600}
        at = AccessTokenResponse(**_info)
        _url = "https://github.com/token"
        with responses.RequestsMock() as rsps:
            rsps.add(
                "POST",
                _url,
                body=at.to_json(),
                adding_headers={"Content-Type": "application/json"},
                status=200,
            )

            self.context.get_service("refresh_token").endpoint = _url
            res = self.rp.refresh_access_token(self.context, self.state, "openid email")
            assert res["access_token"] == "2nd_accessTok"

    def test_get_user_info(self):
        _session = self.rp.get_session_information(self.context, self.state)

        _url = "https://github.com/userinfo"
        with responses.RequestsMock() as rsps:
            rsps.add(
                "GET",
                _url,
                body='{"sub":"EndUserSubject", "mail":"foo@example.com"}',
                adding_headers={"Content-Type": "application/json"},
                status=200,
            )
            self.context.get_service("userinfo").endpoint = _url

            resp = self.rp.get_user_info(self.context, self.state)
            assert set(resp.keys()) == {"sub", "mail"}
            assert resp["mail"] == "foo@example.com"

    def test_has_active_authentication(self):
        assert self.rp.has_active_authentication(self.context, self.state)

    def test_get_valid_access_token(self):
        (token, expires_at) = self.rp.get_valid_access_token(self.context, self.state)
        assert token == "accessTok"
        assert expires_at > 0


class MockResponse:

    def __init__(self, status_code, text, headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class MockOP(object):

    def __init__(self, issuer, keyjar=None):
        self.keyjar = keyjar
        self.issuer = issuer
        self.state = ""
        self.nonce = ""
        self.get_response = {}
        self.register_get_response("default", "OK", 200)
        self.post_response = {}
        self.register_post_response("default", "OK", 200)

    def register_get_response(self, path, data, status_code=200, headers=None):
        _headers = headers or {}
        self.get_response[path] = MockResponse(status_code, data, _headers)

    def register_post_response(self, path, data, status_code=200, headers=None):
        _headers = headers or {}
        self.post_response[path] = MockResponse(status_code, data, _headers)

    def __call__(self, url, method="GET", data=None, headers=None, **kwargs):
        if method == "GET":
            p = urlparse(url)
            try:
                _resp = self.get_response[p.path]
            except KeyError:
                _resp = self.get_response["default"]

            if callable(_resp.text):
                _data = _resp.text(data)
                _resp = MockResponse(_resp.status_code, _data, _resp.headers)

            return _resp
        elif method == "POST":
            p = urlparse(url)
            try:
                _resp = self.post_response[p.path]
            except KeyError:
                _resp = self.post_response["default"]

            if callable(_resp.text):
                _data = _resp.text(data)
                _resp = MockResponse(_resp.status_code, _data, _resp.headers)

            return _resp


def construct_access_token_response(nonce, issuer, client_id, key_jar):
    _aud = client_id

    idval = {"nonce": nonce, "sub": "EndUserSubject", "iss": issuer, "aud": _aud}

    idts = IdToken(**idval)
    _signed_jwt = idts.to_jwt(
        key=key_jar.get_signing_key("rsa", issuer_id=issuer), algorithm="RS256", lifetime=300
    )

    _info = {
        "access_token": "accessTok",
        "id_token": _signed_jwt,
        "token_type": "Bearer",
        "expires_in": 3600,
    }

    return AccessTokenResponse(**_info)


def registration_callback(data):
    _req = json.loads(data)
    # add client_id and client_secret
    _req["client_id"] = "client1"
    _req["client_secret"] = "ClientSecretString"
    return json.dumps(_req)


def test_rphandler_request_uri():
    rp = RP(
        config=CONFIG,
        client_configs=CLIENT_CONFIGS, key_conf=CLI_KEYCONF, module_dirs=["oidc"], base_url=BASE_URL,
        entity_id=BASE_URL
    )

    _url = rp.begin(issuer_id=GITHUB, behaviour_args={"request_param": "request_uri"})
    _qp = parse_qs(urlparse(_url).query)
    assert "request_uri" in _qp


def test_rphandler_request():
    rp = RP(
        config=CONFIG,
        client_configs=CLIENT_CONFIGS, key_conf=CLI_KEYCONF, module_dirs=["oidc"], base_url=BASE_URL,
        entity_id=BASE_URL
    )

    _url = rp.begin(issuer_id=GITHUB, behaviour_args={"request_param": "request"})
    _qp = parse_qs(urlparse(_url).query)
    assert "request" in _qp
