import json
import os
from urllib.parse import parse_qs
from urllib.parse import urlparse
from urllib.parse import urlsplit

from cryptojwt.key_jar import init_key_jar
import pytest
import responses

from idpyoidc.client.entity import Entity
from idpyoidc.client.rp_handler import RPHandler
from idpyoidc.message.oidc import AccessTokenResponse
from idpyoidc.message.oidc import APPLICATION_TYPE_WEB
from idpyoidc.message.oidc import AuthorizationResponse
from idpyoidc.message.oidc import IdToken
from idpyoidc.message.oidc import JRD
from idpyoidc.message.oidc import Link
from idpyoidc.message.oidc import OpenIDSchema
from idpyoidc.message.oidc import ProviderConfigurationResponse
from idpyoidc.message.oidc import RegistrationResponse
from idpyoidc.util import rndstr

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

CLIENT_CONFIG = {
    "": {
        "preference": PREF,
        "redirect_uris": None,
        "base_url": BASE_URL,
        "request_parameter": "request_uris",
        "client_type": "oidc",
        "services": {
            "web_finger": {"class": "idpyoidc.client.oidc.webfinger.WebFinger"},
            "discovery": {
                "class": "idpyoidc.client.oidc.provider_info_discovery.ProviderInfoDiscovery"
            },
            "registration": {"class": "idpyoidc.client.oidc.registration.Registration"},
            "authorization": {"class": "idpyoidc.client.oidc.authorization.Authorization"},
            "access_token": {"class": "idpyoidc.client.oidc.access_token.AccessToken"},
            "refresh_access_token": {
                "class": "idpyoidc.client.oidc.refresh_access_token" ".RefreshAccessToken"
            },
            "userinfo": {"class": "idpyoidc.client.oidc.userinfo.UserInfo"},
        },
    },
    "linkedin": {
        "issuer": "https://www.linkedin.com/oauth/v2/",
        "client_id": "xxxxxxx",
        "client_secret": "yyyyyyyyyyyyyyyyyyyy",
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
        "services": {
            "authorization": {"class": "idpyoidc.client.oidc.authorization.Authorization"},
            "access_token": {"class": "idpyoidc.client.provider.linkedin.AccessToken"},
            "userinfo": {"class": "idpyoidc.client.provider.linkedin.UserInfo"},
        },
    },
    "facebook": {
        "issuer": "https://www.facebook.com/v2.11/dialog/oauth",
        "client_id": "ccccccccc",
        "client_secret": "dddddddddddddd",
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
        "issuer": "https://github.com/login/oauth/authorize",
        "client_id": "eeeeeeeee",
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
    },
    "github2": {
        "issuer": "https://github.com/login/oauth/authorize",
        "client_id": "eeeeeeeee",
        "client_secret": "aaaaaaaaaaaaaaaaaaaa",
        "client_type": "oidc",
        "redirect_uris": ["{}/authz_cb/github".format(BASE_URL)],
        "preference": {
            "response_types_supported": ["code"],
            "scopes_supported": ["user", "public_repo"],
            "token_endpoint_auth_methods_supported": [],
            "verify_args": {"allow_sign_alg_none": True},
            "encrypt_request_object": False,
        },
        "provider_info": {
            "authorization_endpoint": "https://github.com/login/oauth/authorize",
            "token_endpoint": "https://github.com/login/oauth/access_token",
            "userinfo_endpoint": "https://api.github.com/user",
            "request_parameter_supported": True,
            "request_uri_parameter_supported": True,
        },
        "services": {
            "authorization": {"class": "idpyoidc.client.oidc.authorization.Authorization"},
            "access_token": {"class": "idpyoidc.client.oidc.access_token.AccessToken"},
            "userinfo": {
                "class": "idpyoidc.client.oidc.userinfo.UserInfo",
                "kwargs": {"default_authn_method": ""},
            },
            "refresh_access_token": {
                "class": "idpyoidc.client.oidc.refresh_access_token.RefreshAccessToken"
            },
        },
    },
}

KEYDEFS = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

_dirname = os.path.dirname(os.path.abspath(__file__))

ISS = "https://example.com"

CLI_KEY = init_key_jar(
    public_path="{}/pub_client.jwks".format(_dirname),
    private_path="{}/priv_client.jwks".format(_dirname),
    key_defs=KEYDEFS,
    issuer_id="",
)

LINKEDIN_KEY = init_key_jar(
    public_path="{}/pub_linkedin.jwks".format(_dirname),
    private_path="{}/priv_linkedin.jwks".format(_dirname),
    key_defs=KEYDEFS,
    issuer_id=CLIENT_CONFIG["linkedin"]["issuer"],
)

FACEBOOK_KEY = init_key_jar(
    public_path="{}/pub_facebook.jwks".format(_dirname),
    private_path="{}/priv_facebook.jwks".format(_dirname),
    key_defs=KEYDEFS,
    issuer_id=CLIENT_CONFIG["facebook"]["issuer"],
)

GITHUB_KEY = init_key_jar(
    public_path="{}/pub_github.jwks".format(_dirname),
    private_path="{}/priv_github.jwks".format(_dirname),
    key_defs=KEYDEFS,
    issuer_id=CLIENT_CONFIG["github"]["issuer"],
)


def get_state_from_url(url):
    p = urlsplit(url)
    qp = parse_qs(p.query)
    return qp["state"][0]


def iss_id(iss):
    return CLIENT_CONFIG[iss]["issuer"]


class TestRPHandler(object):
    @pytest.fixture(autouse=True)
    def rphandler_setup(self):
        self.rph = RPHandler(
            BASE_URL, client_configs=CLIENT_CONFIG, keyjar=CLI_KEY, module_dirs=["oidc"]
        )

    def test_pick_config(self):
        cnf = self.rph.pick_config("facebook")
        assert cnf["issuer"] == "https://www.facebook.com/v2.11/dialog/oauth"

        cnf = self.rph.pick_config("linkedin")
        assert cnf["issuer"] == "https://www.linkedin.com/oauth/v2/"

        cnf = self.rph.pick_config("github")
        assert cnf["issuer"] == "https://github.com/login/oauth/authorize"

        cnf = self.rph.pick_config("")
        assert "issuer" not in cnf

    def test_init_client(self):
        client = self.rph.init_client("github")
        assert set(client.get_services().keys()) == {
            "authorization",
            "accesstoken",
            "userinfo",
            "refresh_token",
        }

        _context = client.get_context()

        # Neither provider info discovery not client registration has been done
        # So only preferences so far.
        assert _context.get_preference("client_id") == "eeeeeeeee"
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
                              'response_modes_supported',
                              'response_types_supported',
                              'scopes_supported',
                              'subject_types_supported',
                              'token_endpoint_auth_signing_alg_values_supported',
                              'userinfo_signing_alg_values_supported'}

        _github_id = iss_id("github")
        _keyjar = _context.upstream_get("attribute", "keyjar")
        _keyjar.import_jwks(GITHUB_KEY.export_jwks(issuer_id=_github_id), _github_id)

        # The key jar should only contain a symmetric key that is the clients
        # secret. 2 because one is marked for encryption and the other signing
        # usage.

        assert set(_keyjar.owners()) == {"", "eeeeeeeee", _github_id}
        keys = _keyjar.get_issuer_keys("")
        assert len(keys) == 3

        assert _context.base_url == BASE_URL

    def test_do_provider_info(self):
        client = self.rph.init_client("github")
        issuer = self.rph.do_provider_info(client)
        assert issuer == iss_id("github")

        # Make sure the service endpoints are set

        for service_type in ["authorization", "accesstoken", "userinfo"]:
            _srv = client.get_service(service_type)
            _endp = client.get_context().get("provider_info")[_srv.endpoint_name]
            assert _srv.endpoint == _endp

    def test_do_client_registration(self):
        client = self.rph.init_client("github")
        issuer = self.rph.do_provider_info(client)
        self.rph.do_client_registration(client, "github")

        # only 2 things should have happened

        assert self.rph.hash2issuer["github"] == issuer
        assert (
                client.get_context().get_preference("callback_uris").get(
                    "post_logout_redirect_uris")
                is None
        )

    def test_do_client_setup(self):
        client = self.rph.client_setup("github")
        _github_id = iss_id("github")
        _context = client.get_context()

        # Neither provider info discovery not client registration has been done
        # So only preferences so far.
        assert _context.get_preference("client_id") == "eeeeeeeee"
        assert _context.get_preference("client_secret") == "aaaaaaaaaaaaaaaaaaaa"
        assert _context.issuer == _github_id

        _keyjar = _context.upstream_get("attribute", "keyjar")
        _keyjar.import_jwks(GITHUB_KEY.export_jwks(issuer_id=_github_id), _github_id)

        assert set(_keyjar.owners()) == {"", "eeeeeeeee", _github_id}
        keys = _keyjar.get_issuer_keys("")
        assert len(keys) == 3

        for service_type in ["authorization", "accesstoken", "userinfo"]:
            _srv = client.get_service(service_type)
            _endp = _srv.upstream_get("context").get("provider_info")[_srv.endpoint_name]
            assert _srv.endpoint == _endp

    def test_create_callbacks(self):
        client = self.rph.init_client("https://op.example.com/")
        _srv = client.get_service("registration")
        _context = _srv.upstream_get("context")
        cb = _context.get_preference("callback_uris")

        assert set(cb.keys()) == {"request_uris", "redirect_uris"}
        assert set(cb["redirect_uris"].keys()) == {"query", "fragment"}
        _hash = _context.iss_hash

        assert cb["redirect_uris"]["query"] == [f"https://example.com/rp/authz_cb/{_hash}"]

        assert list(self.rph.hash2issuer.keys()) == [_hash]

        assert self.rph.hash2issuer[_hash] == "https://op.example.com/"

    def test_begin(self):
        url = self.rph.begin(issuer_id="github")
        _github_id = iss_id("github")

        client = self.rph.issuer2rp[_github_id]

        assert client.get_context().issuer == _github_id

        part = urlsplit(url)
        assert part.scheme == "https"
        assert part.netloc == "github.com"
        assert part.path == "/login/oauth/authorize"
        query = parse_qs(part.query)

        assert set(query.keys()) == {
            "nonce",
            "state",
            "client_id",
            "redirect_uri",
            "response_type",
            "scope",
        }

        # nonce and state are created on the fly so can't check for those
        # that all values are lists is a parse_qs artifact.
        assert query["client_id"] == ["eeeeeeeee"]
        assert query["redirect_uri"] == ["https://example.com/rp/authz_cb/github"]
        assert query["response_type"] == ["code"]
        assert set(query["scope"][0].split(" ")) == {"openid", "user", "public_repo"}

    def test_get_session_information(self):
        url = self.rph.begin(issuer_id="github")
        _session = self.rph.get_session_information(get_state_from_url(url))
        assert self.rph.client_configs["github"]["issuer"] == _session["iss"]

    def test_get_client_from_session_key(self):
        url = self.rph.begin(issuer_id="linkedin")
        _state = get_state_from_url(url)
        cli1 = self.rph.get_client_from_session_key(state=_state)
        _session = self.rph.get_session_information(_state)
        cli2 = self.rph.issuer2rp[_session["iss"]]
        assert cli1 == cli2
        # redo
        self.rph.do_provider_info(state=_state)
        # get new redirect_uris
        cli2.get_context().set_preference("redirect_uris", [])
        self.rph.do_client_registration(state=_state)

    def test_finalize_auth(self):
        url = self.rph.begin(issuer_id="linkedin")
        _state = get_state_from_url(url)
        _session = self.rph.get_session_information(_state)
        client = self.rph.issuer2rp[_session["iss"]]

        auth_response = AuthorizationResponse(code="access_code", state=_state)
        resp = self.rph.finalize_auth(client, _session["iss"], auth_response.to_dict())
        assert set(resp.keys()) == {"state", "code"}
        _state = client.get_context().cstate.get(_state)
        assert set(_state.keys()) == {
            "client_id",
            "code",
            "iss",
            "nonce",
            "redirect_uri",
            "response_type",
            "scope",
            "state",
        }

    def test_get_client_authn_method(self):
        url = self.rph.begin(issuer_id="github")
        _state = get_state_from_url(url)
        _session = self.rph.get_session_information(_state)
        client = self.rph.issuer2rp[_session["iss"]]
        authn_method = self.rph.get_client_authn_method(client, "token_endpoint")
        assert authn_method == ""

        url = self.rph.begin(issuer_id="linkedin")
        _state = get_state_from_url(url)
        _session = self.rph.get_session_information(_state)
        client = self.rph.issuer2rp[_session["iss"]]
        authn_method = self.rph.get_client_authn_method(client, "token_endpoint")
        assert authn_method == "client_secret_post"

    def test_get_tokens(self):
        url = self.rph.begin(issuer_id="github")
        _state = get_state_from_url(url)
        _session = self.rph.get_session_information(_state)
        client = self.rph.issuer2rp[_session["iss"]]

        _github_id = iss_id("github")
        _context = client.get_context()
        _keyjar = _context.upstream_get("attribute", "keyjar")
        _keyjar.import_jwks(GITHUB_KEY.export_jwks(issuer_id=_github_id), _github_id)

        _nonce = _session["nonce"]
        _iss = _session["iss"]
        _aud = _context.get_client_id()
        idval = {"nonce": _nonce, "sub": "EndUserSubject", "iss": _iss, "aud": _aud}

        idts = IdToken(**idval)
        _signed_jwt = idts.to_jwt(
            key=GITHUB_KEY.get_signing_key(issuer_id=_github_id), algorithm="RS256", lifetime=300
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
            client.get_service("accesstoken").endpoint = _url

            auth_response = AuthorizationResponse(code="access_code", state=_state)
            resp = self.rph.finalize_auth(client, _session["iss"], auth_response.to_dict())

            resp = self.rph.get_tokens(_state, client)
            assert set(resp.keys()) == {
                "access_token",
                "expires_in",
                "id_token",
                "token_type",
                "__verified_id_token",
                "__expires_at",
            }

            _curr = client.get_context().cstate.get(_state)
            assert set(_curr.keys()) == {
                "__expires_at",
                "__verified_id_token",
                "access_token",
                "client_id",
                "code",
                "expires_in",
                "id_token",
                "iss",
                "nonce",
                "redirect_uri",
                "response_type",
                "scope",
                "state",
                "token_type",
            }

    def test_access_and_id_token(self):
        url = self.rph.begin(issuer_id="github")
        _state = get_state_from_url(url)
        _session = self.rph.get_session_information(_state)
        client = self.rph.issuer2rp[_session["iss"]]
        _context = client.get_context()
        _nonce = _session["nonce"]
        _iss = _session["iss"]
        _aud = _context.get_client_id()
        idval = {"nonce": _nonce, "sub": "EndUserSubject", "iss": _iss, "aud": _aud}

        _github_id = iss_id("github")
        _keyjar = _context.upstream_get("attribute", "keyjar")
        _keyjar.import_jwks(GITHUB_KEY.export_jwks(issuer_id=_github_id), _github_id)

        idts = IdToken(**idval)
        _signed_jwt = idts.to_jwt(
            key=GITHUB_KEY.get_signing_key("rsa", issuer_id=_github_id),
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
            client.get_service("accesstoken").endpoint = _url

            _response = AuthorizationResponse(code="access_code", state=_state)
            auth_response = self.rph.finalize_auth(client, _session["iss"], _response.to_dict())
            resp = self.rph.get_access_and_id_token(auth_response, client=client)
            assert resp["access_token"] == "accessTok"
            assert isinstance(resp["id_token"], IdToken)

    def test_access_and_id_token_by_reference(self):
        url = self.rph.begin(issuer_id="github")
        _state = get_state_from_url(url)
        _session = self.rph.get_session_information(_state)
        client = self.rph.issuer2rp[_session["iss"]]
        _context = client.get_context()
        _nonce = _session["nonce"]
        _iss = _session["iss"]
        _aud = _context.get_client_id()
        idval = {"nonce": _nonce, "sub": "EndUserSubject", "iss": _iss, "aud": _aud}

        _github_id = iss_id("github")
        _keyjar = _context.upstream_get("attribute", "keyjar")
        _keyjar.import_jwks(GITHUB_KEY.export_jwks(issuer_id=_github_id), _github_id)

        idts = IdToken(**idval)
        _signed_jwt = idts.to_jwt(
            key=GITHUB_KEY.get_signing_key("rsa", issuer_id=_github_id),
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
            client.get_service("accesstoken").endpoint = _url

            _response = AuthorizationResponse(code="access_code", state=_state)
            _ = self.rph.finalize_auth(client, _session["iss"], _response.to_dict())
            resp = self.rph.get_access_and_id_token(state=_state)
            assert resp["access_token"] == "accessTok"
            assert isinstance(resp["id_token"], IdToken)

    def test_get_user_info(self):
        url = self.rph.begin(issuer_id="github")
        _state = get_state_from_url(url)
        _session = self.rph.get_session_information(_state)
        client = self.rph.issuer2rp[_session["iss"]]
        _context = client.get_context()
        _nonce = _session["nonce"]
        _iss = _session["iss"]
        _aud = _context.get_client_id()
        idval = {"nonce": _nonce, "sub": "EndUserSubject", "iss": _iss, "aud": _aud}

        _github_id = iss_id("github")
        _keyjar = _context.upstream_get("attribute", "keyjar")
        _keyjar.import_jwks(GITHUB_KEY.export_jwks(issuer_id=_github_id), _github_id)

        idts = IdToken(**idval)
        _signed_jwt = idts.to_jwt(
            key=GITHUB_KEY.get_signing_key("rsa", issuer_id=_github_id),
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
            client.get_service("accesstoken").endpoint = _url

            _response = AuthorizationResponse(code="access_code", state=_state)
            auth_response = self.rph.finalize_auth(client, _session["iss"], _response.to_dict())

            token_resp = self.rph.get_access_and_id_token(auth_response, client=client)

        _url = "https://github.com/user_info"
        with responses.RequestsMock() as rsps:
            rsps.add(
                "GET",
                _url,
                body='{"sub":"EndUserSubject"}',
                adding_headers={"Content-Type": "application/json"},
                status=200,
            )
            client.get_service("userinfo").endpoint = _url

            userinfo_resp = self.rph.get_user_info(_state, client, token_resp["access_token"])
            assert userinfo_resp

    def test_userinfo_in_id_token(self):
        url = self.rph.begin(issuer_id="github")
        _state = get_state_from_url(url)
        _session = self.rph.get_session_information(_state)
        client = self.rph.issuer2rp[_session["iss"]]
        _context = client.get_context()
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

        userinfo = self.rph.userinfo_in_id_token(idts)
        assert set(userinfo.keys()) == {"sub", "family_name", "given_name", "occupation"}


def test_get_provider_specific_service():
    srv_desc = {"access_token": {"class": "idpyoidc.client.provider.github.AccessToken"}}
    entity = Entity(services=srv_desc, config={})
    assert entity.get_service("accesstoken").response_body_type == "urlencoded"


class TestRPHandlerTier2(object):
    @pytest.fixture(autouse=True)
    def rphandler_setup(self):
        self.rph = RPHandler(BASE_URL, CLIENT_CONFIG, keyjar=CLI_KEY)
        url = self.rph.begin(issuer_id="github")
        _state = get_state_from_url(url)
        _session = self.rph.get_session_information(_state)
        client = self.rph.issuer2rp[_session["iss"]]
        _context = client.get_context()
        _nonce = _session["nonce"]
        _iss = _session["iss"]
        _aud = _context.get_client_id()
        idval = {"nonce": _nonce, "sub": "EndUserSubject", "iss": _iss, "aud": _aud}

        _github_id = iss_id("github")
        _keyjar = _context.upstream_get("attribute", "keyjar")
        _keyjar.import_jwks(GITHUB_KEY.export_jwks(issuer_id=_github_id), _github_id)

        idts = IdToken(**idval)
        _signed_jwt = idts.to_jwt(
            key=GITHUB_KEY.get_signing_key("rsa", issuer_id=_github_id),
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

            client.get_service("accesstoken").endpoint = _url

            _response = AuthorizationResponse(code="access_code", state=_state)
            auth_response = self.rph.finalize_auth(client, _session["iss"], _response.to_dict())

            token_resp = self.rph.get_access_and_id_token(auth_response, client=client)

        _url = "https://github.com/token"
        with responses.RequestsMock() as rsps:
            rsps.add(
                "GET",
                _url,
                body='{"sub":"EndUserSubject"}',
                adding_headers={"Content-Type": "application/json"},
                status=200,
            )

            client.get_service("userinfo").endpoint = _url
            self.rph.get_user_info(_state, client, token_resp["access_token"])
            self.state = _state

    def test_init_authorization(self):
        _session = self.rph.get_session_information(self.state)
        client = self.rph.issuer2rp[_session["iss"]]
        _url = self.rph.init_authorization(client, req_args={"scope": ["openid", "email"]})
        part = urlsplit(_url)
        _qp = parse_qs(part.query)
        assert _qp["scope"] == ["openid email"]

    def test_refresh_access_token(self):
        _session = self.rph.get_session_information(self.state)
        client = self.rph.issuer2rp[_session["iss"]]

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

            client.get_service("refresh_token").endpoint = _url
            res = self.rph.refresh_access_token(self.state, client, "openid email")
            assert res["access_token"] == "2nd_accessTok"

    def test_get_user_info(self):
        _session = self.rph.get_session_information(self.state)
        client = self.rph.issuer2rp[_session["iss"]]

        _url = "https://github.com/userinfo"
        with responses.RequestsMock() as rsps:
            rsps.add(
                "GET",
                _url,
                body='{"sub":"EndUserSubject", "mail":"foo@example.com"}',
                adding_headers={"Content-Type": "application/json"},
                status=200,
            )
            client.get_service("userinfo").endpoint = _url

            resp = self.rph.get_user_info(self.state, client)
            assert set(resp.keys()) == {"sub", "mail"}
            assert resp["mail"] == "foo@example.com"

    def test_has_active_authentication(self):
        assert self.rph.has_active_authentication(self.state)

    def test_get_valid_access_token(self):
        (token, expires_at) = self.rph.get_valid_access_token(self.state)
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
    rph = RPHandler(BASE_URL, CLIENT_CONFIG, keyjar=CLI_KEY)
    _url = rph.begin(issuer_id="github2", behaviour_args={"request_param": "request_uri"})
    _qp = parse_qs(urlparse(_url).query)
    assert "request_uri" in _qp


def test_rphandler_request():
    rph = RPHandler(BASE_URL, CLIENT_CONFIG, keyjar=CLI_KEY)
    _url = rph.begin(issuer_id="github2", behaviour_args={"request_param": "request"})
    _qp = parse_qs(urlparse(_url).query)
    assert "request" in _qp


class TestRPHandlerWithMockOP(object):
    @pytest.fixture(autouse=True)
    def rphandler_setup(self):
        self.issuer = "https://github.com/login/oauth/authorize"
        # self.mock_op = MockOP(issuer=self.issuer)
        self.rph = RPHandler(BASE_URL, client_configs=CLIENT_CONFIG, keyjar=CLI_KEY)

    def test_finalize(self):
        url = self.rph.begin(issuer_id="github")
        _state = get_state_from_url(url)
        #  The authorization query is sent and after successful authentication
        client = self.rph.get_client_from_session_key(state=_state)
        # register a response
        _url = CLIENT_CONFIG["github"]["provider_info"]["authorization_endpoint"]
        with responses.RequestsMock() as rsps:
            rsps.add(
                "GET",
                _url,
                status=302,
            )
            _ = client.httpc("GET", url)

        #  the user is redirected back to the RP with a positive response
        auth_response = AuthorizationResponse(code="access_code", state=_state)

        # need session information and the client instance
        _session = self.rph.get_session_information(auth_response["state"])
        client = self.rph.get_client_from_session_key(state=auth_response["state"])

        # Faking
        resp = construct_access_token_response(
            _session["nonce"],
            issuer=self.issuer,
            client_id=CLIENT_CONFIG["github"]["client_id"],
            key_jar=GITHUB_KEY,
        )

        _token_url = CLIENT_CONFIG["github"]["provider_info"]["token_endpoint"]
        _user_url = CLIENT_CONFIG["github"]["provider_info"]["userinfo_endpoint"]
        _user_info = OpenIDSchema(
            sub="EndUserSubject", given_name="Diana", family_name="Krall", occupation="Jazz pianist"
        )
        _github_id = iss_id("github")
        _keyjar = client.get_attribute("keyjar")
        _keyjar.import_jwks(GITHUB_KEY.export_jwks(issuer_id=_github_id), _github_id)
        with responses.RequestsMock() as rsps:
            rsps.add(
                "POST",
                _token_url,
                body=resp.to_json(),
                adding_headers={"Content-Type": "application/json"},
                status=200,
            )
            rsps.add(
                "GET",
                _user_url,
                body=_user_info.to_json(),
                adding_headers={"Content-Type": "application/json"},
                status=200,
            )

            # do the rest (= get access token and user info)
            # assume code flow
            resp = self.rph.finalize(_session["iss"], auth_response.to_dict())

        assert set(resp.keys()) == {
            "token",
            "session_state",
            "userinfo",
            "state",
            "issuer",
            "id_token",
        }

    def test_dynamic_setup(self):
        user_id = "acct:foobar@example.com"
        _link = Link(
            rel="http://openid.net/specs/connect/1.0/issuer", href="https://server.example.com"
        )
        webfinger_response = JRD(subject=user_id, links=[_link])
        resp = {
            "authorization_endpoint": "https://server.example.com/connect/authorize",
            "issuer": "https://server.example.com",
            "subject_types_supported": ["public"],
            "token_endpoint": "https://server.example.com/connect/token",
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "private_key_jwt"],
            "userinfo_endpoint": "https://server.example.com/connect/user",
            "check_id_endpoint": "https://server.example.com/connect/check_id",
            "refresh_session_endpoint": "https://server.example.com/connect/refresh_session",
            "end_session_endpoint": "https://server.example.com/connect/end_session",
            "jwks_uri": "https://server.example.com/jwk.json",
            "registration_endpoint": "https://server.example.com/connect/register",
            "scopes_supported": ["openid", "profile", "email", "address", "phone"],
            "response_types_supported": ["code", "code id_token", "token id_token"],
            "acrs_supported": ["1", "2", "http://id.incommon.org/assurance/bronze"],
            "user_id_types_supported": ["public", "pairwise"],
            "userinfo_algs_supported": ["HS256", "RS256", "A128CBC", "A128KW", "RSA1_5"],
            "id_token_signing_alg_values_supported": [
                "HS256",
                "RS256",
                "A128CBC",
                "A128KW",
                "RSA1_5",
            ],
            "request_object_algs_supported": ["HS256", "RS256", "A128CBC", "A128KW", "RSA1_5"],
        }
        pcr = ProviderConfigurationResponse(**resp)
        _crr = {
            "application_type": APPLICATION_TYPE_WEB,
            "response_types": ["code", "code id_token"],
            "redirect_uris": [
                "https://example.com/rp/authz_cb"
                "/7b7308fecf10c90b29303b6ae35ad1ef0f1914e49187f163335ae0b26a769e4f"
            ],
            "grant_types": ["authorization_code", "implicit"],
            "contacts": ["ops@example.com"],
            "subject_type": "public",
            "id_token_signed_response_alg": "RS256",
            "userinfo_signed_response_alg": "RS256",
            "request_object_signing_alg": "RS256",
            "token_endpoint_auth_signing_alg": "RS256",
            "default_max_age": 86400,
            "token_endpoint_auth_method": "client_secret_basic",
        }
        _crr.update({"client_id": "abcdefghijkl", "client_secret": rndstr(32)})
        cli_reg_resp = RegistrationResponse(**_crr)
        with responses.RequestsMock() as rsps:
            rsps.add(
                "GET",
                "https://example.com/.well-known/webfinger",
                body=webfinger_response.to_json(),
                adding_headers={"Content-Type": "application/json"},
                status=200,
            )
            rsps.add(
                "GET",
                "https://server.example.com/.well-known/openid-configuration",
                body=pcr.to_json(),
                status=200,
                adding_headers={"Content-Type": "application/json"},
            )
            rsps.add(
                "POST",
                "https://server.example.com/connect/register",
                body=cli_reg_resp.to_json(),
                status=200,
                adding_headers={"Content-Type": "application/json"},
            )

            auth_query = self.rph.begin(user_id=user_id)
        assert auth_query
