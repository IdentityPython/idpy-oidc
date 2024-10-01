import os
from urllib.parse import parse_qs
from urllib.parse import urlsplit

import responses
from cryptojwt.key_jar import init_key_jar

from idpyoidc.client.rp_handler import RPHandler
from idpyoidc.message.oidc import AccessTokenResponse
from idpyoidc.message.oidc import APPLICATION_TYPE_WEB
from idpyoidc.message.oidc import AuthorizationResponse
from idpyoidc.message.oidc import IdToken

BASE_URL = "https://example.com/rp"

PREFERENCE = {
    "application_type": APPLICATION_TYPE_WEB,
    "contacts": ["ops@example.com"],
    "response_types": [
        "code",
        "id_token",
        "id_token token",
        "code id_token",
        "code id_token token",
        "code token",
    ],
    "token_endpoint_auth_method": "client_secret_basic",
    "scope": ["openid", "profile", "email", "address", "phone"],
    "verify_args": {"allow_sign_alg_none": True},
}

CLIENT_CONFIG = {
    "": {
        "preference": PREFERENCE,
        "redirect_uris": None,
        "services": {
            "web_finger": {"class": "idpyoidc.client.oidc.webfinger.WebFinger"},
            "discovery": {
                "class": "idpyoidc.client.oidc.provider_info_discovery" ".ProviderInfoDiscovery"
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
        "client_type": "oauth2",
        "preference": {
            "response_types": ["code"],
            "scope": ["r_basicprofile", "r_emailaddress"],
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
            "response_types": ["code"],
            "scope": ["email", "public_profile"],
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
        "redirect_uris": ["{}/authz_cb/github".format(BASE_URL)],
        "preference": {
            "response_types": ["code"],
            "scopes_supported": ["user", "public_repo"],
            "token_endpoint_auth_methods_supported": [],
            "verify_args": {"allow_sign_alg_none": True},
        },
        "provider_info": {
            "authorization_endpoint": "https://github.com/login/oauth/authorize",
            "token_endpoint": "https://github.com/login/oauth/access_token",
            "userinfo_endpoint": "https://api.github.com/user",
        },
        "services": {
            "authorization": {"class": "idpyoidc.client.oidc.authorization.Authorization"},
            "access_token": {"class": "idpyoidc.client.oidc.access_token.AccessToken"},
            "userinfo": {
                "class": "idpyoidc.client.oidc.userinfo.UserInfo",
                "kwargs": {"conf": {"default_authn_method": ""}},
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


def iss_id(iss):
    return CLIENT_CONFIG[iss]["issuer"]


def get_state_from_url(url):
    p = urlsplit(url)
    qp = parse_qs(p.query)
    return qp["state"][0]


class TestRPHandler(object):
    def test_pick_config(self):
        rph_1 = RPHandler(
            BASE_URL, client_configs=CLIENT_CONFIG, keyjar=CLI_KEY, module_dirs=["oidc"]
        )
        cnf = rph_1.pick_config("facebook")
        assert cnf["issuer"] == "https://www.facebook.com/v2.11/dialog/oauth"

        cnf = rph_1.pick_config("linkedin")
        assert cnf["issuer"] == "https://www.linkedin.com/oauth/v2/"

        cnf = rph_1.pick_config("github")
        assert cnf["issuer"] == "https://github.com/login/oauth/authorize"

        cnf = rph_1.pick_config("")
        assert "issuer" not in cnf

    def test_do_provider_info(self):
        rph_1 = RPHandler(
            BASE_URL, client_configs=CLIENT_CONFIG, keyjar=CLI_KEY, module_dirs=["oidc"]
        )

        client_1 = rph_1.init_client("github")
        issuer = rph_1.do_provider_info(client_1)
        assert issuer == iss_id("github")

        # Make sure the service endpoints are set

        rph_2 = RPHandler(
            BASE_URL, client_configs=CLIENT_CONFIG, keyjar=CLI_KEY, module_dirs=["oidc"]
        )

        client_2 = rph_2.init_client("github")

        _context_dump = client_1.get_context().dump()
        client_2.get_context().load(_context_dump)
        _service_dump = client_1.get_services().dump()
        client_2.get_services().load(
            _service_dump, init_args={"upstream_get": client_2.upstream_get}
        )

        for service_type in ["authorization", "accesstoken", "userinfo"]:
            _srv = client_2.get_service(service_type)
            _endp = client_2.get_context().provider_info[_srv.endpoint_name]
            assert _srv.endpoint == _endp

    def test_do_client_registration(self):
        rph_1 = RPHandler(
            BASE_URL, client_configs=CLIENT_CONFIG, keyjar=CLI_KEY, module_dirs=["oidc"]
        )

        client = rph_1.init_client("github")
        issuer = rph_1.do_provider_info(client)
        rph_1.do_client_registration(client, "github")

        # only 2 things should have happened

        assert rph_1.hash2issuer["github"] == issuer
        assert not client.get_context().get_usage("post_logout_redirect_uris")

    def test_do_client_setup(self):
        rph_1 = RPHandler(
            BASE_URL, client_configs=CLIENT_CONFIG, keyjar=CLI_KEY, module_dirs=["oidc"]
        )

        client = rph_1.client_setup("github")
        _github_id = iss_id("github")
        _context = client.get_context()

        assert _context.get_client_id() == "eeeeeeeee"
        assert _context.get_usage("client_secret") == "aaaaaaaaaaaaaaaaaaaa"
        assert _context.get("issuer") == _github_id

        _keyjar = _context.upstream_get("attribute", "keyjar")
        _keyjar.import_jwks(GITHUB_KEY.export_jwks(issuer_id=_github_id), _github_id)

        assert set(_keyjar.owners()) == {"", "eeeeeeeee", _github_id}
        keys = _keyjar.get_issuer_keys("")
        assert len(keys) == 3  # one symmetric, one RSA and one EC

        for service_type in ["authorization", "accesstoken", "userinfo"]:
            _srv = client.get_service(service_type)
            _endp = client.get_context().get("provider_info")[_srv.endpoint_name]
            assert _srv.endpoint == _endp

    def test_begin(self):
        rph_1 = RPHandler(
            BASE_URL, client_configs=CLIENT_CONFIG, keyjar=CLI_KEY, module_dirs=["oidc"]
        )

        url = rph_1.begin(issuer_id="github")
        _github_id = iss_id("github")

        client = rph_1.issuer2rp[_github_id]

        assert client.get_context().get("issuer") == _github_id

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
        assert query["client_id"] == ["eeeeeeeee"]
        assert query["redirect_uri"] == ["https://example.com/rp/authz_cb/github"]
        assert query["response_type"] == ["code"]
        assert query["scope"] == ["user public_repo openid"]

    def test_get_session_information(self):
        rph_1 = RPHandler(
            BASE_URL, client_configs=CLIENT_CONFIG, keyjar=CLI_KEY, module_dirs=["oidc"]
        )

        url = rph_1.begin(issuer_id="github")
        _session = rph_1.get_session_information(get_state_from_url(url))
        assert rph_1.client_configs["github"]["issuer"] == _session["iss"]

    def test_get_client_from_session_key(self):
        rph_1 = RPHandler(
            BASE_URL, client_configs=CLIENT_CONFIG, keyjar=CLI_KEY, module_dirs=["oidc"]
        )

        url = rph_1.begin(issuer_id="linkedin")
        _state = get_state_from_url(url)
        cli1 = rph_1.get_client_from_session_key(state=_state)
        _session = rph_1.get_session_information(_state)
        cli2 = rph_1.issuer2rp[_session["iss"]]
        assert cli1 == cli2
        # redo
        rph_1.do_provider_info(state=_state)
        # get new redirect_uris
        cli2.get_context().set_usage("redirect_uris", [])
        rph_1.do_client_registration(state=_state)

    def test_finalize_auth(self):
        rph_1 = RPHandler(
            BASE_URL, client_configs=CLIENT_CONFIG, keyjar=CLI_KEY, module_dirs=["oidc"]
        )

        url = rph_1.begin(issuer_id="linkedin")
        _state = get_state_from_url(url)
        _session = rph_1.get_session_information(_state)
        client = rph_1.issuer2rp[_session["iss"]]

        auth_response = AuthorizationResponse(code="access_code", state=_state)
        resp = rph_1.finalize_auth(client, _session["iss"], auth_response.to_dict())
        assert set(resp.keys()) == {"state", "code"}
        aresp = client.get_service("authorization").upstream_get("context").cstate.get(_state)
        assert set(aresp.keys()) == {
            "state",
            "code",
            "iss",
            "client_id",
            "scope",
            "nonce",
            "response_type",
            "redirect_uri",
        }

    def test_get_client_authn_method(self):
        rph_1 = RPHandler(
            BASE_URL, client_configs=CLIENT_CONFIG, keyjar=CLI_KEY, module_dirs=["oidc"]
        )

        url = rph_1.begin(issuer_id="github")
        _state = get_state_from_url(url)
        _session = rph_1.get_session_information(_state)
        client = rph_1.issuer2rp[_session["iss"]]
        authn_method = rph_1.get_client_authn_method(client, "token_endpoint")
        assert authn_method == ""

        url = rph_1.begin(issuer_id="linkedin")
        _state = get_state_from_url(url)
        _session = rph_1.get_session_information(_state)
        client = rph_1.issuer2rp[_session["iss"]]
        authn_method = rph_1.get_client_authn_method(client, "token_endpoint")
        assert authn_method == "client_secret_post"

    def test_get_tokens(self):
        rph_1 = RPHandler(
            BASE_URL, client_configs=CLIENT_CONFIG, keyjar=CLI_KEY, module_dirs=["oidc"]
        )

        url = rph_1.begin(issuer_id="github")
        _state = get_state_from_url(url)
        _session = rph_1.get_session_information(_state)
        client = rph_1.issuer2rp[_session["iss"]]

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
            resp = rph_1.finalize_auth(client, _session["iss"], auth_response.to_dict())

            resp = rph_1.get_tokens(_state, client)
            assert set(resp.keys()) == {
                "access_token",
                "expires_in",
                "id_token",
                "token_type",
                "__verified_id_token",
                "__expires_at",
            }

            atresp = (
                client.get_service("accesstoken").upstream_get("service_context").cstate.get(_state)
            )
            assert set(atresp.keys()) == {
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
        rph_1 = RPHandler(
            BASE_URL, client_configs=CLIENT_CONFIG, keyjar=CLI_KEY, module_dirs=["oidc"]
        )

        url = rph_1.begin(issuer_id="github")
        _state = get_state_from_url(url)
        _session = rph_1.get_session_information(_state)
        client = rph_1.issuer2rp[_session["iss"]]
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
            auth_response = rph_1.finalize_auth(client, _session["iss"], _response.to_dict())
            resp = rph_1.get_access_and_id_token(auth_response, client=client)
            assert resp["access_token"] == "accessTok"
            assert isinstance(resp["id_token"], IdToken)

    def test_access_and_id_token_by_reference(self):
        rph_1 = RPHandler(
            BASE_URL, client_configs=CLIENT_CONFIG, keyjar=CLI_KEY, module_dirs=["oidc"]
        )

        url = rph_1.begin(issuer_id="github")
        _state = get_state_from_url(url)
        _session = rph_1.get_session_information(_state)
        client = rph_1.issuer2rp[_session["iss"]]
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
            _ = rph_1.finalize_auth(client, _session["iss"], _response.to_dict())
            resp = rph_1.get_access_and_id_token(state=_state)
            assert resp["access_token"] == "accessTok"
            assert isinstance(resp["id_token"], IdToken)

    def test_get_user_info(self):
        rph_1 = RPHandler(
            BASE_URL, client_configs=CLIENT_CONFIG, keyjar=CLI_KEY, module_dirs=["oidc"]
        )

        url = rph_1.begin(issuer_id="github")
        _state = get_state_from_url(url)
        _session = rph_1.get_session_information(_state)
        client = rph_1.issuer2rp[_session["iss"]]
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
            auth_response = rph_1.finalize_auth(client, _session["iss"], _response.to_dict())

            token_resp = rph_1.get_access_and_id_token(auth_response, client=client)

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

            userinfo_resp = rph_1.get_user_info(_state, client, token_resp["access_token"])
            assert userinfo_resp

    def test_userinfo_in_id_token(self):
        rph_1 = RPHandler(
            BASE_URL, client_configs=CLIENT_CONFIG, keyjar=CLI_KEY, module_dirs=["oidc"]
        )

        url = rph_1.begin(issuer_id="github")
        _state = get_state_from_url(url)
        _session = rph_1.get_session_information(_state)
        client = rph_1.issuer2rp[_session["iss"]]
        # _context = client.client_get("service_context")
        _nonce = _session["nonce"]
        _iss = _session["iss"]
        _aud = client.get_client_id()
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

        userinfo = rph_1.userinfo_in_id_token(idts)
        assert set(userinfo.keys()) == {"sub", "family_name", "given_name", "occupation"}
