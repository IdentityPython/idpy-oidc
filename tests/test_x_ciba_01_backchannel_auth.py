import os

import pytest
from cryptojwt import JWT
from cryptojwt import KeyJar
from cryptojwt.jwt import utc_time_sans_frac
from cryptojwt.key_jar import build_keyjar
from cryptojwt.key_jar import init_key_jar

from idpyoidc.client.defaults import DEFAULT_OAUTH2_SERVICES
from idpyoidc.client.oauth2 import Client
from idpyoidc.defaults import JWT_BEARER
from idpyoidc.message.oidc.backchannel_authentication import AuthenticationRequest
from idpyoidc.message.oidc.backchannel_authentication import NotificationRequest
from idpyoidc.message.oidc.backchannel_authentication import TokenRequest
from idpyoidc.server import OPConfiguration
from idpyoidc.server import Server
from idpyoidc.server import init_service
from idpyoidc.server import init_user_info
from idpyoidc.server import user_info
from idpyoidc.server.authn_event import create_authn_event
from idpyoidc.server.client_authn import verify_client
from idpyoidc.server.oidc.backchannel_authentication import BackChannelAuthentication
from idpyoidc.server.oidc.token import Token
from idpyoidc.server.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from . import CRYPT_CONFIG

from . import SESSION_PARAMS
from . import full_path

QUERY_2 = (
    "request=eyJraWQiOiJsdGFjZXNidyIsImFsZyI6IkVTMjU2In0.eyJpc3MiOiJz"
    "NkJoZFJrcXQzIiwiYXVkIjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJl"
    "eHAiOjE1Mzc4MjAwODYsImlhdCI6MTUzNzgxOTQ4NiwibmJmIjoxNTM3ODE4ODg2"
    "LCJqdGkiOiI0TFRDcUFDQzJFU0M1QldDbk4zajU4RW5BIiwic2NvcGUiOiJvcGVu"
    "aWQgZW1haWwgZXhhbXBsZS1zY29wZSIsImNsaWVudF9ub3RpZmljYXRpb25fdG9r"
    "ZW4iOiI4ZDY3ZGM3OC03ZmFhLTRkNDEtYWFiZC02NzcwN2IzNzQyNTUiLCJiaW5k"
    "aW5nX21lc3NhZ2UiOiJXNFNDVCIsImxvZ2luX2hpbnRfdG9rZW4iOiJleUpyYVdR"
    "aU9pSnNkR0ZqWlhOaWR5SXNJbUZzWnlJNklrVlRNalUySW4wLmV5SnpkV0pmYVdR"
    "aU9uc2labTl5YldGMElqb2ljR2h2Ym1VaUxDSndhRzl1WlNJNklpc3hNek13TWpn"
    "eE9EQXdOQ0o5ZlEuR1NxeEpzRmJJeW9qZGZNQkR2M01PeUFwbENWaVZrd1FXenRo"
    "Q1d1dTlfZ25LSXFFQ1ppbHdBTnQxSGZJaDN4M0pGamFFcS01TVpfQjNxZWIxMU5B"
    "dmcifQ.ELJvZ2RfBl05bq7nx7pXhagzL9R75mUwO-yZScB1aT3mp480fCQ5KjRVD"
    "womMMjiMKUI4sx8VrPgAZuTfsNSvA&"
    "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3A"
    "client-assertion-type%3Ajwt-bearer&"
    "client_assertion=eyJraWQiOiJsdGFjZXNidyIsImFsZyI6IkVTMjU2In0.eyJ"
    "pc3MiOiJzNkJoZFJrcXQzIiwic3ViIjoiczZCaGRSa3F0MyIsImF1ZCI6Imh0dHB"
    "zOi8vc2VydmVyLmV4YW1wbGUuY29tIiwianRpIjoiY2NfMVhzc3NmLTJpOG8yZ1B"
    "6SUprMSIsImlhdCI6MTUzNzgxOTQ4NiwiZXhwIjoxNTM3ODE5Nzc3fQ.PWb_VMzU"
    "IbD_aaO5xYpygnAlhRIjzoc6kxg4NixDuD1DVpkKVSBbBweqgbDLV-awkDtuWnyF"
    "yUpHqg83AUV5TA"
)

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

ISSUER = "https://example.com/"

RESPONSE_TYPES_SUPPORTED = [
    ["code"],
    ["token"],
    ["id_token"],
    ["code", "token"],
    ["code", "id_token"],
    ["id_token", "token"],
    ["code", "token", "id_token"],
    ["none"],
]

CAPABILITIES = {
    "response_types_supported": [" ".join(x) for x in RESPONSE_TYPES_SUPPORTED],
    "token_endpoint_auth_methods_supported": [
        "client_secret_post",
        "client_secret_basic",
        "client_secret_jwt",
        "private_key_jwt",
    ],
    "response_modes_supported": ["query", "fragment", "form_post"],
    "subject_types_supported": ["public", "pairwise", "ephemeral"],
    "grant_types_supported": [
        "authorization_code",
        "implicit",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
    ],
    "claim_types_supported": ["normal", "aggregated", "distributed"],
    "claims_parameter_supported": True,
    "request_parameter_supported": True,
    "request_uri_parameter_supported": True,
}

BASEDIR = os.path.abspath(os.path.dirname(__file__))

CLIENT_ID = "client_id"
CLIENT_SECRET = "a_longer_client_secret"
CLI1 = "https://client1.example.com/"


# Locally defined
def parse_login_hint_token(keyjar: KeyJar, login_hint_token: str, context=None) -> str:
    _jwt = JWT(keyjar)
    _info = _jwt.unpack(login_hint_token)
    # here comes the special knowledge
    _sub_id = _info.get("sub_id")
    _sub = ""
    if _sub_id:
        if _sub_id["format"] == "phone":
            _sub = "tel:" + _sub_id["phone"]
        elif _sub_id["format"] == "mail":
            _sub = "mail:" + _sub_id["mail"]

        if _sub and context and context.login_hint_lookup:
            try:
                _sub = context.login_hint_lookup(_sub)
            except KeyError:
                _sub = ""

    return _sub


SERVER_CONF = {
    "issuer": ISSUER,
    "httpc_params": {"verify": False, "timeout": 1},
    "capabilities": CAPABILITIES,
    "keys": {"uri_path": "jwks.json", "key_defs": KEYDEFS},
    "token_handler_args": {
        "jwks_file": "private/token_jwks.json",
        "code": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
        "token": {
            "class": "idpyoidc.server.token.jwt_token.JWTToken",
            "kwargs": {
                "lifetime": 3600,
                "base_claims": {"eduperson_scoped_affiliation": None},
                "add_claims_by_scope": True,
                "aud": ["https://example.org/appl"],
            },
        },
        "refresh": {
            "class": "idpyoidc.server.token.jwt_token.JWTToken",
            "kwargs": {
                "lifetime": 3600,
                "aud": ["https://example.org/appl"],
            },
        },
        "id_token": {
            "class": "idpyoidc.server.token.id_token.IDToken",
            "kwargs": {
                "base_claims": {
                    "email": {"essential": True},
                    "email_verified": {"essential": True},
                }
            },
        },
    },
    "endpoint": {
        "bc_authentication": {
            "path": "backchannel_authn",
            "class": BackChannelAuthentication,
            "kwargs": {
                "client_authn_method": [
                    "client_secret_basic",
                    "client_secret_post",
                    "client_secret_jwt",
                    "private_key_jwt",
                ],
                "parse_login_hint_token": {"func": parse_login_hint_token},
            },
        },
        "token": {"path": "token", "class": Token, "kwargs": {}},
    },
    "client_authn": verify_client,
    "authentication": {
        "anon": {
            "acr": INTERNETPROTOCOLPASSWORD,
            "class": "idpyoidc.server.user_authn.user.NoAuthn",
            "kwargs": {"user": "diana"},
        }
    },
    "template_dir": "template",
    "userinfo": {
        "class": user_info.UserInfo,
        "kwargs": {"db_file": "users.json"},
    },
    "session_params": SESSION_PARAMS,
}


class TestBCAEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        server = Server(OPConfiguration(SERVER_CONF, base_path=BASEDIR))
        self.endpoint_context = server.endpoint_context
        self.endpoint_context.cdb["client_1"] = {
            "client_secret": "hemligt",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "token_endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token", "code id_token", "id_token"],
        }
        self.endpoint = server.server_get("endpoint", "backchannel_authentication")
        self.token_endpoint = server.server_get("endpoint", "token")

        self.client_keyjar = build_keyjar(KEYDEFS)
        # Add servers keys
        self.client_keyjar.import_jwks(server.endpoint_context.keyjar.export_jwks(), ISSUER)
        # The only own key the client has a this point
        self.client_keyjar.add_symmetric("", CLIENT_SECRET, ["sig"])
        # Need to add the client_secret as a symmetric key bound to the client_id
        server.endpoint_context.keyjar.add_symmetric(CLIENT_ID, CLIENT_SECRET, ["sig"])
        server.endpoint_context.keyjar.import_jwks(self.client_keyjar.export_jwks(), CLIENT_ID)

        server.endpoint_context.cdb = {CLIENT_ID: {"client_secret": CLIENT_SECRET}}
        # login_hint
        server.endpoint_context.login_hint_lookup = init_service(
            {"class": "idpyoidc.server.login_hint.LoginHintLookup"}, None
        )
        # userinfo
        _userinfo = init_user_info(
            {
                "class": "idpyoidc.server.user_info.UserInfo",
                "kwargs": {"db_file": full_path("users.json")},
            },
            "",
        )
        server.endpoint_context.login_hint_lookup.userinfo = _userinfo
        self.session_manager = server.endpoint_context.session_manager

    def test_login_hint_token(self):
        _jwt = JWT(self.client_keyjar, iss=CLIENT_ID, sign_alg="HS256")
        _jwt.with_jti = True
        _assertion = _jwt.pack({"aud": [ISSUER]})

        _jwt = JWT(self.client_keyjar, iss=CLIENT_ID, sign_alg="ES256")
        _payload = {"sub_id": {"format": "phone", "phone": "+46907865000"}}
        _login_hint_token = _jwt.pack(_payload, aud=[ISSUER])

        request = {
            "client_assertion": _assertion,
            "client_assertion_type": JWT_BEARER,
            "scope": "openid email example-scope",
            "client_notification_token": "8d67dc78-7faa-4d41-aabd-67707b374255",
            "binding_message": "W4SCT",
            "login_hint_token": _login_hint_token,
        }

        req = AuthenticationRequest(**request)
        req = self.endpoint.parse_request(req.to_urlencoded(), verify_args={"mode": "ping"})
        assert req
        req_user = self.endpoint.do_request_user(req)
        assert req_user == "diana"

    def test_login_hint_token_jwt(self):
        _jwt = JWT(self.client_keyjar, iss=CLIENT_ID, sign_alg="HS256")
        _jwt.with_jti = True
        _assertion = _jwt.pack({"aud": [ISSUER]})

        _jwt = JWT(self.client_keyjar, iss=CLIENT_ID, sign_alg="ES256")
        _payload = {"sub_id": {"format": "phone", "phone": "+46907865000"}}
        _login_hint_token = _jwt.pack(_payload, aud=[ISSUER])

        _jwt = JWT(self.client_keyjar, iss=CLIENT_ID, sign_alg="ES256")
        _jwt.with_jti = True
        _request_payload = {
            "scope": "openid email example-scope",
            "client_notification_token": "8d67dc78-7faa-4d41-aabd-67707b374255",
            "binding_message": "W4SCT",
            "login_hint_token": _login_hint_token,
        }
        _request_object = _jwt.pack(_request_payload, aud=[ISSUER])

        request = {
            "client_assertion": _assertion,
            "client_assertion_type": JWT_BEARER,
            "request": _request_object,
        }

        req = AuthenticationRequest(**request)
        req = self.endpoint.parse_request(req.to_urlencoded())
        assert req
        req_user = self.endpoint.do_request_user(req)
        assert req_user == "diana"

    def test_id_token_hint(self):
        _jwt = JWT(self.client_keyjar, iss=CLIENT_ID, sign_alg="HS256")
        _jwt.with_jti = True
        _assertion = _jwt.pack({"aud": [ISSUER]})

        # The old ID token
        _idt_payload = {
            "sub": "Anna",
            "iss": ISSUER,
            "aud": [CLIENT_ID],
            "exp": utc_time_sans_frac() + 3600,
        }

        _id_token_hint = _jwt.pack(_idt_payload)

        request = {
            "client_assertion": _assertion,
            "client_assertion_type": JWT_BEARER,
            "scope": "openid email example-scope",
            "client_notification_token": "8d67dc78-7faa-4d41-aabd-67707b374255",
            "binding_message": "W4SCT",
            "id_token_hint": _id_token_hint,
        }

        req = AuthenticationRequest(**request)
        req = self.endpoint.parse_request(req.to_urlencoded())
        assert req
        # If ping mode
        assert "client_notification_token" in req
        req_user = self.endpoint.do_request_user(req)
        assert req_user == "Anna"

    def test_login_hint(self):
        _jwt = JWT(self.client_keyjar, iss=CLIENT_ID, sign_alg="HS256")
        _jwt.with_jti = True
        _assertion = _jwt.pack({"aud": [ISSUER]})

        request = {
            "client_assertion": _assertion,
            "client_assertion_type": JWT_BEARER,
            "scope": "openid email example-scope",
            "client_notification_token": "8d67dc78-7faa-4d41-aabd-67707b374255",
            "binding_message": "W4SCT",
            "login_hint": "mail:diana@example.org",
        }

        req = AuthenticationRequest(**request)
        req = self.endpoint.parse_request(req.to_urlencoded())
        assert req
        # If ping mode
        assert "client_notification_token" in req
        req_user = self.endpoint.do_request_user(req)
        assert req_user == "diana"

    def test_login_hint_and_id_token_hint(self):
        _jwt = JWT(self.client_keyjar, iss=CLIENT_ID, sign_alg="HS256")
        _jwt.with_jti = True
        _assertion = _jwt.pack({"aud": [ISSUER]})

        # The old ID token
        _idt_payload = {
            "sub": "Anna",
            "iss": ISSUER,
            "aud": [CLIENT_ID],
            "exp": utc_time_sans_frac() + 3600,
        }

        _id_token_hint = _jwt.pack(_idt_payload)

        request = {
            "client_assertion": _assertion,
            "client_assertion_type": JWT_BEARER,
            "scope": "openid email example-scope",
            "client_notification_token": "8d67dc78-7faa-4d41-aabd-67707b374255",
            "binding_message": "W4SCT",
            "login_hint": "mail:diana@example.org",
            "id_token_hint": _id_token_hint,
        }

        req = AuthenticationRequest(**request)
        req = self.endpoint.parse_request(req.to_urlencoded())
        assert "error" in req

    def test_ping_and_no_client_notification_token(self):
        _jwt = JWT(self.client_keyjar, iss=CLIENT_ID, sign_alg="HS256")
        _jwt.with_jti = True
        _assertion = _jwt.pack({"aud": [ISSUER]})

        request = {
            "client_assertion": _assertion,
            "client_assertion_type": JWT_BEARER,
            "scope": "openid email example-scope",
            "binding_message": "W4SCT",
            "login_hint": "mail:diana@example.org",
        }

        req = AuthenticationRequest(**request)
        req = self.endpoint.parse_request(req.to_urlencoded(), verify_args={"mode": "ping"})
        assert "error" in req

    def test_request_and_extra_parameter(self):
        _jwt = JWT(self.client_keyjar, iss=CLIENT_ID, sign_alg="HS256")
        _jwt.with_jti = True
        _assertion = _jwt.pack({"aud": [ISSUER]})

        _jwt = JWT(self.client_keyjar, iss=CLIENT_ID, sign_alg="ES256")
        _payload = {"sub_id": {"format": "phone", "phone": "+13302818004"}}
        _login_hint_token = _jwt.pack(_payload, aud=[ISSUER])

        _jwt = JWT(self.client_keyjar, iss=CLIENT_ID, sign_alg="ES256")
        _jwt.with_jti = True
        _request_payload = {
            "scope": "openid email example-scope",
            "client_notification_token": "8d67dc78-7faa-4d41-aabd-67707b374255",
            "binding_message": "W4SCT",
            "login_hint_token": _login_hint_token,
        }
        _request_object = _jwt.pack(_request_payload, aud=[ISSUER])

        request = {
            "scope": "openid email example-scope",
            "client_assertion": _assertion,
            "client_assertion_type": JWT_BEARER,
            "request": _request_object,
        }

        req = AuthenticationRequest(**request)
        req = self.endpoint.parse_request(req.to_urlencoded())
        assert "error" in req

    def _create_session(self, user_id, auth_req, sub_type="public", sector_identifier=""):
        if sector_identifier:
            authz_req = auth_req.copy()
            authz_req["sector_identifier_uri"] = sector_identifier
        else:
            authz_req = auth_req
        client_id = authz_req["client_id"]
        ae = create_authn_event(user_id)
        return self.session_manager.create_session(
            ae, authz_req, user_id, client_id=client_id, sub_type=sub_type
        )

    def test_login_hint_response(self):
        _jwt = JWT(self.client_keyjar, iss=CLIENT_ID, sign_alg="HS256")
        _jwt.with_jti = True
        _assertion = _jwt.pack({"aud": [ISSUER]})

        request = {
            "client_assertion": _assertion,
            "client_assertion_type": JWT_BEARER,
            "scope": "openid email example-scope",
            "client_notification_token": "8d67dc78-7faa-4d41-aabd-67707b374255",
            "binding_message": "W4SCT",
            "login_hint": "mail:diana@example.org",
        }

        req = AuthenticationRequest(**request)
        req = self.endpoint.parse_request(req.to_urlencoded())
        _info = self.endpoint.process_request(req)
        assert _info
        sid = self.session_manager.auth_req_id_map[_info["response_args"]["auth_req_id"]]
        _user_id, _client_id, _grant_id = self.session_manager.decrypt_session_id(sid)
        # Some time passes and the client authentication is successfully performed
        session_id_2 = self._create_session(_user_id, req)

        # token request comes in
        _jwt = JWT(self.client_keyjar, iss=CLIENT_ID, sign_alg="HS256")
        _jwt.with_jti = True
        _assertion = _jwt.pack({"aud": [ISSUER + "token"]})

        token_request = {
            "client_assertion": _assertion,
            "client_assertion_type": JWT_BEARER,
            "auth_req_id": _info["response_args"]["auth_req_id"],
            "grant_type": "urn:openid:params:grant-type:ciba",
        }
        _treq = TokenRequest(**token_request)
        _req = self.token_endpoint.parse_request(_treq.to_urlencoded())
        assert _req
        _info = self.token_endpoint.process_request(_req)
        assert _info
        assert set(_info["response_args"].keys()) == {
            "token_type",
            "scope",
            "access_token",
            "expires_in",
            "id_token",
        }


_dirname = os.path.dirname(os.path.abspath(__file__))

KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

CLI_KEY = init_key_jar(
    public_path="{}/pub_client.jwks".format(_dirname),
    private_path="{}/priv_client.jwks".format(_dirname),
    key_defs=KEYSPEC,
    issuer_id="client_id",
)


class TestBCAEndpointService(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        self.ciba = {"server": self._create_server(), "client": self._create_ciba_client()}

    def _create_server(self):
        server = Server(OPConfiguration(SERVER_CONF, base_path=BASEDIR))
        endpoint_context = server.endpoint_context
        endpoint_context.cdb["client_1"] = {
            "client_secret": "hemligt",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "token_endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token", "code id_token", "id_token"],
        }

        client_keyjar = build_keyjar(KEYDEFS)
        # Add servers keys
        client_keyjar.import_jwks(server.endpoint_context.keyjar.export_jwks(), ISSUER)
        # The only own key the client has a this point
        client_keyjar.add_symmetric("", CLIENT_SECRET, ["sig"])
        # Need to add the client_secret as a symmetric key bound to the client_id
        server.endpoint_context.keyjar.add_symmetric(CLIENT_ID, CLIENT_SECRET, ["sig"])
        server.endpoint_context.keyjar.import_jwks(client_keyjar.export_jwks(), CLIENT_ID)

        server.endpoint_context.cdb = {CLIENT_ID: {"client_secret": CLIENT_SECRET}}
        # login_hint
        server.endpoint_context.login_hint_lookup = init_service(
            {"class": "idpyoidc.server.login_hint.LoginHintLookup"}, None
        )
        # userinfo
        _userinfo = init_user_info(
            {
                "class": "idpyoidc.server.user_info.UserInfo",
                "kwargs": {"db_file": full_path("users.json")},
            },
            "",
        )
        server.endpoint_context.login_hint_lookup.userinfo = _userinfo
        return server

    def _create_ciba_client(self):
        config = {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "redirect_uris": ["https://example.com/cb"],
            "services": {
                "client_notification": {
                    "class": "idpyoidc.client.oidc.backchannel_authentication.ClientNotification",
                    "kwargs": {"conf": {"default_authn_method": "client_notification_authn"}},
                },
            },
            "client_authn_methods": {
                "client_notification_authn": "idpyoidc.client.oidc.backchannel_authentication.ClientNotificationAuthn"
            },
        }

        client = Client(keyjar=CLI_KEY, config=config, services=DEFAULT_OAUTH2_SERVICES)

        client.client_get("service_context").provider_info = {
            "client_notification_endpoint": "https://example.com/notify",
        }

        return client

    def _create_session(self, user_id, auth_req, sub_type="public", sector_identifier=""):
        if sector_identifier:
            authz_req = auth_req.copy()
            authz_req["sector_identifier_uri"] = sector_identifier
        else:
            authz_req = auth_req
        client_id = authz_req["client_id"]
        ae = create_authn_event(user_id)
        _session_manager = self.ciba["server"].endpoint_context.session_manager
        return _session_manager.create_session(
            ae, authz_req, user_id, client_id=client_id, sub_type=sub_type
        )

    def test_client_notification(self):
        _keyjar = self.ciba["server"].endpoint_context.keyjar
        _jwt = JWT(_keyjar, iss=CLIENT_ID, sign_alg="HS256")
        _jwt.with_jti = True
        _assertion = _jwt.pack({"aud": [ISSUER]})

        request = {
            "client_assertion": _assertion,
            "client_assertion_type": JWT_BEARER,
            "scope": "openid email example-scope",
            "client_notification_token": "8d67dc78-7faa-4d41-aabd-67707b374255",
            "binding_message": "W4SCT",
            "login_hint": "mail:diana@example.org",
        }

        _authn_endpoint = self.ciba["server"].server_get("endpoint", "backchannel_authentication")

        req = AuthenticationRequest(**request)
        req = _authn_endpoint.parse_request(req.to_urlencoded())
        _info = _authn_endpoint.process_request(req)
        assert _info

        _session_manager = self.ciba["server"].endpoint_context.session_manager
        sid = _session_manager.auth_req_id_map[_info["response_args"]["auth_req_id"]]
        _user_id, _client_id, _grant_id = _session_manager.decrypt_session_id(sid)

        # Some time passes and the client authentication is successfully performed
        # The interaction with the authentication device is not shown
        session_id_2 = self._create_session(_user_id, req)

        # Now it's time to send a client notification
        req_args = {
            "auth_req_id": _info["response_args"]["auth_req_id"],
            "client_notification_token": request["client_notification_token"],
        }

        _service = self.ciba["client"].client_get("service", "client_notification")
        _req_param = _service.get_request_parameters(request_args=req_args)
        assert _req_param
        assert isinstance(_req_param["request"], NotificationRequest)
        assert set(_req_param.keys()) == {"method", "request", "url", "body", "headers"}
        assert _req_param["method"] == "POST"
        # This is the client's notification endpoint
        assert (
            _req_param["url"]
            == self.ciba["client"]
            .client_get("service_context")
            .provider_info["client_notification_endpoint"]
        )
        assert set(_req_param["request"].keys()) == {"auth_req_id"}
