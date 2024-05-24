import json
import os

import pytest

from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.message.oidc import AccessTokenRequest
from idpyoidc.message.oidc import AuthorizationRequest
from idpyoidc.server import Server
from idpyoidc.server import user_info
from idpyoidc.server.authn_event import create_authn_event
from idpyoidc.server.configure import OPConfiguration
from idpyoidc.server.cookie_handler import CookieHandler
from idpyoidc.server.exception import BearerTokenAuthenticationError
from idpyoidc.server.exception import ImproperlyConfigured
from idpyoidc.server.oidc import userinfo
from idpyoidc.server.oidc.authorization import Authorization
from idpyoidc.server.oidc.provider_config import ProviderConfiguration
from idpyoidc.server.oidc.registration import Registration
from idpyoidc.server.oidc.token import Token
from idpyoidc.server.scopes import SCOPE2CLAIMS
from idpyoidc.server.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from idpyoidc.server.user_info import UserInfo
from idpyoidc.time_util import utc_time_sans_frac
from tests import CRYPT_CONFIG
from tests import SESSION_PARAMS

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

# RESPONSE_TYPES_SUPPORTED = [
#     ["code"],
#     ["id_token"],
#     ["code", "id_token"],
# ]

CAPABILITIES = {}

AUTH_REQ = AuthorizationRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    scope=["openid"],
    state="STATE",
    response_type="code",
)

TOKEN_REQ = AccessTokenRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    state="STATE",
    grant_type="authorization_code",
    client_secret="hemligt",
)

TOKEN_REQ_DICT = TOKEN_REQ.to_dict()

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


USERINFO = UserInfo(json.loads(open(full_path("users.json")).read()))


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        conf = {
            "issuer": "https://example.com/",
            "httpc_params": {"verify": False, "timeout": 1},
            "subject_types_supported": ["public", "pairwise", "ephemeral"],
            "claims_supported": [
                "address",
                "birthdate",
                "email",
                "email_verified",
                "eduperson_scoped_affiliation",
                "family_name",
                "gender",
                "given_name",
                "locale",
                "middle_name",
                "name",
                "nickname",
                "phone_number",
                "phone_number_verified",
                "picture",
                "preferred_username",
                "profile",
                "sub",
                "updated_at",
                "website",
                "zoneinfo",
            ],
            "grant_types_supported": [
                "authorization_code",
                "implicit",
                "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "refresh_token",
            ],
            "claim_types_supported": [
                "normal",
                "aggregated",
                "distributed",
            ],
            "cookie_handler": {
                "class": CookieHandler,
                "kwargs": {
                    "encrypter": CRYPT_CONFIG,
                    "name": {
                        "session": "oidc_op",
                        "register": "oidc_op_reg",
                        "session_management": "oidc_op_sman",
                    },
                },
            },
            "keys": {"uri_path": "jwks.json", "key_defs": KEYDEFS},
            "endpoint": {
                "provider_config": {
                    "path": ".well-known/openid-configuration",
                    "class": ProviderConfiguration,
                    "kwargs": {},
                },
                "registration": {
                    "path": "registration",
                    "class": Registration,
                    "kwargs": {},
                },
                "authorization": {
                    "path": "authorization",
                    "class": Authorization,
                    "kwargs": {},
                },
                "token": {
                    "path": "token",
                    "class": Token,
                    "kwargs": {
                        "client_authn_method": [
                            "client_secret_post",
                            "client_secret_basic",
                            "client_secret_jwt",
                            "private_key_jwt",
                        ]
                    },
                },
                "userinfo": {
                    "path": "userinfo",
                    "class": userinfo.UserInfo,
                    "kwargs": {
                        "client_authn_method": ["bearer_header", "bearer_body"],
                    },
                },
            },
            "userinfo": {
                "class": user_info.UserInfo,
                "kwargs": {"db_file": full_path("users.json")},
            },
            # "client_authn": verify_client,
            "authentication": {
                "anon": {
                    "acr": INTERNETPROTOCOLPASSWORD,
                    "class": "idpyoidc.server.user_authn.user.NoAuthn",
                    "kwargs": {"user": "diana"},
                },
                "mfa": {
                    "acr": "https://refeds.org/profile/mfa",
                    "class": "idpyoidc.server.user_authn.user.NoAuthn",
                    "kwargs": {"user": "diana"},
                },
            },
            "template_dir": "template",
            "scopes_to_claims": {
                **SCOPE2CLAIMS,
                "research_and_scholarship": [
                    "name",
                    "given_name",
                    "family_name",
                    "email",
                    "email_verified",
                    "sub",
                    "eduperson_scoped_affiliation",
                ],
            },
            "session_params": SESSION_PARAMS,
            "token_handler_args": {
                "code": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
                "token": {
                    "class": "idpyoidc.server.token.jwt_token.JWTToken",
                    "kwargs": {
                        "lifetime": 3600,
                        "add_claims_by_scope": True,
                        "aud": ["https://example.org/appl"],
                    },
                },
                "refresh": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
            },
        }
        self.server = Server(OPConfiguration(conf=conf, base_path=BASEDIR), cwd=BASEDIR)

        self.context = self.server.context
        self.context.cdb["client_1"] = {
            "client_secret": "hemligt",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "token_endpoint_auth_method": "client_secret_post",
            "response_types_supported": ["code", "code id_token", "id_token"],
            "allowed_scopes": [
                "openid",
                "profile",
                "email",
                "address",
                "phone",
                "offline_access",
                "research_and_scholarship",
            ],
        }
        self.endpoint = self.server.get_endpoint("userinfo")
        self.session_manager = self.context.session_manager
        self.user_id = "diana"

    def _create_session(self, auth_req, sub_type="public", sector_identifier="", authn_info=None):
        if sector_identifier:
            authz_req = auth_req.copy()
            authz_req["sector_identifier_uri"] = sector_identifier
        else:
            authz_req = auth_req
        client_id = authz_req["client_id"]
        ae = create_authn_event(self.user_id, authn_info=authn_info)
        return self.session_manager.create_session(
            ae, authz_req, self.user_id, client_id=client_id, sub_type=sub_type
        )

    def _mint_code(self, grant, session_id):
        # Constructing an authorization code is now done
        return grant.mint_token(
            session_id=session_id,
            context=self.endpoint.upstream_get("context"),
            token_class="authorization_code",
            token_handler=self.session_manager.token_handler["authorization_code"],
            expires_at=utc_time_sans_frac() + 300,  # 5 minutes from now
        )

    def _mint_token(self, token_class, grant, session_id, token_ref=None):
        _session_info = self.session_manager.get_session_info(session_id, grant=True)
        return grant.mint_token(
            session_id=session_id,
            context=self.endpoint.upstream_get("context"),
            token_class=token_class,
            token_handler=self.session_manager.token_handler[token_class],
            expires_at=utc_time_sans_frac() + 900,  # 15 minutes from now
            based_on=token_ref,  # Means the token (tok) was used to mint this token
        )

    def test_init(self):
        assert self.endpoint
        assert set(self.endpoint.upstream_get("context").provider_info["claims_supported"]) == {
            "address",
            "birthdate",
            "email",
            "email_verified",
            "eduperson_scoped_affiliation",
            "family_name",
            "gender",
            "given_name",
            "locale",
            "middle_name",
            "name",
            "nickname",
            "phone_number",
            "phone_number_verified",
            "picture",
            "preferred_username",
            "profile",
            "sub",
            "updated_at",
            "website",
            "zoneinfo",
        }

    def test_parse(self):
        session_id = self._create_session(AUTH_REQ)
        grant = self.session_manager[session_id]

        # Freestanding access token, not based on an authorization code
        access_token = self._mint_token("access_token", grant, session_id)
        http_info = {"headers": {"authorization": "Bearer {}".format(access_token.value)}}
        _req = self.endpoint.parse_request({}, http_info=http_info)
        assert set(_req.keys()) == {"client_id", "access_token"}
        assert _req["client_id"] == AUTH_REQ["client_id"]
        assert _req["access_token"] == access_token.value

    def test_parse_invalid_token(self):
        http_info = {"headers": {"authorization": "Bearer invalid"}}
        _req = self.endpoint.parse_request({}, http_info=http_info)
        assert _req["error"] == "invalid_token"

    def test_process_request(self):
        session_id = self._create_session(AUTH_REQ)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant, session_id)
        access_token = self._mint_token("access_token", grant, session_id, code)

        http_info = {"headers": {"authorization": "Bearer {}".format(access_token.value)}}

        _req = self.endpoint.parse_request({}, http_info=http_info)
        args = self.endpoint.process_request(_req, http_info=http_info)
        assert args

    def test_do_response(self):
        session_id = self._create_session(AUTH_REQ)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant, session_id)
        access_token = self._mint_token("access_token", grant, session_id, code)

        http_info = {"headers": {"authorization": "Bearer {}".format(access_token.value)}}
        _req = self.endpoint.parse_request({}, http_info=http_info)

        args = self.endpoint.process_request(_req)
        assert args
        res = self.endpoint.do_response(request=_req, **args)
        assert res

    def test_do_signed_response(self):
        self.endpoint.upstream_get("context").cdb["client_1"][
            "userinfo_signed_response_alg"
        ] = "ES256"

        session_id = self._create_session(AUTH_REQ)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant, session_id)
        access_token = self._mint_token("access_token", grant, session_id, code)

        http_info = {"headers": {"authorization": "Bearer {}".format(access_token.value)}}
        _req = self.endpoint.parse_request({}, http_info=http_info)

        args = self.endpoint.process_request(_req)
        assert args
        res = self.endpoint.do_response(request=_req, **args)
        assert res

    def test_scopes_to_claims(self):
        _auth_req = AUTH_REQ.copy()
        _auth_req["scope"] = ["openid", "research_and_scholarship"]

        session_id = self._create_session(_auth_req)
        grant = self.session_manager[session_id]
        grant.scope = _auth_req["scope"]
        access_token = self._mint_token("access_token", grant, session_id)

        self.endpoint.kwargs["add_claims_by_scope"] = True
        self.endpoint.upstream_get("context").claims_interface.add_claims_by_scope = True
        grant.claims = {
            "userinfo": self.endpoint.upstream_get("context").claims_interface.get_claims(
                session_id=session_id, scopes=_auth_req["scope"], claims_release_point="userinfo"
            )
        }

        http_info = {"headers": {"authorization": "Bearer {}".format(access_token.value)}}
        _req = self.endpoint.parse_request({}, http_info=http_info)
        args = self.endpoint.process_request(_req, http_info=http_info)

        assert set(args["response_args"].keys()) == {
            "eduperson_scoped_affiliation",
            "given_name",
            "email_verified",
            "email",
            "family_name",
            "name",
            "sub",
        }

    def test_scopes_to_claims_per_client(self):
        self.context.cdb["client_1"]["scopes_to_claims"] = {
            **SCOPE2CLAIMS,
            "research_and_scholarship_2": [
                "name",
                "given_name",
                "family_name",
                "email",
                "email_verified",
                "sub",
                "eduperson_scoped_affiliation",
            ],
        }
        self.context.cdb["client_1"]["allowed_scopes"] = list(
            self.context.cdb["client_1"]["scopes_to_claims"].keys()
        ) + ["aba"]

        _auth_req = AUTH_REQ.copy()
        _auth_req["scope"] = ["openid", "research_and_scholarship_2", "aba"]

        session_id = self._create_session(_auth_req)
        grant = self.session_manager[session_id]
        grant.scope = _auth_req["scope"]
        access_token = self._mint_token("access_token", grant, session_id)

        self.endpoint.kwargs["add_claims_by_scope"] = True
        self.endpoint.upstream_get("context").claims_interface.add_claims_by_scope = True
        grant.claims = {
            "userinfo": self.endpoint.upstream_get("context").claims_interface.get_claims(
                session_id=session_id, scopes=_auth_req["scope"], claims_release_point="userinfo"
            )
        }

        http_info = {"headers": {"authorization": "Bearer {}".format(access_token.value)}}
        _req = self.endpoint.parse_request({}, http_info=http_info)
        args = self.endpoint.process_request(_req, http_info=http_info)

        assert set(args["response_args"].keys()) == {
            "eduperson_scoped_affiliation",
            "given_name",
            "email_verified",
            "email",
            "family_name",
            "name",
            "sub",
        }

    def test_allowed_scopes(self):
        _context = self.endpoint.upstream_get("context")
        _context.scopes_handler.allowed_scopes = list(SCOPE2CLAIMS.keys())
        _auth_req = AUTH_REQ.copy()
        _auth_req["scope"] = ["openid", "research_and_scholarship"]

        session_id = self._create_session(_auth_req)
        grant = self.session_manager[session_id]
        access_token = self._mint_token("access_token", grant, session_id)

        self.endpoint.kwargs["add_claims_by_scope"] = True
        _context.claims_interface.add_claims_by_scope = True
        grant.claims = {
            "userinfo": _context.claims_interface.get_claims(
                session_id=session_id, scopes=_auth_req["scope"], claims_release_point="userinfo"
            )
        }

        http_info = {"headers": {"authorization": "Bearer {}".format(access_token.value)}}
        _req = self.endpoint.parse_request({}, http_info=http_info)
        args = self.endpoint.process_request(_req, http_info=http_info)

        assert set(args["response_args"].keys()) == {
            "eduperson_scoped_affiliation",
            "given_name",
            "email_verified",
            "email",
            "family_name",
            "name",
            "sub",
        }

    def test_allowed_scopes_per_client(self):
        self.context.cdb["client_1"]["scopes_to_claims"] = {
            **SCOPE2CLAIMS,
            "research_and_scholarship_2": [
                "name",
                "given_name",
                "family_name",
                "email",
                "email_verified",
                "sub",
                "eduperson_scoped_affiliation",
            ],
        }
        self.context.cdb["client_1"]["allowed_scopes"] = list(SCOPE2CLAIMS.keys())

        _auth_req = AUTH_REQ.copy()
        _auth_req["scope"] = ["openid", "research_and_scholarship_2"]

        session_id = self._create_session(_auth_req)
        grant = self.session_manager[session_id]
        access_token = self._mint_token("access_token", grant, session_id)

        self.endpoint.kwargs["add_claims_by_scope"] = True
        self.endpoint.upstream_get("context").claims_interface.add_claims_by_scope = True
        grant.claims = {
            "userinfo": self.endpoint.upstream_get("context").claims_interface.get_claims(
                session_id=session_id, scopes=_auth_req["scope"], claims_release_point="userinfo"
            )
        }

        http_info = {"headers": {"authorization": "Bearer {}".format(access_token.value)}}
        _req = self.endpoint.parse_request({}, http_info=http_info)
        args = self.endpoint.process_request(_req, http_info=http_info)

        assert set(args["response_args"].keys()) == {"sub"}

    def test_wrong_type_of_token(self):
        _auth_req = AUTH_REQ.copy()
        _auth_req["scope"] = ["openid", "research_and_scholarship"]

        session_id = self._create_session(_auth_req)
        grant = self.session_manager[session_id]
        refresh_token = self._mint_token("refresh_token", grant, session_id)

        http_info = {"headers": {"authorization": "Bearer {}".format(refresh_token.value)}}
        _req = self.endpoint.parse_request({}, http_info=http_info)
        args = self.endpoint.process_request(_req, http_info=http_info)

        assert isinstance(args, ResponseMessage)
        assert args["error_description"] == "Invalid Token"

    def test_invalid_token(self):
        _auth_req = AUTH_REQ.copy()
        _auth_req["scope"] = ["openid", "research_and_scholarship"]

        session_id = self._create_session(_auth_req)
        grant = self.session_manager[session_id]
        access_token = self._mint_token("access_token", grant, session_id)

        http_info = {"headers": {"authorization": "Bearer {}".format(access_token.value)}}
        _req = self.endpoint.parse_request({}, http_info=http_info)

        access_token.expires_at = utc_time_sans_frac() - 10
        args = self.endpoint.process_request(_req)

        assert isinstance(args, ResponseMessage)
        assert args["error_description"] == "Invalid Token"

    def test_invalid_token_2(self):
        _auth_req = AUTH_REQ.copy()
        _auth_req["scope"] = ["openid", "research_and_scholarship"]

        session_id = self._create_session(_auth_req)
        grant = self.session_manager[session_id]
        access_token = self._mint_token("access_token", grant, session_id)
        self.session_manager.flush()

        http_info = {"headers": {"authorization": "Bearer {}".format(access_token.value)}}
        _req = self.endpoint.parse_request({}, http_info=http_info)
        args = self.endpoint.process_request(_req)

        assert isinstance(args, ResponseMessage)
        assert args["error_description"] == "Invalid Token"

    def test_expired_token(self, monkeypatch):
        _auth_req = AUTH_REQ.copy()
        _auth_req["scope"] = ["openid", "research_and_scholarship"]

        session_id = self._create_session(_auth_req)
        grant = self.session_manager[session_id]
        access_token = self._mint_token("access_token", grant, session_id)

        http_info = {"headers": {"authorization": "Bearer {}".format(access_token.value)}}

        def mock():
            return utc_time_sans_frac() + access_token.expires_at + 1

        monkeypatch.setattr("idpyoidc.server.token.utc_time_sans_frac", mock)

        with pytest.raises(BearerTokenAuthenticationError):
            self.endpoint.parse_request({}, http_info=http_info)

    def test_userinfo_claims(self):
        _acr = "https://refeds.org/profile/mfa"
        _auth_req = AUTH_REQ.copy()
        _auth_req["claims"] = {"userinfo": {"acr": {"value": _acr}}}

        session_id = self._create_session(_auth_req, authn_info=_acr)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant, session_id)
        access_token = self._mint_token("access_token", grant, session_id, code)

        http_info = {"headers": {"authorization": "Bearer {}".format(access_token.value)}}
        _req = self.endpoint.parse_request({}, http_info=http_info)

        args = self.endpoint.process_request(_req)
        assert args
        res = self.endpoint.do_response(request=_req, **args)
        _response = json.loads(res["response"])
        assert _response["acr"] == _acr

    def test_userinfo_claims_acr_none(self):
        _acr = "https://refeds.org/profile/mfa"
        _auth_req = AUTH_REQ.copy()
        _auth_req["claims"] = {"userinfo": {"acr": None}}

        session_id = self._create_session(_auth_req, authn_info=_acr)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant, session_id)
        access_token = self._mint_token("access_token", grant, session_id, code)

        http_info = {"headers": {"authorization": "Bearer {}".format(access_token.value)}}
        _req = self.endpoint.parse_request({}, http_info=http_info)

        args = self.endpoint.process_request(_req)
        assert args
        res = self.endpoint.do_response(request=_req, **args)
        _response = json.loads(res["response"])
        assert _response["acr"] == _acr

    def test_userinfo_claims_post(self):
        _acr = "https://refeds.org/profile/mfa"
        _auth_req = AUTH_REQ.copy()
        _auth_req["claims"] = {"userinfo": {"acr": {"value": _acr}}}

        session_id = self._create_session(_auth_req, authn_info=_acr)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant, session_id)
        access_token = self._mint_token("access_token", grant, session_id, code)

        http_info = {"headers": {"authorization": "Bearer {}".format(access_token.value)}}
        _req = self.endpoint.parse_request({}, http_info=http_info)
        args = self.endpoint.process_request(_req)
        assert args
        res = self.endpoint.do_response(request=_req, **args)
        _response = json.loads(res["response"])
        assert _response["acr"] == _acr

    def test_process_request_absent_userinfo_conf(self):
        # consider to have a configuration without userinfo defined in
        ec = self.endpoint.upstream_get("context")
        ec.userinfo = None

        _auth_req = AUTH_REQ.copy()
        _auth_req["scope"] = ["openid", "email"]

        session_id = self._create_session(_auth_req)
        grant = self.session_manager[session_id]

        code = self._mint_code(grant, session_id)
        with pytest.raises(ImproperlyConfigured):
            self._mint_token("access_token", grant, session_id, code)

    def test_userinfo_policy(self):
        _auth_req = AUTH_REQ.copy()

        session_id = self._create_session(_auth_req)
        grant = self.session_manager[session_id]
        access_token = self._mint_token("access_token", grant, session_id)

        http_info = {"headers": {"authorization": "Bearer {}".format(access_token.value)}}

        def _custom_validate_userinfo_policy(request, token, response_info, **kwargs):
            return {"custom": "policy"}

        self.endpoint.config["policy"] = {}
        self.endpoint.config["policy"]["function"] = _custom_validate_userinfo_policy

        _req = self.endpoint.parse_request({}, http_info=http_info)
        args = self.endpoint.process_request(_req)
        assert args
        res = self.endpoint.do_response(request=_req, **args)
        _response = json.loads(res["response"])
        assert "custom" in _response

    def test_userinfo_policy_per_client(self):
        _auth_req = AUTH_REQ.copy()

        session_id = self._create_session(_auth_req)
        grant = self.session_manager[session_id]
        access_token = self._mint_token("access_token", grant, session_id)

        http_info = {"headers": {"authorization": "Bearer {}".format(access_token.value)}}

        def _custom_validate_userinfo_policy(request, token, response_info, **kwargs):
            return {"custom": "policy"}

        self.context.cdb["client_1"]["userinfo"] = {
            "policy": {"function": _custom_validate_userinfo_policy, "kwargs": {}}
        }

        _req = self.endpoint.parse_request({}, http_info=http_info)
        args = self.endpoint.process_request(_req)
        assert args
        res = self.endpoint.do_response(request=_req, **args)
        _response = json.loads(res["response"])
        assert "custom" in _response
