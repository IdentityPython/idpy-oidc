import os

from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.jws.jws import factory
from cryptojwt.key_jar import init_key_jar
import pytest

from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.client.oauth2 import Client
from idpyoidc.key_import import store_under_other_id
from idpyoidc.message.oauth2 import AccessTokenRequest
from idpyoidc.message.oauth2 import AuthorizationRequest
from idpyoidc.server import Server
from idpyoidc.server import user_info
from idpyoidc.server.authn_event import create_authn_event
from idpyoidc.server.client_authn import verify_client
from idpyoidc.server.configure import OPConfiguration
from idpyoidc.server.oauth2.add_on.dpop import DPoPProof
from idpyoidc.server.oidc.authorization import Authorization
from idpyoidc.server.oidc.token import Token
from idpyoidc.server.oidc.userinfo import UserInfo
from idpyoidc.server.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from idpyoidc.time_util import utc_time_sans_frac
from tests import CRYPT_CONFIG
from tests import SESSION_PARAMS

_dirname = os.path.dirname(os.path.abspath(__file__))

DPOP_HEADER = (
    "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMz"
    "R0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFq"
    "SG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwia"
    "HRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjY"
    "yNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg"
)


def test_verify_header():
    _dpop = DPoPProof()
    assert _dpop.verify_header(DPOP_HEADER)
    assert set(_dpop.keys()) == {"typ", "alg", "jwk", "jti", "htm", "htu", "iat"}
    assert _dpop.verify() is None

    _dpop_dict = _dpop.to_dict()
    _dpop2 = DPoPProof().from_dict(_dpop_dict)
    assert isinstance(_dpop2.key, ECKey)

    ec_key = new_ec_key(crv="P-256")
    _dpop2.key = ec_key
    _dpop2["jwk"] = ec_key.to_dict()

    _header = _dpop2.create_header()

    _dpop3 = DPoPProof()
    assert _dpop3.verify_header(_header)
    # should have the same content as _dpop only the key is different

    assert _dpop["htm"] == _dpop3["htm"]


ISSUER = "https://example.com/"

KEYJAR = init_key_jar(key_defs=DEFAULT_KEY_DEFS, issuer_id=ISSUER)
KEYJAR = store_under_other_id(KEYJAR, ISSUER, "", True)

AUTH_REQ = AuthorizationRequest(
    scope=["openid"],
    response_type="code",
)

TOKEN_REQ = AccessTokenRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    state="STATE",
    grant_type="authorization_code",
    client_secret="hemligt",
)

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def create_client():
    config = {
        "client_id": "client_1",
        "client_secret": "a longesh password",
        "redirect_uris": ["https://example.com/cli/authz_cb"],
        "preference": {"response_types": ["code"]},
        "add_ons": {
            "dpop": {
                "function": "idpyoidc.client.oauth2.add_on.dpop.add_support",
                "kwargs": {"dpop_signing_alg_values_supported": ["ES256", "ES512"]},
            }
        },
        "client_authn_methods": {
            "dpop": {
                "class": "idpyoidc.client.oauth2.add_on.dpop.DPoPClientAuth",
                "kwargs": {}
            }
        }
    }

    services = {
        "discovery": {"class": "idpyoidc.client.oauth2.server_metadata.ServerMetadata"},
        "authorization": {"class": "idpyoidc.client.oauth2.authorization.Authorization"},
        "access_token": {"class": "idpyoidc.client.oauth2.access_token.AccessToken"},
        "refresh_access_token": {
            "class": "idpyoidc.client.oauth2.refresh_access_token.RefreshAccessToken"
        },
        "userinfo": {"class": "idpyoidc.client.oidc.userinfo.UserInfo"},
    }

    CLI_KEY = init_key_jar(
        public_path="{}/pub_client.jwks".format(_dirname),
        private_path="{}/priv_client.jwks".format(_dirname),
        key_defs=DEFAULT_KEY_DEFS,
        issuer_id="client_id",
    )

    client = Client(keyjar=CLI_KEY, config=config, services=services)

    client.get_context().provider_info = {
        "authorization_endpoint": "https://example.com/auth",
        "token_endpoint": "https://example.com/token",
        "dpop_signing_alg_values_supported": ["RS256", "ES256"],
        "userinfo_endpoint": "https://example.com/user",
    }

    return client


def create_server():
    RESPONSE_TYPES_SUPPORTED = [
        ["code"],
        ["id_token"],
        ["code", "id_token"],
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
        "claim_types_supported": ["normal", "aggregated", "distributed"],
        "claims_parameter_supported": True,
        "request_parameter_supported": True,
        # "request_uri_parameter_supported": True,
        "client_authn_methods": {
            "dpop": {
                "class": "idpyoidc.server.oauth2.add_on.dpop.DPoPClientAuth"
            }
        }
    }

    conf = {
        "issuer": ISSUER,
        "httpc_params": {"verify": False, "timeout": 1},
        "preference": CAPABILITIES,
        "add_on": {
            "dpop": {
                "function": "idpyoidc.server.oauth2.add_on.dpop.add_support",
                "kwargs": {"dpop_signing_alg_values_supported": ["ES256"]},
            },
        },
        "keys": {"uri_path": "jwks.json", "key_defs": DEFAULT_KEY_DEFS},
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
            "authorization": {
                "path": "{}/authorization",
                "class": Authorization,
                "kwargs": {},
            },
            "token": {
                "path": "{}/token",
                "class": Token,
                "kwargs": {"client_authn_method": ["client_secret_basic"]},
            },
            "user_info": {
                "path": "{}/user",
                "class": UserInfo,
                "kwargs": {"client_authn_method": ["dpop"]},
            },
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
    server = Server(OPConfiguration(conf, base_path=BASEDIR), keyjar=KEYJAR)
    return server


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_setup(self):
        self.server = create_server()
        self.user_id = "diana"
        self.token_endpoint = self.server.get_endpoint("token")
        self.user_info_endpoint = self.server.get_endpoint("userinfo")

        self.client = create_client()
        self.context = self.server.context
        self.context.cdb["client_1"] = self.client.context.prefers()
        self.session_manager = self.context.session_manager

        self.authz_service = self.client.get_service("authorization")

    def _create_session(self, auth_req, sub_type="public", sector_identifier=""):
        if sector_identifier:
            authz_req = auth_req.copy()
            authz_req["sector_identifier_uri"] = sector_identifier
        else:
            authz_req = auth_req
        client_id = authz_req["client_id"]
        ae = create_authn_event(self.user_id)
        return self.session_manager.create_session(
            ae, authz_req, self.user_id, client_id=client_id, sub_type=sub_type
        )

    def _mint_token(self, token_class, grant, session_id, based_on=None, **kwargs):
        # Constructing an authorization code is now done
        return grant.mint_token(
            session_id=session_id,
            context=self.token_endpoint.upstream_get("context"),
            token_class=token_class,
            token_handler=self.session_manager.token_handler.handler[token_class],
            expires_at=utc_time_sans_frac() + 300,  # 5 minutes from now
            based_on=based_on,
            **kwargs
        )

    def _access_token_request_response(self):
        # Authz
        auth_req = AUTH_REQ.copy()
        auth_req["client_id"] = self.client.client_id
        _redirect_uri = self.client.context.claims.get_preference("redirect_uris")[0]
        auth_req["redirect_uri"] = _redirect_uri
        _context = self.client.context
        auth_req["state"] = _context.cstate.create_state(iss=_context.get("issuer"))
        session_id = self._create_session(auth_req)
        # Consent handling
        grant = self.token_endpoint.upstream_get("endpoint_context").authz(session_id, auth_req)
        self.session_manager[session_id] = grant
        code = self._mint_token("authorization_code", grant, session_id)
        _context.cstate.update(auth_req["state"], auth_req)

        # Access token request from the RP
        token_serv = self.client.get_service("accesstoken")
        req_args = {
            "grant_type": "authorization_code",
            "code": code.value,
            "redirect_uri": _redirect_uri
        }
        req_info = token_serv.get_request_parameters(request_args=req_args, state=auth_req["state"])
        assert "headers" in req_info
        assert "dpop" in req_info["headers"]

        # On the OP's side
        req = self.token_endpoint.parse_request(
            req_args,
            http_info={"headers": req_info["headers"], "url": _redirect_uri, "method": "POST"})
        resp = self.token_endpoint.process_request(req)
        _context.cstate.update(auth_req["state"], resp["response_args"])
        return resp, auth_req["state"]

    def test_post_parse_request(self):
        # DPoP Access Token Request
        _response, state = self._access_token_request_response()
        assert "response_args" in _response

    def test_process_request(self):
        _response, state = self._access_token_request_response()

        # The RP creates the user info request
        _user_info_service = self.client.get_service("userinfo")
        _request = _user_info_service.get_request_parameters(state=state, authn_method="dpop")

        http_info = {
            "headers": _request["headers"],
            "method": _request["method"],
            "url": _request["url"]
        }

        assert set(http_info["headers"].keys()) == {"Authorization", "dpop"}
        assert http_info["headers"]["Authorization"].startswith("DPoP ")

        _jws = factory(http_info["headers"]["dpop"])
        _payload = _jws.jwt.payload()
        assert "htm" in _payload
        assert "htu" in _payload

        _req = self.user_info_endpoint.parse_request(request=_request, http_info=http_info)
        _resp = self.user_info_endpoint.process_request(_req)
        assert _resp["response_args"]
        assert "sub" in _resp["response_args"]
