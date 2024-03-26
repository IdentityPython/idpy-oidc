import json
import os
import shutil

import pytest
from cryptojwt.jwt import utc_time_sans_frac
from cryptojwt.key_jar import init_key_jar

from idpyoidc.message.oidc import AccessTokenRequest
from idpyoidc.message.oidc import AuthorizationRequest
from idpyoidc.server import Server
from idpyoidc.server import user_info
from idpyoidc.server.authn_event import create_authn_event
from idpyoidc.server.authz import AuthzHandling
from idpyoidc.server.configure import OPConfiguration
from idpyoidc.server.oidc import userinfo
from idpyoidc.server.oidc.authorization import Authorization
from idpyoidc.server.oidc.provider_config import ProviderConfiguration
from idpyoidc.server.oidc.registration import Registration
from idpyoidc.server.oidc.token import Token
from idpyoidc.server.scopes import SCOPE2CLAIMS
from idpyoidc.server.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from idpyoidc.server.user_info import UserInfo
from tests import CRYPT_CONFIG
from tests import SESSION_PARAMS

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

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
    "subject_types_supported": ["public", "pairwise", "ephemeral"],
    "grant_types_supported": [
        "authorization_code",
        "implicit",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "refresh_token",
    ],
}

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

AUTH_REQ_2 = AuthorizationRequest(
    client_id="client_2",
    redirect_uri="https://two.example.com/cb",
    scope=["openid"],
    state="STATE",
    response_type="code",
)

TOKEN_REQ_2 = AccessTokenRequest(
    client_id="client_2",
    redirect_uri="https://two.example.com/cb",
    state="STATE",
    grant_type="authorization_code",
    client_secret="hemligt",
)

TOKEN_REQ_DICT = TOKEN_REQ.to_dict()

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


USERINFO = UserInfo(json.loads(open(full_path("users.json")).read()))

ENDPOINT_CONTEXT_CONFIG = {
    "issuer": "https://example.com/",
    "httpc_params": {"verify": False, "timeout": 1},
    "capabilities": CAPABILITIES,
    # "keys": {"uri_path": "jwks.json", "key_defs": KEYDEFS},
    "token_handler_args": {
        "jwks_file": "private/token_jwks.json",
        "code": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
        "token": {
            "class": "idpyoidc.server.token.jwt_token.JWTToken",
            "kwargs": {
                "lifetime": 3600,
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
        "id_token": {"class": "idpyoidc.server.token.id_token.IDToken", "kwargs": {}},
    },
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
                "claim_types_supported": [
                    "normal",
                    "aggregated",
                    "distributed",
                ],
                "client_authn_method": ["bearer_header"],
                "add_claims_by_scope": True,
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
        }
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
    "authz": {
        "class": AuthzHandling,
        "kwargs": {
            "grant_config": {
                "usage_rules": {
                    "authorization_code": {
                        "supports_minting": [
                            "access_token",
                            "refresh_token",
                            "id_token",
                        ],
                        "max_usage": 1,
                    },
                    "access_token": {},
                    "refresh_token": {
                        "supports_minting": ["access_token", "refresh_token"],
                    },
                },
                "expires_in": 43200,
            }
        },
    },
    "session_params": SESSION_PARAMS,
}


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        try:
            shutil.rmtree("db")
        except FileNotFoundError:
            pass

        # Both have to use the same keyjar
        _keyjar = init_key_jar(key_defs=KEYDEFS)
        _keyjar.import_jwks_as_json(
            _keyjar.export_jwks_as_json(True, ""), ENDPOINT_CONTEXT_CONFIG["issuer"]
        )
        server1 = Server(
            OPConfiguration(conf=ENDPOINT_CONTEXT_CONFIG, base_path=BASEDIR),
            cwd=BASEDIR,
            keyjar=_keyjar,
        )

        server2 = Server(
            OPConfiguration(conf=ENDPOINT_CONTEXT_CONFIG, base_path=BASEDIR),
            cwd=BASEDIR,
            keyjar=_keyjar,
        )
        # The top most part (Server class instance) is not

        server1.context.cdb = {
            "client_1": {
                "client_secret": "hemligt",
                "redirect_uris": [("https://example.com/cb", None)],
                "client_salt": "salted",
                "token_endpoint_auth_method": "client_secret_post",
                "response_types": ["code", "token", "code id_token", "id_token"],
                "allowed_scopes": [
                    "openid",
                    "profile",
                    "email",
                    "address",
                    "phone",
                    "offline_access",
                    "research_and_scholarship",
                ],
            },
            "client_2": {
                "client_secret": "hemligt_ord",
                "redirect_uris": [("https://two.example.com/cb", None)],
                "client_salt": "salted peanuts",
                "token_endpoint_auth_method": "client_secret_post",
                "response_types": ["code", "code id_token", "id_token"],
                "allowed_scopes": [
                    "openid",
                    "profile",
                    "email",
                    "address",
                    "phone",
                    "offline_access",
                    "research_and_scholarship",
                ]
            }
        }

        # make server2 endpoint context a copy of server 1 endpoint context
        _store = server1.context.dump()
        server2.context.load(
            _store,
            init_args={
                "upstream_get": server2.upstream_get,
                "handler": server2.context.session_manager.token_handler,
            },
        )
        server2.context.upstream_get = server2.unit_get

        self.endpoint = {
            1: server1.get_endpoint("userinfo"),
            2: server2.get_endpoint("userinfo"),
        }

        self.session_manager = {
            1: server1.context.session_manager,
            2: server2.context.session_manager,
        }
        self.context_unit_get = {
            1: server1.context.unit_get,
            2: server2.context.unit_get
        }
        self.user_id = "diana"

    def _create_session(self, auth_req, sub_type="public", sector_identifier="", index=1):
        if sector_identifier:
            authz_req = auth_req.copy()
            authz_req["sector_identifier_uri"] = sector_identifier
        else:
            authz_req = auth_req
        client_id = authz_req["client_id"]
        ae = create_authn_event(self.user_id)
        return self.session_manager[index].create_session(
            ae, authz_req, self.user_id, client_id=client_id, sub_type=sub_type
        )

    def _mint_code(self, grant, session_id, index=1):
        # Constructing an authorization code is now done
        _code = grant.mint_token(
            session_id,
            context=self.endpoint[index].upstream_get("context"),
            token_class="authorization_code",
            token_handler=self.session_manager[index].token_handler["authorization_code"],
        )

        self.session_manager[index].set(
            self.session_manager[index].decrypt_session_id(session_id), grant
        )

        return _code

    def _mint_access_token(self, grant, session_id, token_ref=None, index=1):
        _session_info = self.session_manager[index].get_session_info(
            session_id, client_session_info=True
        )

        _token = grant.mint_token(
            session_id=session_id,
            context=self.endpoint[index].upstream_get("context"),
            token_class="access_token",
            token_handler=self.session_manager[index].token_handler["access_token"],
            based_on=token_ref,  # Means the token (tok) was used to mint this token
        )

        self.session_manager[index].set([self.user_id, _session_info["client_id"], grant.id], grant)

        return _token

    def _dump_restore(self, fro, to):
        _store = self.session_manager[fro].dump()
        context_unit_get = self.endpoint[to].upstream_get("unit").context.unit_get
        self.session_manager[to].load(
            _store, init_args={"upstream_get": context_unit_get}
        )

    def test_init(self):
        assert self.endpoint[1]
        assert set(self.endpoint[1].upstream_get("context").provider_info["scopes_supported"]) == {
            "openid"
        }
        assert (
                self.endpoint[1].upstream_get("context").provider_info["claims_parameter_supported"]
                == self.endpoint[2].upstream_get("context").provider_info[
                    "claims_parameter_supported"]
        )

    def test_parse(self):
        session_id = self._create_session(AUTH_REQ, index=1)
        grant = self.endpoint[1].upstream_get("context").authz(session_id, AUTH_REQ)
        # grant, session_id = self._do_grant(AUTH_REQ, index=1)
        code = self._mint_code(grant, session_id, index=1)
        access_token = self._mint_access_token(grant, session_id, code, 1)

        # switch to another endpoint context instance

        self._dump_restore(1, 2)

        http_info = {"headers": {"authorization": "Bearer {}".format(access_token.value)}}
        _req = self.endpoint[2].parse_request({}, http_info=http_info)

        assert set(_req.keys()) == {"client_id", "access_token"}

    def test_process_request(self):
        session_id = self._create_session(AUTH_REQ, index=1)
        grant = self.endpoint[1].upstream_get("context").authz(session_id, AUTH_REQ)
        code = self._mint_code(grant, session_id, index=1)
        access_token = self._mint_access_token(grant, session_id, code, 1)

        self._dump_restore(1, 2)

        http_info = {"headers": {"authorization": "Bearer {}".format(access_token.value)}}
        _req = self.endpoint[2].parse_request({}, http_info=http_info)
        args = self.endpoint[2].process_request(_req)
        assert args

    def test_process_request_not_allowed(self):
        session_id = self._create_session(AUTH_REQ, index=2)
        grant = self.endpoint[2].upstream_get("context").authz(session_id, AUTH_REQ)
        code = self._mint_code(grant, session_id, index=2)
        access_token = self._mint_access_token(grant, session_id, code, 2)

        access_token.expires_at = utc_time_sans_frac() - 60
        self.session_manager[2].set([self.user_id, AUTH_REQ["client_id"], grant.id], grant)

        self._dump_restore(2, 1)

        http_info = {"headers": {"authorization": "Bearer {}".format(access_token.value)}}

        _req = self.endpoint[1].parse_request({}, http_info=http_info)

        args = self.endpoint[1].process_request(_req)
        assert set(args.keys()) == {"error", "error_description"}
        assert args["error"] == "invalid_token"

    # Don't test for offline_access right now. Should be expressed in supports_minting
    # def test_process_request_offline_access(self):
    #     auth_req = AUTH_REQ.copy()
    #     auth_req["scope"] = ["openid", "offline_access"]
    #     self._create_session(auth_req, index=2)
    #     grant, session_id = self._do_grant(auth_req, index=2)
    #     code = self._mint_code(grant, auth_req["client_id"], index=2)
    #     access_token = self._mint_access_token(grant, session_id, code, 2)
    #
    #     _req = self.endpoint[1].parse_request(
    #         {}, auth="Bearer {}".format(access_token.value)
    #     )
    #     args = self.endpoint[1].process_request(_req)
    #     assert set(args["response_args"].keys()) == {"sub"}

    def test_do_response(self):
        session_id = self._create_session(AUTH_REQ, index=2)
        grant = self.endpoint[2].upstream_get("context").authz(session_id, AUTH_REQ)
        code = self._mint_code(grant, session_id, index=2)
        access_token = self._mint_access_token(grant, session_id, code, 2)

        self._dump_restore(2, 1)

        http_info = {"headers": {"authorization": "Bearer {}".format(access_token.value)}}

        _req = self.endpoint[1].parse_request({}, http_info=http_info)
        args = self.endpoint[1].process_request(_req)
        assert args

        self._dump_restore(1, 2)

        res = self.endpoint[2].do_response(request=_req, **args)
        assert res

    def test_do_signed_response(self):
        self.endpoint[2].upstream_get("context").cdb["client_1"][
            "userinfo_signed_response_alg"
        ] = "ES256"

        session_id = self._create_session(AUTH_REQ, index=2)
        grant = self.endpoint[2].upstream_get("context").authz(session_id, AUTH_REQ)
        code = self._mint_code(grant, session_id, index=2)
        access_token = self._mint_access_token(grant, session_id, code, 2)

        self._dump_restore(2, 1)

        http_info = {"headers": {"authorization": "Bearer {}".format(access_token.value)}}

        _req = self.endpoint[1].parse_request({}, http_info=http_info)
        args = self.endpoint[1].process_request(_req)
        assert args
        res = self.endpoint[1].do_response(request=_req, **args)
        assert res

    def test_custom_scope(self):
        _auth_req = AUTH_REQ.copy()
        _auth_req["scope"] = ["openid", "research_and_scholarship"]

        session_id = self._create_session(_auth_req, index=2)
        grant = self.endpoint[2].upstream_get("context").authz(session_id, _auth_req)

        self._dump_restore(2, 1)

        grant.claims = {
            "userinfo": self.endpoint[1]
            .upstream_get("context")
            .claims_interface.get_claims(
                session_id, scopes=_auth_req["scope"], claims_release_point="userinfo"
            )
        }

        self._dump_restore(1, 2)

        self.session_manager[2].set(self.session_manager[2].decrypt_session_id(session_id), grant)

        code = self._mint_code(grant, session_id, index=2)
        access_token = self._mint_access_token(grant, session_id, code, 2)

        self._dump_restore(2, 1)

        http_info = {"headers": {"authorization": "Bearer {}".format(access_token.value)}}

        _req = self.endpoint[1].parse_request({}, http_info=http_info)
        args = self.endpoint[1].process_request(_req)
        assert set(args["response_args"].keys()) == {
            "sub",
            "name",
            "given_name",
            "family_name",
            "email",
            "email_verified",
            "eduperson_scoped_affiliation",
        }

    def test_sman_db_integrity(self):
        """
        this test assures that session database remains consistent after
            - many consecutives flush
            - deletion of key or salt
            - some mess with values overwritten runtime
        it show that flush and loads method will keep order, anyway.
        """
        session_id = self._create_session(AUTH_REQ, index=1)
        grant = self.endpoint[1].upstream_get("context").authz(session_id, AUTH_REQ)
        sman = self.session_manager[1]
        session_dump = sman.dump()

        # after an exception a database could be inconsistent
        # it would be better to always flush database when a new http request come
        # and load session from previously loaded sessions
        sman.flush()
        # yes, two times to simulate those things that happens in real world
        sman.flush()

        # check that a sman db schema is consistent after a flush
        tdump = sman.dump()
        for i in ["db", "crypt_config"]:
            if i not in tdump:
                raise ValueError(f"{i} not found in session dump after a flush!")

        # test that key and salt have not been touched after the flush
        # they wouldn't change runtime (even if they are randomic).
        if session_dump["crypt_config"] != tdump["crypt_config"]:
            raise ValueError(
                f"Inconsistent Session schema dump after a flush. "
                f"'crypt_config' has changed compared to which was configured."
            )

        # ok, load the session and assert that everything is in the right place
        # some mess before doing that
        sman.crypt_config = {"password": "ingoalla", "salt": "fantozzi"}

        # ok, end of the game, session have been loaded and all the things should finally be there!
        sman.load(session_dump)
        for i in "db", "crypt_config":
            assert session_dump[i] == sman.dump()[i]

    def _get_client_session_info(self, client_id, db):
        res = {}
        for key, info in db.items():
            val = self.session_manager[1].unpack_branch_key(key)
            if len(val) > 1 and val[1] == client_id:
                res[key] = info
                if val[0] not in res:
                    res[val[0]] = db[val[0]]

        return res

    def test_multiple_sessions(self):
        session_id = self._create_session(AUTH_REQ, index=1)
        grant = self.endpoint[1].upstream_get("context").authz(session_id, AUTH_REQ)
        code = self._mint_code(grant, session_id, index=1)
        access_token_1 = self._mint_access_token(grant, session_id, code, 1)

        session_id = self._create_session(AUTH_REQ_2, index=1)
        grant = self.endpoint[1].upstream_get("context").authz(session_id, AUTH_REQ_2)
        code = self._mint_code(grant, session_id, index=1)
        access_token_2 = self._mint_access_token(grant, session_id, code, 1)

        _session_state = self.session_manager[1].dump()
        _orig_db = _session_state["db"]
        _client_1_db = self._get_client_session_info('client_1', _orig_db)
        _session_state["db"] = _client_1_db

        self.session_manager[2].load(
            _session_state, init_args={"upstream_get": self.endpoint[2].upstream_get}
        )

        http_info = {"headers": {"authorization": "Bearer {}".format(access_token_1.value)}}
        _req = self.endpoint[2].parse_request({}, http_info=http_info)
        args = self.endpoint[2].process_request(_req)
        assert args["client_id"] == "client_1"

        # this should not work

        http_info = {"headers": {"authorization": "Bearer {}".format(access_token_2.value)}}
        _req = self.endpoint[2].parse_request({}, http_info=http_info)

        assert _req["error"] == "invalid_token"

        _token_info = self.session_manager[1].token_handler.info(access_token_2.value)
        sid = _token_info.get("sid")
        _path = self.session_manager[1].decrypt_branch_id(sid)

        _client_db = self._get_client_session_info(_path[1], _orig_db)
        _session_state["db"] = _client_db

        self.session_manager[2].load(
            _session_state, init_args={"upstream_get": self.endpoint[2].upstream_get}
        )

        http_info = {"headers": {"authorization": "Bearer {}".format(access_token_2.value)}}
        _req = self.endpoint[2].parse_request({}, http_info=http_info)
        args = self.endpoint[2].process_request(_req)
        assert args["client_id"] == "client_2"
