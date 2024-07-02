import json
import os

import pytest

from idpyoidc.message.oidc import OpenIDRequest
from idpyoidc.server import Server
from idpyoidc.server.authn_event import create_authn_event
from idpyoidc.server.configure import OPConfiguration
from idpyoidc.server.oidc import userinfo
from idpyoidc.server.oidc.authorization import Authorization
from idpyoidc.server.oidc.provider_config import ProviderConfiguration
from idpyoidc.server.oidc.registration import Registration
from idpyoidc.server.scopes import SCOPE2CLAIMS
from idpyoidc.server.session.claims import ClaimsInterface
from idpyoidc.server.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from idpyoidc.server.user_info import UserInfo
from tests import CRYPT_CONFIG
from tests import SESSION_PARAMS

CLAIMS = {
    "userinfo": {
        "given_name": {"essential": True},
        "nickname": None,
        "email": {"essential": True},
        "email_verified": {"essential": True},
        "picture": None,
        "http://example.info/claims/groups": {"value": "red"},
    },
    "id_token": {
        "auth_time": {"essential": True},
        "acr": {"values": ["urn:mace:incommon:iap:silver"]},
    },
}

CLAIMS_2 = {
    "userinfo": {
        "eduperson_scoped_affiliation": {"essential": True},
        "nickname": None,
        "email": {"essential": True},
        "email_verified": {"essential": True},
    }
}
CLIENT_ID = "client1"

OIDR = OpenIDRequest(
    response_type="code",
    client_id=CLIENT_ID,
    redirect_uri="http://example.com/authz",
    scope=["openid"],
    state="state000",
    claims=CLAIMS,
)

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

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


USERINFO_DB = json.loads(open(full_path("users.json")).read())

PROVIDER_INFO = {
    "claims_supported": [
        "auth_time",
        "acr",
        "given_name",
        "nickname",
        "email",
        "email_verified",
        "picture",
        "http://example.info/claims/groups",
    ]
}

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]


class TestCollectUserInfo:
    @pytest.fixture(autouse=True)
    def create_endpoint_context(self):
        conf = {
            "userinfo": {"class": UserInfo, "kwargs": {"db": USERINFO_DB}},
            "password": "we didn't start the fire",
            "issuer": "https://example.com/op",
            "token_handler_args": {
                "jwks_def": {
                    "private_path": "private/token_jwks.json",
                    "read_only": False,
                    "key_defs": [{"type": "oct", "bytes": "24", "use": ["enc"], "kid": "code"}],
                },
                "code": {"kwargs": {"lifetime": 600}},
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
                "id_token": {
                    "class": "idpyoidc.server.token.id_token.IDToken",
                    "kwargs": {
                        "base_claims": {
                            "email": None,
                            "email_verified": None,
                        },
                        "enable_claims_per_client": True,
                    },
                },
            },
            "endpoint": {
                "provider_config": {
                    "path": "{}/.well-known/openid-configuration",
                    "class": ProviderConfiguration,
                    "kwargs": {},
                },
                "registration": {
                    "path": "{}/registration",
                    "class": Registration,
                    "kwargs": {},
                },
                "authorization": {
                    "path": "{}/authorization",
                    "class": Authorization,
                    "kwargs": {
                        "response_types_supported": [" ".join(x) for x in RESPONSE_TYPES_SUPPORTED],
                        "response_modes_supported": [
                            "query",
                            "fragment",
                            "form_post",
                        ],
                        "claims_parameter_supported": True,
                        "request_parameter_supported": True,
                        "request_uri_parameter_supported": True,
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
                        "base_claims": {
                            "eduperson_scoped_affiliation": None,
                            "email": None,
                        },
                        "add_claims_by_scope": True,
                        "enable_claims_per_client": True,
                    },
                },
            },
            "keys": {
                "public_path": "jwks.json",
                "key_defs": KEYDEFS,
                "uri_path": "static/jwks.json",
            },
            "authentication": {
                "anon": {
                    "acr": INTERNETPROTOCOLPASSWORD,
                    "class": "idpyoidc.server.user_authn.user.NoAuthn",
                    "kwargs": {"user": "diana"},
                }
            },
            "template_dir": "template",
            "session_params": {"encrypter": SESSION_PARAMS},
        }

        server = Server(OPConfiguration(conf=conf, base_path=BASEDIR), cwd=BASEDIR)
        self.endpoint_context = server.context
        # Just has to be there
        self.endpoint_context.cdb[CLIENT_ID] = {
            "add_claims": {
                "always": {},
                "by_scope": {},
            },
            "allowed_scopes": ["openid", "profile", "email", "address", "phone", "offline_access"],
        }
        self.session_manager = self.endpoint_context.session_manager
        self.claims_interface = ClaimsInterface(server.unit_get)
        self.user_id = "diana"
        self.server = server

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

    def test_collect_user_info(self):
        _req = OIDR.copy()
        _req["claims"] = CLAIMS_2

        session_id = self._create_session(_req)

        _userinfo_restriction = self.claims_interface.get_claims(
            session_id=session_id, scopes=OIDR["scope"], claims_release_point="userinfo"
        )

        res = self.claims_interface.get_user_claims("diana", _userinfo_restriction, CLIENT_ID)

        assert res == {
            "eduperson_scoped_affiliation": ["staff@example.org"],
            "email": "diana@example.org",
            "nickname": "Dina",
            "email_verified": False,
        }

        _id_token_restriction = self.claims_interface.get_claims(
            session_id=session_id, scopes=OIDR["scope"], claims_release_point="id_token"
        )

        res = self.claims_interface.get_user_claims("diana", _id_token_restriction, CLIENT_ID)

        assert res == {
            "email": "diana@example.org",
            "email_verified": False,
        }

        _restriction = self.claims_interface.get_claims(
            session_id=session_id, scopes=OIDR["scope"], claims_release_point="introspection"
        )

        res = self.claims_interface.get_user_claims("diana", _restriction, CLIENT_ID)

        assert res == {}

    def test_collect_user_info_2(self):
        _req = OIDR.copy()
        _req["scope"] = "openid email address"
        del _req["claims"]

        session_id = self._create_session(_req)
        _uid, _cid, _gid = self.session_manager.decrypt_session_id(session_id)

        _userinfo_restriction = self.claims_interface.get_claims(
            session_id=session_id, scopes=_req["scope"], claims_release_point="userinfo"
        )

        res = self.claims_interface.get_user_claims("diana", _userinfo_restriction, CLIENT_ID)

        assert res == {
            "address": {
                "country": "Sweden",
                "locality": "Umeå",
                "postal_code": "SE-90187",
                "street_address": "Umeå Universitet",
            },
            "eduperson_scoped_affiliation": ["staff@example.org"],
            "email": "diana@example.org",
            "email_verified": False,
        }

    def test_collect_user_info_scope_not_supported_no_base_claims(self):
        _req = OIDR.copy()
        _req["scope"] = "openid email address"
        del _req["claims"]

        session_id = self._create_session(_req)
        _uid, _cid, _gid = self.session_manager.decrypt_session_id(session_id)

        _userinfo_endpoint = self.server.get_endpoint("userinfo")
        _userinfo_endpoint.kwargs["add_claims_by_scope"] = False
        _userinfo_endpoint.kwargs["enable_claims_per_client"] = False
        del _userinfo_endpoint.kwargs["base_claims"]

        _userinfo_restriction = self.claims_interface.get_claims(
            session_id=session_id, scopes=_req["scope"], claims_release_point="userinfo"
        )

        res = self.claims_interface.get_user_claims("diana", _userinfo_restriction, CLIENT_ID)

        assert res == {}

    def test_collect_user_info_enable_claims_per_client(self):
        _req = OIDR.copy()
        _req["scope"] = "openid email address"
        del _req["claims"]

        session_id = self._create_session(_req)
        _uid, _cid, _gid = self.session_manager.decrypt_session_id(session_id)

        _userinfo_endpoint = self.server.get_endpoint("userinfo")
        _userinfo_endpoint.kwargs["add_claims_by_scope"] = False
        _userinfo_endpoint.kwargs["enable_claims_per_client"] = True
        del _userinfo_endpoint.kwargs["base_claims"]

        self.endpoint_context.cdb[_req["client_id"]]["add_claims"]["always"]["userinfo"] = {
            "phone_number": None
        }

        _userinfo_restriction = self.claims_interface.get_claims(
            session_id=session_id, scopes=_req["scope"], claims_release_point="userinfo"
        )

        res = self.claims_interface.get_user_claims("diana", _userinfo_restriction, CLIENT_ID)

        assert res == {"phone_number": "+46907865000"}


class TestCollectUserInfoCustomScopes:
    @pytest.fixture
    def conf(self):
        return {
            "userinfo": {"class": UserInfo, "kwargs": {"db": USERINFO_DB}},
            "password": "we didn't start the fire",
            "issuer": "https://example.com/op",
            "claims_interface": {
                "class": "idpyoidc.server.session.claims.ClaimsInterface",
                "kwargs": {},
            },
            "endpoint": {
                "provider_config": {
                    "path": "{}/.well-known/openid-configuration",
                    "class": ProviderConfiguration,
                    "kwargs": {},
                },
                "registration": {
                    "path": "{}/registration",
                    "class": Registration,
                    "kwargs": {},
                },
                "authorization": {
                    "path": "{}/authorization",
                    "class": Authorization,
                    "kwargs": {
                        "response_types_supported": [" ".join(x) for x in RESPONSE_TYPES_SUPPORTED],
                        "response_modes_supported": [
                            "query",
                            "fragment",
                            "form_post",
                        ],
                        "claims_parameter_supported": True,
                        "request_parameter_supported": True,
                        "request_uri_parameter_supported": True,
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
                        "base_claims": {
                            "eduperson_scoped_affiliation": None,
                            "email": None,
                        },
                        "add_claims_by_scope": True,
                        "enable_claims_per_client": True,
                    },
                },
            },
            "scopes_to_claims": {
                "openid": ["sub"],
                "research_and_scholarship": [
                    "name",
                    "given_name",
                    "family_name",
                    "email",
                    "email_verified",
                    "sub",
                    "iss",
                    "eduperson_scoped_affiliation",
                ],
            },
            "keys": {
                "public_path": "jwks.json",
                "key_defs": KEYDEFS,
                "uri_path": "static/jwks.json",
            },
            "authentication": {
                "anon": {
                    "acr": INTERNETPROTOCOLPASSWORD,
                    "class": "idpyoidc.server.user_authn.user.NoAuthn",
                    "kwargs": {"user": "diana"},
                }
            },
            "template_dir": "template",
            "session_params": SESSION_PARAMS,
            "token_handler_args": {
                "code": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
                "token": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
                "refresh": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
            },
        }

    @pytest.fixture(autouse=True)
    def create_endpoint_context(self, conf):
        self.server = Server(conf)
        self.endpoint_context = self.server.context
        self.endpoint_context.cdb[CLIENT_ID] = {
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
        self.session_manager = self.endpoint_context.session_manager
        self.claims_interface = ClaimsInterface(self.server.unit_get)
        self.user_id = "diana"

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

    # def _do_grant(self, auth_req):
    #     client_id = auth_req['client_id']
    #     # The user consent module produces a Grant instance
    #     grant = Grant(scope=auth_req['scope'], resources=[client_id])
    #
    #     # the grant is assigned to a session (user_id, client_id)
    #     self.session_manager.set([self.user_id, client_id, grant.id], grant)
    #     return session_key(self.user_id, client_id, grant.id)

    def test_collect_user_info_custom_scope(self):
        _req = OIDR.copy()
        _req["scope"] = "openid research_and_scholarship"
        del _req["claims"]

        session_id = self._create_session(_req)

        _restriction = self.claims_interface.get_claims(
            session_id=session_id, scopes=_req["scope"], claims_release_point="userinfo"
        )

        res = self.claims_interface.get_user_claims("diana", _restriction, CLIENT_ID)

        assert res == {
            "eduperson_scoped_affiliation": ["staff@example.org"],
            "email": "diana@example.org",
            "email_verified": False,
            "family_name": "Krall",
            "given_name": "Diana",
            "name": "Diana Krall",
        }

    def test_collect_user_info_scope_mapping_per_client(self, conf):
        conf["scopes_to_claims"] = SCOPE2CLAIMS
        server = Server(conf)
        endpoint_context = server.context
        self.session_manager = endpoint_context.session_manager
        claims_interface = endpoint_context.claims_interface
        endpoint_context.cdb[CLIENT_ID] = {
            "allowed_scopes": ["openid", "profile", "email", "address", "phone", "offline_access"]
        }

        _req = OIDR.copy()
        _req["scope"] = "openid research_and_scholarship"
        del _req["claims"]

        session_id = self._create_session(_req)

        _restriction = claims_interface.get_claims(
            session_id=session_id, scopes=_req["scope"], claims_release_point="userinfo"
        )

        res = claims_interface.get_user_claims("diana", _restriction, CLIENT_ID)
        assert res == {
            "eduperson_scoped_affiliation": ["staff@example.org"],
            "email": "diana@example.org",
        }
