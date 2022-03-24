import json
import os

from idpyoidc.message.oidc import OpenIDRequest
from idpyoidc.server.scopes import SCOPE2CLAIMS
from idpyoidc.server.scopes import convert_scopes2claims
from idpyoidc.server.session.claims import STANDARD_CLAIMS
from idpyoidc.server.user_info import UserInfo
from idpyoidc.server.user_info import dict_subset

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

OIDR = OpenIDRequest(
    response_type="code",
    client_id="client1",
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


def test_default_scope2claims():
    assert convert_scopes2claims(["openid"], STANDARD_CLAIMS) == {"sub": None}
    assert set(convert_scopes2claims(["profile"], STANDARD_CLAIMS).keys()) == {
        "name",
        "given_name",
        "family_name",
        "middle_name",
        "nickname",
        "profile",
        "picture",
        "website",
        "gender",
        "birthdate",
        "zoneinfo",
        "locale",
        "updated_at",
        "preferred_username",
    }
    assert set(convert_scopes2claims(["email"], STANDARD_CLAIMS).keys()) == {
        "email",
        "email_verified",
    }
    assert set(convert_scopes2claims(["address"], STANDARD_CLAIMS).keys()) == {"address"}
    assert set(convert_scopes2claims(["phone"], STANDARD_CLAIMS).keys()) == {
        "phone_number",
        "phone_number_verified",
    }
    assert convert_scopes2claims(["offline_access"], STANDARD_CLAIMS) == {}

    assert convert_scopes2claims(["openid", "email", "phone"], STANDARD_CLAIMS) == {
        "sub": None,
        "email": None,
        "email_verified": None,
        "phone_number": None,
        "phone_number_verified": None,
    }


def test_custom_scopes():
    custom_scopes = {
        "research_and_scholarship": [
            "name",
            "given_name",
            "family_name",
            "email",
            "email_verified",
            "sub",
            "iss",
            "eduperson_scoped_affiliation",
        ]
    }

    _scopes = SCOPE2CLAIMS.copy()
    _scopes.update(custom_scopes)
    _available_claims = STANDARD_CLAIMS[:]
    _available_claims.append("eduperson_scoped_affiliation")

    assert set(
        convert_scopes2claims(["email"], _available_claims, scope2claim_map=_scopes).keys()
    ) == {"email", "email_verified", }
    assert set(
        convert_scopes2claims(["address"], _available_claims, scope2claim_map=_scopes).keys()
    ) == {"address"}
    assert set(
        convert_scopes2claims(["phone"], _available_claims, scope2claim_map=_scopes).keys()
    ) == {"phone_number", "phone_number_verified", }

    assert set(
        convert_scopes2claims(
            ["research_and_scholarship"], _available_claims, scope2claim_map=_scopes
        ).keys()
    ) == {
               "name",
               "given_name",
               "family_name",
               "email",
               "email_verified",
               "sub",
               "eduperson_scoped_affiliation",
           }


def test_dict_subset_true():
    a = {"foo": 1, "bar": 2}

    assert dict_subset(a, {"foo": 1, "bar": 2, "xty": 3})
    assert dict_subset(a, {"foo": 1, "bar": [2, 3], "xty": 3})

    a = {"foo": [1, 3], "bar": 2}
    assert dict_subset(a, {"foo": [1, 3], "bar": [2, 3], "xty": 3})


def test_dict_subset_false():
    a = {"foo": 1, "bar": 2}

    assert dict_subset(a, {"foo": 1, "xty": 3}) is False
    assert dict_subset(a, {"foo": 1, "bar": [3, 4], "xty": 3}) is False

    a = {"foo": [1, 3], "bar": 2}
    assert dict_subset(a, {"foo": [2, 3], "bar": [2, 3]}) is False


def test_userinfo():
    ui = UserInfo()
    res = ui.filter(USERINFO_DB["diana"], CLAIMS["userinfo"])
    assert set(res.keys()) == {"given_name", "nickname", "email", "email_verified"}
