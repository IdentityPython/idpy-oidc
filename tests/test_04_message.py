import json
from urllib.parse import parse_qs
from urllib.parse import urlparse

import pytest
from cryptojwt.exception import HeaderError
from cryptojwt.jwk.hmac import SYMKey
from cryptojwt.jwk.rsa import new_rsa_key
from cryptojwt.jws.exception import NoSuitableSigningKeys
from cryptojwt.key_bundle import KeyBundle
from cryptojwt.key_jar import KeyJar
from cryptojwt.key_jar import build_keyjar

from idpyoidc.exception import DecodeError
from idpyoidc.exception import MessageException
from idpyoidc.exception import OidcMsgError
from idpyoidc.key_import import store_under_other_id
from idpyoidc.message import OPTIONAL_LIST_OF_MESSAGES
from idpyoidc.message import OPTIONAL_LIST_OF_STRINGS
from idpyoidc.message import OPTIONAL_MESSAGE
from idpyoidc.message import REQUIRED_LIST_OF_STRINGS
from idpyoidc.message import SINGLE_OPTIONAL_INT
from idpyoidc.message import SINGLE_OPTIONAL_JSON
from idpyoidc.message import SINGLE_OPTIONAL_STRING
from idpyoidc.message import SINGLE_REQUIRED_STRING
from idpyoidc.message import json_deserializer
from idpyoidc.message import json_serializer
from idpyoidc.message import msg_ser
from idpyoidc.message import sp_sep_list_deserializer
from idpyoidc.message.oauth2 import Message

__author__ = "Roland Hedberg"

from idpyoidc.message.oauth2 import ResponseMessage

keys = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "RSA", "use": ["enc"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["enc"]},
]

keym = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "RSA", "use": ["sig"]},
    {"type": "RSA", "use": ["sig"]},
]

KEYJAR = build_keyjar(keys)

IKEYJAR = build_keyjar(keys)
IKEYJAR = store_under_other_id(IKEYJAR, "", "issuer", True)
del IKEYJAR[""]

KEYJARS = {}
for iss in ["A", "B", "C"]:
    _kj = build_keyjar(keym)
    _kj = store_under_other_id(_kj, "", iss, True)
    del _kj[""]
    KEYJARS[iss] = _kj


def url_compare(url1, url2):
    url1 = urlparse(url1)
    url2 = urlparse(url2)

    if url1.scheme != url2.scheme:
        return False
    if url1.netloc != url2.netloc:
        return False
    if url1.path != url2.path:
        return False
    if not query_string_compare(url1.query, url2.query):
        return False
    if not query_string_compare(url1.fragment, url2.fragment):
        return False

    return True


def query_string_compare(query_str1, query_str2):
    return parse_qs(query_str1) == parse_qs(query_str2)


def _eq(l1, l2):
    return set(l1) == set(l2)


def test_sp_sep_list_deserializer():
    vals = sp_sep_list_deserializer("foo bar zen")
    assert len(vals) == 3
    assert _eq(vals, ["foo", "bar", "zen"])

    vals = sp_sep_list_deserializer(["foo bar zen"])
    assert len(vals) == 3
    assert _eq(vals, ["foo", "bar", "zen"])


def test_json_serializer():
    val = json_serializer({"foo": ["bar", "stool"]})
    val_obj = json.loads(val)
    assert val_obj == {"foo": ["bar", "stool"]}


def test_json_deserializer():
    _dict = {"foo": ["bar", "stool"]}
    val = json_serializer(_dict)

    sdict = json_deserializer(val)
    assert _dict == sdict


class DummyMessage(Message):
    c_param = {
        "req_str": SINGLE_REQUIRED_STRING,
        "opt_str": SINGLE_OPTIONAL_STRING,
        "opt_int": SINGLE_OPTIONAL_INT,
        "opt_str_list": OPTIONAL_LIST_OF_STRINGS,
        "req_str_list": REQUIRED_LIST_OF_STRINGS,
        "opt_json": SINGLE_OPTIONAL_JSON,
    }


class TestMessage(object):
    def test_json_serialization(self):
        item = DummyMessage(
            req_str="Fair",
            opt_str="game",
            opt_int=9,
            opt_str_list=["one", "two"],
            req_str_list=["spike", "lee"],
            opt_json='{"ford": "green"}',
        )

        jso = item.serialize(method="json")
        item2 = DummyMessage().deserialize(jso, "json")
        assert _eq(
            item2.keys(),
            ["opt_str", "req_str", "opt_json", "req_str_list", "opt_str_list", "opt_int"],
        )

    def test_from_dict(self):
        _dict = {"req_str": "Fair", "req_str_list": ["spike", "lee"], "opt_int": 9}
        _msg = DummyMessage()
        _msg.from_dict(_dict)
        assert set(_msg.keys()) == set(_dict.keys())

    def test_from_dict_lang_tag_unknown_key(self):
        _dict = {
            "req_str": "Fair",
            "req_str_list": ["spike", "lee"],
            "opt_int": 9,
            "attribute#se": "value",
        }
        _msg = DummyMessage()
        _msg.from_dict(_dict)
        assert set(_msg.keys()) == set(_dict.keys())

    def test_from_dict_lang_tag(self):
        _dict = {"req_str#se": "Fair", "req_str_list": ["spike", "lee"], "opt_int": 9}
        _msg = DummyMessage()
        _msg.from_dict(_dict)
        assert set(_msg.keys()) == set(_dict.keys())

    def test_from_json(self):
        jso = '{"req_str": "Fair", "req_str_list": ["spike", "lee"], ' '"opt_int": 9}'
        item = DummyMessage().deserialize(jso, "json")

        assert _eq(item.keys(), ["req_str", "req_str_list", "opt_int"])
        assert item["opt_int"] == 9

    def test_single_optional(self):
        jso = '{"req_str": "Fair", "req_str_list": ["spike", "lee"], ' '"opt_int": [9, 10]}'
        with pytest.raises(ValueError):
            DummyMessage().deserialize(jso, "json")

    def test_extra_param(self):
        jso = '{"req_str": "Fair", "req_str_list": ["spike", "lee"], "extra": ' "" "" '"out"}'
        item = DummyMessage().deserialize(jso, "json")

        assert _eq(item.keys(), ["req_str", "req_str_list", "extra"])
        assert item["extra"] == "out"

    def test_to_from_jwt(self):
        item = DummyMessage(
            req_str="Fair",
            opt_str="game",
            opt_int=9,
            opt_str_list=["one", "two"],
            req_str_list=["spike", "lee"],
            opt_json='{"ford": "green"}',
        )
        keyjar = KeyJar()
        keyjar.add_symmetric("", b"A1B2C3D4E5F6G7H8")
        jws = item.to_jwt(key=keyjar.get_signing_key("oct"), algorithm="HS256")

        jitem = DummyMessage().from_jwt(jws, keyjar)

        assert _eq(
            jitem.keys(),
            ["opt_str", "req_str", "opt_json", "req_str_list", "opt_str_list", "opt_int"],
        )

    def test_to_from_jwe(self):
        msg = DummyMessage(
            req_str="Fair",
            opt_str="game",
            opt_int=9,
            opt_str_list=["one", "two"],
            req_str_list=["spike", "lee"],
            opt_json='{"ford": "green"}',
        )
        keys = [SYMKey(key="A1B2C3D4E5F6G7H8")]
        jwe = msg.to_jwe(keys, alg="A128KW", enc="A128CBC-HS256")

        jitem = DummyMessage().from_jwe(jwe, keys=keys)

        assert _eq(
            jitem.keys(),
            ["opt_str", "req_str", "opt_json", "req_str_list", "opt_str_list", "opt_int"],
        )

    def test_to_jwe_from_jwt(self):
        msg = DummyMessage(
            req_str="Fair",
            opt_str="game",
            opt_int=9,
            opt_str_list=["one", "two"],
            req_str_list=["spike", "lee"],
            opt_json='{"ford": "green"}',
        )
        keys = [SYMKey(key="A1B2C3D4E5F6G7H8")]
        jwe = msg.to_jwe(keys, alg="A128KW", enc="A128CBC-HS256")

        keyjar = KeyJar()
        keyjar.add_symmetric("", "A1B2C3D4E5F6G7H8")
        jitem = DummyMessage().from_jwt(jwe, keyjar)

        assert _eq(
            jitem.keys(),
            ["opt_str", "req_str", "opt_json", "req_str_list", "opt_str_list", "opt_int"],
        )

    def test_verify(self):
        _dict = {
            "req_str": "Fair",
            "opt_str": "game",
            "opt_int": 9,
            "opt_str_list": ["one", "two"],
            "req_str_list": ["spike", "lee"],
            "opt_json": '{"ford": "green"}',
        }

        cls = DummyMessage(**_dict)
        assert cls.verify()
        assert _eq(
            cls.keys(),
            ["opt_str", "req_str", "opt_json", "req_str_list", "opt_str_list", "opt_int"],
        )

        _dict = {
            "req_str": "Fair",
            "opt_str": "game",
            "opt_int": 9,
            "opt_str_list": ["one", "two"],
            "req_str_list": ["spike", "lee"],
            "opt_json": '{"ford": "green"}',
            "extra": "internal",
        }

        cls = DummyMessage(**_dict)
        assert cls.verify()
        assert _eq(
            cls.keys(),
            ["opt_str", "req_str", "extra", "opt_json", "req_str_list", "opt_str_list", "opt_int"],
        )

        _dict = {
            "req_str": "Fair",
            "opt_str": "game",
            "opt_int": 9,
            "opt_str_list": ["one", "two"],
            "req_str_list": ["spike", "lee"],
        }

        cls = DummyMessage(**_dict)
        cls.verify()
        assert _eq(cls.keys(), ["opt_str", "req_str", "req_str_list", "opt_str_list", "opt_int"])

    def test_request(self):
        req = DummyMessage(req_str="Fair", req_str_list=["game"]).request("http://example.com")
        assert url_compare(req, "http://example.com?req_str=Fair&req_str_list=game")

    def test_get(self):
        _dict = {
            "req_str": "Fair",
            "opt_str": "game",
            "opt_int": 9,
            "opt_str_list": ["one", "two"],
            "req_str_list": ["spike", "lee"],
            "opt_json": '{"ford": "green"}',
        }

        cls = DummyMessage(**_dict)

        assert cls.get("req_str") == "Fair"
        assert cls.get("opt_int", 8) == 9
        assert cls.get("missing") is None
        assert cls.get("missing", []) == []

    def test_int_instead_of_string(self):
        with pytest.raises(ValueError):
            DummyMessage(req_str=2, req_str_list=["foo"])


@pytest.mark.parametrize("keytype,alg", [("RSA", "RS256"), ("EC", "ES256")])
def test_to_jwt(keytype, alg):
    msg = Message(a="foo", b="bar", c="tjoho")
    _jwt = msg.to_jwt(KEYJAR.get_signing_key(keytype, ""), alg)
    msg1 = Message().from_jwt(_jwt, KEYJAR)
    assert msg1 == msg


@pytest.mark.parametrize(
    "keytype,alg,enc",
    [
        ("RSA", "RSA1_5", "A128CBC-HS256"),
        ("EC", "ECDH-ES", "A128GCM"),
    ],
)
def test_to_jwe(keytype, alg, enc):
    msg = Message(a="foo", b="bar", c="tjoho")
    _jwe = msg.to_jwe(KEYJAR.get_encrypt_key(keytype, ""), alg=alg, enc=enc)
    msg1 = Message().from_jwe(_jwe, KEYJAR.get_encrypt_key(keytype, ""))
    assert msg1 == msg


def test_to_dict_with_message_obj():
    content = Message(a={"a": {"foo": {"bar": [{"bat": []}]}}})
    _dict = content.to_dict()
    content_fixture = {"a": {"a": {"foo": {"bar": [{"bat": []}]}}}}
    assert _dict == content_fixture


def test_to_dict_with_raw_types():
    msg = Message(c_default=[])
    content_fixture = {"c_default": []}
    _dict = msg.to_dict()
    assert _dict == content_fixture


def test_msg_deserializer():
    class MsgMessage(Message):
        c_param = {
            "msg": OPTIONAL_MESSAGE,
            "opt_str": SINGLE_OPTIONAL_STRING,
        }

    _dict = {"req_str": "Fair", "req_str_list": ["spike", "lee"], "opt_int": 9}
    _msg = DummyMessage()
    _msg.from_dict(_dict)

    msg = MsgMessage()
    msg["msg"] = _msg
    msg["opt_str"] = "string"

    mjson = msg.to_json()
    mm = MsgMessage().from_json(mjson)

    assert mm["opt_str"] == "string"
    assert set(mm["msg"].keys()) == set(_msg.keys())


def test_msg_list_deserializer():
    class MsgMessage(Message):
        c_param = {
            "msgs": OPTIONAL_LIST_OF_MESSAGES,
            "opt_str": SINGLE_OPTIONAL_STRING,
        }

    _dict = {"req_str": "Fair", "req_str_list": ["spike", "lee"], "opt_int": 9}
    _msg = DummyMessage()
    _msg.from_dict(_dict)

    msg = MsgMessage()
    msg["msgs"] = [_msg]
    msg["opt_str"] = "string"

    mjson = msg.to_json()
    mm = MsgMessage().from_json(mjson)

    assert mm["opt_str"] == "string"
    assert len(mm["msgs"]) == 1
    assert set(mm["msgs"][0].keys()) == set(_msg.keys())


def test_msg_list_deserializer_dict():
    class MsgMessage(Message):
        c_param = {
            "msgs": OPTIONAL_LIST_OF_MESSAGES,
            "opt_str": SINGLE_OPTIONAL_STRING,
        }

    _dict = {"req_str": "Fair", "req_str_list": ["spike", "lee"], "opt_int": 9}

    msg = MsgMessage()
    msg["msgs"] = _dict
    msg["opt_str"] = "string"

    mjson = msg.to_json()
    mm = MsgMessage().from_json(mjson)

    assert mm["opt_str"] == "string"
    assert len(mm["msgs"]) == 1
    assert set(mm["msgs"][0].keys()) == set(_dict.keys())


def test_msg_list_deserializer_url():
    class MsgMessage(Message):
        c_param = {
            "msgs": OPTIONAL_LIST_OF_MESSAGES,
            "opt_str": SINGLE_OPTIONAL_STRING,
        }

    _dict = {"req_str": "Fair", "req_str_list": ["spike", "lee"], "opt_int": 9}

    _msg = DummyMessage(**_dict)

    msg = MsgMessage()
    with pytest.raises(DecodeError):
        msg["msgs"] = [_msg.to_urlencoded()]


def test_add_value():
    with pytest.raises(ValueError):
        DummyMessage(req_str=["1", "2"])


def test_type_check():
    d = DummyMessage()
    assert d._type_check(int, [1, 2], 3) == False
    assert d._type_check([int], [1, 2], [2, 3]) == False
    assert d._type_check([int], [1, 2], [2, 1])
    assert d._type_check(bool, True, None, True)


def test_json_type_error():
    val = '{"key":"A byte string"}'
    m = Message()
    m.from_json(val)
    assert "key" in m


@pytest.mark.parametrize(
    "keytype,alg,enc",
    [
        ("RSA", "RSA1_5", "A128CBC-HS256"),
        ("EC", "ECDH-ES", "A128GCM"),
    ],
)
def test_to_jwe(keytype, alg, enc):
    msg = Message(a="foo", b="bar", c="tjoho")
    _jwe = msg.to_jwe(KEYJAR.get_encrypt_key(keytype, ""), alg=alg, enc=enc)
    with pytest.raises(HeaderError):
        Message().from_jwt(_jwe, KEYJAR, encalg="RSA-OAEP", encenc=enc)
    with pytest.raises(HeaderError):
        Message().from_jwt(_jwe, KEYJAR, encenc="A256CBC-HS512", encalg=alg)


NEW_KEYJAR = KEYJAR.copy()
kb = KeyBundle()
k = new_rsa_key()
NEW_KID = k.kid
kb.append(k)
NEW_KEYJAR.add_kb("", kb)


def test_no_suitable_keys():
    keytype = "RSA"
    alg = "RS256"
    msg = Message(a="foo", b="bar", c="tjoho")
    _jwt = msg.to_jwt(NEW_KEYJAR.get_signing_key(keytype, "", kid=NEW_KID), alg)
    with pytest.raises(NoSuitableSigningKeys):
        Message().from_jwt(_jwt, KEYJAR)


def test_only_extras():
    m = DummyMessage(foo="bar", extra="value")
    assert m.only_extras()

    m["req_str"] = "string"
    assert m.only_extras() is False


def test_weed():
    m = DummyMessage(foo="bar", extra="value")
    m["req_str"] = "string"

    assert set(m.keys()) == {"req_str", "foo", "extra"}
    m.weed()
    assert set(m.keys()) == {"req_str"}


def test_msg_ser():
    assert msg_ser("a.b.c", "dict") == "a.b.c"
    with pytest.raises(MessageException):
        msg_ser([1, 2], "dict")
    with pytest.raises(OidcMsgError):
        msg_ser([1, 2], "list")


def test_error_description():
    msg = ResponseMessage(error="foobar", error_description="ÅÄÖ")
    with pytest.raises(ValueError):
        msg.verify()

    msg = ResponseMessage(error="foobar", error_description="abc\ndef")
    with pytest.raises(ValueError):
        msg.verify()

    msg = ResponseMessage(error="foobar", error_description="abc def")
    msg.verify()
