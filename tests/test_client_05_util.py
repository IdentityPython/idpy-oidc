import json
from http.cookiejar import FileCookieJar
from http.cookies import SimpleCookie
from urllib.parse import parse_qs
from urllib.parse import urlsplit

import pytest

from idpyoidc.client.exception import WrongContentType
from idpyoidc.client.util import get_content_type
from idpyoidc.client.util import get_deserialization_method
from idpyoidc.client.util import get_http_body
from idpyoidc.client.util import get_http_url
from idpyoidc.client.util import set_cookie
from idpyoidc.client.util import unreserved
from idpyoidc.client.util import verify_header
from idpyoidc.constant import DEFAULT_POST_CONTENT_TYPE
from idpyoidc.constant import JSON_ENCODED
from idpyoidc.constant import URL_ENCODED
from idpyoidc.defaults import BASECHR
from idpyoidc.message.oauth2 import AuthorizationRequest


def test_unreserved():
    code_verifier = unreserved(36)
    assert len(code_verifier) == 36
    assert all([x in BASECHR for x in code_verifier])


def test_get_http_url():
    request = AuthorizationRequest(
        response_type="query",
        redirect_uri="https://rp.example.org",
        client_id="client",
        state="state",
    )
    _url = get_http_url("https://op.example.com/", request, method="GET")
    assert _url
    _p = urlsplit(_url)
    msg = parse_qs(_p.query)
    assert msg == {
        "client_id": ["client"],
        "redirect_uri": ["https://rp.example.org"],
        "response_type": ["query"],
        "state": ["state"],
    }


def test_get_http_body():
    request = AuthorizationRequest(
        response_type="query",
        redirect_uri="https://rp.example.org",
        client_id="client",
        state="state",
    )

    # default urlencoded
    _body = get_http_body(request)
    args = parse_qs(_body)
    assert set(args.keys()) == {"response_type", "redirect_uri", "client_id", "state"}

    _body = get_http_body(request, content_type=JSON_ENCODED)
    args = json.loads(_body)
    assert set(args.keys()) == {"response_type", "redirect_uri", "client_id", "state"}


def test_set_cookie():
    cookiejar = FileCookieJar()
    _cookie = {"value_0": "v_0", "value_1": "v_1", "value_2": "v_2"}
    c = SimpleCookie(_cookie)

    domain_0 = ".test_domain"
    domain_1 = "test_domain"
    max_age = "09 Feb 1994 22:23:32 GMT"
    path = "test/path"

    c["value_0"]["max-age"] = max_age
    c["value_0"]["domain"] = domain_0
    c["value_0"]["path"] = path
    c["value_1"]["domain"] = domain_1

    set_cookie(cookiejar, c)
    assert len(cookiejar) == 3
    k1 = cookiejar._cookies.get("test_domain")
    assert k1
    k2 = cookiejar._cookies.get(".test_domain")
    assert k2
    assert k1 != k2


def test_set_cookie_del():
    cookiejar = FileCookieJar()
    _cookie = {"value_0": "v_0"}
    c = SimpleCookie(_cookie)

    c["value_0"]["max-age"] = 0

    set_cookie(cookiejar, c)
    assert len(cookiejar) == 0


class FakeResponse:
    def __init__(self, header):
        self.headers = {"content-type": header}
        self.text = "TEST_RESPONSE"


def test_verify_header():
    json_header = "application/json"
    jwt_header = "application/jwt"
    default_header = DEFAULT_POST_CONTENT_TYPE
    plain_text_header = "text/plain"
    undefined_header = "undefined"

    assert verify_header(FakeResponse(json_header), "json") == "json"
    assert verify_header(FakeResponse(jwt_header), "json") == "jwt"
    assert verify_header(FakeResponse(jwt_header), "jwt") == "jwt"
    assert verify_header(FakeResponse(default_header), "urlencoded") == "urlencoded"
    assert verify_header(FakeResponse(plain_text_header), "urlencoded") == "urlencoded"
    assert verify_header(FakeResponse("text/html"), "txt")
    assert verify_header(FakeResponse("text/plain"), "txt")

    assert verify_header(FakeResponse(json_header), "") == "json"
    assert verify_header(FakeResponse(jwt_header), "") == "jwt"
    assert verify_header(FakeResponse(jwt_header), "") == "jwt"
    assert verify_header(FakeResponse(default_header), "") == "urlencoded"
    assert verify_header(FakeResponse(plain_text_header), "") == "txt"
    assert verify_header(FakeResponse("text/html"), "") == "txt"

    with pytest.raises(WrongContentType):
        verify_header(FakeResponse(json_header), "urlencoded")
        verify_header(FakeResponse(jwt_header), "urlencoded")
        verify_header(FakeResponse(default_header), "json")
        verify_header(FakeResponse(plain_text_header), "jwt")
        verify_header(FakeResponse(undefined_header), "json")

    with pytest.raises(ValueError):
        verify_header(FakeResponse(json_header), "undefined")


def test_get_deserialization_method_json():
    resp = FakeResponse("application/json")
    ctype = get_content_type(resp)
    assert get_deserialization_method(ctype) == "json"

    resp = FakeResponse("application/json; charset=utf-8")
    ctype = get_content_type(resp)
    assert get_deserialization_method(ctype) == "json"

    resp.headers["content-type"] = "application/jrd+json"
    ctype = get_content_type(resp)
    assert get_deserialization_method(ctype) == "json"

    resp.headers["content-type"] = "application/entity-statement+json"
    ctype = get_content_type(resp)
    assert get_deserialization_method(ctype) == "json"

def test_get_deserialization_method_jwt():
    resp = FakeResponse("application/jwt")
    ctype = get_content_type(resp)
    assert get_deserialization_method(ctype) == "jwt"


def test_get_deserialization_method_urlencoded():
    resp = FakeResponse(URL_ENCODED)
    ctype = get_content_type(resp)
    assert get_deserialization_method(ctype) == "urlencoded"


def test_get_deserialization_method_text():
    resp = FakeResponse("text/html")
    ctype = get_content_type(resp)
    assert get_deserialization_method(ctype) == ""

    resp = FakeResponse("text/plain")
    ctype = get_content_type(resp)
    assert get_deserialization_method(ctype) == ""
