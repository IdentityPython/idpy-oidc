from cryptojwt.jwe.jwe import factory
from cryptojwt.key_jar import build_keyjar

from idpyoidc.client.oidc.utils import construct_request_uri
from idpyoidc.client.oidc.utils import request_object_encryption
from idpyoidc.client.service_context import ServiceContext
from idpyoidc.message.oidc import AuthorizationRequest

KEYSPEC = [
    {"type": "RSA", "use": ["enc"]},
    {"type": "EC", "crv": "P-256", "use": ["enc"]},
]

RECEIVER = "https://example.org/op"

KEYJAR = build_keyjar(KEYSPEC, issuer_id=RECEIVER)


def test_request_object_encryption():
    msg = AuthorizationRequest(
        state="ABCDE", redirect_uri="https://example.com/cb", response_type="code"
    )

    conf = {
        "redirect_uris": ["https://example.com/cli/authz_cb"],
        "client_id": "client_1",
        "client_secret": "abcdefghijklmnop",
    }
    service_context = ServiceContext(keyjar=KEYJAR, config=conf)
    _condition = service_context.work_environment
    _condition.set_usage("request_object_encryption_alg", "RSA1_5")
    _condition.set_usage("request_object_encryption_enc", "A128CBC-HS256")

    _jwe = request_object_encryption(msg.to_json(), service_context, KEYJAR, target=RECEIVER)
    assert _jwe

    _decryptor = factory(_jwe)

    assert _decryptor.jwt.verify_headers(alg="RSA1_5", enc="A128CBC-HS256")


def test_construct_request_uri():
    local_dir = "home"
    base_path = "https://example.com/"
    a, b = construct_request_uri(local_dir, base_path)
    assert a.startswith("home") and a.endswith(".jwt")
    d, f = a.split("/")
    assert b == "{}{}".format(base_path, f)
