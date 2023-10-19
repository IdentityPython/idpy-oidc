import time
from urllib.parse import quote_plus

from idpyoidc.message.oidc.identity_assurance import VerificationElement
from idpyoidc.message.oidc.identity_assurance import VerifiedClaims
from idpyoidc.message.oidc.identity_assurance import from_iso8601_2004_time
from idpyoidc.message.oidc.identity_assurance import to_iso8601_2004_time
from idpyoidc.time_util import time_sans_frac


def test_time_stamp():
    now = time_sans_frac()
    iso = to_iso8601_2004_time()

    d = from_iso8601_2004_time(iso)

    assert now == d


def test_verification_element():
    ve = VerificationElement(trust_framework="TrustAreUs", time=time.time())
    ve_dict1 = ve.to_dict()

    ve = VerificationElement(trust_framework="TrustAreUs")
    ve["time"] = time.time()
    ve_dict2 = ve.to_dict()

    assert ve_dict1 == ve_dict2

    ve = VerificationElement().from_dict(ve_dict1)

    assert ve

    s = "2020-01-11T11:00:00+0100"
    ve_2 = VerificationElement(trust_framework="TrustAreUs")
    ve_2["time"] = s

    assert quote_plus("2020-01-11T11:00:00+0100") in ve_2.to_urlencoded()


def test_userinfo_response():
    resp = {
        "sub": "248289761001",
        "email": "janedoe@example.com",
        "email_verified": True,
        "verified_claims": {
            "verification": {
                "trust_framework": "de_aml",
                "time": "2012-04-23T18:25:43.511+01",
                "verification_process": "676q3636461467647q8498785747q487",
                "evidence": [
                    {
                        "type": "document",
                        "method": "pipp",
                        "document": {
                            "type": "idcard",
                            "issuer": {"name": "Stadt Augsburg", "country": "DE"},
                            "number": "53554554",
                            "date_of_issuance": "2012-04-23",
                            "date_of_expiry": "2022-04-22",
                        },
                    }
                ],
            },
            "claims": {"given_name": "Max", "family_name": "Meier", "birthdate": "1956-01-28"},
        },
    }

    v = VerifiedClaims(**resp["verified_claims"])
    assert v
    assert set(v.keys()) == {"verification", "claims"}

    _ver = v["verification"]
    assert isinstance(_ver, VerificationElement)

    assert set(_ver.keys()) == {"trust_framework", "time", "verification_process", "evidence"}
    _evidence = _ver["evidence"]
    assert len(_evidence) == 1
    _evidence_1 = _evidence[0]
    assert _evidence_1["type"] == "document"


def test_embedded_attachments():
    document = {
        "verified_claims": {
            "verification": {
                "trust_framework": "eidas",
                "assurance_level": "substantial",
                "evidence": [
                    {
                        "type": "document",
                        "method": "pipp",
                        "time": "2012-04-22T11:30Z",
                        "document_details": {
                            "type": "idcard",
                            "issuer": {"name": "Stadt Augsburg", "country": "DE"},
                            "document_number": "53554554",
                            "date_of_issuance": "2010-03-23",
                            "date_of_expiry": "2020-03-22",
                        },
                        "attachments": [
                            {
                                "desc": "Front of id document",
                                "content_type": "image/png",
                                "content": "Wkd0bWFtVnlhWFI2Wlc0Mk16VER2RFUyY0RRMWFUbDBNelJ1TlRjd31dzdaM1pTQXJaWGRsTXpNZ2RETmxDZwo=",
                            },
                            {
                                "desc": "Back of id document",
                                "content_type": "image/png",
                                "content": "iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAYAAABytg0kAADSFsjdkhjwhAABJRU5ErkJggg==",
                            },
                        ],
                    }
                ],
            },
            "claims": {"given_name": "Max", "family_name": "Mustermann", "birthdate": "1956-01-28"},
        }
    }

    vc = VerifiedClaims(**document["verified_claims"])
    vc.verify()
    assert len(vc["verification"]["evidence"][0]["attachments"]) == 2
    assert {a.__class__.__name__ for a in vc["verification"]["evidence"][0]["attachments"]} == {
        "EmbeddedAttachments"
    }


def test_external_attachments():
    doc = {
        "verified_claims": {
            "verification": {
                "trust_framework": "eidas",
                "assurance_level": "substantial",
                "evidence": [
                    {
                        "type": "document",
                        "method": "pipp",
                        "time": "2012-04-22T11:30Z",
                        "document_details": {
                            "type": "idcard",
                            "issuer": {"name": "Stadt Augsburg", "country": "DE"},
                            "document_number": "53554554",
                            "date_of_issuance": "2010-03-23",
                            "date_of_expiry": "2020-03-22",
                        },
                        "attachments": [
                            {
                                "desc": "Front of id document",
                                "digest": {
                                    "alg": "sha-256",
                                    "value": "qC1zE5AfxylOFLrCnOIURXJUvnZwSFe5uUj8t6hdQVM=",
                                },
                                "url": "https://example.com/attachments/pGL9yz4hZQ",
                                "access_token": "ksj3n283dke",
                                "expires_in": 30,
                            },
                            {
                                "desc": "Back of id document",
                                "digest": {
                                    "alg": "sha-256",
                                    "value": "2QcDeLJ/qeXJn4nP+v3nijMgxOBCT9WJaV0LjRS4aT8=",
                                },
                                "url": "https://example.com/attachments/4Ag8IpOf95",
                            },
                            {
                                "desc": "Signed document",
                                "digest": {
                                    "alg": "sha-256",
                                    "value": "i3O7U79LiyKmmesIgULKT2Q8LAxNO0CpwJVcbepaYf8=",
                                },
                                "url": "https://example.com/attachments/4Ag8IpOf95",
                                "expires_in": 30,
                            },
                        ],
                    }
                ],
            },
            "claims": {"given_name": "Max", "family_name": "Mustermann", "birthdate": "1956-01-28"},
        }
    }

    vc = VerifiedClaims(**doc["verified_claims"])
    vc.verify()
    assert len(vc["verification"]["evidence"][0]["attachments"]) == 3
    assert {a.__class__.__name__ for a in vc["verification"]["evidence"][0]["attachments"]} == {
        "ExternalAttachments"
    }
