import time
from urllib.parse import quote_plus

from idpyoidc.message.oidc import Claims
from idpyoidc.message.oidc.identity_assurance import ClaimsConstructor
from idpyoidc.message.oidc.identity_assurance import from_iso8601_2004_time
from idpyoidc.message.oidc.identity_assurance import IDAClaimsRequest
from idpyoidc.message.oidc.identity_assurance import to_iso8601_2004_time
from idpyoidc.message.oidc.identity_assurance import VerificationElement
from idpyoidc.message.oidc.identity_assurance import VerifiedClaims
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


def test_verified_claims():
    s = {
        "userinfo": {
            "verified_claims": {
                "claims": {"given_name": None, "family_name": None, "birthdate": None}
            }
        }
    }

    c = Claims(**s)
    assert "userinfo" in c


def test_verified_claims_2():
    s = {
        "verified_claims": {
            "verification": {
                "trust_framework": "trust_framework_example"
            },
            "claims": {
                "given_name": "Max",
                "family_name": "Meier"
            }
        }
    }

    vc = VerifiedClaims(**s['verified_claims'])
    vc.verify()
    assert set(vc.keys()) == {'verification', 'claims'}
    assert isinstance(vc["claims"], Claims)


def test_verfication_element_from_dict():
    d = {
        "verification": {"trust_framework": "eidas_ial_substantial"},
        "claims": {
            "given_name": "Max",
            "family_name": "Meier",
            "birthdate": "1956-01-28",
            "place_of_birth": {"country": "DE", "locality": "Musterstadt"},
            "nationality": "DE",
            "address": {
                "locality": "Maxstadt",
                "postal_code": "12344",
                "country": "DE",
                "street_address": "An der Sanddüne 22",
            },
        },
    }
    v = VerifiedClaims(**d)
    assert v


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


def test_userinfo_claims_request_5_1_1():
    userinfo_claims = {
        "userinfo": {
            "verified_claims": {
                "claims": {"given_name": None, "family_name": None, "birthdate": None}
            }
        }
    }

    icr = IDAClaimsRequest(**userinfo_claims["userinfo"])
    icr.verify()
    assert isinstance(icr["verified_claims"], VerifiedClaims)


def test_userinfo_claims_request_5_1_2():
    userinfo_claims = {
        "userinfo": {
            "verified_claims": {
                "claims": {
                    "given_name": {"essential": True},
                    "family_name": {"essential": True},
                    "birthdate": None,
                }
            }
        }
    }

    icr = IDAClaimsRequest(**userinfo_claims["userinfo"])
    icr.verify()
    assert isinstance(icr["verified_claims"], VerifiedClaims)


def test_userinfo_claims_request_5_1_3():
    userinfo_claims = {
        "userinfo": {
            "verified_claims": {
                "claims": {
                    "given_name": {
                        "essential": True,
                        "purpose": "To make communication look more personal",
                    },
                    "family_name": {"essential": True},
                    "birthdate": {"purpose": "To send you best wishes on your birthday"},
                }
            }
        }
    }

    icr = IDAClaimsRequest(**userinfo_claims["userinfo"])
    icr.verify()
    assert isinstance(icr["verified_claims"], VerifiedClaims)


def test_userinfo_claims_request_5_1_4():
    userinfo_claims = {"userinfo": {"verified_claims": {"claims": None}}}

    icr = IDAClaimsRequest(**userinfo_claims["userinfo"])
    icr.verify()
    assert isinstance(icr["verified_claims"], VerifiedClaims)


def test_userinfo_claims_request_5_2_1():
    verified_claims = {
        "verified_claims": {"verification": {"time": None, "evidence": None}, "claims": None}
    }

    icr = IDAClaimsRequest(**verified_claims)
    icr.verify()
    assert icr


def test_userinfo_claims_request_5_3_1():
    userinfo_claims = {
        "userinfo": {
            "verified_claims": {
                "verification": {
                    "trust_framework": "de_aml",
                    "evidence": [
                        {
                            "type": "document",
                            "method": "pipp",
                            "document_details": {"type": ["idcard", "passport"]},
                        }
                    ],
                },
            }
        }
    }

    icr = IDAClaimsRequest(**userinfo_claims["userinfo"])
    icr.verify()
    assert icr


def test_userinfo_claims_request_5_3_2():
    userinfo_claims = {
        "userinfo": {
            "verified_claims": {"verification": {"date": {"max_age": 63113852}}}
        }
    }

    icr = IDAClaimsRequest(**userinfo_claims["userinfo"])
    icr.verify()
    assert icr


def test_example_6_1():
    verified_claims = {
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
            "claims": {
                "given_name": "Max",
                "family_name": "Meier",
                "birthdate": "1956-01-28",
                "place_of_birth": {"country": "DE", "locality": "Musterstadt"},
                "nationality": "DE",
                "address": {
                    "locality": "Maxstadt",
                    "postal_code": "12344",
                    "country": "DE",
                    "street_address": "An der Sanddüne 22",
                },
            },
        }
    }

    vc = VerifiedClaims(**verified_claims["verified_claims"])
    vc.verify()
    assert vc["verification"]["trust_framework"] == "de_aml"
    assert vc["verification"]["evidence"][0]["type"] == "document"


def test_example_6_2():
    verified_claims = {
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
                            "document_type": "de_erp_replacement_idcard",
                            "issuer": {"name": "Stadt Augsburg", "country": "DE"},
                            "number": "53554554",
                            "date_of_issuance": "2012-04-23",
                            "date_of_expiry": "2022-04-22",
                        },
                    },
                    {
                        "type": "utility_bill",
                        "provider": {
                            "name": "Stadtwerke Musterstadt",
                            "country": "DE",
                            "region": "Thüringen",
                            "street_address": "Energiestrasse 33",
                        },
                        "date": "2013-01-31",
                    },
                ],
            },
            "claims": {
                "given_name": "Max",
                "family_name": "Meier",
                "birthdate": "1956-01-28",
                "place_of_birth": {"country": "DE", "locality": "Musterstadt"},
                "nationality": "DE",
                "address": {
                    "locality": "Maxstadt",
                    "postal_code": "12344",
                    "country": "DE",
                    "street_address": "An der Sanddüne 22",
                },
            },
        }
    }

    vc = VerifiedClaims(**verified_claims["verified_claims"])
    vc.verify()
    assert vc["verification"]["trust_framework"] == "de_aml"
    assert len(vc["verification"]["evidence"]) == 2

    evidence_types = [e["type"] for e in vc["verification"]["evidence"]]
    assert set(evidence_types) == {"document", "utility_bill"}


def test_example_6_3():
    verified_claims = {
        "verified_claims": {
            "verification": {"trust_framework": "eidas_ial_substantial"},
            "claims": {
                "given_name": "Max",
                "family_name": "Meier",
                "birthdate": "1956-01-28",
                "place_of_birth": {"country": "DE", "locality": "Musterstadt"},
                "nationality": "DE",
                "address": {
                    "locality": "Maxstadt",
                    "postal_code": "12344",
                    "country": "DE",
                    "street_address": "An der Sanddüne 22",
                },
            },
        }
    }

    vc = VerifiedClaims(**verified_claims["verified_claims"])
    vc.verify()
    assert vc["verification"]["trust_framework"] == "eidas_ial_substantial"


def test_example_6_4_2():
    userinfo_response = {
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

    vc = VerifiedClaims(**userinfo_response["verified_claims"])
    vc.verify()
    assert vc["verification"]["trust_framework"] == "de_aml"


def test_construct_5_2_1():
    _verification = ClaimsConstructor(VerificationElement)
    _verification["time"] = None
    _verification["evidence"] = None

    verified_claims = ClaimsConstructor("idpyoidc.message.oidc.identity_assurance.VerifiedClaims")
    verified_claims["verification"] = _verification
    verified_claims["claims"] = None

    _val = verified_claims.to_json()
    assert _val == '{"verification": {"time": null, "evidence": null}, "claims": null}'


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
                            "issuer": {
                                "name": "Stadt Augsburg",
                                "country": "DE"
                            },
                            "document_number": "53554554",
                            "date_of_issuance": "2010-03-23",
                            "date_of_expiry": "2020-03-22"
                        },
                        "attachments": [
                            {
                                "desc": "Front of id document",
                                "content_type": "image/png",
                                "content": "Wkd0bWFtVnlhWFI2Wlc0Mk16VER2RFUyY0RRMWFUbDBNelJ1TlRjd31dzdaM1pTQXJaWGRsTXpNZ2RETmxDZwo="
                            },
                            {
                                "desc": "Back of id document",
                                "content_type": "image/png",
                                "content": "iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAYAAABytg0kAADSFsjdkhjwhAABJRU5ErkJggg=="
                            }
                        ]
                    }
                ]
            },
            "claims": {
                "given_name": "Max",
                "family_name": "Mustermann",
                "birthdate": "1956-01-28"
            }
        }
    }

    vc = VerifiedClaims(**document["verified_claims"])
    vc.verify()
    assert len(vc['verification']['evidence'][0]['attachments']) == 2
    assert {type(a) for a in vc['verification']['evidence'][0]['attachments']} == {}


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
                            "issuer": {
                                "name": "Stadt Augsburg",
                                "country": "DE"
                            },
                            "document_number": "53554554",
                            "date_of_issuance": "2010-03-23",
                            "date_of_expiry": "2020-03-22"
                        },
                        "attachments": [
                            {
                                "desc": "Front of id document",
                                "digest": {
                                    "alg": "sha-256",
                                    "value": "qC1zE5AfxylOFLrCnOIURXJUvnZwSFe5uUj8t6hdQVM="
                                },
                                "url": "https://example.com/attachments/pGL9yz4hZQ",
                                "access_token": "ksj3n283dke",
                                "expires_in": 30
                            },
                            {
                                "desc": "Back of id document",
                                "digest": {
                                    "alg": "sha-256",
                                    "value": "2QcDeLJ/qeXJn4nP+v3nijMgxOBCT9WJaV0LjRS4aT8="
                                },
                                "url": "https://example.com/attachments/4Ag8IpOf95"
                            },
                            {
                                "desc": "Signed document",
                                "digest": {
                                    "alg": "sha-256",
                                    "value": "i3O7U79LiyKmmesIgULKT2Q8LAxNO0CpwJVcbepaYf8="
                                },
                                "url": "https://example.com/attachments/4Ag8IpOf95",
                                "access_token": null,
                                "expires_in": 30
                            }
                        ]
                    }
                ]
            },
            "claims": {
                "given_name": "Max",
                "family_name": "Mustermann",
                "birthdate": "1956-01-28"
            }
        }
    }
