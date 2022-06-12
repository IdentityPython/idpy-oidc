import json

from cryptojwt.jwt import JWT
from cryptojwt.key_jar import init_key_jar
import requests
import responses

from idpyoidc.client.oidc.add_on.identity_assurance import map_request
from idpyoidc.client.oidc.userinfo import collect_claim_sources
from idpyoidc.message.oidc.identity_assurance import Attachment
from idpyoidc.message.oidc.identity_assurance import Document
from idpyoidc.message.oidc.identity_assurance import DocumentDetails
from idpyoidc.message.oidc.identity_assurance import ElectronicRecord
from idpyoidc.message.oidc.identity_assurance import EndUser
from idpyoidc.message.oidc.identity_assurance import ExternalAttachment
from idpyoidc.message.oidc.identity_assurance import VerifiedClaim
from idpyoidc.message.oidc.identity_assurance import Vouch
from idpyoidc.message.oidc.identity_assurance import do_evidence
from idpyoidc.message.oidc.identity_assurance import do_verified_claims
from idpyoidc.message.oidc.identity_assurance import verify_attachments


def test_5_1_2_1():
    document_details = {
        "type": "idcard",
        "issuer": {
            "name": "Stadt Augsburg",
            "country": "DE"
        },
        "document_number": "53554554",
        "date_of_issuance": "2010-03-23",
        "date_of_expiry": "2020-03-22"
    }
    dd = DocumentDetails(**document_details)
    dd.verify()

    attachments = [
        {
            "desc": "Front of id document",
            "content_type": "image/png",
            "content":
                "Wkd0bWFtVnlhWFI2Wlc0Mk16VER2RFUyY0RRMWFUbDBNelJ1TlRjd31dzdaM1pTQXJaWGRsTXpNZ2RETmxDZwo=="
        },
        {
            "desc": "Back of id document",
            "content_type": "image/png",
            "content":
                "iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAYAAABytg0kAADSFsjdkhjwhAABJRU5ErkJggg=="
        }
    ]
    al = verify_attachments(attachments)
    assert len(al) == 2

    evidence = [
        {
            "type": "document",
            "method": "pipp",
            "time": "2012-04-22T11:30Z",
            "document_details": document_details,
            "attachments": attachments
        }
    ]
    evl = do_evidence(evidence)
    assert len(evl) == 1
    assert isinstance(evl[0], Document)
    _doc = evl[0]
    assert len(_doc["attachments"]) == 2
    assert isinstance(_doc["attachments"][0], Attachment)
    assert isinstance(_doc["attachments"][1], Attachment)

    info = {
        "verified_claims": {
            "verification": {
                "trust_framework": "eidas",
                "assurance_level": "substantial",
                "evidence": evidence
            },
            "claims": {
                "given_name": "Max",
                "family_name": "Mustermann",
                "birthdate": "1956-01-28"
            }
        }
    }

    vc = do_verified_claims(info)
    vc[0].verify()
    assert vc[0]
    assert isinstance(vc[0]["verification"]["evidence"][0], Document)


def test_5_1_2_2():
    msg = {
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
                                    "alg": "SHA-256",
                                    "value": "nVW19w6EVNWNQ8fmRCxrxqw4xLUs+T8eI0tpjZo820Bc"
                                },
                                "url": "https://example.com/attachments/pGL9yz4hZQ",
                                "access_token": "ksj3n283dke",
                                "expires_in": 30
                            },
                            {
                                "desc": "Back of id document",
                                "digest": {
                                    "alg": "SHA-256",
                                    "value": "2QcDeLJ/qeXJn4nP+v3nijMgxOBCT9WJaV0LjRS4aT8"
                                },
                                "url": "https://example.com/attachments/4Ag8IpOf95"
                            },
                            {
                                "desc": "Signed document",
                                "digest": {
                                    "alg": "SHA-256",
                                    "value": "i3O7U79LiyKmmesIgULKT2Q8LAxNO0CpwJVcbepaYf8"
                                },
                                "url": "https://example.com/attachments/4Ag8IpOf95",
                                "access_token": None,
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

    vc = VerifiedClaim(**msg["verified_claims"])
    vc.verify()
    assert vc
    assert isinstance(vc["verification"]["evidence"][0], Document)
    _document = vc["verification"]["evidence"][0]
    assert len(_document["attachments"]) == 3
    for _att in _document["attachments"]:
        assert isinstance(_att, ExternalAttachment)


def test_8_2():
    msg = {
        "verified_claims": {
            "verification": {
                "trust_framework": "uk_tfida",
                "assurance_level": "medium",
                "assurance_process": {
                    "policy": "gpg45",
                    "procedure": "m1b"
                },
                "time": "2021-05-11T14:29Z",
                "verification_process": "7675D80F-57E0-AB14-9543-26B41FC22",
                "evidence": [
                    {
                        "type": "document",
                        "validation_method": {
                            "type": "vpiruv",
                            "policy": "gpg45",
                            "procedure": "score_3"
                        },
                        "verification_method": {
                            "type": "pvp",
                            "policy": "gpg45",
                            "procedure": "score_3"
                        },
                        "time": "2021-04-09T14:12Z",
                        "document_details": {
                            "type": "driving_permit",
                            "personal_number": "MORGA753116SM9IJ",
                            "document_number": "MORGA753116SM9IJ35",
                            "serial_number": "ZG21000001",
                            "date_of_issuance": "2021-01-01",
                            "date_of_expiry": "2030-12-31",
                            "issuer": {
                                "name": "DVLA",
                                "country": "UK",
                                "country_code": "GBR",
                                "jurisdiction": "GB-GBN"
                            }
                        }
                    }
                ]
            },
            "claims": {
                "given_name": "Sarah",
                "family_name": "Meredyth",
                "birthdate": "1976-03-11",
                "place_of_birth": {
                    "country": "UK"
                },
                "address": {
                    "locality": "Edinburgh",
                    "postal_code": "EH1 9GP",
                    "country": "UK",
                    "street_address": "122 Burns Crescent"
                }
            }
        }
    }

    vc = VerifiedClaim(**msg["verified_claims"])
    vc.verify()
    assert vc
    assert isinstance(vc["verification"]["evidence"][0], Document)
    _document = vc["verification"]["evidence"][0]


def test_8_3():
    msg = {
        "verified_claims": {
            "verification": {
                "trust_framework": "de_aml",
                "time": "2012-04-23T18:25Z",
                "verification_process": "f24c6f-6d3f-4ec5-973e-b0d8506f3bc7",
                "evidence": [
                    {
                        "type": "document",
                        "method": "pipp",
                        "verifier": {
                            "organization": "Deutsche Post",
                            "txn": "1aa05779-0775-470f-a5c4-9f1f5e56cf06"
                        },
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
                        }
                    }
                ]
            },
            "claims": {
                "given_name": "Max",
                "family_name": "Meier",
                "birthdate": "1956-01-28",
                "place_of_birth": {
                    "country": "DE",
                    "locality": "Musterstadt"
                },
                "nationalities": [
                    "DE"
                ],
                "address": {
                    "locality": "Maxstadt",
                    "postal_code": "12344",
                    "country": "DE",
                    "street_address": "An der Weide 22"
                }
            }
        }
    }

    vc = VerifiedClaim(**msg["verified_claims"])
    vc.verify()
    assert vc
    assert isinstance(vc["verification"]["evidence"][0], Document)
    _document = vc["verification"]["evidence"][0]


def test_8_4():
    # Document with external attachments
    msg = {
        "verified_claims": {
            "verification": {
                "trust_framework": "de_aml",
                "time": "2012-04-23T18:25Z",
                "verification_process": "f24c6f-6d3f-4ec5-973e-b0d8506f3bc7",
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
                                    "alg": "SHA-256",
                                    "value": "n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="
                                },
                                "url": "https://example.com/attachments/pGL9yz4hZQ"
                            },
                            {
                                "desc": "Back of id document",
                                "digest": {
                                    "alg": "SHA-256",
                                    "value": "/WGgOvT3fYcPwh4F5+gGeAlcktgIz7O1wnnuBMdKyhM="
                                },
                                "url": "https://example.com/attachments/4Ag8IpOf95"
                            }
                        ]
                    }
                ]
            },
            "claims": {
                "given_name": "Max",
                "family_name": "Meier",
                "birthdate": "1956-01-28",
                "place_of_birth": {
                    "country": "DE",
                    "locality": "Musterstadt"
                },
                "nationalities": [
                    "DE"
                ],
                "address": {
                    "locality": "Maxstadt",
                    "postal_code": "12344",
                    "country": "DE",
                    "street_address": "An der Weide 22"
                }
            }
        }
    }

    vc = VerifiedClaim(**msg["verified_claims"])
    vc.verify()
    assert vc
    assert isinstance(vc["verification"]["evidence"][0], Document)
    _document = vc["verification"]["evidence"][0]


def test_8_5():
    # Document with other checks
    msg = {
        "verified_claims": {
            "verification": {
                "trust_framework": "uk_tfida",
                "assurance_level": "medium",
                "assurance_process": {
                    "policy": "gpg45",
                    "procedure": "m1b"
                },
                "time": "2021-05-11T14:29Z",
                "verification_process": "7675D80F-57E0-AB14-9543-26B41FC22",
                "evidence": [
                    {
                        "type": "document",
                        "validation_method": {
                            "type": "vpiruv",
                            "policy": "gpg45",
                            "procedure": "score_3"
                        },
                        "verification_method": {
                            "type": "pvr",
                            "policy": "gpg45",
                            "procedure": "score_3"
                        },
                        "time": "2021-04-09T14:12Z",
                        "document_details": {
                            "type": "driving_permit",
                            "personal_number": "MORGA753116SM9IJ",
                            "document_number": "MORGA753116SM9IJ35",
                            "serial_number": "ZG21000001",
                            "date_of_issuance": "2021-01-01",
                            "date_of_expiry": "2030-12-31",
                            "issuer": {
                                "name": "DVLA",
                                "country": "UK",
                                "country_code": "GBR",
                                "jurisdiction": "GB-GBN"
                            }
                        }
                    },
                    {
                        "type": "electronic_record",
                        "validation_method": {
                            "type": "data",
                            "policy": "gpg45",
                            "procedure": "score_2",
                            "status": "false_positive"
                        },
                        "time": "2021-04-09T14:12Z",
                        "record": {
                            "type": "death_register",
                            "source": {
                                "name": "General Register Office",
                                "street_address": "PO BOX 2",
                                "locality": "Southport",
                                "postal_code": "PR8 2JD",
                                "country": "UK",
                                "country_code": "GBR",
                                "jurisdiction": "GB-EAW"
                            }
                        }
                    }
                ]
            },
            "claims": {
                "given_name": "Sarah",
                "family_name": "Meredyth",
                "birthdate": "1976-03-11",
                "place_of_birth": {
                    "country": "UK"
                },
                "address": {
                    "locality": "Edinburgh",
                    "postal_code": "EH1 9GP",
                    "country": "UK",
                    "street_address": "122 Burns Crescent"
                }
            }
        }
    }

    vc = VerifiedClaim(**msg["verified_claims"])
    vc.verify()
    assert vc
    assert isinstance(vc["verification"]["evidence"][0], Document)
    _document = vc["verification"]["evidence"][0]


def test_8_6():
    # Utility statement with attachments
    msg = {
        "verified_claims": {
            "verification": {
                "trust_framework": "de_aml",
                "time": "2012-04-23T18:25Z",
                "verification_process": "513645-e44b-4951-942c-7091cf7d891d",
                "evidence": [
                    {
                        "type": "document",
                        "validation_method": {
                            "type": "vpip"
                        },
                        "time": "2021-04-09T14:12Z",
                        "document_details": {
                            "type": "utility_statement",
                            "date_of_issuance": "2013-01-31",
                            "issuer": {
                                "name": "Stadtwerke Musterstadt",
                                "country": "DE",
                                "region": "Niedersachsen",
                                "street_address": "Energiestrasse 33"
                            }
                        },
                        "attachments": [
                            {
                                "desc": "scan of bill",
                                "content_type": "application/pdf",
                                "content":
                                    "iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAYAAABytg0kAADSFsjdkhjwhAABJRU5ErkJggg=="
                            }
                        ]
                    }
                ]
            },
            "claims": {
                "given_name": "Max",
                "family_name": "Meier",
                "birthdate": "1956-01-28",
                "place_of_birth": {
                    "country": "DE",
                    "locality": "Musterstadt"
                },
                "nationalities": [
                    "DE"
                ],
                "address": {
                    "locality": "Maxstadt",
                    "postal_code": "12344",
                    "country": "DE",
                    "street_address": "An der Weide 22"
                }
            }
        }
    }

    vc = VerifiedClaim(**msg["verified_claims"])
    vc.verify()
    assert vc
    assert isinstance(vc["verification"]["evidence"][0], Document)
    _document = vc["verification"]["evidence"][0]


def test_8_7():
    # Document + utility statement
    msg = {
        "verified_claims": {
            "verification": {
                "trust_framework": "de_aml",
                "time": "2012-04-23T18:25Z",
                "verification_process": "513645-e44b-4951-942c-7091cf7d891d",
                "evidence": [
                    {
                        "type": "document",
                        "validation_method": {
                            "type": "vpip"
                        },
                        "verification_method": {
                            "type": "pvp"
                        },
                        "time": "2012-04-22T11:30Z",
                        "document_details": {
                            "type": "de_erp_replacement_idcard",
                            "issuer": {
                                "name": "Stadt Augsburg",
                                "country": "DE"
                            },
                            "document_number": "53554554",
                            "date_of_issuance": "2010-04-23",
                            "date_of_expiry": "2020-04-22"
                        }
                    },
                    {
                        "type": "document",
                        "validation_method": {
                            "type": "vpip"
                        },
                        "time": "2012-04-22T11:30Z",
                        "document_details": {
                            "type": "utility_statement",
                            "issuer": {
                                "name": "Stadtwerke Musterstadt",
                                "country": "DE",
                                "region": "Niedersachsen",
                                "street_address": "Energiestrasse 33"
                            },
                            "date_of_issuance": "2013-01-31"
                        }
                    }
                ]
            },
            "claims": {
                "given_name": "Max",
                "family_name": "Meier",
                "birthdate": "1956-01-28",
                "place_of_birth": {
                    "country": "DE",
                    "locality": "Musterstadt"
                },
                "nationalities": [
                    "DE"
                ],
                "address": {
                    "locality": "Maxstadt",
                    "postal_code": "12344",
                    "country": "DE",
                    "street_address": "An der Weide 22"
                }
            }
        }
    }

    vc = VerifiedClaim(**msg["verified_claims"])
    vc.verify()
    assert vc
    assert isinstance(vc["verification"]["evidence"][0], Document)
    _document = vc["verification"]["evidence"][0]


# def test_8_8():
#     # *********
#     msg = {}
#
#     vc = VerifiedClaim(**msg["verified_claims"])
#     vc.verify()
#     assert vc
#     assert isinstance(vc["verification"]["evidence"][0], Document)
#     _document = vc["verification"]["evidence"][0]


def test_8_9():
    # Notified eID system (eIDAS)
    msg = {
        "verified_claims": {
            "verification": {
                "trust_framework": "eidas",
                "assurance_level": "substantial"
            },
            "claims": {
                "given_name": "Max",
                "family_name": "Meier",
                "birthdate": "1956-01-28",
                "place_of_birth": {
                    "country": "DE",
                    "locality": "Musterstadt"
                },
                "nationalities": [
                    "DE"
                ]
            }
        }
    }

    vc = do_verified_claims(msg)
    assert len(vc) == 1
    vc[0].verify()
    assert vc[0]
    assert vc[0]["verification"]["trust_framework"] == 'eidas'


def test_8_10():
    # Electronic_record
    msg = {
        "verified_claims": {
            "verification": {
                "trust_framework": "se_bankid",
                "assurance_level": "al_2",
                "time": "2021-03-03T09:42Z",
                "verification_process": "4346D80F-57E0-4E26-9543-26B41FC22",
                "evidence": [
                    {
                        "type": "electronic_record",
                        "validation_method": {
                            "type": "data"
                        },
                        "verification_method": {
                            "type": "token"
                        },
                        "time": "2021-02-15T16:51Z",
                        "record": {
                            "type": "population_register",
                            "source": {
                                "name": "Skatteverket",
                                "country": "Sverige",
                                "country_code": "SWE"
                            },
                            "personal_number": "4901224131",
                            "created_at": "1979-01-22"
                        }
                    }
                ]
            },
            "claims": {
                "given_name": "Fredrik",
                "family_name": "Str&#246;mberg",
                "birthdate": "1979-01-22",
                "place_of_birth": {
                    "country": "SWE",
                    "locality": "&#214;rnsk&#246;ldsvik"
                },
                "nationalities": [
                    "SE"
                ],
                "address": {
                    "locality": "Karlstad",
                    "postal_code": "65344",
                    "country": "SWE",
                    "street_address": "Gatunamn 221b"
                }
            }
        }
    }

    vc = do_verified_claims(msg)
    assert len(vc) == 1
    vc[0].verify()
    assert vc[0]
    assert isinstance(vc[0]["verification"]["evidence"][0], ElectronicRecord)


def test_8_11():
    # Vouch
    msg = {
        "verified_claims": {
            "verification": {
                "trust_framework": "uk_tfida",
                "assurance_level": "very_high",
                "time": "2020-03-19T13:05Z",
                "verification_process": "76755DA2-81E1-5N14-9543-26B415B77",
                "evidence": [
                    {
                        "type": "vouch",
                        "validation_method": {
                            "type": "vcrypt"
                        },
                        "verification_method": {
                            "type": "bvr"
                        },
                        "time": "2020-03-19T12:42Z",
                        "attestation": {
                            "type": "digital_attestation",
                            "reference_number": "6485-1619-3976-6671",
                            "date_of_issuance": "2021-06-04",
                            "voucher": {
                                "organization": "HMP Dartmoor"
                            }
                        }
                    }
                ]
            },
            "claims": {
                "given_name": "Sam",
                "family_name": "Lawler",
                "birthdate": "1981-04-13",
                "place_of_birth": {
                    "country": "GBR"
                },
                "address": {
                    "postal_code": "98015",
                    "country": "Monaco"
                }
            }
        }
    }

    vc = do_verified_claims(msg)
    assert len(vc) == 1
    vc[0].verify()
    assert vc[0]
    assert isinstance(vc[0]["verification"]["evidence"][0], Vouch)


def test_8_12():
    # Vouch with embedded attachments
    msg = {
        "verified_claims": {
            "verification": {
                "trust_framework": "uk_tfida",
                "assurance_level": "high",
                "assurance_process": {
                    "policy": "gpg45",
                    "procedure": "h1b"
                },
                "time": "2020-09-23T14:12Z",
                "verification_process": "99476DA2-ACDC-5N13-10WC-26B415B52",
                "evidence": [
                    {
                        "type": "vouch",
                        "validation_method": {
                            "type": "vpip",
                            "policy": "gpg45",
                            "procedure": "score_3"
                        },
                        "verification_method": {
                            "type": "pvr",
                            "policy": "gpg45",
                            "procedure": "score_3"
                        },
                        "time": "2020-02-23T07:52Z",
                        "attestation": {
                            "type": "written_attestation",
                            "reference_number": "6485-1619-3976-6671",
                            "date_of_issuance": "2020-02-13",
                            "voucher": {
                                "given_name": "Peter",
                                "family_name": "Crowe",
                                "occupation": "Executive Principal",
                                "organization": "Kristin School"
                            }
                        },
                        "attachments": [
                            {
                                "desc": "scan of vouch",
                                "content_type": "application/pdf",
                                "content":
                                    "d16d2552e35582810e5a40e523716504525b6016ae96844ddc533163059b3067=="
                            }
                        ]
                    }
                ]
            },
            "claims": {
                "given_name": "Megan",
                "family_name": "Howard",
                "birthdate": "2000-01-31",
                "place_of_birth": {
                    "country": "NZL"
                },
                "address": {
                    "locality": "Croydon",
                    "country": "UK",
                    "street_address": "69 Kidderminster Road"
                }
            }
        }
    }

    vc = do_verified_claims(msg)
    assert len(vc) == 1
    vc[0].verify()
    assert vc[0]
    assert isinstance(vc[0]["verification"]["evidence"][0], Vouch)
    _vouch = vc[0]["verification"]["evidence"][0]
    assert len(_vouch["attachments"]) == 1
    assert isinstance(_vouch["attachments"][0], Attachment)
    assert _vouch["attachments"][0]["content_type"] == "application/pdf"


def test_8_13():
    # Document with validation and verification details
    msg = {
        "verified_claims": {
            "verification": {
                "trust_framework": "it_spid",
                "time": "2019-04-20T20:16Z",
                "verification_process": "b54c6f-6d3f-4ec5-973e-b0d8506f3bc7",
                "evidence": [
                    {
                        "type": "document",
                        "validation_method": {
                            "type": "vcrypt"
                        },
                        "verification_method": {
                            "type": "bvr"
                        },
                        "time": "2019-04-20T20:11Z",
                        "document_details": {
                            "type": "passport",
                            "issuer": {
                                "name": "Ministro Affari Esteri",
                                "country": "ITA"
                            },
                            "document_number": "83774554",
                            "date_of_issuance": "2011-04-20",
                            "date_of_expiry": "2021-04-19"
                        }
                    }
                ]
            },
            "claims": {
                "given_name": "Maria",
                "family_name": "Rossi",
                "birthdate": "1980-01-11",
                "place_of_birth": {
                    "country": "ITA",
                    "locality": "Roma"
                },
                "nationalities": [
                    "IT"
                ],
                "address": {
                    "locality": "Imola BO",
                    "postal_code": "40026",
                    "country": "ITA",
                    "street_address": "Viale Dante Alighieri, 26"
                }
            }
        }
    }

    vc = do_verified_claims(msg)
    assert len(vc) == 1
    vc[0].verify()
    assert vc[0]
    assert isinstance(vc[0]["verification"]["evidence"][0], Document)
    _document = vc[0]["verification"]["evidence"][0]
    assert _document["validation_method"]["type"] == "vcrypt"
    assert _document["verification_method"]["type"] == "bvr"


def test_8_14():
    # Multiple Verified Claims
    msg = {"verified_claims": [
        {
            "verification": {
                "trust_framework": "eidas",
                "assurance_level": "substantial"
            },
            "claims": {
                "given_name": "Max",
                "family_name": "Meier",
                "birthdate": "1956-01-28",
                "place_of_birth": {
                    "country": "DE",
                    "locality": "Musterstadt"
                },
                "nationalities": [
                    "DE"
                ]
            }
        },
        {
            "verification": {
                "trust_framework": "de_aml",
                "time": "2012-04-23T18:25Z",
                "verification_process": "f24c6f-6d3f-4ec5-973e-b0d8506f3bc7",
                "evidence": [
                    {
                        "type": "document",
                        "method": "pipp",
                        "time": "2012-04-22T11:30Z",
                        "document": {
                            "type": "idcard"
                        }
                    }
                ]
            },
            "claims": {
                "address": {
                    "locality": "Maxstadt",
                    "postal_code": "12344",
                    "country": "DE",
                    "street_address": "An der Weide 22"
                }
            }
        }
    ]}

    vc = do_verified_claims(msg)
    assert len(vc) == 2
    vc[0].verify()
    vc[1].verify()

    assert vc[0]["verification"]["trust_framework"] == "eidas"
    assert vc[1]["verification"]["trust_framework"] == "de_aml"
    assert set(vc[0]["claims"].keys()) == {'family_name', 'place_of_birth', 'given_name',
                                           'nationalities', 'birthdate'}
    assert set(vc[1]["claims"].keys()) == {'address'}


def test_8_15():
    # *********
    msg = {
        "sub": "248289761001",
        "email": "janedoe@example.com",
        "email_verified": True,
        "verified_claims": {
            "verification": {
                "trust_framework": "de_aml"
            },
            "claims": {
                "given_name": "Max",
                "family_name": "Meier",
                "birthdate": "1956-01-28"
            }
        }
    }

    vc = do_verified_claims(msg)
    assert len(vc) == 1
    vc[0].verify()
    assert vc[0]["verification"]["trust_framework"] == "de_aml"


def test_8_16():
    # ID Token
    msg = {
        "iss": "https://server.example.com",
        "sub": "24400320",
        "aud": "s6BhdRkqt3",
        "nonce": "n-0S6_WzA2Mj",
        "exp": 1311281970,
        "iat": 1311280970,
        "auth_time": 1311280969,
        "acr": "urn:mace:incommon:iap:silver",
        "email": "janedoe@example.com",
        "preferred_username": "j.doe",
        "picture": "http://example.com/janedoe/me.jpg",
        "verified_claims": {
            "verification": {
                "trust_framework": "de_aml",
                "time": "2012-04-23T18:25Z",
                "verification_process": "f24c6f-6d3f-4ec5-973e-b0d8506f3bc7",
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
                        }
                    }
                ]
            },
            "claims": {
                "given_name": "Max",
                "family_name": "Meier",
                "birthdate": "1956-01-28"
            }
        }
    }

    vc = do_verified_claims(msg)
    assert len(vc) == 1
    vc[0].verify()
    assert vc[0]["verification"]["trust_framework"] == "de_aml"


def test_8_17():
    KEYSPEC = [
        {"type": "RSA", "use": ["sig"]},
        {"type": "EC", "crv": "P-256", "use": ["sig"]},
    ]

    keyjar = init_key_jar(
        key_defs=KEYSPEC,
        issuer_id="s6BhdRkqt3",
    )

    other_msg = {
        "iss": "https://server.otherop.com",
        "sub": "e8148603-8934-4245-825b-c108b8b6b945",
        "verified_claims": {
            "verification": {
                "trust_framework": "ial_example_gold"
            },
            "claims": {
                "given_name": "Max",
                "family_name": "Meier",
                "birthdate": "1956-01-28"
            }
        }
    }

    _jwt = JWT(key_jar=keyjar, iss="s6BhdRkqt3")
    _jws = _jwt.pack(other_msg)

    # Claims provided by the OP and external sources
    msg = {
        "iss": "https://server.example.com",
        "sub": "248289761001",
        "email": "janedoe@example.com",
        "email_verified": True,
        "verified_claims": {
            "verification": {
                "trust_framework": "trust_framework_example"
            },
            "claims": {
                "given_name": "Max",
                "family_name": "Meier"
            }
        },
        "_claim_names": {
            "verified_claims": [
                "src1"
                # "src2"
            ]
        },
        "_claim_sources": {
            "src1": {
                "JWT": _jws
            }
            # "src2": {
            #     "endpoint": "https://server.yetanotherop.com/claim_source",
            #     "access_token": "ksj3n283dkeafb76cdef"
            # }
        }
    }

    user = EndUser(**msg)
    user.verify()
    user = collect_claim_sources(user["_claim_sources"], user, EndUser, keyjar, requests.request)
    assert user
    assert len(user["verified_claims"]) == 2


def test_8_18():
    # Self-Issued OpenID Connect Provider and External Claims
    KEYSPEC = [
        {"type": "RSA", "use": ["sig"]},
        {"type": "EC", "crv": "P-256", "use": ["sig"]},
    ]

    keyjar = init_key_jar(
        key_defs=KEYSPEC,
        issuer_id="s6BhdRkqt3",
    )

    other_msg = {
        "iss": "https://server.otherop.com",
        "sub": "e8148603-8934-4245-825b-c108b8b6b945",
        "verified_claims": {
            "verification": {
                "trust_framework": "ial_example_gold"
            },
            "claims": {
                "given_name": "Max",
                "family_name": "Meier",
                "birthdate": "1956-01-28"
            }
        }
    }

    _jwt = JWT(key_jar=keyjar, iss="s6BhdRkqt3")
    _jws = _jwt.pack(other_msg)

    url_msg = {
        "iss": "https://server.yetanotherop.com",
        "sub": "abcdefghijklmn",
        "verified_claims": {
            "verification": {
                "trust_framework": "de_aml"
            },
            "claims": {
                "given_name": "Maximillian",
                "family_name": "Meier",
                "place_of_birth": {"locality": "Ruhpolding"}
            }
        }
    }

    msg = {
        "iss": "https://self-issued.me",
        "sub": "248289761001",
        "preferred_username": "superman445",
        "_claim_names": {
            "verified_claims": [
                "src1",
                "src2"
            ]
        },
        "_claim_sources": {
            "src1": {"JWT": _jws},
            "src2": {
                "endpoint": "https://op.mymno.com/claim_source",
                "access_token": "ksj3n283dkeafb76cdef"
            }
        }
    }

    user = EndUser(**msg)
    user.verify()
    with responses.RequestsMock() as rsps:
        rsps.add("GET", "https://op.mymno.com/claim_source", body=json.dumps(url_msg), status=200)

        user = collect_claim_sources(user["_claim_sources"], user, EndUser, keyjar,
                                     requests.request)

    assert user
    assert len(user["verified_claims"]) == 2
    assert user["verified_claims"][0]["verification"]["trust_framework"] == "ial_example_gold"
    assert user["verified_claims"][1]["verification"]["trust_framework"] == "de_aml"


def test_8_16_2():
    claims_request = {
        "id_token": {
            "email": None,
            "preferred_username": None,
            "picture": None,
            "verified_claims": {
                "verification": {
                    "trust_framework": None,
                    "time": None,
                    "verification_process": None,
                    "evidence": [
                        {
                            "type": {
                                "value": "document"
                            },
                            "method": None,
                            "time": None,
                            "document_details": {
                                "type": None,
                                "issuer": {
                                    "name": None,
                                    "country": None
                                },
                                "document_number": None,
                                "date_of_issuance": None,
                                "date_of_expiry": None
                            }
                        }
                    ]
                },
                "claims": {
                    "given_name": None,
                    "family_name": None,
                    "birthdate": None
                }
            }
        }
    }

    # ID Token
    msg = {
        "iss": "https://server.example.com",
        "sub": "24400320",
        "aud": "s6BhdRkqt3",
        "nonce": "n-0S6_WzA2Mj",
        "exp": 1311281970,
        "iat": 1311280970,
        "auth_time": 1311280969,
        "acr": "urn:mace:incommon:iap:silver",
        "email": "janedoe@example.com",
        "preferred_username": "j.doe",
        "picture": "http://example.com/janedoe/me.jpg",
        "verified_claims": {
            "verification": {
                "trust_framework": "de_aml",
                "time": "2012-04-23T18:25Z",
                "verification_process": "f24c6f-6d3f-4ec5-973e-b0d8506f3bc7",
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
                        }
                    }
                ]
            },
            "claims": {
                "given_name": "Max",
                "family_name": "Meier",
                "birthdate": "1956-01-28"
            }
        }
    }

    vc = do_verified_claims(msg)
    assert len(vc) == 1
    vc[0].verify()
    res = vc[0].match_request(claims_request["id_token"]["verified_claims"])
    assert res


def test_8_17_claims_requests():
    KEYSPEC = [
        {"type": "RSA", "use": ["sig"]},
        {"type": "EC", "crv": "P-256", "use": ["sig"]},
    ]

    keyjar = init_key_jar(
        key_defs=KEYSPEC,
        issuer_id="s6BhdRkqt3",
    )

    other_msg = {
        "iss": "https://server.otherop.com",
        "sub": "e8148603-8934-4245-825b-c108b8b6b945",
        "verified_claims": {
            "verification": {
                "trust_framework": "ial_example_gold"
            },
            "claims": {
                "given_name": "Maximillian",
                "family_name": "Meier",
                "birthdate": "1956-01-28"
            }
        }
    }

    _jwt = JWT(key_jar=keyjar, iss="s6BhdRkqt3")
    _jws = _jwt.pack(other_msg)

    url_msg = {
        "iss": "https://server.yetanotherop.com",
        "sub": "abcdefghijklmn",
        "verified_claims": {
            "verification": {
                "trust_framework": "de_aml"
            },
            "claims": {
                "given_name": "Maximillian",
                "family_name": "Meier",
                "place_of_birth": {"locality": "Ruhpolding"}
            }
        }
    }

    # Claims provided by the OP and external sources
    msg = {
        "iss": "https://server.example.com",
        "sub": "248289761001",
        "email": "janedoe@example.com",
        "email_verified": True,
        "verified_claims": {
            "verification": {
                "trust_framework": "trust_framework_example"
            },
            "claims": {
                "given_name": "Max",
                "family_name": "Meier"
            }
        },
        "_claim_names": {
            "verified_claims": ["src1", "src2"]
        },
        "_claim_sources": {
            "src1": {
                "JWT": _jws
            },
            "src2": {
                "endpoint": "https://server.yetanotherop.com/claim_source",
                "access_token": "ksj3n283dkeafb76cdef"
            }
        }
    }

    user = EndUser(**msg)
    user.verify()

    with responses.RequestsMock() as rsps:
        rsps.add("GET", "https://server.yetanotherop.com/claim_source", body=json.dumps(url_msg),
                 status=200)

        user = collect_claim_sources(user["_claim_sources"], user, EndUser, keyjar,
                                     requests.request)

    assert user
    assert len(user["verified_claims"]) == 3

    claims_request = [
        {
            "userinfo": {
                "verified_claims": {
                    "verification": {
                        "trust_framework": {"value": "trust_framework_example"}
                    },
                    "claims": {
                        "given_name": None,
                        "family_name": None
                    }
                }
            }
        }, {
            "userinfo": {
                "verified_claims": {
                    "verification": {
                        "trust_framework": {"value": "ial_example_gold"}
                    },
                    "claims": {
                        "given_name": None,
                        "family_name": None,
                        "birthdate": None
                    }
                }
            }
        }, {
            "userinfo": {
                "verified_claims": {
                    "verification": {
                        "trust_framework": {"value": "de_aml"}
                    },
                    "claims": {
                        "given_name": None,
                        "family_name": None,
                        "place_of_birth": None
                    }
                }
            }
        }
    ]

    res = []
    for vc in user["verified_claims"]:
        for cr in claims_request:
            _res = map_request(cr, vc, "userinfo")
            if _res:
                res.append(_res)

    assert len(res) == 3
