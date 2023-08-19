import abc
import datetime
import json

from cryptojwt.utils import importer

from idpyoidc.message import Message
from idpyoidc.message import OPTIONAL_ANY_LIST
from idpyoidc.message import OPTIONAL_LIST_OF_MESSAGES
from idpyoidc.message import OPTIONAL_LIST_OF_STRINGS
from idpyoidc.message import OPTIONAL_MESSAGE
from idpyoidc.message import SINGLE_OPTIONAL_ANY
from idpyoidc.message import SINGLE_OPTIONAL_INT
from idpyoidc.message import SINGLE_OPTIONAL_STRING
from idpyoidc.message import SINGLE_REQUIRED_STRING
from idpyoidc.message import msg_list_ser
from idpyoidc.message import msg_ser
from idpyoidc.message.oauth2 import error_chars
from idpyoidc.message.oidc import AddressClaim
from idpyoidc.message.oidc import ClaimsRequest
from idpyoidc.message.oidc import OPTIONAL_MULTIPLE_Claims
from idpyoidc.message.oidc import OpenIDSchema
from idpyoidc.message.oidc import SINGLE_OPTIONAL_BOOLEAN
from idpyoidc.message.oidc import claims_request_deser
from idpyoidc.message.oidc import deserialize_from_one_of
from idpyoidc.message.oidc import msg_ser_json


class PlaceOfBirth(Message):
    c_param = {
        "country": SINGLE_REQUIRED_STRING,
        "region": SINGLE_OPTIONAL_STRING,
        "locality": SINGLE_REQUIRED_STRING,
    }


def place_of_birth_deser(val, sformat="json"):
    # never 'urlencoded'
    if sformat == "urlencoded":
        sformat = "json"

    if sformat == "json":
        if not isinstance(val, str):
            val = json.dumps(val)
            sformat = "json"
    elif sformat == "dict":
        if isinstance(val, str):
            val = json.loads(val)

    return PlaceOfBirth().deserialize(val, sformat)


SINGLE_OPTIONAL_PLACE_OF_BIRTH = (PlaceOfBirth, False, msg_ser_json, place_of_birth_deser, False)

# YYYY-MM-DDThh:mm:ss±hh
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S%z"
DATE_FORMAT = "%Y-%m-%d"


def to_iso8601_2004(val=0, format=TIME_FORMAT):
    """
    :param val: integer/float/datetime.datetime
    :return: A string following the DATE_FORMAT format
    """

    # Finds the local time zone
    ltz = datetime.datetime.utcnow().astimezone().tzinfo

    if val:
        if isinstance(val, datetime.datetime):
            d = val
        elif isinstance(val, (int, float)):
            d = datetime.datetime.fromtimestamp(val)
        else:
            raise ValueError("Unsupported value type")
    else:
        d = datetime.datetime.now()

    return d.replace(tzinfo=ltz).strftime(format)


def from_iso8601_2004(isotime, format=TIME_FORMAT):
    """
    :param isotime: A string following the DATE_FORMAT format
    :return: A time stamp (int)
    """
    d = datetime.datetime.strptime(isotime, format)
    return d.timestamp()


def to_iso8601_2004_time(val=0):
    return to_iso8601_2004(val, format=TIME_FORMAT)


def to_iso8601_2004_date(val=0):
    return to_iso8601_2004(val, format=DATE_FORMAT)


def from_iso8601_2004_time(val):
    return from_iso8601_2004(val, format=TIME_FORMAT)


def from_iso8601_2004_date(val):
    return from_iso8601_2004(val, format=DATE_FORMAT)


def time_stamp_ser(val, sformat="", lev=0):
    """
    Convert from seconds since epoch to ISO 8601:2004 [ISO8601-2004] YYYY-MM-DDThh:mm:ss±hh format.
    """
    if isinstance(val, int):
        return to_iso8601_2004_time(val)
    elif isinstance(val, float):
        return to_iso8601_2004_time(int(val))
    elif isinstance(val, str):
        return to_iso8601_2004_time(int(val))
    else:
        raise ValueError("Wrong type of value")


def time_stamp_deser(val, sformat="", lev=0):
    if isinstance(val, (int, float)):
        return val
    else:  # A string following the
        return from_iso8601_2004_time(val)


REQURIED_TIME_STAMP = (str, True, time_stamp_ser, time_stamp_deser, False)
OPTIONAL_TIME_STAMP = (str, False, time_stamp_ser, time_stamp_deser, False)


def date_ser(val, sformat="", lev=0):
    """
    Convert from seconds since epoch to ISO 8601:2004 [ISO8601-2004] YYYY-MM-DDThh:mm:ss±hh format.
    """
    if isinstance(val, int):
        return to_iso8601_2004_date(val)
    elif isinstance(val, float):
        return to_iso8601_2004_date(int(val))
    elif isinstance(val, str):
        return to_iso8601_2004_date(int(val))
    else:
        raise ValueError("Wrong type of value")


def date_deser(val, sformat="", lev=0):
    if isinstance(val, (int, float)):
        return val
    else:  # A string following the
        return from_iso8601_2004_date(val)


REQURIED_DATE = (str, True, date_ser, date_deser, False)
OPTIONAL_DATE = (str, False, date_ser, date_deser, False)


# ------------------------------------------------------------------------------

class IdentityAssuranceClaims(OpenIDSchema):
    c_param = OpenIDSchema.c_param.copy()
    c_param.update(
        {
            "place_of_birth": SINGLE_OPTIONAL_PLACE_OF_BIRTH,
            "nationalities": OPTIONAL_LIST_OF_STRINGS,
            "birth_family_name": SINGLE_OPTIONAL_STRING,
            "birth_given_name": SINGLE_OPTIONAL_STRING,
            "birth_middle_name": SINGLE_OPTIONAL_STRING,
            "salutation": SINGLE_OPTIONAL_STRING,
            "title": SINGLE_OPTIONAL_STRING,
            "msisdn": SINGLE_OPTIONAL_STRING,
            "also_known_as": SINGLE_OPTIONAL_STRING
        }
    )


def identity_assurance_claims_deser(val, sformat="json"):
    return deserialize_from_one_of(val, IdentityAssuranceClaims, sformat)


OPTIONAL_IDA_CLAIMS = (
    IdentityAssuranceClaims, False, msg_ser, identity_assurance_claims_deser, False)
REQUIRED_IDA_CLAIMS = (
    IdentityAssuranceClaims, True, msg_ser, identity_assurance_claims_deser, False)


# ------------------------------------------------------------------------------

class Address(AddressClaim):
    c_param = AddressClaim.c_param.copy()
    c_param.update({"country_code": SINGLE_OPTIONAL_STRING})


def address_deser(val, sformat="urlencoded"):
    return deserialize_from_one_of(val, Address, sformat)


OPTIONAL_ADDRESS = (Address, False, msg_ser, address_deser, False)


# ------------------------------------------------------------------------------
class Verifier(Message):
    c_param = {
        "organization": SINGLE_REQUIRED_STRING,
        "txn": SINGLE_REQUIRED_STRING
    }


def verifier_deser(val, sformat="json"):
    return deserialize_from_one_of(val, Verifier, sformat)


REQUIRED_VERIFIER = (Verifier, True, msg_ser, verifier_deser, False)


def verifier_list_deser(val, sformat="json"):
    return [verifier_deser(v, sformat) for v in val]


OPTIONAL_VERIFIERS = ([Verifier], False, msg_ser, verifier_list_deser, False)


# ------------------------------------------------------------------------------
class Issuer(Message):
    c_param = {
        "name": SINGLE_REQUIRED_STRING,
        "country_code": SINGLE_REQUIRED_STRING,
        "jurisdiction": SINGLE_OPTIONAL_STRING
    }
    c_param.update(AddressClaim.c_param)


def issuer_deser(val, sformat="urlencoded"):
    if isinstance(val, Message):
        return val
    elif sformat in ["dict", "json"]:
        if not isinstance(val, str):
            val = json.dumps(val)
            sformat = "json"
    return Issuer().deserialize(val, sformat)


REQUIRED_ISSUER = (Issuer, True, msg_ser, issuer_deser, False)
OPTIONAL_ISSUER = (Issuer, False, msg_ser, issuer_deser, False)


def json_list_deserializer(insts, sformat):
    if sformat == 'dict':
        return insts
    elif sformat == 'json':
        return json.loads(insts)


# MULTIPLE_OPTIONAL_JSON = ([dict], False, msg_ser, json_list_deserializer, False)


class EmbeddedAttachments(Message):
    c_param = {
        "desc": SINGLE_OPTIONAL_STRING,
        "content_type": SINGLE_REQUIRED_STRING,
        "content": SINGLE_REQUIRED_STRING,
        "txn": SINGLE_OPTIONAL_STRING
    }


class Digest(Message):
    c_param = {
        "alg": SINGLE_REQUIRED_STRING,
        "value": SINGLE_REQUIRED_STRING
    }


def digest_deser(val, sformat="json"):
    return deserialize_from_one_of(val, Digest, sformat)


OPTIONAL_DIGEST = (Digest, False, msg_ser, digest_deser, False)


class ExternalAttachments(Message):
    c_param = {
        "desc": SINGLE_OPTIONAL_STRING,
        "url": SINGLE_REQUIRED_STRING,
        "access_token": SINGLE_OPTIONAL_STRING,
        "expires_in": SINGLE_OPTIONAL_INT,
        "digest": OPTIONAL_DIGEST,
        "txn": SINGLE_OPTIONAL_STRING
    }


# -----------------------------------------------------------------

class Evidence(Message):
    c_param = {
        "type": SINGLE_REQUIRED_STRING,
        "attachments": OPTIONAL_LIST_OF_MESSAGES
    }

    def verify(self, **kwargs):
        super(Evidence, self).verify(**kwargs)
        if "attachments" in self:
            _items = []
            for attch in self['attachments']:
                if "url" in attch:
                    _items.append(ExternalAttachments(**attch))
                else:
                    _items.append(EmbeddedAttachments(**attch))
            self._dict["attachments"] = _items

        _type = self.get("type")
        if _type not in EVIDENCE_TYPES:
            raise ValueError("Unknown event type")

        _evidence_cls = EVIDENCE_TYPES.get(_type)
        if _evidence_cls:
            _evidence_instance = _evidence_cls(**self.to_dict())
            _evidence_instance.verify(**kwargs)
        else:
            raise ValueError("Unknown type")


def evidence_deser(val, sformat="urlencoded"):
    return deserialize_from_one_of(val, Evidence, sformat)


def evidence_list_deser(val, sformat="urlencoded", lev=0):
    if isinstance(val, dict):
        return [Message(**val)]

    _res = [evidence_deser(v, sformat) for v in val]
    return _res


OPTIONAL_EVIDENCE_LIST = ([Evidence], False, msg_list_ser, evidence_list_deser, True)


# ------------------------------------------------------------------------------
class CheckDetails(Message):
    c_param = {
        "check_method": SINGLE_REQUIRED_STRING,
        "organization": SINGLE_OPTIONAL_STRING,
        "txn": SINGLE_OPTIONAL_STRING,
        "time": OPTIONAL_TIME_STAMP
    }


def check_details_deser(val, sformat="urlencoded"):
    return deserialize_from_one_of(val, CheckDetails, sformat)

def check_details_list_deser(val, sformat="json"):
    return [check_details_deser(v, sformat) for v in val]


OPTIONAL_CHECK_DETAILS_LIST = ([CheckDetails], False, msg_list_ser, check_details_list_deser, True)


# ------------------------------------------------------------------------------
class DocumentDetails(Message):
    c_param = {
        "type": SINGLE_REQUIRED_STRING,
        "document_number": SINGLE_REQUIRED_STRING,
        "personal_number": SINGLE_OPTIONAL_STRING,
        "serial_number": SINGLE_OPTIONAL_STRING,
        "date_of_issuance": REQURIED_TIME_STAMP,
        "date_of_expiry": REQURIED_TIME_STAMP,
        "issuer": REQUIRED_ISSUER,
    }

def document_details_deser(val, sformat="urlencoded"):
    return deserialize_from_one_of(val, Document, sformat)


REQUIRED_DOCUMENT_DETAILS = (DocumentDetails, True, msg_ser, document_details_deser, False)
OPTIONAL_DOCUMENT_DETAILS = (DocumentDetails, False, msg_ser, document_details_deser, False)

# ------------------------------------------------------------------------------

class Document(Message):
    c_param = Evidence.c_param.copy()
    c_param.update({
        "check_details": OPTIONAL_CHECK_DETAILS_LIST,
        "method": SINGLE_OPTIONAL_STRING,
        "verifier": OPTIONAL_VERIFIERS,
        "time": OPTIONAL_TIME_STAMP,
        "document_details": OPTIONAL_DOCUMENT_DETAILS
    })


# ------------------------------------------------------------------------------


def document_deser(val, sformat="urlencoded"):
    return deserialize_from_one_of(val, Document, sformat)


REQUIRED_DOCUMENT = (Document, True, msg_ser, document_deser, False)
OPTIONAL_DOCUMENT = (Document, False, msg_ser, document_deser, False)


# ------------------------------------------------------------------------------

class Provider(AddressClaim):
    c_param = AddressClaim.c_param.copy()
    c_param.update(
        {
            "name": SINGLE_OPTIONAL_STRING,
            "country_code": SINGLE_OPTIONAL_STRING
        }
    )


def provider_deser(val, sformat="urlencoded"):
    if isinstance(val, Message):
        return val
    elif sformat in ["dict", "json"]:
        if not isinstance(val, str):
            val = json.dumps(val)
            sformat = "json"
    return Provider().deserialize(val, sformat)


REQUIRED_PROVIDER = (Provider, True, msg_ser, provider_deser, False)


# ------------------------------------------------------------------------------

class UtilityBill(Message):
    c_param = Evidence.c_param.copy()
    c_param.update({
        "provider": REQUIRED_PROVIDER,
        "date": OPTIONAL_TIME_STAMP,
        "method": SINGLE_OPTIONAL_STRING,
        "time": SINGLE_OPTIONAL_INT
    })


# ------------------------------------------------------------------------------

class Record(Message):
    c_param = {
        "type": SINGLE_REQUIRED_STRING,
        "personal_number": SINGLE_OPTIONAL_STRING,
        "created_at": OPTIONAL_DATE,
        "date_of_expiry": OPTIONAL_DATE,
        "source": OPTIONAL_ISSUER
    }


def record_deser(val, sformat="json"):
    return deserialize_from_one_of(val, Record, sformat)


OPTIONAL_RECORD = (Record, False, msg_list_ser, record_deser, True)


# ------------------------------------------------------------------------------

class ElectronicRecord(Message):
    c_param = Evidence.c_param.copy()
    c_param.update(
        {
            "check_details": OPTIONAL_CHECK_DETAILS_LIST,
            "time": SINGLE_OPTIONAL_INT,
            "record": OPTIONAL_RECORD
        }
    )


# ------------------------------------------------------------------------------

class ElectronicSignature(Message):
    c_param = Evidence.c_param.copy()
    c_param.update(
        {
            "signature_type": SINGLE_REQUIRED_STRING,
            "issuer": SINGLE_REQUIRED_STRING,
            "serial_number": SINGLE_REQUIRED_STRING,
            "created_at": OPTIONAL_DATE
        }
    )


# ------------------------------------------------------------------------------

class Voucher(Message):
    c_param = {
        "name": SINGLE_OPTIONAL_STRING,
        "birthdate": SINGLE_OPTIONAL_STRING,
        "country_code": SINGLE_OPTIONAL_STRING,
        "occupation": SINGLE_OPTIONAL_STRING,
        "organization": SINGLE_OPTIONAL_STRING
    }


def voucher_deser(val, sformat="json"):
    return deserialize_from_one_of(val, Voucher, sformat)


OPTIONAL_VOUCHER = (Voucher, False, msg_ser, voucher_deser, False)

# ------------------------------------------------------------------------------

EVIDENCE_TYPES = {
    "document": Document,
    "utility_bill": UtilityBill,
    "electronic_record": ElectronicRecord,
    "voucher": Voucher,
    "electronic_signature": ElectronicSignature
}


# ------------------------------------------------------------------------------

class Attestation(Message):
    c_param = {
        "type": SINGLE_REQUIRED_STRING,
        "reference_number": SINGLE_OPTIONAL_STRING,
        "date_of_issuance": OPTIONAL_DATE,
        "date_of_expiry": OPTIONAL_DATE,
        "voucher": OPTIONAL_VOUCHER
    }


def attestation_deser(val, sformat="json"):
    return deserialize_from_one_of(val, Attestation, sformat)


OPTIONAL_ATTESTATION = (Attestation, False, msg_ser, attestation_deser, False)


# ------------------------------------------------------------------------------

class Vouch(Message):
    c_param = Evidence.c_param.copy()
    c_param.update(
        {
            "check_details": OPTIONAL_CHECK_DETAILS_LIST,
            "time": SINGLE_OPTIONAL_INT,
            "attestation": OPTIONAL_ATTESTATION
        }
    )


def vouch_deser(val, sformat="urlencoded"):
    if isinstance(val, Message):
        return val
    elif sformat in ["dict", "json"]:
        if not isinstance(val, str):
            val = json.dumps(val)
            sformat = "json"
    return Vouch().deserialize(val, sformat)


REQUIRED_VOUCH = (Vouch, True, msg_ser, vouch_deser, False)
OPTIONAL_VOUCH = (Vouch, False, msg_ser, vouch_deser, False)


# ------------------------------------------------------------------------------


class EvidenceMetadata(Message):
    c_param = {
        "evidence_classification": SINGLE_OPTIONAL_STRING
    }


def evidence_metadata_deser(val, sformat="urlencoded"):
    return deserialize_from_one_of(val, EvidenceMetadata, sformat)


OPTIONAL_EVIDENCE_METADATA = (EvidenceMetadata, False, msg_ser, evidence_metadata_deser, False)


class EvidenceRef(Message):
    c_param = {
        "txn": SINGLE_REQUIRED_STRING,
        "evidence_metadata": OPTIONAL_EVIDENCE_METADATA
    }


def evidence_ref_deser(val, sformat="urlencoded"):
    return deserialize_from_one_of(val, EvidenceRef, sformat)


OPTIONAL_EVIDENCE_REFS = (EvidenceRef, False, msg_ser, evidence_ref_deser, False)


class AssuranceDetails(Message):
    c_param = {
        "assurance_type": SINGLE_OPTIONAL_STRING,
        "assurance_classification": SINGLE_OPTIONAL_STRING,
        "evidence_ref": OPTIONAL_EVIDENCE_REFS
    }


def assurance_details_deser(val, sformat="urlencoded"):
    return deserialize_from_one_of(val, AssuranceDetails, sformat)


OPTIONAL_ASSURANCE_DETAILS = (AssuranceDetails, False, msg_ser, assurance_details_deser, False)


class AssuranceProcess(Message):
    c_param = {
        "policy": SINGLE_OPTIONAL_STRING,
        "procedure": SINGLE_OPTIONAL_STRING,
        "assurance_details": OPTIONAL_ASSURANCE_DETAILS
    }


def assurance_process_deser(val, sformat="urlencoded"):
    return deserialize_from_one_of(val, AssuranceProcess, sformat)


OPTIONAL_ASSURANCE_PROFILE = (AssuranceProcess, False, msg_ser, assurance_process_deser, False)


class VerificationElement(Message):
    c_param = {
        "trust_framework": SINGLE_REQUIRED_STRING,
        "time": OPTIONAL_TIME_STAMP,
        "verification_process": SINGLE_OPTIONAL_STRING,
        "evidence": OPTIONAL_EVIDENCE_LIST,
        "assurance_level": SINGLE_OPTIONAL_STRING,
        "assurance_process": OPTIONAL_ASSURANCE_PROFILE
    }

    def verify(self, **kwargs):
        if "evidence" in self and self["evidence"]:
            for evid in self["evidence"]:
                evid.verify(**kwargs)
        if "assurance_process" in self and self["assurance_process"]:
            self["assurance_process"].verify(**kwargs)


def verification_element_deser(val, sformat="urlencoded"):
    if isinstance(val, Message):
        return val
    elif sformat in ["dict", "json"]:
        if isinstance(val, dict):
            return VerificationElement(**val)

        if not isinstance(val, str):
            val = json.dumps(val)
            sformat = "json"

        return VerificationElement().deserialize(val, sformat)


REQUIRED_VERIFICATION_ELEMENT = (
    VerificationElement,
    True,
    msg_ser,
    verification_element_deser,
    False,
)

OPTIONAL_VERIFICATION_ELEMENT = (VerificationElement, False, msg_ser, verification_element_deser,
                                 False)


class VerifiedClaims(Message):
    c_param = {
        "verification": OPTIONAL_VERIFICATION_ELEMENT,
        "claims": OPTIONAL_MULTIPLE_Claims
    }

    def verify(self, **kwargs):
        super(VerifiedClaims, self).verify(**kwargs)
        if "verification" in self:
            self['verification'].verify()
        if "claims" in self and self['claims']:
            self['claims'].verify()


# ============================================================================================

SINGLE_OPTIONAL_CLAIMSREQ = (ClaimsRequest, False, msg_ser_json, claims_request_deser, False)

OPTIONAL_VERIFICATION_REQUEST = OPTIONAL_MESSAGE


def _correct_value_type(val, value_type):
    if isinstance(value_type, Message):
        pass
    else:
        if not isinstance(val, value_type):  # the simple case
            return False
    return True


class ClaimsSpec(Message):
    c_param = {
        "essential": SINGLE_OPTIONAL_BOOLEAN,
        "value": SINGLE_OPTIONAL_ANY,
        "values": OPTIONAL_ANY_LIST,
        "purpose": SINGLE_OPTIONAL_STRING,
        "max_age": SINGLE_OPTIONAL_INT
    }

    def _verify_claims_request_value(self, value, value_type=str):
        if value is None:
            return True
        elif isinstance(value, dict):
            # know about keys: essential, value and values, purpose
            if not value.get("essential") in (None, True, False):
                return False

            _v = value.get("value")
            if _v:
                if not _correct_value_type(_v, value_type):
                    return False

            _vs = value.get("values", [])
            for _v in _vs:
                if not _correct_value_type(_v, value_type):
                    return False

            _p = value.get("purpose")
            if _p:
                if len(_p) < 3 or len(_p) > 300:
                    return False
                if not all(x in error_chars for x in _p):
                    return False
            _p = value.get("max_age")
            if _p:
                if not isinstance(_p, int):
                    return False

        return True


class VerificationElementRequest(Message):
    c_param = {
        "trust_framework": SINGLE_REQUIRED_STRING,
        "time": OPTIONAL_TIME_STAMP,
        "verification_process": SINGLE_OPTIONAL_STRING,
        "evidence": OPTIONAL_EVIDENCE_LIST,
    }

    def verify(self, **kwargs):
        super(VerificationElementRequest, self).verify(**kwargs)


def verification_element_request_deser(val, sformat="urlencoded"):
    return deserialize_from_one_of(val, VerificationElementRequest, sformat)


OPTIONAL_VERIFICATION_ELEMENT_REQUEST = (
    VerificationElementRequest,
    False,
    msg_ser,
    verification_element_request_deser,
    True,
)

class IDAClaimsRequest(ClaimsRequest):

    def verify(self, **kwargs):
        super(IDAClaimsRequest, self).verify(**kwargs)
        _vc = self.get("verified_claims")
        if isinstance(_vc, list) or isinstance(_vc, str):
            self["verified_claims"] = _vc
        else:  # should be a dict
            _vci = VerifiedClaims(**_vc)
            _vci.verify()
            self["verified_claims"] = _vci


class ClaimsConstructor:

    def __init__(self, base_class=Message):
        if isinstance(base_class, str):
            self.base_class = importer(base_class)()
        elif isinstance(base_class, Message):
            self.base_class = base_class
        elif type(base_class) == abc.ABCMeta:
            self.base_class = base_class()

        self.info = {}

    def __setitem__(self, key, value):
        """

        :param key:
        :param value: one of None or a dictionary with keys: "essential",
        "value", "values" or "max_age".
        :return:
        """
        if value is not None:
            _value_type = self.base_class.value_type(key)
            if _value_type:
                if isinstance(value, ClaimsConstructor):
                    if not isinstance(value.base_class, _value_type):
                        raise ValueError(
                            "Wrong type of value '{}':'{}'".format(key, type(value.base_class))
                        )
                elif not _correct_value_type(value, _value_type):
                    raise ValueError("Wrong type of value '{}':'{}'".format(key, type(value)))

        self.info[key] = value

    def to_dict(self):
        res = {}
        for key, val in self.info.items():
            if isinstance(val, ClaimsConstructor):
                res[key] = val.to_dict()
            else:
                res[key] = val
        return res

    def to_json(self):
        return json.dumps(self.to_dict())


class ClaimsDeconstructor():
    def __init__(self, base_class=Message, **kwargs):
        if isinstance(base_class, str):
            self.base_class = importer(base_class)()
        elif isinstance(base_class, Message):
            self.base_class = base_class
        elif type(base_class) == abc.ABCMeta:
            self.base_class = base_class()

        self.info = {}
        if kwargs:
            self.from_dict(**kwargs)

    def _is_simple_type(self, typ):
        if isinstance(typ, str) or isinstance(typ, int):
            return True
        else:
            return False

    def _list_of_simple_type(self, typ):
        return self._is_simple_type(typ[0])

    def from_dict(self, **kwargs):
        for key, spec in self.base_class.items():
            val = kwargs.get(key)
            if val:
                _value_type = self.base_class.value_type(key)
                if self._is_simple_type(_value_type):
                    if isinstance(val, dict):  # should be a claims request then
                        val = ClaimsSpec(**val)
                elif self._list_of_simple_type(_value_type):
                    pass
                elif isinstance(_value_type, Message):
                    _val = ClaimsDeconstructor(_value_type, **val)
                else:
                    raise ValueError(f'Other value_type: {_value_type}')

            self.info[key] = val

        for key, val in kwargs.items():
            if key not in self.base_class:
                if val is None:
                    pass
                elif isinstance(val, dict):
                    _val = ClaimsSpec(**val)
                    try:
                        _val.verify()
                    except Exception:
                        pass
                    else:
                        val = _val

                self.info[key] = val