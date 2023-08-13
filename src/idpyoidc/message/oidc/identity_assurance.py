import abc
import datetime
import json

from cryptojwt.utils import importer

from idpyoidc.message import Message
from idpyoidc.message import OPTIONAL_LIST_OF_STRINGS
from idpyoidc.message import OPTIONAL_MESSAGE
from idpyoidc.message import SINGLE_OPTIONAL_STRING
from idpyoidc.message import SINGLE_REQUIRED_STRING
from idpyoidc.message import msg_deser
from idpyoidc.message import msg_list_ser
from idpyoidc.message import msg_ser
from idpyoidc.message.oauth2 import error_chars
from idpyoidc.message.oidc import AddressClaim
from idpyoidc.message.oidc import ClaimsRequest
from idpyoidc.message.oidc import OpenIDSchema
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


class Address(AddressClaim):
    c_param = AddressClaim.c_param.copy()
    c_param.update({"country_code": SINGLE_OPTIONAL_STRING})


OPTIONAL_IDA_CLAIMS = (IdentityAssuranceClaims, False, msg_ser, msg_deser, False)
REQUIRED_IDA_CLAIMS = (IdentityAssuranceClaims, True, msg_ser, msg_deser, False)


class Verifier(Message):
    c_param = {"organization": SINGLE_REQUIRED_STRING, "txn": SINGLE_REQUIRED_STRING}


def verifier_deser(val, sformat="urlencoded"):
    if isinstance(val, Message):
        return val
    elif sformat in ["dict", "json"]:
        if not isinstance(val, str):
            val = json.dumps(val)
            sformat = "json"
    return Verifier().deserialize(val, sformat)


REQUIRED_VERIFIER = (Verifier, True, msg_ser, verifier_deser, False)


class Issuer(Message):
    c_param = {
        "name": SINGLE_REQUIRED_STRING,
        "country": SINGLE_REQUIRED_STRING
    }


def issuer_deser(val, sformat="urlencoded"):
    if isinstance(val, Message):
        return val
    elif sformat in ["dict", "json"]:
        if not isinstance(val, str):
            val = json.dumps(val)
            sformat = "json"
    return Issuer().deserialize(val, sformat)


REQUIRED_ISSUER = (Issuer, True, msg_ser, issuer_deser, False)


class Document(Message):
    c_param = {
        "type": SINGLE_REQUIRED_STRING,
        "number": SINGLE_REQUIRED_STRING,
        "issuer": REQUIRED_ISSUER,
        "date_of_issuance": REQURIED_TIME_STAMP,
        "date_of_expiry": REQURIED_TIME_STAMP,
    }


def document_deser(val, sformat="urlencoded"):
    return deserialize_from_one_of(val, Document, sformat)


OPTIONAL_DOCUMENT = (Document, False, msg_ser, document_deser, False)


class Evidence(Message):
    c_param = {"type": SINGLE_OPTIONAL_STRING}

    def verify(self, **kwargs):
        _type = self.get("type")
        if _type:
            if _type == "id_document":
                _doc = IdDocument(**self.to_dict())
                _doc.verify(**kwargs)
            elif _type == "utility_bill":
                _bill = UtilityBill(**self.to_dict())
                _bill.verify(**kwargs)
            elif _type == "qes":
                _qes = QES(**self.to_dict())
                _qes.verify(**kwargs)
            else:
                raise ValueError("Unknown type")
        else:  # let the guessing begin
            if all(x in self.keys() for x in IdDocument.c_param.keys()):
                _doc = IdDocument(**self.to_dict())
                _doc.verify(**kwargs)
                self["type"] = "id_document"
            elif all(x in self.keys() for x in UtilityBill.c_param.keys()):
                _bill = UtilityBill(**self.to_dict())
                _bill.verify(**kwargs)
                self["type"] = "utility_bill"
            elif all(x in self.keys() for x in QES.c_param.keys()):
                _qes = QES(**self.to_dict())
                _qes.verify(**kwargs)
                self["type"] = "qes"
            else:
                raise ValueError("Unknown object")


def evidence_deser(val, sformat="urlencoded"):
    return deserialize_from_one_of(val, Evidence, sformat)


def evidence_list_deser(val, sformat="urlencoded", lev=0):
    if isinstance(val, dict):
        return [Message(**val)]

    _res = [evidence_deser(v, sformat) for v in val]
    return _res


OPTIONAL_EVIDENCE_LIST = ([Evidence], False, msg_list_ser, evidence_list_deser, True)


class IdDocument(Evidence):
    c_param = Evidence.c_param.copy()
    c_param.update(
        {
            "method": SINGLE_REQUIRED_STRING,
            "verifier": REQUIRED_VERIFIER,
            "time": OPTIONAL_TIME_STAMP,
            "document": OPTIONAL_DOCUMENT,
        }
    )


def id_document_deser(val, sformat="urlencoded"):
    if isinstance(val, Message):
        return val
    elif sformat in ["dict", "json"]:
        if not isinstance(val, str):
            val = json.dumps(val)
            sformat = "json"
    return IdDocument().deserialize(val, sformat)


REQUIRED_ID_DOCUMENT = (IdDocument, True, msg_ser, id_document_deser, False)
OPTIONAL_ID_DOCUMENT = (IdDocument, False, msg_ser, id_document_deser, False)


class Provider(AddressClaim):
    c_param = AddressClaim.c_param.copy()
    c_param.update(
        {
            "name": SINGLE_OPTIONAL_STRING,
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


class UtilityBill(Evidence):
    c_param = Evidence.c_param.copy()
    c_param.update({"provider": REQUIRED_PROVIDER, "date": OPTIONAL_TIME_STAMP})


def utility_bill_deser(val, sformat="urlencoded"):
    if isinstance(val, Message):
        return val
    elif sformat in ["dict", "json"]:
        if not isinstance(val, str):
            val = json.dumps(val)
            sformat = "json"
    return UtilityBill().deserialize(val, sformat)


REQUIRED_UTILITY_BILL = (UtilityBill, True, msg_ser, utility_bill_deser, False)
OPTIONAL_UTILITY_BILL = (UtilityBill, False, msg_ser, utility_bill_deser, False)


class QES(Evidence):
    c_param = Evidence.c_param.copy()
    c_param.update(
        {
            "issuer": SINGLE_REQUIRED_STRING,
            "serial_number": SINGLE_REQUIRED_STRING,
            "created_at": REQURIED_TIME_STAMP,
        }
    )


def qes_deser(val, sformat="urlencoded"):
    if isinstance(val, Message):
        return val
    elif sformat in ["dict", "json"]:
        if not isinstance(val, str):
            val = json.dumps(val)
            sformat = "json"
    return QES().deserialize(val, sformat)


REQUIRED_QES = (QES, True, msg_ser, qes_deser, False)
OPTIONAL_QES = (QES, False, msg_ser, qes_deser, False)


def address_deser(val, sformat="urlencoded"):
    return deserialize_from_one_of(val, Address, sformat)


OPTIONAL_ADDRESS = (Address, False, msg_ser, address_deser, False)


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


def verification_element_deser(val, sformat="urlencoded"):
    if isinstance(val, Message):
        return val
    elif sformat in ["dict", "json"]:
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


SINGLE_OPTIONAL_CLAIMSREQ = (ClaimsRequest, False, msg_ser_json, claims_request_deser, False)

OPTIONAL_VERIFICATION_REQUEST = OPTIONAL_MESSAGE


def _correct_value_type(val, value_type):
    if isinstance(value_type, Message):
        pass
    else:
        if not isinstance(val, value_type):  # the simple case
            return False
    return True


def _verify_claims_request_value(value, value_type=str):
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

    return True


def verify_claims_request(instance, base_cls_instance):
    for key, spec in base_cls_instance.c_param.items():
        try:
            _val = instance[key]
        except KeyError:
            continue

        _value_type = spec[0]

        if _value_type in (str, int, bool):
            if not _verify_claims_request_value(_val, _value_type):
                raise ValueError("{}: '{}'".format(key, _val))
        elif type(_value_type) == abc.ABCMeta:
            if _val is None:
                continue
            verify_claims_request(_val, _value_type())
        elif isinstance(_value_type, list):
            if _val is None:
                continue
            _item_val_type = _value_type[0]
            for _v in _val:
                if _item_val_type in (str, int, bool):
                    if not _verify_claims_request_value(_v, _item_val_type):
                        raise ValueError("{}: '{}'".format(key, _v))
                elif type(_item_val_type) == abc.ABCMeta:
                    if _v is None:
                        continue
                    verify_claims_request(_v, _item_val_type())


class VerificationElementRequest(Message):
    c_param = {
        "trust_framework": SINGLE_REQUIRED_STRING,
        "time": OPTIONAL_TIME_STAMP,
        "verification_process": SINGLE_OPTIONAL_STRING,
        "evidence": OPTIONAL_EVIDENCE_LIST,
    }

    def verify(self, **kwargs):
        super(VerificationElementRequest, self).verify(**kwargs)
        verify_claims_request(self, VerificationElement())


def verification_element_request_deser(val, sformat="urlencoded"):
    return deserialize_from_one_of(val, VerificationElementRequest, sformat)


OPTIONAL_VERIFICATION_ELEMENT_REQUEST = (
    VerificationElementRequest,
    False,
    msg_ser,
    verification_element_request_deser,
    True,
)


class VerifiedClaims(Message):
    c_param = {
        "verification": OPTIONAL_MESSAGE,
        "claims": OPTIONAL_IDA_CLAIMS
    }

    def verify(self, **kwargs):
        super(VerifiedClaims, self).verify(**kwargs)
        verify_claims_request(self, VerifiedClaims())


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
        "value" or "values.
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
