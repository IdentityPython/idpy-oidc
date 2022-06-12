import abc
import base64
import datetime
import json

from cryptojwt.utils import importer

from idpyoidc.exception import MissingRequiredAttribute
from idpyoidc.message import Message
from idpyoidc.message import OPTIONAL_LIST_OF_MESSAGES
from idpyoidc.message import OPTIONAL_LIST_OF_STRINGS
from idpyoidc.message import OPTIONAL_MESSAGE
from idpyoidc.message import SINGLE_OPTIONAL_INT
from idpyoidc.message import SINGLE_OPTIONAL_JSON
from idpyoidc.message import SINGLE_OPTIONAL_STRING
from idpyoidc.message import SINGLE_REQUIRED_STRING
from idpyoidc.message import msg_list_ser
from idpyoidc.message import msg_ser
from idpyoidc.message.oauth2 import error_chars
from idpyoidc.message.oidc import AddressClaim
from idpyoidc.message.oidc import ClaimsRequest
from idpyoidc.message.oidc import OpenIDSchema
from idpyoidc.message.oidc import claims_request_deser
from idpyoidc.message.oidc import deserialize_from_one_of
from idpyoidc.message.oidc import msg_ser_json
from idpyoidc.util import claims_match


def type_compare(typ, request, response):
    if isinstance(typ, abc.ABCMeta):
        return response.match_request(request)
    elif isinstance(typ, list):
        _list = []
        if isinstance(typ[0], abc.ABCMeta):
            for _req in request:
                for _resp in response:
                    _res = _resp.match_request(_req)
                    if _res:
                        _list.append(_res)
        else:
            for _req in request:
                for _resp in response:
                    _res = type_compare(typ[0], _resp, _req)
                    if _res:
                        _list.append(_res)
        return _list
    else:
        if claims_match(response, request):
            return response


class IAMessage(Message):
    def __cmp__(self, other):
        for key, val in self.items():
            _v = other.get(key)
            if _v and _v == val:
                continue
            else:
                return False

    def match_request(self, request: dict):
        """
        Return a new set with elements common to the set and all others.
        """
        _matches = {}
        for attr, val in self.items():
            try:
                _v = request[attr]
            except KeyError:
                pass
            else:
                if _v is None:
                    _matches[attr] = val
                else:
                    if _v:
                        _comp = type_compare(self.c_param[attr][0], _v, val)
                        if _comp:
                            _matches[attr] = _comp
        if _matches:
            _res = self.__class__()
            for k, v in _matches.items():
                _res.set(k, v)
            return _res
        else:
            return None


class PlaceOfBirth(IAMessage):
    c_param = {
        "country": SINGLE_REQUIRED_STRING,
        "region": SINGLE_OPTIONAL_STRING,
        "locality": SINGLE_REQUIRED_STRING
    }


def place_of_birth_deser(val, sformat="json"):
    # never 'urlencoded'
    if sformat == "urlencoded":
        sformat = "json"

    if sformat == "json":
        if not isinstance(val, str):
            val = json.dumps(val)
            sformat = "json"
    elif sformat == 'dict':
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
        try:
            _int_val = int(val)
            to_iso8601_2004_time(_int_val)
        except:
            # Should do a sanity check
            return val
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


class Place(IAMessage):
    c_param = {
        "country": OPTIONAL_LIST_OF_STRINGS,
        "region": SINGLE_OPTIONAL_STRING,
        "locality": SINGLE_REQUIRED_STRING
    }


def place_deser(val, sformat="json", lev=0):
    return deserialize_from_one_of(val, Place, sformat)


SINGLE_OPTIONAL_PLACE = (Place, False, msg_ser, place_deser, False)


class IdentityAssuranceClaims(IAMessage, OpenIDSchema):
    c_param = OpenIDSchema.c_param.copy()
    c_param.update({
        "place_of_birth": SINGLE_OPTIONAL_PLACE,
        "nationalities": OPTIONAL_LIST_OF_STRINGS,
        "birth_family_name": SINGLE_OPTIONAL_STRING,
        "birth_given_name": SINGLE_OPTIONAL_STRING,
        "birth_middle_name": SINGLE_OPTIONAL_STRING,
        "salutation": SINGLE_OPTIONAL_STRING,
        "title": SINGLE_OPTIONAL_STRING
    })


def identity_assurance_claims_deser(val, sformat="urlencoded"):
    if isinstance(val, Message):
        return val
    elif sformat in ["dict", "json"]:
        if not isinstance(val, str):
            val = json.dumps(val)
            sformat = "json"
    return IdentityAssuranceClaims().deserialize(val, sformat)


OPTIONAL_IDA_CLAIMS = (
    IdentityAssuranceClaims, False, msg_ser, identity_assurance_claims_deser, False)


class Verifier(IAMessage):
    c_param = {
        "organization": SINGLE_REQUIRED_STRING,
        "txn": SINGLE_REQUIRED_STRING
    }


def verifier_deser(val, sformat="urlencoded"):
    if isinstance(val, Message):
        return val
    elif sformat in ["dict", "json"]:
        if not isinstance(val, str):
            val = json.dumps(val)
            sformat = "json"
    return Verifier().deserialize(val, sformat)


REQUIRED_VERIFIER = (Verifier, True, msg_ser, verifier_deser, False)
OPTIONAL_VERIFIER = (Verifier, False, msg_ser, verifier_deser, False)


class Issuer(AddressClaim, IAMessage):
    c_param = AddressClaim.c_param.copy()
    c_param.update({
        "name": SINGLE_OPTIONAL_STRING,
        "country_code": SINGLE_OPTIONAL_STRING,
        "jurisdiction": SINGLE_OPTIONAL_STRING
    })


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


class DocumentDetails(IAMessage):
    c_param = {
        "type": SINGLE_REQUIRED_STRING,
        "document_number": SINGLE_OPTIONAL_STRING,
        "personal_number": SINGLE_OPTIONAL_STRING,
        "serial_number": SINGLE_OPTIONAL_STRING,
        "date_of_issuance": OPTIONAL_TIME_STAMP,
        "date_of_expiry": OPTIONAL_TIME_STAMP,
        "issuer": REQUIRED_ISSUER,
    }

    def intersection(self, *other):
        """
        Return a new set with elements common to the set and all others.
        """
        _common = {v: True for v in self.keys()}
        for attr, val in self.items():
            for o in other:
                _v = o.get(attr)
                if _v and type_compare(self.c_param[attr], _v, val):
                    continue
                else:
                    _common[attr] = False
        _common_attrs = {a: v for a, v in _common if v is True}
        return DocumentDetails(**_common_attrs)


def document_details_deser(val, sformat="urlencoded"):
    return deserialize_from_one_of(val, DocumentDetails, sformat)


OPTIONAL_DOCUMENT_DETAILS = (DocumentDetails, False, msg_ser, document_details_deser, False)


class ValidationMethod(IAMessage):
    c_param = {
        "type": SINGLE_REQUIRED_STRING,
        "policy": SINGLE_OPTIONAL_STRING,
        "procedure": SINGLE_OPTIONAL_STRING,
        "status": SINGLE_OPTIONAL_STRING
    }

    def intersection(self, *other):
        """
        Return a new set with elements common to the set and all others.
        """
        pass


def validation_method_deser(val, sformat="json"):
    return deserialize_from_one_of(val, ValidationMethod, sformat)


OPTIONAL_VALIDATION_METHOD = (ValidationMethod, False, msg_ser, validation_method_deser, False)


class VerificationMethod(IAMessage):
    c_param = {
        "type": SINGLE_REQUIRED_STRING,
        "policy": SINGLE_OPTIONAL_STRING,
        "procedure": SINGLE_OPTIONAL_STRING,
        "status": SINGLE_OPTIONAL_STRING
    }


def verification_method_deser(val, sformat="json"):
    return deserialize_from_one_of(val, VerificationMethod, sformat)


OPTIONAL_VERIFICATION_METHOD = (
    VerificationMethod, False, msg_ser, verification_method_deser, False)


# ************* Record *****************

class Record(IAMessage):
    c_param = {
        "type": SINGLE_REQUIRED_STRING,
        "personal_number": SINGLE_OPTIONAL_STRING,
        "created_at": OPTIONAL_TIME_STAMP,
        "date_of_expiry": OPTIONAL_TIME_STAMP,
        "source": OPTIONAL_ISSUER
    }


def record_deser(val, sformat="json"):
    return deserialize_from_one_of(val, Record, sformat)


OPTIONAL_RECORD = (Record, False, msg_ser, record_deser, False)


# ************* Voucher *****************


class Voucher(AddressClaim):
    c_param = AddressClaim.c_param.copy()
    c_param.update({
        "name": SINGLE_OPTIONAL_STRING,
        "birthdate": SINGLE_OPTIONAL_STRING,
        "occupation": SINGLE_OPTIONAL_STRING,
        "organization": SINGLE_OPTIONAL_STRING
    })


def voucher_deser(val, sformat="json"):
    return deserialize_from_one_of(val, Voucher, sformat)


OPTIONAL_VOUCHER = (Voucher, False, msg_ser, voucher_deser, False)


# ************* Attestation *****************

class Attestation(IAMessage):
    c_param = {
        "type": SINGLE_REQUIRED_STRING,
        "reference_number": SINGLE_OPTIONAL_STRING,
        "personal_number": SINGLE_OPTIONAL_STRING,
        "date_of_issuance": OPTIONAL_TIME_STAMP,
        "date_of_expiry": OPTIONAL_TIME_STAMP,
        "voucher": OPTIONAL_VOUCHER,
    }


def attestation_deser(val, sformat="json"):
    return deserialize_from_one_of(val, Attestation, sformat)


OPTIONAL_ATTESTATION = (Attestation, False, msg_ser, attestation_deser, False)


# ************* Evidence *****************

def verify_attachments(attachments, **kwargs):
    _res = []
    for item in attachments:
        if "url" in item:
            _inst = ExternalAttachment(**item)
        elif "content" in item:
            _inst = Attachment(**item)
        else:
            raise ValueError("Required claim missing in attachment")
        _inst.verify(**kwargs)
        _res.append(_inst)
    return _res


class Evidence(IAMessage):
    c_param = {
        "type": SINGLE_REQUIRED_STRING,
        "attachments": OPTIONAL_LIST_OF_MESSAGES
    }

    def verify(self, **kwargs):
        _type = self.get("type")
        if not _type:
            raise MissingRequiredAttribute("type")

        _args = dict(self.items())
        if _type == "document":
            _evidence_type = Document(**_args)
            _evidence_type.verify(**kwargs)
        elif _type == "electronic_record":
            _evidence_type = ElectronicRecord(**_args)
            _evidence_type.verify(**kwargs)
        elif _type == "utility_bill":
            _evidence_type = UtilityBill(**_args)
            _evidence_type.verify(**kwargs)
        elif _type == "vouch":
            _evidence_type = Vouch(**_args)
            _evidence_type.verify(**kwargs)
        elif _type == "electronic_signature":
            _evidence_type = ElectronicSignature(**_args)
            _evidence_type.verify(**kwargs)
        else:
            raise ValueError("Unknown type")
        self._evidence_type = _evidence_type

        _at_list = self.get("attachments")
        if _at_list:
            self._evidence_type.update({"attachments": verify_attachments(_at_list, **kwargs)})

    def intersection(self, *other):
        """
        Return a new set with elements common to the set and all others.
        """
        pass


def evidence_deser(val, sformat="urlencoded"):
    return deserialize_from_one_of(val, Evidence, sformat)


def evidence_list_deser(val, sformat="urlencoded", lev=0):
    if isinstance(val, dict):
        return [IAMessage(**val)]

    _res = [evidence_deser(v, sformat) for v in val]
    return _res


OPTIONAL_EVIDENCE_LIST = ([Evidence], False, msg_list_ser, evidence_list_deser, True)


def do_evidence(evidence, **kwargs):
    _res = []
    for _ev in evidence:
        _inst = Evidence(**_ev)
        _inst.verify(**kwargs)
        _res.append(_inst._evidence_type)
    return _res


class Document(Evidence):
    c_param = Evidence.c_param.copy()
    c_param.update({
        "validation_method": OPTIONAL_VALIDATION_METHOD,
        "verification_method": OPTIONAL_VERIFICATION_METHOD,
        "method": SINGLE_OPTIONAL_STRING,
        "verifier": OPTIONAL_VERIFIER,
        "time": OPTIONAL_TIME_STAMP,
        "document_details": OPTIONAL_DOCUMENT_DETAILS
    })

    def verify(self, **kwargs):
        IAMessage.verify(self, **kwargs)

    def intersection(self, *other):
        """
        Return a new set with elements common to the set and all others.
        """
        pass


class ElectronicRecord(Evidence):
    c_param = Evidence.c_param.copy()
    c_param.update({
        "validation_method": OPTIONAL_VALIDATION_METHOD,
        "verification_method": OPTIONAL_VERIFICATION_METHOD,
        "method": SINGLE_OPTIONAL_STRING,
        "verifier": OPTIONAL_VERIFIER,
        "time": OPTIONAL_TIME_STAMP,
        "record": OPTIONAL_RECORD
    })

    def verify(self, **kwargs):
        IAMessage.verify(self, **kwargs)

    def intersection(self, *other):
        """
        Return a new set with elements common to the set and all others.
        """
        pass


class Vouch(Evidence):
    c_param = Evidence.c_param.copy()
    c_param.update({
        "validation_method": OPTIONAL_VALIDATION_METHOD,
        "verification_method": OPTIONAL_VERIFICATION_METHOD,
        "method": SINGLE_OPTIONAL_STRING,
        "verifier": OPTIONAL_VERIFIER,
        "time": OPTIONAL_TIME_STAMP,
        "attestation": OPTIONAL_ATTESTATION
    })

    def verify(self, **kwargs):
        IAMessage.verify(self, **kwargs)


class ElectronicSignature(Evidence):
    c_param = Evidence.c_param.copy()
    c_param.update({
        "signature_type": SINGLE_REQUIRED_STRING,
        "issuer": SINGLE_REQUIRED_STRING,
        "serial_number": SINGLE_REQUIRED_STRING,
        "created_at": OPTIONAL_TIME_STAMP
    })

    def verify(self, **kwargs):
        IAMessage.verify(self, **kwargs)


class Attachment(IAMessage):
    c_param = {
        "desc": SINGLE_OPTIONAL_STRING,
        "content_type": SINGLE_REQUIRED_STRING,
        "content": SINGLE_REQUIRED_STRING
    }

    def verify(self, **kwargs):
        _content = self.get("content")
        if _content:
            base64.b64decode(_content)


class Digest(IAMessage):
    c_param = {
        "alg": SINGLE_REQUIRED_STRING,
        "value": SINGLE_REQUIRED_STRING
    }


def digest_deser(val, sformat="json"):
    return deserialize_from_one_of(val, Digest, sformat)


REQUIRED_DIGEST = (Digest, True, msg_ser, digest_deser, False)


class ExternalAttachment(IAMessage):
    c_param = {
        "desc": SINGLE_OPTIONAL_STRING,
        "url": SINGLE_REQUIRED_STRING,
        "access_token": SINGLE_OPTIONAL_STRING,
        "expires_in": SINGLE_OPTIONAL_INT,
        "digest": REQUIRED_DIGEST
    }


class Provider(AddressClaim):
    c_param = AddressClaim.c_param.copy()
    c_param.update({
        "name": SINGLE_OPTIONAL_STRING,
    })


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
    c_param.update({
        "provider": REQUIRED_PROVIDER,
        "date": OPTIONAL_TIME_STAMP
    })


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
    c_param.update({
        "issuer": SINGLE_REQUIRED_STRING,
        "serial_number": SINGLE_REQUIRED_STRING,
        "created_at": REQURIED_TIME_STAMP
    })


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
    return deserialize_from_one_of(val, AddressClaim, sformat)


OPTIONAL_ADDRESS = (AddressClaim, False, msg_ser, address_deser, False)


class AssuranceProcess(IAMessage):
    c_param = {
        "policy": SINGLE_OPTIONAL_STRING,
        "procedure": SINGLE_OPTIONAL_STRING,
        "status": SINGLE_OPTIONAL_STRING
    }


def assurance_process_deser(val, sformat="json"):
    return deserialize_from_one_of(val, AssuranceProcess, sformat)


OPTIONAL_ASSURANCE_PROCESS = (AssuranceProcess, False, msg_ser, assurance_process_deser, False)


class VerificationElement(IAMessage):
    c_param = {
        "trust_framework": SINGLE_REQUIRED_STRING,
        "assurance_level": SINGLE_OPTIONAL_STRING,
        "assurance_process": OPTIONAL_ASSURANCE_PROCESS,
        "time": OPTIONAL_TIME_STAMP,
        "verification_process": SINGLE_OPTIONAL_STRING,
        "evidence": OPTIONAL_EVIDENCE_LIST,
    }

    def verify(self, **kwargs):
        IAMessage.verify(self, **kwargs)
        _evidence = self.get("evidence")
        if _evidence:
            _interm = do_evidence(_evidence, **kwargs)
            self.update({"evidence": _interm})

    def intersection(self, *other):
        """
        Return a new set with elements common to the set and all others.
        """
        pass


def verification_element_deser(val, sformat="urlencoded"):
    if isinstance(val, Message):
        return val
    elif sformat in ["dict", "json"]:
        if not isinstance(val, str):
            val = json.dumps(val)
            sformat = "json"
    return VerificationElement().deserialize(val, sformat)


OPTIONAL_VERIFICATION_ELEMENT = (
    VerificationElement, False, msg_ser, verification_element_deser, False)


class VerifiedClaim(IAMessage):
    c_param = {
        "verification": OPTIONAL_VERIFICATION_ELEMENT,
        "claims": OPTIONAL_IDA_CLAIMS
    }

    def verify(self, **kwargs):
        Message.verify(self, **kwargs)
        _verification = self.get("verification")
        if _verification:
            _verification.verify()

    def intersection(self, *other):
        """
        Return a new set with elements common to the set and all others.
        """
        pass


SINGLE_OPTIONAL_CLAIMSREQ = (ClaimsRequest, False, msg_ser_json, claims_request_deser, False)

OPTIONAL_VERIFICATION_REQUEST = OPTIONAL_MESSAGE


def do_verified_claims(msg):
    _item = msg.get("verified_claims")
    if isinstance(_item, list):
        return [VerifiedClaim(**_vc) for _vc in _item]
    elif isinstance(_item, dict):
        return [VerifiedClaim(**_item)]

    return []


def verified_claim_element_deser(val, sformat="json"):
    if isinstance(val, Message):
        return val
    if sformat == "dict":
        if isinstance(val, dict):
            return VerifiedClaim(**val)
        if isinstance(val, str):
            _val = json.loads(val)
            return VerifiedClaim(**_val)
    if not isinstance(val, str):
        val = json.dumps(val)
        sformat = "json"
    return VerifiedClaim().deserialize(val, sformat)


def verified_claim_element_list_deser(val, sformat="json"):
    if isinstance(val, list):
        return [verified_claim_element_deser(v, sformat) for v in val]
    else:
        return [verified_claim_element_deser(val, sformat)]


OPTIONAL_LIST_OF_VERIFIED_CLAIMS = (
    [VerifiedClaim], False, msg_list_ser, verified_claim_element_list_deser, False)


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
                raise ValueError(f"{key}: '{_val}'")
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


class VerificationElementRequest(IAMessage):
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
    VerificationElementRequest, False, msg_ser, verification_element_request_deser, True)


class VerifiedClaimsRequest(IAMessage):
    c_param = {
        "verification": OPTIONAL_MESSAGE,
        "claims": OPTIONAL_IDA_CLAIMS
    }

    def verify(self, **kwargs):
        super(VerifiedClaimsRequest, self).verify(**kwargs)
        verify_claims_request(self, VerifiedClaim())


class IDAClaimsRequest(ClaimsRequest):
    def verify(self, **kwargs):
        super(IDAClaimsRequest, self).verify(**kwargs)
        _vc = self.get("verified_claims")
        if _vc:
            _vci = VerifiedClaimsRequest(**_vc)
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
                            "Wrong type of value '{}':'{}'".format(key, type(value.base_class)))
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


class EndUser(OpenIDSchema, IAMessage):
    c_param = OpenIDSchema.c_param.copy()
    c_param.update({
        "place_of_birth": SINGLE_OPTIONAL_JSON,
        "nationalities": OPTIONAL_LIST_OF_STRINGS,
        "birth_family_name": SINGLE_OPTIONAL_STRING,
        "birth_given_name": SINGLE_OPTIONAL_STRING,
        "birth_middle_name": SINGLE_OPTIONAL_STRING,
        "salutation": SINGLE_OPTIONAL_STRING,
        "title": SINGLE_OPTIONAL_STRING,
        "msisdn": SINGLE_OPTIONAL_STRING,
        "also_known_as": SINGLE_OPTIONAL_STRING,
        "verified_claims": OPTIONAL_LIST_OF_VERIFIED_CLAIMS
    })

    def verify(self, **kwargs):
        super(EndUser, self).verify(**kwargs)

        if "place_of_birth" in self:
            if set(self["place_of_birth"].keys()).issubset({"country", "region", "locality"}):
                _set = set(self["place_of_birth"].keys()).difference(
                    {"country", "region", "locality"})
                raise ValueError(f"Illegal member in 'place_of_birth': {_set}")


class ExtendedAddressClaim(AddressClaim):
    c_param = AddressClaim.c_param.copy()
    c_param.update({
        "country_code": SINGLE_OPTIONAL_STRING
    })
