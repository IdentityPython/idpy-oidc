from idpyoidc.message import Message
from idpyoidc.message import OPTIONAL_LIST_OF_STRINGS
from idpyoidc.message import REQUIRED_LIST_OF_STRINGS
from idpyoidc.message import SINGLE_REQUIRED_BOOLEAN


class VCProviderInfo(Message):
    c_param = {
        "verified_claims_supported": SINGLE_REQUIRED_BOOLEAN,
        "trust_frameworks_supported": REQUIRED_LIST_OF_STRINGS,
        "evidence_supported": REQUIRED_LIST_OF_STRINGS,
        "documents_supported":OPTIONAL_LIST_OF_STRINGS,
        "documents_methods_supported": OPTIONAL_LIST_OF_STRINGS,
        "documents_validation_methods_supported": OPTIONAL_LIST_OF_STRINGS,
        "documents_verification_methods_supported": OPTIONAL_LIST_OF_STRINGS,
        "electronic_records_supported": REQUIRED_LIST_OF_STRINGS,
        "claims_in_verified_claims_supported":REQUIRED_LIST_OF_STRINGS,
        "attachments_supported": OPTIONAL_LIST_OF_STRINGS,
        "digest_algorithms_supported": REQUIRED_LIST_OF_STRINGS
    }