__author__ = "Roland Hedberg"


class OidcMsgError(Exception):
    def __init__(self, errmsg, content_type="", *args):
        Exception.__init__(self, errmsg, *args)
        self.content_type = content_type


class MissingAttribute(OidcMsgError):
    pass


class UnsupportedMethod(OidcMsgError):
    pass


class MissingParameter(OidcMsgError):
    pass


class UnknownAssertionType(OidcMsgError):
    pass


class ParameterError(OidcMsgError):
    pass


class URIError(OidcMsgError):
    pass


class ParseError(OidcMsgError):
    pass


class FailedAuthentication(OidcMsgError):
    pass


class NotForMe(OidcMsgError):
    pass


class UnSupported(Exception):
    pass


class MessageException(OidcMsgError):
    pass


class IssuerMismatch(OidcMsgError):
    pass


class RestrictionError(OidcMsgError):
    pass


class InvalidRedirectUri(Exception):
    pass


class MissingPage(Exception):
    pass


class ModificationForbidden(Exception):
    pass


class RegistrationError(OidcMsgError):
    pass


class CommunicationError(OidcMsgError):
    pass


class RequestError(OidcMsgError):
    pass


class AuthnToOld(OidcMsgError):
    pass


class ImproperlyConfigured(OidcMsgError):
    pass


class SubMismatch(OidcMsgError):
    pass


class FormatError(OidcMsgError):
    pass


class VerificationError(OidcMsgError):
    pass


class MissingRequiredValue(MessageException):
    pass


class MissingSigningKey(OidcMsgError):
    pass


class TooManyValues(MessageException):
    pass


class DecodeError(MessageException):
    pass


class GrantExpired(OidcMsgError):
    pass


class OldAccessToken(OidcMsgError):
    pass


class SchemeError(MessageException):
    pass


class NotAllowedValue(MessageException):
    pass


class WrongSigningAlgorithm(MessageException):
    pass


class WrongEncryptionAlgorithm(MessageException):
    pass


class MissingRequiredAttribute(MessageException):
    def __init__(self, attr, message=""):
        Exception.__init__(self, attr)
        self.message = message

    def __str__(self):
        return "Missing required attribute '%s'" % self.args[0]


class InvalidRequest(OidcMsgError):
    pass


class KeyIOError(OidcMsgError):
    pass
