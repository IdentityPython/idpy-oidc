import base64
import logging
from typing import Callable
from typing import Dict
from typing import Optional
from typing import Union

from cryptojwt.exception import BadSignature
from cryptojwt.exception import Invalid
from cryptojwt.exception import MissingKey
from cryptojwt.jwt import JWT
from cryptojwt.jwt import utc_time_sans_frac
from cryptojwt.utils import as_bytes
from cryptojwt.utils import as_unicode

from idpyoidc.message import Message
from idpyoidc.message.oidc import JsonWebToken
from idpyoidc.message.oidc import verified_claim_name
from idpyoidc.server.constant import JWT_BEARER
from idpyoidc.server.exception import BearerTokenAuthenticationError
from idpyoidc.server.exception import ClientAuthenticationError
from idpyoidc.server.exception import InvalidClient
from idpyoidc.server.exception import InvalidToken
from idpyoidc.server.exception import ToOld
from idpyoidc.server.exception import UnknownClient
from idpyoidc.util import importer
from idpyoidc.util import sanitize

logger = logging.getLogger(__name__)

__author__ = "roland hedberg"


class ClientAuthnMethod(object):
    tag = None

    def __init__(self, upstream_get):
        """
        :param upstream_get: A method that can be used to get general server information.
        """
        self.upstream_get = upstream_get

    def _verify(
            self,
            request: Optional[Union[dict, Message]] = None,
            authorization_token: Optional[str] = None,
            endpoint=None,  # Optional[Endpoint]
            **kwargs,
    ):
        """
        Verify authentication information in a request
        :param kwargs:
        :return:
        """
        raise NotImplementedError()

    def verify(
            self,
            request: Optional[Union[dict, Message]] = None,
            authorization_token: Optional[str] = None,
            endpoint=None,  # Optional[Endpoint]
            get_client_id_from_token: Optional[Callable] = None,
            **kwargs,
    ):
        """
        Verify authentication information in a request
        :param kwargs:
        :return:
        """
        res = self._verify(
            request=request,
            authorization_token=authorization_token,
            endpoint=endpoint,
            get_client_id_from_token=get_client_id_from_token,
            **kwargs,
        )
        res["method"] = self.tag
        return res

    def is_usable(
            self,
            request: Optional[Union[dict, Message]] = None,
            authorization_token: Optional[str] = None,
    ):
        """
        Verify that this authentication method is applicable.

        :param request: The request
        :param authorization_token: The authorization token
        :return: True/False
        """
        raise NotImplementedError()


def basic_authn(authorization_token: str):
    if not authorization_token.startswith("Basic "):
        raise ClientAuthenticationError("Wrong type of authorization token")

    _tok = as_bytes(authorization_token[6:])
    # Will raise ValueError type exception if not base64 encoded
    _tok = base64.b64decode(_tok)
    part = as_unicode(_tok).split(":", 1)
    if len(part) != 2:
        raise ValueError("Illegal token")

    return dict(zip(["id", "secret"], part))


class NoneAuthn(ClientAuthnMethod):
    """
    Used for testing purposes
    """

    tag = "none"

    def is_usable(self, request=None, authorization_token=None):
        return request is not None

    def _verify(
            self,
            request: Optional[Union[dict, Message]] = None,
            authorization_token: Optional[str] = None,
            endpoint=None,  # Optional[Endpoint]
            **kwargs,
    ):
        return {"client_id": request.get("client_id")}


class PublicAuthn(ClientAuthnMethod):
    """
    Used for public clients, that don't require any form of authentication other
    than their client_id
    """

    tag = "public"

    def is_usable(self, request=None, authorization_token=None):
        return request and "client_id" in request

    def _verify(
            self,
            request: Optional[Union[dict, Message]] = None,
            authorization_token: Optional[str] = None,
            endpoint=None,  # Optional[Endpoint]
            **kwargs,
    ):
        return {"client_id": request["client_id"]}


class ClientSecretBasic(ClientAuthnMethod):
    """
    Clients that have received a client_secret value from the Authorization
    Server, authenticate with the Authorization Server in accordance with
    Section 3.2.1 of OAuth 2.0 [RFC6749] using HTTP Basic authentication scheme.
    """

    tag = "client_secret_basic"

    def is_usable(self, request=None, authorization_token=None):
        if authorization_token is not None and authorization_token.startswith("Basic "):
            return True
        return False

    def _verify(
            self,
            request: Optional[Union[dict, Message]] = None,
            authorization_token: Optional[str] = None,
            endpoint=None,  # Optional[Endpoint]
            **kwargs,
    ):
        client_info = basic_authn(authorization_token)
        _context = self.upstream_get("context")
        if _context.cdb[client_info["id"]]["client_secret"] == client_info["secret"]:
            return {"client_id": client_info["id"]}
        else:
            raise ClientAuthenticationError()


class ClientSecretPost(ClientSecretBasic):
    """
    Clients that have received a client_secret value from the Authorization
    Server, authenticate with the Authorization Server in accordance with
    Section 3.2.1 of OAuth 2.0 [RFC6749] by including the Client Credentials in
    the request body.
    """

    tag = "client_secret_post"

    def is_usable(self, request=None, authorization_token=None):
        if request is None:
            return False
        if "client_id" in request and "client_secret" in request:
            return True
        return False

    def _verify(
            self,
            request: Optional[Union[dict, Message]] = None,
            authorization_token: Optional[str] = None,
            endpoint=None,  # Optional[Endpoint]
            **kwargs,
    ):
        _context = self.upstream_get("context")
        if _context.cdb[request["client_id"]]["client_secret"] == request["client_secret"]:
            return {"client_id": request["client_id"]}
        else:
            raise ClientAuthenticationError("secrets doesn't match")


class BearerHeader(ClientSecretBasic):
    """"""

    tag = "bearer_header"

    def is_usable(self, request=None, authorization_token=None):
        if authorization_token is not None and authorization_token.startswith("Bearer "):
            return True
        return False

    def _verify(
            self,
            request: Optional[Union[dict, Message]] = None,
            authorization_token: Optional[str] = None,
            endpoint=None,  # Optional[Endpoint]
            get_client_id_from_token: Optional[Callable] = None,
            **kwargs,
    ):
        logger.debug(f"Client Auth method: {self.tag}")
        token = authorization_token.split(" ", 1)[1]
        _context = self.upstream_get("context")
        client_id = ""
        if get_client_id_from_token:
            try:
                client_id = get_client_id_from_token(_context, token, request)
            except ToOld:
                raise BearerTokenAuthenticationError("Expired token")
            except KeyError:
                raise BearerTokenAuthenticationError("Unknown token")
            except Exception as err:
                logger.debug(f"Exception in {self.tag}")

        return {"token": token, "client_id": client_id, "method": self.tag}


class BearerBody(ClientSecretPost):
    """
    Same as Client Secret Post
    """

    tag = "bearer_body"

    def is_usable(self, request=None, authorization_token=None):
        if request is not None and "access_token" in request:
            return True
        return False

    def _verify(
            self,
            request: Optional[Union[dict, Message]] = None,
            authorization_token: Optional[str] = None,
            endpoint=None,  # Optional[Endpoint]
            get_client_id_from_token: Optional[Callable] = None,
            **kwargs,
    ):
        _token = request.get("access_token")
        if _token is None:
            raise ClientAuthenticationError("No access token")

        res = {"token": _token}
        _context = self.upstream_get("context")
        _client_id = get_client_id_from_token(_context, _token, request)
        if _client_id:
            res["client_id"] = _client_id
        return res


class JWSAuthnMethod(ClientAuthnMethod):

    def is_usable(self, request=None, authorization_token=None):
        if request is None:
            return False
        if "client_assertion" in request:
            return True
        return False

    def _verify(
            self,
            request: Optional[Union[dict, Message]] = None,
            authorization_token: Optional[str] = None,
            endpoint=None,  # Optional[Endpoint]
            key_type: Optional[str] = None,
            **kwargs,
    ):
        _context = self.upstream_get("context")
        _keyjar = self.upstream_get("attribute", "keyjar")
        _jwt = JWT(_keyjar, msg_cls=JsonWebToken)
        try:
            ca_jwt = _jwt.unpack(request["client_assertion"])
        except (Invalid, MissingKey, BadSignature) as err:
            logger.info("%s" % sanitize(err))
            raise ClientAuthenticationError("Could not verify client_assertion.")

        _sign_alg = ca_jwt.jws_header.get("alg")
        if _sign_alg and _sign_alg.startswith("HS"):
            if key_type == "private_key":
                raise AttributeError("Wrong key type")
            keys = _keyjar.get("sig", "oct", ca_jwt["iss"], ca_jwt.jws_header.get("kid"))
            _secret = _context.cdb[ca_jwt["iss"]].get("client_secret")
            if _secret and keys[0].key != as_bytes(_secret):
                raise AttributeError("Oct key used for signing not client_secret")
        else:
            if key_type == "client_secret":
                raise AttributeError("Wrong key type")

        authtoken = sanitize(ca_jwt.to_dict())
        logger.debug("authntoken: {}".format(authtoken))

        if endpoint is None or not endpoint:
            if _context.issuer in ca_jwt["aud"]:
                pass
            else:
                raise InvalidToken("Not for me!")
        else:
            if set(ca_jwt["aud"]).intersection(endpoint.allowed_target_uris()):
                pass
            else:
                raise InvalidToken("Not for me!")

        # If there is a jti use it to make sure one-time usage is true
        _jti = ca_jwt.get("jti")
        if _jti:
            _key = "{}:{}".format(ca_jwt["iss"], _jti)
            if _key in _context.jti_db:
                raise InvalidToken("Have seen this token once before")
            else:
                _context.jti_db[_key] = utc_time_sans_frac()

        request[verified_claim_name("client_assertion")] = ca_jwt
        client_id = kwargs.get("client_id") or ca_jwt["iss"]

        return {"client_id": client_id, "jwt": ca_jwt}


class ClientSecretJWT(JWSAuthnMethod):
    """
    Clients that have received a client_secret value from the Authorization
    Server create a JWT using an HMAC SHA algorithm, such as HMAC SHA-256.
    The HMAC (Hash-based Message Authentication Code) is calculated using the
    bytes of the UTF-8 representation of the client_secret as the shared key.
    """

    tag = "client_secret_jwt"

    def _verify(
            self,
            request: Optional[Union[dict, Message]] = None,
            authorization_token: Optional[str] = None,
            endpoint=None,  # Optional[Endpoint]
            **kwargs,
    ):
        res = super()._verify(
            request=request, key_type="client_secret", endpoint=endpoint, **kwargs
        )
        # Verify that a HS alg was used
        return res


class PrivateKeyJWT(JWSAuthnMethod):
    """
    Clients that have registered a public key sign a JWT using that key.
    """

    tag = "private_key_jwt"

    def _verify(
            self,
            request: Optional[Union[dict, Message]] = None,
            authorization_token: Optional[str] = None,
            endpoint=None,  # Optional[Endpoint]
            **kwargs,
    ):
        res = super()._verify(
            request=request,
            authorization_token=authorization_token,
            endpoint=endpoint,
            **kwargs,
            key_type="private_key",
        )
        # Verify that an RS or ES alg was used ?
        return res


class RequestParam(ClientAuthnMethod):
    tag = "request_param"

    def is_usable(self, request=None, authorization_token=None):
        if request and "request" in request:
            return True

    def _verify(
            self,
            request: Optional[Union[dict, Message]] = None,
            authorization_token: Optional[str] = None,
            endpoint=None,  # Optional[Endpoint]
            **kwargs,
    ):
        _context = self.upstream_get("context")
        _jwt = JWT(self.upstream_get("attribute", "keyjar"), msg_cls=JsonWebToken)
        try:
            _jwt = _jwt.unpack(request["request"])
        except (Invalid, MissingKey, BadSignature) as err:
            logger.info("%s" % sanitize(err))
            raise ClientAuthenticationError("Could not verify client_assertion.")

        # If there is a jti use it to make sure one-time usage is true
        _jti = _jwt.get("jti")
        if _jti:
            _key = "{}:{}".format(_jwt["iss"], _jti)
            if _key in _context.jti_db:
                raise InvalidToken("Have seen this token once before")
            else:
                _context.jti_db[_key] = utc_time_sans_frac()

        request[verified_claim_name("client_assertion")] = _jwt
        client_id = kwargs.get("client_id") or _jwt["iss"]

        return {"client_id": client_id, "jwt": _jwt}


class PushedAuthorization(ClientAuthnMethod):
    # The premise here is that there has been a client authentication at the
    # pushed authorization endpoint
    tag = "pushed_authz"

    def is_usable(self, request=None, authorization_token=None):
        _request_uri = request.get("request_uri", None)
        if _request_uri:
            _context = self.upstream_get("context")
            if _request_uri.startswith("urn:uuid:") and _request_uri in _context.par_db:
                return True

    def _verify(
            self,
            request: Optional[Union[dict, Message]] = None,
            authorization_token: Optional[str] = None,
            endpoint=None,  # Optional[Endpoint]
            **kwargs,
    ):
        client_id = request["client_id"]
        return {"client_id": client_id}


CLIENT_AUTHN_METHOD = dict(
    client_secret_basic=ClientSecretBasic,
    client_secret_post=ClientSecretPost,
    bearer_header=BearerHeader,
    bearer_body=BearerBody,
    client_secret_jwt=ClientSecretJWT,
    private_key_jwt=PrivateKeyJWT,
    request_param=RequestParam,
    public=PublicAuthn,
    none=NoneAuthn,
    pushed_authz=PushedAuthorization
)

TYPE_METHOD = [(JWT_BEARER, JWSAuthnMethod)]


def valid_client_secret(cinfo):
    if "client_secret" in cinfo:
        eta = cinfo.get("client_secret_expires_at", 0)
        if eta != 0 and eta < utc_time_sans_frac():
            return False
    return True


def verify_client(
        request: Union[dict, Message],
        http_info: Optional[dict] = None,
        get_client_id_from_token: Optional[Callable] = None,
        endpoint=None,  # Optional[Endpoint]
        also_known_as: Optional[Dict[str, str]] = None,
        **kwargs,
) -> dict:
    """
    Initiated Guessing !

    :param also_known_as:
    :param endpoint: Endpoint instance
    :param context: EndpointContext instance
    :param request: The request
    :param http_info: Client authentication information
    :param get_client_id_from_token: Function that based on a token returns a client id.
    :return: dictionary containing client id, client authentication method and
        possibly access token.
    """

    if http_info and "headers" in http_info:
        authorization_token = http_info["headers"].get("authorization")
        if not authorization_token:
            authorization_token = http_info["headers"].get("Authorization")
    else:
        authorization_token = None

    auth_info = {}

    _context = endpoint.upstream_get("context")
    methods = getattr(_context, "client_authn_methods", None)

    client_id = None
    allowed_methods = getattr(endpoint, "client_authn_method")
    if not allowed_methods:
        allowed_methods = list(methods.keys())  # If not specific for this endpoint then all

    logger.info(f"Allowed client authentication methods: {allowed_methods}")

    _method = None
    _cdb = _cinfo = None
    _tested = []
    for _method in (methods[meth] for meth in allowed_methods):
        if not _method.is_usable(request=request, authorization_token=authorization_token):
            continue
        try:
            logger.info(f"Verifying client authentication using {_method.tag}")
            _tested.append(_method.tag)
            auth_info = _method.verify(
                keyjar=endpoint.upstream_get("attribute", "keyjar"),
                request=request,
                authorization_token=authorization_token,
                endpoint=endpoint,
                get_client_id_from_token=get_client_id_from_token,
            )
        # except (BearerTokenAuthenticationError, ClientAuthenticationError):
        #     raise
        except Exception as err:
            logger.info("Verifying auth using {} failed: {}".format(_method.tag, err))
            continue

        logger.debug(f"Verify returned: {auth_info}")

        if auth_info.get("method") == "none" and auth_info.get("client_id") is None:
            break

        client_id = auth_info.get("client_id")
        if client_id is None:
            raise ClientAuthenticationError("Failed to verify client")

        if also_known_as:
            client_id = also_known_as[client_id]
            auth_info["client_id"] = client_id

        _get_client_info = kwargs.get("get_client_info", None)
        if _get_client_info:
            _cinfo = _get_client_info(client_id, endpoint)
        else:
            _cdb = getattr(_context, "cdb", None)
            try:
                _cinfo = _cdb[client_id]
            except KeyError:
                _auto_reg = getattr(endpoint, "automatic_registration", None)
                if _auto_reg:
                    _cinfo = {"client_id": client_id}
                    _cdb[client_id] = _cinfo
                else:
                    raise UnknownClient("Unknown Client ID")

        if not _cinfo:
            raise UnknownClient("Unknown Client ID")

        if not valid_client_secret(_cinfo):
            logger.warning("Client secret has expired.")
            raise InvalidClient("Not valid client")

        # Validate that the used method is allowed for this client/endpoint
        client_allowed_methods = _cinfo.get(
            f"{endpoint.endpoint_name}_client_authn_method", _cinfo.get("client_authn_method", None)
        )
        if client_allowed_methods is not None and auth_info["method"] not in client_allowed_methods:
            logger.info(
                f"Allowed methods for client: {client_id} at endpoint: {endpoint.name} are: "
                f"`{', '.join(client_allowed_methods)}`"
            )
            auth_info = {}
            continue
        break

    logger.debug(f"Authn methods applied")
    logger.debug(f"Method tested: {_tested}")

    # store what authn method was used
    if "method" in auth_info and client_id and _cdb:
        _request_type = request.__class__.__name__
        _used_authn_method = _cinfo.get("auth_method")
        if _used_authn_method:
            _cdb[client_id]["auth_method"][_request_type] = auth_info["method"]
        else:
            _cdb[client_id]["auth_method"] = {_request_type: auth_info["method"]}

    return auth_info


def client_auth_setup(upstream_get, auth_set=None):
    if auth_set is None:
        auth_set = CLIENT_AUTHN_METHOD
    else:
        auth_set.update(CLIENT_AUTHN_METHOD)
    res = {}

    for name, cls in auth_set.items():
        if isinstance(cls, str):
            cls = importer(cls)
        res[name] = cls(upstream_get)
    return res


def get_client_authn_methods():
    return list(CLIENT_AUTHN_METHOD.keys())
