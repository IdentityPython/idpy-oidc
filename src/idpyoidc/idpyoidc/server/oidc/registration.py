import hashlib
import hmac
import json
import logging
import secrets
from typing import List
from urllib.parse import urlencode
from urllib.parse import urlparse

from cryptojwt.jws.utils import alg2keytype
from cryptojwt.utils import as_bytes

from idpyoidc.exception import MessageException
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.message.oidc import ClientRegistrationErrorResponse
from idpyoidc.message.oidc import RegistrationRequest
from idpyoidc.message.oidc import RegistrationResponse
from idpyoidc.server.endpoint import Endpoint
from idpyoidc.server.exception import CapabilitiesMisMatch
from idpyoidc.server.exception import InvalidRedirectURIError
from idpyoidc.server.exception import InvalidSectorIdentifier
from idpyoidc.time_util import utc_time_sans_frac
from idpyoidc.util import importer
from idpyoidc.util import rndstr
from idpyoidc.util import sanitize
from idpyoidc.util import split_uri

logger = logging.getLogger(__name__)


def match_sp_sep(first, second):
    """
    Verify that all the values in 'first' appear in 'second'.
    The values can either be in the form of lists or as space separated
    items.

    :param first:
    :param second:
    :return: True/False
    """
    if isinstance(first, list):
        one = [set(v.split(" ")) for v in first]
    else:
        one = [{v} for v in first.split(" ")]

    if isinstance(second, list):
        other = [set(v.split(" ")) for v in second]
    else:
        other = [{v} for v in second.split(" ")]

    # all values in one must appear in other
    if any(rt not in other for rt in one):
        return False
    return True


def verify_url(url: str, urlset: List[list]) -> bool:
    part = urlparse(url)

    for reg, qp in urlset:
        _part = urlparse(reg)
        if part.scheme == _part.scheme and part.netloc == _part.netloc:
            return True

    return False


def secret(seed: str, sid: str):
    msg = "{}{}{}".format(utc_time_sans_frac(), secrets.token_urlsafe(16), sid).encode("utf-8")
    csum = hmac.new(as_bytes(seed), msg, hashlib.sha224)
    return csum.hexdigest()


def comb_uri(args):
    redirect_uris = args.get("redirect_uris")
    if redirect_uris:
        val = []
        for base, query_dict in redirect_uris:
            if query_dict:
                query_string = urlencode([(key, v) for key in query_dict for v in query_dict[key]])
                val.append(f"{base}?{query_string}")
            else:
                val.append(base)

        args["redirect_uris"] = val

    post_logout_redirect_uri = args.get("post_logout_redirect_uri")
    if post_logout_redirect_uri:
        base, query_dict = post_logout_redirect_uri
        if query_dict:
            query_string = urlencode([(key, v) for key in query_dict for v in query_dict[key]])
            val = f"{base}?{query_string}"
        else:
            val = base
        args["post_logout_redirect_uri"] = val

    request_uris = args.get("request_uris")
    if request_uris:
        val = []
        for base, frag in request_uris:
            if frag:
                val.append("{}#{}".format(base, frag))
            else:
                val.append(base)
        args["request_uris"] = val


def random_client_id(length: int = 16, reserved: list = None, **kwargs):
    # create new id och secret
    client_id = rndstr(16)
    # cdb client_id MUST be unique!
    if reserved:
        while client_id in reserved:
            client_id = rndstr(16)
    return client_id


class Registration(Endpoint):
    request_cls = RegistrationRequest
    response_cls = RegistrationResponse
    error_response = ClientRegistrationErrorResponse
    request_format = "json"
    request_placement = "body"
    response_format = "json"
    endpoint_name = "registration_endpoint"
    name = "registration"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Those that use seed wants bytes but I can only store str.
        # seed
        _seed = kwargs.get("seed") or rndstr(32)
        self.seed = as_bytes(_seed)

    def match_claim(self, claim, val):
        _context = self.upstream_get("context")

        # Use my defaults
        _my_key = _context.claims.register2preferred.get(claim, claim)
        try:
            _val = _context.provider_info[_my_key]
        except KeyError:
            return val

        try:
            _claim_spec = _context.claims.registration_response.c_param[claim]
        except KeyError:  # something I don't know anything about
            return None

        if _val:
            if isinstance(_claim_spec[0], list):
                if isinstance(val, str):
                    if val in _val:
                        return val
                else:
                    _ret = list(set(_val).intersection(set(val)))
                    if len(_ret) > 0:
                        return _ret
                    else:
                        raise CapabilitiesMisMatch(_my_key)
            else:
                if isinstance(_val, list):
                    if val in _val:
                        return val
                elif val == _val:
                    return val

        return None

    def filter_client_request(self, request: dict) -> dict:
        _args = {}
        _context = self.upstream_get("context")
        for key, val in request.items():
            if key not in _context.claims.register2preferred:
                _args[key] = val
                continue

            _val = self.match_claim(key, val)
            if _val:
                _args[key] = _val
            else:
                logger.error(f"Capabilities mismatch: {key}={val} not supported")
        return _args

    def do_client_registration(self, request, client_id, ignore=None):
        if ignore is None:
            ignore = []
        _context = self.upstream_get("context")
        _cinfo = _context.cdb[client_id].copy()
        logger.debug("_cinfo: %s" % sanitize(_cinfo))

        for key, val in request.items():
            if key not in ignore:
                _cinfo[key] = val

        _uri = request.get("post_logout_redirect_uri")
        if _uri:
            if urlparse(_uri).fragment:
                err = self.error_cls(
                    error="invalid_configuration_parameter",
                    error_description="post_logout_redirect_uri contains fragment",
                )
                return err
            _cinfo["post_logout_redirect_uri"] = split_uri(_uri)

        if "redirect_uris" in request:
            try:
                ruri = self.verify_redirect_uris(request)
                _cinfo["redirect_uris"] = ruri
            except InvalidRedirectURIError as e:
                return self.error_cls(error="invalid_redirect_uri", error_description=str(e))

        if "request_uris" in request:
            _uris = []
            for uri in request["request_uris"]:
                _up = urlparse(uri)
                if _up.query:
                    err = self.error_cls(
                        error="invalid_configuration_parameter",
                        error_description="request_uris contains query part",
                    )
                    return err
                if _up.fragment:
                    # store base and fragment
                    _uris.append(uri.split("#"))
                else:
                    _uris.append([uri, ""])
            _cinfo["request_uris"] = _uris

        if "sector_identifier_uri" in request:
            try:
                (
                    _cinfo["si_redirects"],
                    _cinfo["sector_id"],
                ) = self._verify_sector_identifier(request)
            except InvalidSectorIdentifier as err:
                return ResponseMessage(
                    error="invalid_configuration_parameter", error_description=str(err)
                )

        for item in ["policy_uri", "logo_uri", "tos_uri"]:
            if item in request:
                if verify_url(request[item], _cinfo["redirect_uris"]):
                    _cinfo[item] = request[item]
                else:
                    return ResponseMessage(
                        error="invalid_configuration_parameter",
                        error_description="%s pointed to illegal URL" % item,
                    )

        _keyjar = self.upstream_get("attribute", "keyjar")
        # Do I have the necessary keys
        for item in ["id_token_signed_response_alg", "userinfo_signed_response_alg"]:
            if item in request:
                _claim = _context.claims.register2preferred[item]
                _support = _context.provider_info.get(_claim)
                if _support is None:
                    logger.warning(f'Lacking support for "{item}"')
                    del _cinfo[item]
                    continue

                if request[item] in _support:
                    ktyp = alg2keytype(request[item])
                    # do I have this ktyp and for EC type keys the curve
                    if ktyp not in ["none", "oct"]:
                        _k = []
                        for iss in ["", _context.issuer]:
                            _k.extend(
                                _keyjar.get_signing_key(ktyp, alg=request[item], issuer_id=iss)
                            )
                        if not _k:
                            logger.warning('Lacking support for "{}"'.format(request[item]))
                            del _cinfo[item]

        t = {"jwks_uri": "", "jwks": None}

        for item in ["jwks_uri", "jwks"]:
            if item in request:
                t[item] = request[item]

        # if it can't load keys because the URL is false it will
        # just silently fail. Waiting for better times.
        _keyjar.load_keys(client_id, jwks_uri=t["jwks_uri"], jwks=t["jwks"])

        n_keys = 0
        for kb in _keyjar.get(client_id, []):
            n_keys += len(kb.keys())
        msg = "found {} keys for client_id={}"
        logger.debug(msg.format(n_keys, client_id))

        return _cinfo

    @staticmethod
    def verify_redirect_uris(registration_request):
        verified_redirect_uris = []
        client_type = registration_request.get("application_type", "web")

        must_https = False
        if client_type == "web":
            must_https = True
            if registration_request.get("response_types") == ["code"]:
                must_https = False

        for uri in registration_request["redirect_uris"]:
            _custom = False
            p = urlparse(uri)
            if client_type == "native":
                if p.scheme not in ["http", "https"]:  # Custom scheme
                    _custom = True
                elif p.scheme == "http" and p.hostname in ["localhost", "127.0.0.1"]:
                    pass
                else:
                    logger.error(
                        "InvalidRedirectURI: scheme:%s, hostname:%s",
                        p.scheme,
                        p.hostname,
                    )
                    raise InvalidRedirectURIError(
                        "Redirect_uri must use custom " "scheme or http and localhost"
                    )
            elif must_https and p.scheme != "https":
                msg = "None https redirect_uri not allowed"
                raise InvalidRedirectURIError(msg)
            elif p.scheme not in ["http", "https"]:
                # Custom scheme
                raise InvalidRedirectURIError("Custom redirect_uri not allowed for web client")
            elif p.fragment:
                raise InvalidRedirectURIError("redirect_uri contains fragment")

            if _custom:  # Can not verify a custom scheme
                verified_redirect_uris.append((uri, {}))
            else:
                base, query = split_uri(uri)
                if query:
                    verified_redirect_uris.append((base, query))
                else:
                    verified_redirect_uris.append((base, {}))

        return verified_redirect_uris

    def _verify_sector_identifier(self, request):
        """
        Verify `sector_identifier_uri` is reachable and that it contains
        `redirect_uri`s.

        :param request: Provider registration request
        :return: si_redirects, sector_id
        :raises: InvalidSectorIdentifier
        """
        si_url = request["sector_identifier_uri"]
        try:
            res = self.upstream_get("context").httpc(
                "GET", si_url, **self.upstream_get("context").httpc_params
            )
            logger.debug("sector_identifier_uri => %s", sanitize(res.text))
        except Exception as err:
            logger.error(err)
            # res = None
            raise InvalidSectorIdentifier("Couldn't read from sector_identifier_uri")

        try:
            si_redirects = json.loads(res.text)
        except ValueError:
            raise InvalidSectorIdentifier("Error deserializing sector_identifier_uri content")

        if "redirect_uris" in request:
            logger.debug("redirect_uris: %s", request["redirect_uris"])
            for uri in request["redirect_uris"]:
                if uri not in si_redirects:
                    raise InvalidSectorIdentifier("redirect_uri missing from sector_identifiers")

        return si_redirects, si_url

    def add_registration_api(self, cinfo, client_id, context):
        _rat = rndstr(32)

        cinfo["registration_access_token"] = _rat
        endpoint = self.upstream_get("endpoints")
        cinfo["registration_client_uri"] = "{}?client_id={}".format(
            endpoint["registration_read"].full_path, client_id
        )

        context.registration_access_token[_rat] = client_id

    def client_secret_expiration_time(self):
        """
        Returns client_secret expiration time.
        """
        if not self.kwargs.get("client_secret_expires", True):
            return 0

        _expiration_time = self.kwargs.get("client_secret_expires_in", 2592000)
        return utc_time_sans_frac() + _expiration_time

    def add_client_secret(self, cinfo, client_id, context):
        client_secret = secret(self.seed, client_id)
        cinfo["client_secret"] = client_secret
        _eat = self.client_secret_expiration_time()
        if _eat:
            cinfo["client_secret_expires_at"] = _eat

        return client_secret

    def client_registration_setup(self, request, new_id=True, set_secret=True):
        try:
            request.verify()
        except (MessageException, ValueError) as err:
            logger.error("request.verify() error on %s", request)
            _error = "invalid_configuration_request"
            if len(err.args) > 1:
                if err.args[1] == "initiate_login_uri":
                    _error = "invalid_client_claims"

            return ResponseMessage(error=_error, error_description="%s" % err)

        request.rm_blanks()
        _context = self.upstream_get("context")

        try:
            request = self.filter_client_request(request)
        except CapabilitiesMisMatch as err:
            return ResponseMessage(
                error="invalid_request",
                error_description="Don't support proposed %s" % err,
            )

        if new_id:
            if self.kwargs.get("client_id_generator"):
                cid_generator = importer(self.kwargs["client_id_generator"]["class"])
                cid_gen_kwargs = self.kwargs["client_id_generator"].get("kwargs", {})
            else:
                cid_generator = importer("idpyoidc.server.oidc.registration.random_client_id")
                cid_gen_kwargs = {}
            client_id = cid_generator(reserved=_context.cdb.keys(), **cid_gen_kwargs)
            if "client_id" in request:
                del request["client_id"]
        else:
            client_id = request.get("client_id")
            if not client_id:
                raise ValueError("Missing client_id")

        _cinfo = {"client_id": client_id, "client_salt": rndstr(8)}

        if self.upstream_get("endpoint", "registration_read"):
            self.add_registration_api(_cinfo, client_id, _context)

        if new_id:
            _cinfo["client_id_issued_at"] = utc_time_sans_frac()

        client_secret = ""
        if set_secret:
            client_secret = self.add_client_secret(_cinfo, client_id, _context)

        logger.debug("Stored client info in CDB under cid={}".format(client_id))

        _context.cdb[client_id] = _cinfo
        _cinfo = self.do_client_registration(
            request,
            client_id,
            ignore=["redirect_uris", "policy_uri", "logo_uri", "tos_uri"],
        )
        if isinstance(_cinfo, ResponseMessage):
            return _cinfo

        args = dict([(k, v) for k, v in _cinfo.items() if k in self.response_cls.c_param])

        comb_uri(args)
        response = self.response_cls(**args)

        # Add the client_secret as a symmetric key to the key jar
        if client_secret:
            self.upstream_get("attribute", "keyjar").add_symmetric(client_id, str(client_secret))

        logger.debug("Stored updated client info in CDB under cid={}".format(client_id))
        logger.debug("ClientInfo: {}".format(_cinfo))
        _context.cdb[client_id] = _cinfo

        # Not all databases can be sync'ed
        if hasattr(_context.cdb, "sync") and callable(_context.cdb.sync):
            _context.cdb.sync()

        msg = "registration_response: {}"
        logger.info(msg.format(sanitize(response.to_dict())))

        return response

    def process_request(self, request=None, new_id=True, set_secret=True, **kwargs):
        try:
            reg_resp = self.client_registration_setup(request, new_id, set_secret)
        except Exception as err:
            logger.error("client_registration_setup: %s", request)
            return ResponseMessage(
                error="invalid_configuration_request", error_description="%s" % err
            )

        if "error" in reg_resp:
            return reg_resp
        else:
            _context = self.upstream_get("context")
            _cookie = _context.new_cookie(
                name=_context.cookie_handler.name["register"],
                client_id=reg_resp["client_id"],
            )

            return {"response_args": reg_resp, "cookie": _cookie, "response_code": 201}

    def process_verify_error(self, exception):
        _error = "invalid_request"
        if isinstance(exception, ValueError):
            if len(exception.args) > 1:
                if exception.args[1] == "initiate_login_uri":
                    _error = "invalid_client_claims"

        return self.error_cls(error=_error, error_description=f"{exception}")
