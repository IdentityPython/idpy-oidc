import json
import logging
import sys
import traceback
from typing import Callable
from typing import List
from typing import Optional
from typing import Union

from cryptojwt.jwt import utc_time_sans_frac
from cryptojwt.key_bundle import keybundle_from_local_file
from cryptojwt.key_jar import KeyJar

from idpyoidc.claims import Claims
from idpyoidc.client.client_auth import BearerHeader
from idpyoidc.client.defaults import DEFAULT_RESPONSE_MODE
from idpyoidc.client.entity import load_registration_response
from idpyoidc.client.exception import ConfigurationError
from idpyoidc.client.exception import HttpError
from idpyoidc.client.exception import OidcServiceError
from idpyoidc.client.exception import Unsupported
from idpyoidc.client.oauth2 import Client
from idpyoidc.client.oauth2.utils import pick_redirect_uri
from idpyoidc.client.service_context import ServiceContext
from idpyoidc.configure import Configuration
from idpyoidc.context import OidcContext
from idpyoidc.exception import MissingRequiredAttribute
from idpyoidc.key_import import add_kb
from idpyoidc.key_import import import_jwks_from_file
from idpyoidc.message import Message
from idpyoidc.message.oauth2 import is_error_message
from idpyoidc.message.oidc import AuthorizationRequest
from idpyoidc.message.oidc import AuthorizationResponse
from idpyoidc.message.oidc import OpenIDSchema
from idpyoidc.message.oidc import RegistrationRequest
from idpyoidc.util import rndstr

logger = logging.getLogger(__name__)


class RP(Client):
    entity_type = 'openid_relying_party'
    metadata_class = RegistrationRequest

    def __init__(
            self,
            keyjar: Optional[KeyJar] = None,
            config: Optional[Union[dict, Configuration]] = None,
            services: Optional[dict] = None,
            httpc: Optional[Callable] = None,
            httpc_params: Optional[dict] = None,
            context: Optional[OidcContext] = None,
            upstream_get: Optional[Callable] = None,
            key_conf: Optional[dict] = None,
            entity_id: Optional[str] = "",
            verify_ssl: Optional[bool] = True,
            jwks_uri: Optional[str] = "",
            client_type: Optional[str] = "oidc",
            client_configs: Optional[dict] = None,
            **kwargs
    ):

        # if use_default_keys(keyjar, key_conf, config):
        #    key_conf = KEYDEFS

        Client.__init__(self, keyjar, config, services, httpc, httpc_params, context,
                        upstream_get, key_conf, entity_id, verify_ssl, jwks_uri,
                        client_type, client_configs, **kwargs)

    def do_client_registration(
            self,
            context,
            request_args: Optional[dict] = None,
            behaviour_args: Optional[dict] = None,
            issuer: Optional[str] = ""
    ):
        """
        Prepare for and do client registration if configured to do so

        :param issuer: Issuer ID
        :param behaviour_args: To fine tune behaviour
        :param request_args: Client registration request arguments
        """

        logger.debug(20 * "*" + " do_client_registration " + 20 * "*")

        # This should only be interesting if the client supports Single Log Out
        # if context.callback.get("post_logout_redirect_uri") is None:
        #     context.callback["post_logout_redirect_uri"] = [self.base_url]

        if not context.client_id:  # means I have to do dynamic client registration
            if request_args is None:
                request_args = {}

            if behaviour_args:
                _params = RegistrationRequest().parameters()
                request_args.update({k: v for k, v in behaviour_args.items() if k in _params})

            load_registration_response(self, context, request_args=request_args)
        else:
            context.map_preferred_to_registered()

    def do_webfinger(self, user: str) -> Message:
        """
        Does OpenID Provider Issuer discovery using webfinger.

        :param user: Identifier for the target End-User that is the subject of the discovery
            request.
        :return: A Client instance
        """

        logger.debug(20 * "*" + " do_webfinger " + 20 * "*")

        _context = self.get_context("")
        return self.do_request(_context, "webfinger", resource=user)

    def do_provider_info(
            self,
            context,
            behaviour_args: Optional[dict] = None,
    ) -> str:
        """
        Either get the provider info from configuration or through dynamic
        discovery.

        :param behaviour_args: Behaviour specific attributes
        :return: issuer ID
        """
        logger.debug(20 * "*" + " do_provider_info " + 20 * "*")

        _pi = context.get("provider_info")
        if _pi is None or _pi == {}:
            dynamic_provider_info_discovery(self, context, behaviour_args=behaviour_args)
            _pi = context.provider_info
        elif len(_pi) == 1 and "issuer" in _pi:
            context.issuer = _pi["issuer"]
            dynamic_provider_info_discovery(self, context, behaviour_args=behaviour_args)
            _pi = context.provider_info
        else:
            for key, val in _pi.items():
                # All service endpoint parameters in the provider info has
                # a name ending in '_endpoint' so I can look specifically
                # for those
                if key.endswith("_endpoint"):
                    for _srv in self.get_services(context).values():
                        # Every service has an endpoint_name assigned
                        # when initiated. This name *MUST* match the
                        # endpoint names used in the provider info
                        if _srv.endpoint_name == key:
                            _srv.endpoint = val

            if "keys" in _pi:
                _kj = self.get_attribute("keyjar")
                for typ, _spec in _pi["keys"].items():
                    if typ == "url":
                        for _iss, _url in _spec.items():
                            _kj.add_url(_iss, _url)
                    elif typ == "file":
                        for kty, _name in _spec.items():
                            if kty == "jwks":
                                _kj = import_jwks_from_file(_kj, _name, context.get("issuer"))
                            elif kty == "rsa":  # PEM file
                                _kb = keybundle_from_local_file(_name, "der", ["sig"])
                                _kj = add_kb(_kj, context.get("issuer"), _kb)
                    else:
                        raise ValueError("Unknown provider JWKS type: {}".format(typ))

        context.map_supported_to_preferred(info=_pi)

        try:
            return context.provider_info["issuer"]
        except:
            return context.issuer

    def context_setup(
            self,
            server_entity_id: Optional[str] = "",
            user: Optional[str] = "",
            behaviour_args: Optional[dict] = None,
    ):
        """
        First if no issuer ID is given then the identifier for the user is
        used by the webfinger service to try to find the issuer ID.
        Once the method has an issuer ID if no context is bound to this issuer
        one is created and initiated with
        the necessary information for the client to be able to communicate
        with the OP/AS that has the provided issuer ID.

        :param behaviour_args: To fine tune behaviour
        :param server_entity_id: The issuer ID
        :param user: A user identifier
        :return: A :py:class:`idpyoidc.client.service_context.ServiceContext` instance
        """

        logger.debug(20 * "*" + " context_setup " + 20 * "*")

        logger.info(f"client_setup: server_entity_id={server_entity_id}, user={user}")

        if not server_entity_id:
            if not user:
                raise ValueError("Need issuer or user")

            logger.debug("Connecting to previously unknown OP")
            response = self.do_webfinger(user)
            context = self.add_new_context(response['issuer'])
        else:
            try:
                context = self.get_context(server_entity_id)
            except KeyError:
                logger.debug(f"Creating new context for: {server_entity_id}")
                context = self.add_new_context(server_entity_id)

        logger.debug("Get provider info")
        issuer = self.do_provider_info(context, behaviour_args=behaviour_args)

        logger.debug("Do client registration")
        self.do_client_registration(context, behaviour_args=behaviour_args,
                                    issuer=server_entity_id)

        return context

    def begin(self, issuer_id="", user_id="", req_args=None, behaviour_args=None):
        """
        This is the first of the 3 high level methods that most users of this
        library should confine them self to use.
        It will use client_setup to produce a Client instance ready to be used
        against the OP/AS the user wants to use.
        Once it has the client it will construct an Authorization
        request.

        :param behaviour_args:
        :param req_args:
        :param issuer_id: Issuer ID
        :param user_id: A user identifier
        :return: A dictionary containing **url** the URL that will redirect the
            user to the OP/AS and **state** the session key which will
            allow higher level code to access session information.
        """

        # Get the client instance that has been assigned to this issuer
        context = self.context_setup(issuer_id, user_id, behaviour_args=behaviour_args)

        try:
            res = self.init_authorization(context, req_args=req_args,
                                          behaviour_args=behaviour_args)
        except Exception:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            raise
        else:
            return res

    def get_tokens(self, context, state):
        """
        Use the 'accesstoken' service to get an access token from the OP/AS.

        :param state: The state key (the state parameter in the
            authorization request)
        :return: A :py:class:`idpyoidc.message.oidc.AccessTokenResponse` or
            :py:class:`idpyoidc.message.oauth2.AuthorizationResponse`
        """
        logger.debug(20 * "*" + " get_tokens " + 20 * "*")

        _claims = context.cstate.get_set(state, claim=["code", "redirect_uri"])

        req_args = {
            "code": _claims["code"],
            "state": state,
            "redirect_uri": _claims["redirect_uri"],
            "grant_type": "authorization_code",
            "client_id": self.get_client_id(context),
            "client_secret": context.claims.get_usage("client_secret"),
        }
        logger.debug("request_args: {}".format(req_args))
        try:
            tokenresp = self.do_request(
                context,
                "accesstoken",
                request_args=req_args,
                authn_method=self.get_client_authn_method(context, "token_endpoint"),
                state=state,
            )
        except Exception:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            raise
        else:
            if is_error_message(tokenresp):
                raise OidcServiceError(tokenresp["error"])

        return tokenresp

    def refresh_access_token(self, context, state, scope=""):
        """
        Refresh an access token using a refresh_token. When asking for a new
        access token the RP can ask for another scope for the new token.

        :param state: The state key (the state parameter in the
            authorization request)
        :param scope: What the returned token should be valid for.
        :return: A :py:class:`idpyoidc.message.oidc.AccessTokenResponse` instance
        """

        logger.debug(20 * "*" + " refresh_access_token " + 20 * "*")

        if scope:
            req_args = {"scope": scope}
        else:
            req_args = {}

        try:
            tokenresp = self.do_request(
                context,
                "refresh_token",
                authn_method=self.get_client_authn_method(context, "token_endpoint"),
                state=state,
                request_args=req_args,
            )
        except Exception:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            raise
        else:
            if is_error_message(tokenresp):
                raise OidcServiceError(tokenresp["error"])

        return tokenresp

    def has_active_authentication(self, context, state):
        """
        Find out if the user has an active authentication

        :param state:
        :return: True/False
        """

        # Look for an IdToken
        _arg = context.cstate.get_set(state, claim=["__verified_id_token"])

        if _arg:
            _now = utc_time_sans_frac()
            exp = _arg["__verified_id_token"]["exp"]
            return _now < exp
        else:
            return False

    def get_valid_access_token(self, context, state: str) -> tuple:
        """
        Find a valid access token.

        :param state:
        :return: An access token if a valid one exists and when it
            expires else raise exception.
        """

        token_info = None
        indefinite = []
        now = utc_time_sans_frac()

        _args = context.cstate.get_set(state, claim=["access_token", "__expires_at"])
        if "access_token" in _args:
            access_token = _args["access_token"]
            _exp = _args.get("__expires_at", 0)
            if not _exp:  # No expiry date, lives forever
                indefinite.append((access_token, 0))
            else:
                if _exp > now:  # expires sometime in the future
                    token_info = (access_token, _exp)

        if indefinite:
            return indefinite[0]
        else:
            if token_info:
                return token_info
            else:
                raise OidcServiceError("No valid access token")

    def get_user_info(self, context, state, access_token="", **kwargs):
        """
        use the access token previously acquired to get some userinfo

        :param state: The state value, this is the key into the session
            data store
        :param access_token: An access token
        :param kwargs: Extra keyword arguments
        :return: A :py:class:`idpyoidc.message.oidc.OpenIDSchema` instance
        """

        logger.debug(20 * "*" + " get_user_info " + 20 * "*")

        if not access_token:
            _arg = context.cstate.get_set(state, claim=["access_token"])
            access_token = _arg["access_token"]

        request_args = {"access_token": access_token}

        resp = self.do_request(context, "userinfo", state=state, request_args=request_args,
                               **kwargs)
        if is_error_message(resp):
            raise OidcServiceError(resp["error"])

        return resp

    @staticmethod
    def userinfo_in_id_token(id_token: Message, user_info_claims: Optional[List] = None) -> dict:
        """
        Given a verified ID token return all the claims that may be user information.

        :param id_token: An :py:class:`idpyoidc.message.oidc.IDToken` instance
        :return: A dictionary with user information
        """
        if user_info_claims is None:
            user_info_claims = list(OpenIDSchema.c_param.keys())

        res = dict([(k, id_token[k]) for k in user_info_claims if k in id_token])
        res.update(id_token.extra())
        return res

    def get_access_and_id_token(
            self,
            context: Optional[ServiceContext] = None,
            authorization_response: Optional[Message] = None,
            state: Optional[str] = "",
            behaviour_args: Optional[dict] = None,
    ):
        """
        There are a number of services where access tokens and ID tokens can
        occur in the response. This method goes through the possible places
        based on the response_type the client uses.

        :param behaviour_args: For finetuning behaviour
        :param authorization_response: The Authorization response
        :param state: The state key (the state parameter in the
            authorization request)
        :return: A dictionary with 2 keys: **access_token** with the access
            token as value and **id_token** with a verified ID Token if one
            was returned otherwise None.
        """

        logger.debug(20 * "*" + " get_access_and_id_token " + 20 * "*")

        if context is None:
            context = self.state2context({"state": state})

        resp_attr = authorization_response
        if not resp_attr:
            resp_attr = context.cstate.get_set(state, message=AuthorizationResponse)

        if resp_attr is None:
            raise ValueError("One of authorization_response or state must be provided")

        if not state:
            state = authorization_response["state"]

        _req_attr = context.cstate.get_set(state, AuthorizationRequest)
        if isinstance(_req_attr["response_type"], list):
            _resp_type = set(_req_attr["response_type"])
        else:
            _resp_type = set(_req_attr["response_type"].split(" "))

        access_token = None
        id_token = None
        if _resp_type in [{"id_token"}, {"id_token", "token"}, {"code", "id_token", "token"}]:
            id_token = authorization_response["__verified_id_token"]

        if _resp_type in [
            {"token"},
            {"id_token", "token"},
            {"code", "token"},
            {"code", "id_token", "token"},
        ]:
            access_token = authorization_response["access_token"]
            if behaviour_args:
                if behaviour_args.get("collect_tokens", False):
                    # get what you can from the token endpoint
                    token_resp = self.get_tokens(context, state)
                    if is_error_message(token_resp):
                        return False, "Invalid response %s." % token_resp["error"]
                    # Now which access_token should I use
                    access_token = token_resp["access_token"]
                    # May or may not get an ID Token
                    id_token = token_resp.get("__verified_id_token")

        elif _resp_type in [{"code"}, {"code", "id_token"}]:
            # get the access token
            token_resp = self.get_tokens(context, state)
            if is_error_message(token_resp):
                return False, "Invalid response %s." % token_resp["error"]

            access_token = token_resp["access_token"]
            # May or may not get an ID Token
            id_token = token_resp.get("__verified_id_token")

        return {"access_token": access_token, "id_token": id_token}

    def _get_response_type(self, context, req_args: Optional[dict] = None):
        if req_args:
            return req_args.get("response_type", context.claims.get_usage("response_types")[0])
        else:
            return context.claims.get_usage("response_types")[0]

    def _get_response_mode(self, context, response_type, request_args):
        if request_args:
            _requested = request_args.get("response_mode")
        else:
            _requested = None
        _supported = context.claims.get_usage("response_modes")
        if _requested:
            if _supported and _requested not in _supported:
                raise ValueError(
                    "You can not use a response_mode you have not stated should be supported"
                )

            if DEFAULT_RESPONSE_MODE[response_type] == _requested:
                return None
            else:
                return _requested
        elif _supported:
            _type = response_type.split(" ")
            _type.sort()
            response_type = " ".join(_type)
            # Is it the default response mode
            if DEFAULT_RESPONSE_MODE[response_type] in _supported:
                return None
            else:
                return _supported[0]
        else:
            return None

    def init_authorization(
            self,
            context,
            req_args: Optional[dict] = None,
            behaviour_args: Optional[dict] = None,
    ) -> str:
        """
        Constructs the URL that will redirect the user to the authorization
        endpoint of the OP/AS.

        :param behaviour_args:
        :param req_args: Non-default Request arguments
        :return: A dictionary with 2 keys: **url** The authorization redirect
            URL and **state** the key to the session information in the
            state data store.
        """

        logger.debug(20 * "*" + " init_authorization " + 20 * "*")

        _response_type = self._get_response_type(context, req_args)
        _response_mode = self._get_response_mode(context, _response_type, req_args)
        try:
            _redirect_uri = pick_redirect_uri(
                context,
                request_args=req_args,
                response_type=_response_type,
                response_mode=_response_mode,
            )
        except KeyError:
            raise Unsupported(
                "Could not pick a redirect_uri based on the given response_type and "
                "response_mode"
            )
        except [MissingRequiredAttribute, ValueError]:
            raise

        request_args = {
            "redirect_uri": _redirect_uri,
            "response_type": _response_type,
        }

        if _response_mode:
            request_args["response_mode"] = _response_mode

        _nonce = ""
        if self.client_type == "oidc":
            _nonce = rndstr(24)
            request_args["nonce"] = _nonce

        _scope = context.claims.get_usage("scope")
        if _scope:
            request_args["scope"] = _scope

        _req_args = context.config.get("request_args")
        if _req_args:
            if "claims" in _req_args:
                _req_args["claims"] = Claims(**_req_args["claims"])
            request_args.update(_req_args)

        if req_args is not None:
            request_args.update(req_args)

        # Need a new state for a new authorization request
        _current = context.cstate
        _state = _current.create_key()
        request_args["state"] = _state
        if _nonce:
            _current.bind_key(_nonce, _state)

        _current.set(_state, {"iss": context.get("issuer")})

        logger.debug("Authorization request args: {}".format(request_args))

        # if behaviour_args and "request_param" not in behaviour_args:
        #     _pi = context.get("provider_info")

        _srv = self.get_service(context, "authorization")
        _info = _srv.get_request_parameters(context,
                                            request_args=request_args,
                                            behaviour_args=behaviour_args
                                            )
        logger.debug("Authorization info: {}".format(_info))
        return _info["url"]

    def state2issuer(self, state):
        """
        Given the state value find the Issuer ID of the OP/AS that state value
        was used against.
        Will raise a KeyError if the state is unknown.

        :param state: The state value
        :return: An Issuer ID
        """
        for ctx in self.context.values():
            try:
                _set = ctx.cstate.get_set(state, claim=["iss"])
            except KeyError:
                continue

            _iss = _set.get("iss")
            if _iss:
                return _iss
        return None

    def issuer2context(self, issuer):
        for ctx in self.context.values():
            if ctx.server_entity_id == issuer:
                return ctx
        return None

    def get_session_information(self, context, key):
        """
        This is the second of the methods users of this class should know about.
        It will return the complete session information as an
        :py:class:`idpyoidc.client.current.Current` instance.

        :param context: The service context
        :param key: The session key (state)
        :return: A State instance
        """

        return context.cstate.get(key)

    def finalize_auth(self, response: dict,
                      context: Optional[ServiceContext] = None,
                      behaviour_args: Optional[dict] = None):
        """
        Given the response returned to the redirect_uri, parse and verify it.

        :param behaviour_args: For finetuning behaviour
        :param response: The authorization response as a dictionary
        :return: An :py:class:`idpyoidc.message.oidc.AuthorizationResponse` or
            :py:class:`idpyoidc.message.oauth2.AuthorizationResponse` instance.
        """

        logger.debug(20 * "*" + " finalize_auth " + 20 * "*")
        if context is None:
            context = self.state2context(response)

        _srv = self.get_service(context, "authorization")
        try:
            authorization_response = _srv.parse_response(
                context, response, sformat="dict", behaviour_args=behaviour_args
            )
        except Exception as err:
            logger.error("Parsing authorization_response: {}".format(err))
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            raise
        else:
            logger.debug("Authz response: {}".format(authorization_response.to_dict()))

        if is_error_message(authorization_response):
            return authorization_response

        try:
            _iss = context.cstate.get_set(authorization_response["state"], claim=["iss"]).get(
                "iss"
            )
        except KeyError:
            raise KeyError("Unknown state value")

        try:
            issuer = context.provider_info["issuer"]
        except KeyError:
            issuer = context.issuer

        if _iss != issuer:
            logger.error("Issuer problem: {} != {}".format(_iss, issuer))
            # got it from the wrong bloke
            raise ValueError("Impersonator {}".format(issuer))

        context.cstate.update(authorization_response["state"], authorization_response)
        _srv.update_service_context(context, authorization_response,
                                    key=authorization_response["state"])
        return authorization_response

    @staticmethod
    def get_client_authn_method(context, endpoint):
        """
        Return the client authentication method a client wants to use a
        specific endpoint

        :param context: A Context instance
        :param endpoint: The endpoint at which the client has to authenticate
        :return: The client authentication method
        """
        if endpoint == "token_endpoint":
            am = context.get_usage("token_endpoint_auth_method")
            if not am:
                return ""
            else:
                if isinstance(am, str):
                    return am
                else:  # a list
                    return am[0]

    def fetch_distributed_claims(self, context, userinfo, callback=None):
        """

        :param userinfo: A :py:class:`idpyoidc.message.Message` subclass
            instance
        :param callback: A function that can be used to fetch things
        :return: Updated userinfo instance
        """
        try:
            _csrc = userinfo["_claim_sources"]
        except KeyError:
            pass
        else:
            for csrc, spec in _csrc.items():
                if "endpoint" in spec:
                    if "access_token" in spec:
                        cauth = BearerHeader()
                        httpc_params = cauth.construct(
                            context,
                            service=context.get_service("userinfo"),
                            access_token=spec["access_token"],
                        )
                        _resp = self.httpc("GET", spec["endpoint"], **httpc_params)
                    else:
                        if callback:
                            token = callback(spec["endpoint"])
                            cauth = BearerHeader()
                            httpc_params = cauth.construct(
                                context,
                                service=context.get_service("userinfo"), access_token=token
                            )
                            _resp = self.httpc("GET", spec["endpoint"], **httpc_params)
                        else:
                            _resp = self.httpc("GET", spec["endpoint"])

                    if _resp.status_code == 200:
                        _uinfo = json.loads(_resp.text)
                    else:  # There shouldn't be any redirect
                        raise HttpError(
                            "HTTP error {}: {}".format(_resp.status_code, _resp.reason)
                        )

                    claims = [
                        value for value, src in userinfo["_claim_names"].items() if src == csrc
                    ]

                    if set(claims) != set(_uinfo.keys()):
                        logger.warning(
                            "Claims from claim source doesn't match what's in " "the userinfo"
                        )

                    # only add those I expected
                    for key in claims:
                        userinfo[key] = _uinfo[key]

            return userinfo

    def state2context(self, response):
        _state = response["state"]
        if isinstance(self.context, dict):
            for server_entity_id, cntx in self.context.items():
                if _state in cntx.cstate.keys():
                    return cntx
        else:
            return self.context

        return None


def dynamic_provider_info_discovery(client: Client, context,
                                    behaviour_args: Optional[dict] = None):
    """
    This is about performing dynamic Provider Info discovery

    :param behaviour_args:
    :param client: A :py:class:`idpyoidc.client.oidc.Client` instance
    """

    if client.client_type == "oidc" and client.get_service(context, "provider_info"):
        service = "provider_info"
    elif client.client_type == "oauth2" and client.get_service(context, "server_metadata"):
        service = "server_metadata"
    else:
        raise ConfigurationError("Can not do dynamic provider info discovery")

    try:
        context.set("issuer", context.config["srv_discovery_url"])
    except KeyError:
        pass

    logger.debug(f"{service}")
    response = client.do_request(context, service, behaviour_args=behaviour_args)
    if is_error_message(response):
        raise OidcServiceError(response["error"])
