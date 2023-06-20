import logging
import sys
import traceback
from typing import List
from typing import Optional

from cryptojwt import as_unicode
from cryptojwt.key_bundle import keybundle_from_local_file

from idpyoidc import verified_claim_name
from idpyoidc.client.defaults import DEFAULT_RESPONSE_MODE
from idpyoidc.client.exception import ConfigurationError
from idpyoidc.client.exception import OidcServiceError
from idpyoidc.client.exception import Unsupported
from idpyoidc.client.oauth2 import Client
from idpyoidc.client.oauth2 import dynamic_provider_info_discovery
from idpyoidc.client.oauth2.utils import pick_redirect_uri
from idpyoidc.exception import MessageException
from idpyoidc.exception import MissingRequiredAttribute
from idpyoidc.exception import NotForMe
from idpyoidc.message import Message
from idpyoidc.message.oauth2 import is_error_message
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.message.oidc import AuthorizationRequest
from idpyoidc.message.oidc import AuthorizationResponse
from idpyoidc.message.oidc import Claims
from idpyoidc.message.oidc import OpenIDSchema
from idpyoidc.message.oidc import RegistrationRequest
from idpyoidc.message.oidc.session import BackChannelLogoutRequest
from idpyoidc.time_util import utc_time_sans_frac
from idpyoidc.util import rndstr

logger = logging.getLogger(__name__)


class StandAloneClient(Client):

    def get_session_information(self, key):
        """
        This is the second of the methods users of this class should know about.
        It will return the complete session information as an
        :py:class:`idpyoidc.client.current.Current` instance.

        :param key: The session key (state)
        :return: A State instance
        """

        return self.get_context().cstate.get(key)

    def do_provider_info(
            self,
            behaviour_args: Optional[dict] = None,
    ) -> str:
        """
        Either get the provider info from configuration or through dynamic
        discovery.

        :param behaviour_args: Behaviour specific attributes
        :return: issuer ID
        """
        logger.debug(20 * "*" + " do_provider_info " + 20 * "*")

        _context = self.get_context()
        _pi = _context.get("provider_info")
        if _pi is None or _pi == {}:
            dynamic_provider_info_discovery(self, behaviour_args=behaviour_args)
            _pi = _context.provider_info
        elif len(_pi) == 1 and 'issuer' in _pi:
            _context.issuer = _pi['issuer']
            dynamic_provider_info_discovery(self, behaviour_args=behaviour_args)
            _pi = _context.provider_info
        else:
            for key, val in _pi.items():
                # All service endpoint parameters in the provider info has
                # a name ending in '_endpoint' so I can look specifically
                # for those
                if key.endswith("_endpoint"):
                    for _srv in self.get_services().values():
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
                                _kj.import_jwks_from_file(_name, _context.get("issuer"))
                            elif kty == "rsa":  # PEM file
                                _kb = keybundle_from_local_file(_name, "der", ["sig"])
                                _kj.add_kb(_context.get("issuer"), _kb)
                    else:
                        raise ValueError("Unknown provider JWKS type: {}".format(typ))

        _context.map_supported_to_preferred(info=_pi)

        try:
            return _context.provider_info['issuer']
        except:
            return _context.issuer

    def do_client_registration(
            self,
            request_args: Optional[dict] = None,
            behaviour_args: Optional[dict] = None,
    ):
        """
        Prepare for and do client registration if configured to do so

        :param iss_id: Issuer ID
        :param behaviour_args: To fine tune behaviour
        :param client: A Client instance
        :param state: A key by which the state of the session can be
            retrieved
        """

        logger.debug(20 * "*" + " do_client_registration " + 20 * "*")

        _context = self.get_context()

        # This should only be interesting if the client supports Single Log Out
        # if _context.callback.get("post_logout_redirect_uri") is None:
        #     _context.callback["post_logout_redirect_uri"] = [self.base_url]

        if not self.get_client_id():  # means I have to do dynamic client registration
            if request_args is None:
                request_args = {}

            if behaviour_args:
                _params = RegistrationRequest().parameters()
                request_args.update({k: v for k, v in behaviour_args.items() if k in _params})

            load_registration_response(self, request_args=request_args)
        else:
            _context.map_preferred_to_registered()

    def _get_response_type(self, context, req_args: Optional[dict] = None):
        if req_args:
            return req_args.get("response_type", context.claims.get_usage("response_types")[0])
        else:
            return context.claims.get_usage("response_types")[0]

    def _get_response_mode(self, context, response_type, request_args):
        if request_args:
            _requested = request_args.get('response_mode')
        else:
            _requested = None
        _supported = context.claims.get_usage('response_modes')
        if _requested:
            if _supported and _requested not in _supported:
                raise ValueError(
                    "You can not use a response_mode you have not stated should be supported")

            if DEFAULT_RESPONSE_MODE[response_type] == _requested:
                return None
            else:
                return _requested
        elif _supported:
            _type = response_type.split(' ')
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

        _context = self.get_context()
        _response_type = self._get_response_type(_context, req_args)
        _response_mode = self._get_response_mode(_context, _response_type, req_args)
        try:
            _redirect_uri = pick_redirect_uri(
                _context, request_args=req_args, response_type=_response_type,
                response_mode=_response_mode
            )
        except KeyError:
            raise Unsupported(
                'Could not pick a redirect_uri based on the given response_type and response_mode')
        except [MissingRequiredAttribute, ValueError]:
            raise

        request_args = {
            "redirect_uri": _redirect_uri,
            "response_type": _response_type,
        }

        if _response_mode:
            request_args['response_mode'] = _response_mode

        _nonce = ''
        if self.client_type == 'oidc':
            _nonce = rndstr(24)
            request_args['nonce'] = _nonce

        _scope = _context.claims.get_usage("scope")
        if _scope:
            request_args["scope"] = _scope

        _req_args = _context.config.get("request_args")
        if _req_args:
            if "claims" in _req_args:
                _req_args["claims"] = Claims(**_req_args["claims"])
            request_args.update(_req_args)

        if req_args is not None:
            request_args.update(req_args)

        # Need a new state for a new authorization request
        _current = _context.cstate
        _state = _current.create_key()
        request_args["state"] = _state
        if _nonce:
            _current.bind_key(_nonce, _state)

        _current.set(_state, {"iss": _context.get("issuer")})

        logger.debug("Authorization request args: {}".format(request_args))

        # if behaviour_args and "request_param" not in behaviour_args:
        #     _pi = _context.get("provider_info")

        _srv = self.get_service("authorization")
        _info = _srv.get_request_parameters(
            request_args=request_args, behaviour_args=behaviour_args
        )
        logger.debug("Authorization info: {}".format(_info))
        return _info["url"]

    @staticmethod
    def get_client_authn_method(self, endpoint):
        """
        Return the client authentication method a client wants to use at a
        specific endpoint

        :param endpoint: The endpoint at which the client has to authenticate
        :return: The client authentication method
        """
        if endpoint == "token_endpoint":
            auth_method = self.get_context().get_usage("token_endpoint_auth_method")
            if not auth_method:
                return ""
            else:
                if isinstance(auth_method, str):
                    return auth_method
                else:  # a list
                    return auth_method[0]
        return ""

    def get_tokens(self, state):
        """
        Use the 'accesstoken' service to get an access token from the OP/AS.

        :param state: The state key (the state parameter in the
            authorization request)
        :return: A :py:class:`idpyoidc.message.oidc.AccessTokenResponse` or
            :py:class:`idpyoidc.message.oauth2.AuthorizationResponse`
        """
        logger.debug(20 * "*" + " get_tokens " + 20 * "*")

        _context = self.get_context()
        _claims = _context.cstate.get_set(state, claim=["code", "redirect_uri"])

        req_args = {
            "code": _claims["code"],
            "state": state,
            "redirect_uri": _claims["redirect_uri"],
            "grant_type": "authorization_code",
            "client_id": self.get_client_id(),
            "client_secret": _context.claims.get_usage("client_secret"),
        }
        logger.debug("request_args: {}".format(req_args))
        try:
            tokenresp = self.do_request(
                "accesstoken",
                request_args=req_args,
                authn_method=self.get_client_authn_method(self, "token_endpoint"),
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

    def refresh_access_token(self, state, scope=""):
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
                "refresh_token",
                authn_method=self.get_client_authn_method(self, "token_endpoint"),
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

    def get_user_info(self, state, access_token="", **kwargs):
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
            _arg = self.get_context().cstate.get_set(state, claim=["access_token"])
            access_token = _arg["access_token"]

        request_args = {"access_token": access_token}

        resp = self.do_request("userinfo", state=state, request_args=request_args, **kwargs)
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

    def finalize_auth(
            self, response: dict, behaviour_args: Optional[dict] = None
    ):
        """
        Given the response returned to the redirect_uri, parse and verify it.

        :param behaviour_args: For finetuning behaviour
        :param response: The authorization response as a dictionary
        :return: An :py:class:`idpyoidc.message.oidc.AuthorizationResponse` or
            :py:class:`idpyoidc.message.oauth2.AuthorizationResponse` instance.
        """

        logger.debug(20 * "*" + " finalize_auth " + 20 * "*")

        _srv = self.get_service("authorization")
        try:
            authorization_response = _srv.parse_response(
                response, sformat="dict", behaviour_args=behaviour_args
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

        _context = self.get_context()
        try:
            _iss = _context.cstate.get_set(authorization_response["state"], claim=["iss"]).get(
                "iss"
            )
        except KeyError:
            raise KeyError("Unknown state value")

        try:
            issuer = _context.provider_info['issuer']
        except KeyError:
            issuer = _context.issuer

        if _iss != issuer:
            logger.error("Issuer problem: {} != {}".format(_iss, issuer))
            # got it from the wrong bloke
            raise ValueError("Impersonator {}".format(issuer))

        _srv.update_service_context(authorization_response, key=authorization_response["state"])
        return authorization_response

    def get_access_and_id_token(
            self,
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

        _context = self.get_context()

        resp_attr = authorization_response or _context.cstate.get_set(
            state, message=AuthorizationResponse
        )
        if resp_attr is None:
            raise ValueError("One of authorization_response or state must be provided")

        if not state:
            state = authorization_response["state"]

        _req_attr = _context.cstate.get_set(state, AuthorizationRequest)
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
                    token_resp = self.get_tokens(state)
                    if is_error_message(token_resp):
                        return False, "Invalid response %s." % token_resp["error"]
                    # Now which access_token should I use
                    access_token = token_resp["access_token"]
                    # May or may not get an ID Token
                    id_token = token_resp.get("__verified_id_token")

        elif _resp_type in [{"code"}, {"code", "id_token"}]:
            # get the access token
            token_resp = self.get_tokens(state)
            if is_error_message(token_resp):
                return False, "Invalid response %s." % token_resp["error"]

            access_token = token_resp["access_token"]
            # May or may not get an ID Token
            id_token = token_resp.get("__verified_id_token")

        return {"access_token": access_token, "id_token": id_token}

    # noinspection PyUnusedLocal
    def finalize(self, response, behaviour_args: Optional[dict] = None):
        """
        The third of the high level methods that a user of this Class should
        know about.
        Once the consumer has redirected the user back to the
        callback URL there might be a number of services that the client should
        use. Which one those are defined by the client configuration.

        :param behaviour_args: For finetuning
        :param issuer: Who sent the response
        :param response: The Authorization response as a dictionary
        :returns: A dictionary with the following keys:
            **state** The key under which the session information is
            stored in the data store and
            **token** The access token
            **id_token:: the ID Token
            **userinfo** The collected user information
            **session_state** If logout is supported the special session_state claim
        """

        authorization_response = self.finalize_auth(response)
        if is_error_message(authorization_response):
            return {
                "state": authorization_response["state"],
                "error": authorization_response["error"],
            }

        _state = authorization_response["state"]
        token = self.get_access_and_id_token(
            authorization_response, state=_state, behaviour_args=behaviour_args
        )
        _id_token = token.get("id_token")
        logger.debug(f"ID Token: {_id_token}")

        if self.get_service("userinfo") and token["access_token"]:
            inforesp = self.get_user_info(
                state=authorization_response["state"],
                access_token=token["access_token"],
            )

            if isinstance(inforesp, ResponseMessage) and "error" in inforesp:
                return {"error": "Invalid response %s." % inforesp["error"], "state": _state}

        elif _id_token:  # look for it in the ID Token
            inforesp = self.userinfo_in_id_token(_id_token)
        else:
            inforesp = {}

        logger.debug("UserInfo: %s", inforesp)

        _context = self.get_context()
        try:
            _sid_support = _context.get("provider_info")["backchannel_logout_session_required"]
        except KeyError:
            try:
                _sid_support = _context.get("provider_info")["frontchannel_logout_session_required"]
            except Exception:
                _sid_support = False

        if _sid_support and _id_token:
            try:
                sid = _id_token["sid"]
            except KeyError:
                pass
            else:
                _context.cstate.bind_key(sid, _state)

        if _id_token:
            _context.cstate.bind_key(_id_token["sub"], _state)
        else:
            _context.cstate.bind_key(inforesp["sub"], _state)

        return {
            "userinfo": inforesp,
            "state": authorization_response["state"],
            "token": token["access_token"],
            "id_token": _id_token,
            "session_state": authorization_response.get("session_state", ""),
            "issuer": _context.issuer
        }

    def has_active_authentication(self, state):
        """
        Find out if the user has an active authentication

        :param state:
        :return: True/False
        """

        # Look for an IdToken
        _arg = self.get_context().cstate.get_set(state, claim=["__verified_id_token"])

        if _arg:
            _now = utc_time_sans_frac()
            exp = _arg["__verified_id_token"]["exp"]
            return _now < exp
        else:
            return False

    def get_valid_access_token(self, state: str) -> tuple:
        """
        Find a valid access token.

        :param state:
        :return: An access token if a valid one exists and when it
            expires else raise exception.
        """

        token_info = None
        indefinite = []
        now = utc_time_sans_frac()

        _context = self.get_context()
        _args = _context.cstate.get_set(state, claim=["access_token", "__expires_at"])
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

    def logout(
            self,
            state: str,
            post_logout_redirect_uri: Optional[str] = "",
    ) -> dict:
        """
        Does an RP initiated logout from an OP. After logout the user will be
        redirected by the OP to a URL of choice (post_logout_redirect_uri).

        :param state: Key to an active session
        :param client: Which client to use
        :param post_logout_redirect_uri: If a special post_logout_redirect_uri
            should be used
        :return: Request arguments
        """

        logger.debug(20 * "*" + " logout " + 20 * "*")

        try:
            srv = self.get_service("end_session")
        except KeyError:
            raise OidcServiceError("Does not know how to logout")

        if post_logout_redirect_uri:
            request_args = {"post_logout_redirect_uri": post_logout_redirect_uri}
        else:
            request_args = {}

        _info = srv.get_request_parameters(state=state, request_args=request_args)

        logger.debug(f"EndSession Request: {_info['request'].to_dict()}")
        return _info

    def close(
            self, state: str, post_logout_redirect_uri: Optional[str] = ""
    ) -> dict:

        logger.debug(20 * "*" + " close " + 20 * "*")

        return self.logout(
            state=state, post_logout_redirect_uri=post_logout_redirect_uri
        )

    def clear_session(self, state):
        self.get_context().cstate.remove_state(state)


def backchannel_logout(client, request="", request_args=None):
    """

    :param request: URL encoded logout request
    :return:
    """
    if request:
        req = BackChannelLogoutRequest().from_urlencoded(as_unicode(request))
    elif request_args:
        req = BackChannelLogoutRequest(**request_args)
    else:
        raise MissingRequiredAttribute("logout_token")

    _context = client.get_context()
    kwargs = {
        "aud": client.get_client_id(),
        "iss": _context.get("issuer"),
        "keyjar": client.get_attribute("keyjar"),
        "allowed_sign_alg": _context.get("registration_response").get(
            "id_token_signed_response_alg", "RS256"
        ),
    }

    logger.debug(f"(backchannel_logout) Verifying request using: {kwargs}")
    try:
        req.verify(**kwargs)
    except (MessageException, ValueError, NotForMe) as err:
        raise MessageException("Bogus logout request: {}".format(err))
    else:
        logger.debug("Request verified OK")

    # Find the subject through 'sid' or 'sub'
    sub = req[verified_claim_name("logout_token")].get("sub")
    sid = None
    if not sub:
        sid = req[verified_claim_name("logout_token")].get("sid")

    if not sub and not sid:
        raise MessageException('Neither "sid" nor "sub"')
    elif sub:
        _state = _context.cstate.get_base_key(sub)
    elif sid:
        _state = _context.cstate.get_base_key(sid)
    else:
        _state = None

    return _state


def load_registration_response(client, request_args=None):
    """
    If the client has been statically registered that information
    must be provided during the configuration. If expected to be
    done dynamically this method will do dynamic client registration.

    :param client: A :py:class:`idpyoidc.client.oidc.Client` instance
    """
    if not client.get_context().get_client_id():
        try:
            response = client.do_request("registration", request_args=request_args)
        except KeyError:
            raise ConfigurationError("No registration info")
        except Exception as err:
            logger.error(err)
            raise
        else:
            if "error" in response:
                raise OidcServiceError(response.to_json())
