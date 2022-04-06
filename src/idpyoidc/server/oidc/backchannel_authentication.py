import logging
import uuid
from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt.jwe.exception import JWEException
from cryptojwt.jws.exception import NoSuitableSigningKeys
from cryptojwt.jwt import utc_time_sans_frac

from idpyoidc import verified_claim_name
from idpyoidc.message import Message
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.message.oidc.backchannel_authentication import AuthenticationRequest
from idpyoidc.message.oidc.backchannel_authentication import AuthenticationResponse
from idpyoidc.server import Endpoint
from idpyoidc.server import EndpointContext
from idpyoidc.server.client_authn import ClientSecretBasic
from idpyoidc.server.exception import NoSuchAuthentication
from idpyoidc.server.oidc.token_helper import AccessTokenHelper
from idpyoidc.server.session.token import MintingNotAllowed
from idpyoidc.server.util import execute

logger = logging.getLogger(__name__)

DEFAULT_EXPIRES_IN = 120
DEFAULT_INTERVAL = 2


class BackChannelAuthentication(Endpoint):
    request_cls = AuthenticationRequest
    response_cls = AuthenticationResponse
    error_cls = ResponseMessage
    request_format = "urlencoded"
    response_format = "urlencoded"
    response_placement = "url"
    endpoint_name = "backchannel_authentication_endpoint"
    name = "backchannel_authentication"
    provider_info_attributes = {
        "backchannel_token_delivery_modes_supported": ['poll', 'ping', 'push'],
        "backchannel_authentication_request_signing_alg_values_supported": None,
        "backchannel_user_code_parameter_supported": True,
    }

    def __init__(self, server_get: Callable, **kwargs):
        Endpoint.__init__(self, server_get, **kwargs)
        # self.pre_construct.append(self._pre_construct)
        # self.post_parse_request.append(self._do_request_uri)
        # self.post_parse_request.append(self._post_parse_request)
        self.parse_login_hint_token = kwargs.get("parse_login_hint_token")
        self.expires_in = kwargs.get("expires_in", DEFAULT_EXPIRES_IN)
        self.interval = kwargs.get("interval", DEFAULT_INTERVAL)

    def do_request_user(self, request):
        cn = verified_claim_name("id_token_hint")
        _request_user = ''
        if request.get(cn):
            _request_user = request[cn].get("sub", "")
        elif request.get("login_hint"):
            _login_hint = request.get("login_hint")
            if _login_hint:
                _context = self.server_get("endpoint_context")
                if _context.login_hint_lookup:
                    _request_user = _context.login_hint_lookup(_login_hint)
        elif request.get('login_hint_token'):
            _context = self.server_get("endpoint_context")
            _request_user = execute(self.parse_login_hint_token,
                                    keyjar=_context.keyjar,
                                    login_hint_token=request.get('login_hint_token'),
                                    context=_context)

        return _request_user

    def allowed_target_uris(self):
        """
        The OP MUST accept its Issuer Identifier, Token Endpoint URL, or Backchannel
        Authentication Endpoint URL as values that identify it as an intended audience.
        """
        _context = self.server_get("endpoint_context")
        res = [_context.issuer]
        res.append(self.full_path)
        res.append(self.server_get("endpoint", "token").full_path)
        return set(res)

    def process_request(
            self,
            request: Optional[Union[Message, dict]] = None,
            http_info: Optional[dict] = None,
            **kwargs
    ):
        try:
            request_user = self.do_request_user(request)
        except KeyError:
            logger.error("Login hint didn't lead to a known user")
            _error_msg = self.error_cls(error="invalid_request",
                                        error_description="Login hint didn't lead to a known user")
            return _error_msg

        if request_user:  # Got a request for a legitimate user, create a session
            _context = self.server_get("endpoint_context")
            _sid = _context.session_manager.create_session(
                None, request, request_user, client_id=request["client_id"]
            )

            auth_req_id = uuid.uuid4().hex
            _context.session_manager.auth_req_id_map[auth_req_id] = _sid

            return {"response_args": {"auth_req_id": auth_req_id, "expires_in": self.expires_in,
                                      "interval": self.interval}}
        else:
            _error_msg = self.error_cls(
                error="invalid_request",
                error_description="Don't know which user you're looking for")
            return _error_msg


class CIBATokenHelper(AccessTokenHelper):
    def _get_session_info(self, request, session_manager):
        _path = request["_session_path"]
        _grant = session_manager.get(_path)
        session_info = {"user_id": _path[0], "client_id": _path[1], "grant_id": _path[2],
                        "session_id": request["_session_id"]}
        return session_info, _grant

    def post_parse_request(
            self, request: Union[Message, dict], client_id: Optional[str] = "", **kwargs
    ) -> Union[Message, dict]:
        _context = self.endpoint.server_get("endpoint_context")
        _mngr = _context.session_manager
        _session_id = _mngr.auth_req_id_map[request["auth_req_id"]]
        _info = _mngr.get_session_info(_session_id)
        # There should be 2 grants for the user_id, client_id combination
        # one without authentication information, the other one with
        logger.debug(f"Session info: {_info}")
        # There should be zero or one
        _subs = [s for s in _mngr.get(
            [_info["user_id"], _info["client_id"]]).subordinate if s != _info["grant_id"]]

        if len(_subs) == 0:  # No successful authentication performed
            logger.warning("No authentication found")
            resp = self.error_cls(
                error="invalid_request",
                error_description="No authentication found",
            )
            return resp
        if len(_subs) > 1:  # more than one authentication, shouldn't happen
            logger.warning("More then one authentication found")
            resp = self.error_cls(
                error="invalid_request",
                error_description="More then one authentication found",
            )
            return resp

        _path = [_info["user_id"], _info["client_id"], _subs[0]]
        request["_session_path"] = _path
        request["_session_id"] = _session_id
        return request

    def process_request(self, req: Union[Message, dict], **kwargs):
        """

        :param req:
        :param kwargs:
        :return:
        """
        _context = self.endpoint.server_get("endpoint_context")

        _mngr = _context.session_manager
        logger.debug("OIDC Access Token")

        _session_info, grant = self._get_session_info(req, _mngr)

        logger.debug(f"Session info: {_session_info}")

        client_id = _session_info["client_id"]
        if client_id != req["client_id"]:
            logger.debug("{} owner of token".format(client_id))
            logger.warning("{} using token it was not given".format(req["client_id"]))
            return self.error_cls(error="invalid_grant", error_description="Wrong client")

        if "grant_types_supported" in _context.cdb[client_id]:
            grant_types_supported = _context.cdb[client_id].get("grant_types_supported")
        else:
            grant_types_supported = _context.provider_info["grant_types_supported"]

        token_type = "Bearer"

        # Is DPOP supported
        try:
            _dpop_enabled = _context.dpop_enabled
        except AttributeError:
            _dpop_enabled = False

        if _dpop_enabled:
            _dpop_jkt = req.get("dpop_jkt")
            if _dpop_jkt:
                grant.extra["dpop_jkt"] = _dpop_jkt
                token_type = "DPoP"

        _authn_req = grant.authorization_request

        # If redirect_uri was in the initial authorization request
        # verify that the one given here is the correct one.
        if "redirect_uri" in _authn_req:
            if req["redirect_uri"] != _authn_req["redirect_uri"]:
                return self.error_cls(
                    error="invalid_request", error_description="redirect_uri mismatch"
                )

        logger.debug("All checks OK")

        issue_refresh = kwargs.get("issue_refresh", None)
        # The existence of offline_access scope overwrites issue_refresh
        if issue_refresh is None and "offline_access" in grant.scope:
            issue_refresh = True

        _response = {
            "token_type": token_type,
            "scope": grant.scope,
        }

        try:
            token = self._mint_token(
                token_class="access_token",
                grant=grant,
                session_id=_session_info["session_id"],
                client_id=_session_info["client_id"],
                token_type=token_type,
            )
        except MintingNotAllowed as err:
            logger.warning(err)
        else:
            _response["access_token"] = token.value
            if token.expires_at:
                _response["expires_in"] = token.expires_at - utc_time_sans_frac()

        if issue_refresh and "refresh_token" in grant_types_supported:
            try:
                refresh_token = self._mint_token(
                    token_class="refresh_token",
                    grant=grant,
                    session_id=_session_info["session_id"],
                    client_id=_session_info["client_id"],
                )
            except MintingNotAllowed as err:
                logger.warning(err)
            else:
                _response["refresh_token"] = refresh_token.value

        # since the grant content has changed. Make sure it's stored
        _mngr[_session_info["session_id"]] = grant

        if "openid" in _authn_req["scope"]:
            try:
                _idtoken = self._mint_token(
                    token_class="id_token",
                    grant=grant,
                    session_id=_session_info["session_id"],
                    client_id=_session_info["client_id"],
                )
            except (JWEException, NoSuitableSigningKeys) as err:
                logger.warning(str(err))
                resp = self.error_cls(
                    error="invalid_request",
                    error_description="Could not sign/encrypt id_token",
                )
                return resp

            _response["id_token"] = _idtoken.value

        return _response


class ClientNotification(Endpoint):
    request_cls = AuthenticationRequest
    response_cls = AuthenticationResponse
    error_cls = ResponseMessage
    request_format = "json"
    endpoint_name = "client_notification_endpoint"
    name = "client_notification"
    provider_info_attributes = {
        "backchannel_client_notification_endpoint": None,
    }

    def __init__(self, server_get: Callable, **kwargs):
        Endpoint.__init__(self, server_get, **kwargs)

    def process_request(
                self,
                request: Optional[Union[Message, dict]] = None,
                http_info: Optional[dict] = None,
                **kwargs
        ) -> Union[Message, dict]:
        return {}


class ClientNotificationAuthn(ClientSecretBasic):
    """The authentication method used at the notification endpoint."""

    tag = "client_notification_authn"

    def is_usable(self, request=None, authorization_token=None):
        if authorization_token is not None and authorization_token.startswith("Bearer "):
            return True
        return False

    def _verify(
            self,
            endpoint_context: EndpointContext,
            request: Optional[Union[dict, Message]] = None,
            authorization_token: Optional[str] = None,
            endpoint=None,  # Optional[Endpoint]
            get_client_id_from_token: Optional[Callable] = None,
            **kwargs
    ):
        ttype, token = authorization_token.split(" ", 1)
        if ttype != "Bearer":
            raise NoSuchAuthentication(f"No support for {ttype}")
        if get_client_id_from_token:
            client_id = get_client_id_from_token(token)
        else:
            client_id = ""
        return {"token": token, "client_id": client_id}
