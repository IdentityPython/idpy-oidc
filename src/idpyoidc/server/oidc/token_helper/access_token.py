import logging
from typing import Optional
from typing import Union

from cryptojwt.jwe.exception import JWEException
from cryptojwt.jws.exception import NoSuitableSigningKeys
from cryptojwt.jwt import utc_time_sans_frac

from idpyoidc.message import Message
from idpyoidc.server.oauth2.token_helper import TokenEndpointHelper
from idpyoidc.server.session.token import AuthorizationCode
from idpyoidc.server.session.token import MintingNotAllowed
from idpyoidc.server.token.exception import UnknownToken
from idpyoidc.util import sanitize

logger = logging.getLogger(__name__)


class AccessTokenHelper(TokenEndpointHelper):
    def _get_session_info(self, request, session_manager):
        if request["grant_type"] != "authorization_code":
            return self.error_cls(error="invalid_request", error_description="Unknown grant_type")

        try:
            _access_code = request["code"].replace(" ", "+")
        except KeyError:  # Missing code parameter - absolutely fatal
            return self.error_cls(error="invalid_request", error_description="Missing code")

        _session_info = session_manager.get_session_info_by_token(
            _access_code, grant=True, handler_key="authorization_code"
        )
        logger.debug(f"Session info: {_session_info}")
        return _session_info, _access_code

    def process_request(self, req: Union[Message, dict], **kwargs):
        """

        :param req:
        :param kwargs:
        :return:
        """
        _context = self.endpoint.upstream_get("context")

        _mngr = _context.session_manager
        logger.debug("OIDC Access Token")

        _session_info, _access_code = self._get_session_info(req, _mngr)
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
        grant = _session_info["grant"]

        token_type = "Bearer"

        # Is DPOP supported
        _dpop_enabled = False
        _dpop_args = _context.add_on.get("dpop")
        if _dpop_args:
            _dpop_enabled = True

        if _dpop_enabled:
            _dpop_jkt = req.get("dpop_jkt")
            if _dpop_jkt:
                grant.extra["dpop_jkt"] = _dpop_jkt
                token_type = "DPoP"

        _based_on = grant.get_token(_access_code)
        _supports_minting = _based_on.usage_rules.get("supports_minting", [])

        _authn_req = grant.authorization_request

        # Check if refresh_token is at the client's grant_types_supported 
        # but not in global configuration then we should grant it
        if "refresh_token" in grant_types_supported and "refresh_token" not in _supports_minting:
            _supports_minting.append("refresh_token")

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

        if "access_token" in _supports_minting:
            try:
                token = self._mint_token(
                    token_class="access_token",
                    grant=grant,
                    session_id=_session_info["branch_id"],
                    client_id=_session_info["client_id"],
                    based_on=_based_on,
                    token_type=token_type,
                )
            except MintingNotAllowed as err:
                logger.warning(err)
            else:
                _response["access_token"] = token.value
                if token.expires_at:
                    _response["expires_in"] = token.expires_at - utc_time_sans_frac()

        if issue_refresh and "refresh_token" in _supports_minting:
            try:
                refresh_token = self._mint_token(
                    token_class="refresh_token",
                    grant=grant,
                    session_id=_session_info["branch_id"],
                    client_id=_session_info["client_id"],
                    based_on=_based_on,
                )
            except MintingNotAllowed as err:
                logger.warning(err)
            else:
                _response["refresh_token"] = refresh_token.value

        # since the grant content has changed. Make sure it's stored
        _mngr[_session_info["branch_id"]] = grant

        if "openid" in _authn_req["scope"] and "id_token" in _supports_minting:
            if "id_token" in _based_on.usage_rules.get("supports_minting"):
                try:
                    _idtoken = self._mint_token(
                        token_class="id_token",
                        grant=grant,
                        session_id=_session_info["branch_id"],
                        client_id=_session_info["client_id"],
                        based_on=_based_on,
                    )
                except (JWEException, NoSuitableSigningKeys) as err:
                    logger.warning(str(err))
                    resp = self.error_cls(
                        error="invalid_request",
                        error_description="Could not sign/encrypt id_token",
                    )
                    return resp

                _response["id_token"] = _idtoken.value

        _based_on.register_usage()

        return _response

    def post_parse_request(
        self, request: Union[Message, dict], client_id: Optional[str] = "", **kwargs
    ) -> Union[Message, dict]:
        """
        This is where clients come to get their access tokens

        :param request: The request
        :param client_id: Client identifier
        :returns:
        """

        _mngr = self.endpoint.upstream_get("context").session_manager
        try:
            _session_info = _mngr.get_session_info_by_token(
                request["code"], grant=True, handler_key="authorization_code"
            )
        except (KeyError, UnknownToken):
            logger.error("Access Code invalid")
            return self.error_cls(error="invalid_grant", error_description="Unknown code")

        grant = _session_info["grant"]
        code = grant.get_token(request["code"])
        if not isinstance(code, AuthorizationCode):
            return self.error_cls(error="invalid_request", error_description="Wrong token type")

        if code.used:  # Has been used already
            # invalidate all tokens that has been minted using this code
            grant.revoke_token(based_on=request["code"], recursive=True)
            return self.error_cls(error="invalid_grant", error_description="Code inactive")

        if code.is_active() is False:
            return self.error_cls(error="invalid_grant", error_description="Code inactive")

        _auth_req = grant.authorization_request

        if "client_id" not in request:  # Optional for access token request
            request["client_id"] = _auth_req["client_id"]

        logger.debug("%s: %s" % (request.__class__.__name__, sanitize(request)))

        return request
