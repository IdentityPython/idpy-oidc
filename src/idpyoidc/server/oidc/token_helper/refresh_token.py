import logging
from typing import Optional
from typing import Union

from cryptojwt import BadSyntax
from cryptojwt.jwe.exception import JWEException
from cryptojwt.jws.exception import NoSuitableSigningKeys
from cryptojwt.jwt import utc_time_sans_frac

from ...exception import InvalidBranchID
from idpyoidc.exception import MissingRequiredAttribute
from idpyoidc.message import Message
from idpyoidc.message.oidc import RefreshAccessTokenRequest
from idpyoidc.server.oauth2.token_helper import TokenEndpointHelper
from idpyoidc.server.session.token import AuthorizationCode
from idpyoidc.server.session.token import MintingNotAllowed
from idpyoidc.server.session.token import RefreshToken
from idpyoidc.server.token.exception import UnknownToken
from idpyoidc.util import sanitize

logger = logging.getLogger(__name__)


class RefreshTokenHelper(TokenEndpointHelper):
    def process_request(self, req: Union[Message, dict], **kwargs):
        _context = self.endpoint.upstream_get("context")
        _mngr = _context.session_manager

        if req["grant_type"] != "refresh_token":
            return self.error_cls(error="invalid_request", error_description="Wrong grant_type")

        token_value = req["refresh_token"]

        _session_info = _mngr.get_session_info_by_token(
            token_value, handler_key="refresh_token", grant=True
        )
        if _session_info["client_id"] != req["client_id"]:
            logger.debug("{} owner of token".format(_session_info["client_id"]))
            logger.warning("{} using token it was not given".format(req["client_id"]))
            return self.error_cls(error="invalid_grant", error_description="Wrong client")

        _grant = _session_info["grant"]

        token_type = "Bearer"

        # Is DPOP supported
        if "dpop_signing_alg_values_supported" in _context.provider_info:
            _dpop_jkt = req.get("dpop_jkt")
            if _dpop_jkt:
                _grant.extra["dpop_jkt"] = _dpop_jkt
                token_type = "DPoP"

        token = _grant.get_token(token_value)
        scope = _grant.find_scope(token.based_on)
        if "scope" in req:
            scope = req["scope"]
        access_token = self._mint_token(
            token_class="access_token",
            grant=_grant,
            session_id=_session_info["branch_id"],
            client_id=_session_info["client_id"],
            based_on=token,
            scope=scope,
            token_type=token_type,
        )

        _resp = {
            "access_token": access_token.value,
            "token_type": token_type,
            "scope": scope,
        }

        if access_token.expires_at:
            _resp["expires_in"] = access_token.expires_at - utc_time_sans_frac()

        _mints = token.usage_rules.get("supports_minting")

        issue_refresh = kwargs.get("issue_refresh", None)
        # The existence of offline_access scope overwrites issue_refresh
        if issue_refresh is None and "offline_access" in scope:
            issue_refresh = True

        if "refresh_token" in _mints and issue_refresh:
            refresh_token = self._mint_token(
                token_class="refresh_token",
                grant=_grant,
                session_id=_session_info["branch_id"],
                client_id=_session_info["client_id"],
                based_on=token,
                scope=scope,
            )
            refresh_token.usage_rules = token.usage_rules.copy()
            _resp["refresh_token"] = refresh_token.value

        if "id_token" in _mints and "openid" in scope:
            try:
                _idtoken = self._mint_token(
                    token_class="id_token",
                    grant=_grant,
                    session_id=_session_info["branch_id"],
                    client_id=_session_info["client_id"],
                    based_on=token,
                    scope=scope,
                )
            except (JWEException, NoSuitableSigningKeys) as err:
                logger.warning(str(err))
                resp = self.error_cls(
                    error="invalid_request",
                    error_description="Could not sign/encrypt id_token",
                )
                return resp

            _resp["id_token"] = _idtoken.value

        token.register_usage()

        if (
            "client_id" in req
            and req["client_id"] in _context.cdb
            and "revoke_refresh_on_issue" in _context.cdb[req["client_id"]]
        ):
            revoke_refresh = _context.cdb[req["client_id"]].get("revoke_refresh_on_issue")
        else:
            revoke_refresh = self.endpoint.revoke_refresh_on_issue

        if revoke_refresh:
            token.revoke()

        return _resp

    def post_parse_request(
        self, request: Union[Message, dict], client_id: Optional[str] = "", **kwargs
    ):
        """
        This is where clients come to refresh their access tokens

        :param request: The request
        :param client_id: Client identifier
        :returns:
        """

        request = RefreshAccessTokenRequest(**request.to_dict())
        _context = self.endpoint.upstream_get("context")

        try:
            request.verify(
                keyjar=self.endpoint.upstream_get("attribute", "keyjar"), opponent_id=client_id
            )
        except MissingRequiredAttribute as e:
            return self.error_cls(error="invalid_grant", error_description=str(e))

        _mngr = _context.session_manager
        try:
            _session_info = _mngr.get_session_info_by_token(
                request["refresh_token"], handler_key="refresh_token", grant=True
            )
        except (KeyError, UnknownToken, BadSyntax, InvalidBranchID):
            logger.error("Refresh token invalid")
            return self.error_cls(error="invalid_grant", error_description="Invalid refresh token")

        grant = _session_info["grant"]
        token = grant.get_token(request["refresh_token"])

        if not isinstance(token, RefreshToken):
            return self.error_cls(error="invalid_request", error_description="Wrong token type")

        if token.is_active() is False:
            return self.error_cls(
                error="invalid_request", error_description="Refresh token inactive"
            )

        if "scope" in request:
            req_scopes = set(request["scope"])
            scopes = set(grant.find_scope(token.based_on))
            if not req_scopes.issubset(scopes):
                return self.error_cls(
                    error="invalid_request",
                    error_description="Invalid refresh scopes",
                )

        return request
