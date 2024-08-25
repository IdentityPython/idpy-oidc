import logging
from typing import Optional
from typing import Union

from cryptojwt.jwt import utc_time_sans_frac
from cryptojwt.utils import importer

from idpyoidc.exception import ImproperlyConfigured
from idpyoidc.message import Message
from idpyoidc.message.oauth2 import TokenErrorResponse
from idpyoidc.util import sanitize

from ...session import MintingNotAllowed
from ...session.token import AuthorizationCode
from ...token import UnknownToken
from . import TokenEndpointHelper
from . import validate_resource_indicators_policy

logger = logging.getLogger(__name__)


class AccessTokenHelper(TokenEndpointHelper):
    def process_request(self, req: Union[Message, dict], **kwargs):
        """

        :param req:
        :param kwargs:
        :return:
        """
        _context = self.endpoint.upstream_get("context")
        _mngr = _context.session_manager
        logger.debug("Access Token")

        if req["grant_type"] != "authorization_code":
            return self.error_cls(error="invalid_request", error_description="Unknown grant_type")

        try:
            _access_code = req["code"].replace(" ", "+")
        except KeyError:  # Missing code parameter - absolutely fatal
            return self.error_cls(error="invalid_request", error_description="Missing code")

        _session_info = _mngr.get_session_info_by_token(
            _access_code, grant=True, handler_key="authorization_code"
        )
        client_id = _session_info["client_id"]
        if client_id != req["client_id"]:
            logger.debug("{} owner of token".format(client_id))
            logger.warning("Client using token it was not given")
            return self.error_cls(error="invalid_grant", error_description="Wrong client")

        _cinfo = self.endpoint.upstream_get("context").cdb.get(client_id)

        if "resource_indicators" in _cinfo and "access_token" in _cinfo["resource_indicators"]:
            resource_indicators_config = _cinfo["resource_indicators"]["access_token"]
        else:
            resource_indicators_config = self.endpoint.kwargs.get("resource_indicators", None)

        if resource_indicators_config is not None:
            if "policy" not in resource_indicators_config:
                policy = {"policy": {"function": validate_resource_indicators_policy}}
                resource_indicators_config.update(policy)

            req = self._enforce_resource_indicators_policy(req, resource_indicators_config)

            if isinstance(req, TokenErrorResponse):
                return req

        grant = _session_info["grant"]
        token_type = "Bearer"

        # Is DPOP supported
        try:
            _dpop_enabled = _context.add_on.get("dpop")
        except AttributeError:
            _dpop_enabled = False

        if _dpop_enabled:
            _dpop_jkt = req.get("dpop_jkt")
            if _dpop_jkt:
                grant.extra["dpop_jkt"] = _dpop_jkt
                token_type = "DPoP"

        _based_on = grant.get_token(_access_code)
        _supports_minting = _based_on.usage_rules.get("supports_minting", [])

        _authn_req = grant.authorization_request

        # If redirect_uri was in the initial authorization request
        # verify that the one given here is the correct one.
        if "redirect_uri" in _authn_req:
            if req["redirect_uri"] != _authn_req["redirect_uri"]:
                return self.error_cls(
                    error="invalid_request", error_description="redirect_uri mismatch"
                )

        logger.debug("All checks OK")

        if resource_indicators_config is not None:
            scope = req["scope"]
        else:
            scope = grant.scope

        if "offline_access" in scope and "refresh_token" in _supports_minting:
            issue_refresh = True
        else:
            issue_refresh = kwargs.get("issue_refresh", False)

        _response = {
            "token_type": token_type,
            "scope": scope,
        }

        if "access_token" in _supports_minting:

            resources = req.get("resource", None)
            if resources:
                token_args = {"resources": resources}
            else:
                token_args = {}

            _aud = grant.authorization_request.get("audience")
            if _aud:
                token_args["aud"] = _aud

            try:
                token = self._mint_token(
                    token_class="access_token",
                    grant=grant,
                    session_id=_session_info["branch_id"],
                    client_id=_session_info["client_id"],
                    based_on=_based_on,
                    token_args=token_args,
                )
            except MintingNotAllowed as err:
                logger.warning(err)
            else:
                _response["access_token"] = token.value
                if token.expires_at:
                    _response["expires_in"] = token.expires_at - utc_time_sans_frac()

        if issue_refresh and "refresh_token" in _supports_minting:
            if token:
                _based_on.used -= 1
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

        _based_on.register_usage()

        return _response

    def _enforce_resource_indicators_policy(self, request, config):
        _context = self.endpoint.upstream_get("context")

        policy = config["policy"]
        function = policy["function"]
        kwargs = policy.get("kwargs", {})

        if isinstance(function, str):
            try:
                fn = importer(function)
            except Exception:
                raise ImproperlyConfigured(f"Error importing {function} policy function")
        else:
            fn = function
        try:
            return fn(request, context=_context, **kwargs)
        except Exception as e:
            logger.error(f"Error while executing the {fn} policy function: {e}")
            return self.error_cls(error="server_error", error_description="Internal server error")

    def post_parse_request(
        self, request: Union[Message, dict], client_id: Optional[str] = "", **kwargs
    ):
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

        if code.is_active() is False:
            return self.error_cls(error="invalid_request", error_description="Code inactive")

        _auth_req = grant.authorization_request

        if "client_id" not in request:  # Optional for access token request
            request["client_id"] = _auth_req["client_id"]

        logger.debug("%s: %s" % (request.__class__.__name__, sanitize(request)))

        return request
