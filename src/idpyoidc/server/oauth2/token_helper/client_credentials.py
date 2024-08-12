import logging
from typing import Optional
from typing import Union

from idpyoidc.exception import ImproperlyConfigured
from idpyoidc.message import Message
from idpyoidc.message.oauth2 import TokenErrorResponse, AuthorizationErrorResponse
from idpyoidc.message.oauth2 import CCAccessTokenRequest
from idpyoidc.time_util import utc_time_sans_frac
from idpyoidc.util import importer
from idpyoidc.util import sanitize

from . import TokenEndpointHelper

logger = logging.getLogger(__name__)


class ClientCredentials(TokenEndpointHelper):
    def __init__(self, endpoint, config=None):
        TokenEndpointHelper.__init__(self, endpoint, config)

    def process_request(self, req: Union[Message, dict], **kwargs):
        _context = self.endpoint.upstream_get("context")
        _mngr = _context.session_manager
        logger.debug("Client credentials flow")

        # verify the client and the user

        client_id = req["client_id"]
        _authenticated = req.get("authenticated", False)
        if not _authenticated:
            if _context.cdb[client_id] != req["client_secret"]:
                logger.warning("Client authentication failed")
                return self.error_cls(error="invalid_request", error_description="Wrong client")

        _grant_types_supported = _context.cdb[client_id].get("grant_types_supported")
        if _grant_types_supported and "client_credentials" not in _grant_types_supported:
            return self.error_cls(
                error="invalid_request", error_description="Unsupported grant type"
            )

        # Is there a previous session ?
        try:
            _session_info = _mngr.get(["client_credentials", client_id])
            _grant = _session_info["grant"]
        except KeyError:
            logger.debug("No previous session")
            branch_id = _mngr.add_grant(["client_credentials", client_id])
            _session_info = _mngr.get_session_info(branch_id)

        _grant = _session_info["grant"]

        token_type = "Bearer"

        _allowed = _context.cdb[client_id].get("allowed_scopes", [])
        
        self._apply_client_credentials_filter_policy(req, _grant)

        access_token = self._mint_token(
            token_class="access_token",
            grant=_grant,
            session_id=_session_info["branch_id"],
            client_id=_session_info["client_id"],
            based_on=None,
            scope=_allowed,
            token_type=token_type
        )

        _resp = {
            "access_token": access_token.value,
            "token_type": access_token.token_class,
            "scope": _allowed,
        }

        if access_token.expires_at:
            _resp["expires_in"] = access_token.expires_at - utc_time_sans_frac()

        return _resp

    def post_parse_request(
        self, request: Union[Message, dict], client_id: Optional[str] = "", **kwargs
    ):
        request = CCAccessTokenRequest(**request.to_dict())
        logger.debug("%s: %s" % (request.__class__.__name__, sanitize(request)))
        return request

    def _apply_client_credentials_filter_policy(self, request, grant):
        _context = self.endpoint.upstream_get("context")

        policy = self.config["policy"]
        function = policy[""]["function"]
        kwargs = policy.get("kwargs", {})
        if isinstance(function, str):
            try:
                fn = importer(function)
            except Exception:
                raise ImproperlyConfigured(f"Error importing {function} policy function")
        else:
            fn = function
        try:
            return fn(request, context=_context, grant= grant, **kwargs)
        except Exception as e:
            logger.error(f"Error while executing the {fn} policy function: {e}")
            return self.error_cls(error="server_error", error_description="Internal server error")
