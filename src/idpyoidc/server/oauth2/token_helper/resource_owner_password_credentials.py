import logging
from typing import Optional
from typing import Union

from idpyoidc.exception import FailedAuthentication
from idpyoidc.message import Message
from idpyoidc.time_util import utc_time_sans_frac
from idpyoidc.util import instantiate

from ...user_authn.authn_context import pick_auth
from . import TokenEndpointHelper

logger = logging.getLogger(__name__)


class ResourceOwnerPasswordCredentials(TokenEndpointHelper):
    def __init__(self, endpoint, config=None):
        TokenEndpointHelper.__init__(self, endpoint, config)
        self.user_db = {}
        if config:
            _db = config.get("db")
            if _db:
                _db_kwargs = _db.get("kwargs", {})
                self.user_db = instantiate(_db["class"], **_db_kwargs)

    def process_request(self, req: Union[Message, dict], **kwargs):
        _context = self.endpoint.upstream_get("context")
        _mngr = _context.session_manager
        logger.debug("Client credentials flow")

        # verify the client and the user

        client_id = req["client_id"]
        _cinfo = _context.cdb.get(client_id)
        if not _cinfo:
            logger.error("Unknown client")
            return self.error_cls(error="invalid_grant", error_description="Unknown client")

        if _cinfo["client_secret"] != req["client_secret"]:
            logger.warning("Client secret mismatch")
            return self.error_cls(error="invalid_grant", error_description="Wrong client")

        _auth_method = None
        _acr = kwargs.get("acr")
        if _acr:
            _auth_method = _context.authn_broker.pick(_acr)
        else:
            try:
                _auth_method = pick_auth(_context, req)
            except Exception as exc:
                logger.exception(f"An error occurred while picking the authN broker: {exc}")

        if not _auth_method:
            return self.error_cls(
                error="invalid_request", error_description="Can't authenticate user"
            )

        authn = _auth_method["method"]
        # authn_class_ref = _auth_method["acr"]

        try:
            _username = authn.verify(username=req["username"], password=req["password"])
        except FailedAuthentication:
            logger.warning("User password did not match")
            return self.error_cls(error="invalid_grant", error_description="Wrong user")

        # Is there a previous session ?
        try:
            _session_info = _mngr.get([_username, client_id])
            _grant = _session_info["grant"]
        except KeyError:
            logger.debug("No previous session")
            branch_id = _mngr.add_grant([_username, client_id])
            _session_info = _mngr.get_session_info(branch_id)

        _grant = _session_info["grant"]

        token_type = "Bearer"

        _allowed = _context.cdb[client_id].get("allowed_scopes", [])
        access_token = self._mint_token(
            token_class="access_token",
            grant=_grant,
            session_id=_session_info["branch_id"],
            client_id=_session_info["client_id"],
            based_on=None,
            scope=_allowed,
            token_type=token_type,
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
        return request
