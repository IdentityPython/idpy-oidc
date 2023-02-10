"""Implements RFC7009"""

import logging

from idpyoidc.exception import ImproperlyConfigured
from idpyoidc.message import oauth2
from idpyoidc.server.endpoint import Endpoint
from idpyoidc.server.token.exception import UnknownToken
from idpyoidc.server.token.exception import WrongTokenClass
from idpyoidc.util import importer

logger = logging.getLogger(__name__)


class TokenRevocation(Endpoint):
    """Implements RFC7009"""

    request_cls = oauth2.TokenRevocationRequest
    response_cls = oauth2.TokenRevocationResponse
    error_cls = oauth2.TokenRevocationErrorResponse
    request_format = "urlencoded"
    response_format = "json"
    endpoint_name = "revocation_endpoint"
    name = "token_revocation"
    default_capabilities = {
        "client_authn_method": [
            "client_secret_basic",
            "client_secret_post",
            "client_secret_jwt",
            "bearer_header",
            "private_key_jwt",
        ]
    }

    token_types_supported = ["authorization_code", "access_token", "refresh_token"]

    def __init__(self, upstream_get, **kwargs):
        Endpoint.__init__(self, upstream_get, **kwargs)
        self.token_revocation_kwargs = kwargs

    def get_client_id_from_token(self, endpoint_context, token, request=None):
        _info = endpoint_context.session_manager.get_session_info_by_token(
            token, handler_key="access_token"
        )
        return _info["client_id"]

    def process_request(self, request=None, **kwargs):
        """
        :param request: The revocation request as a dictionary
        :param kwargs:
        :return:
        """
        _revoke_request = self.request_cls(**request)
        if "error" in _revoke_request:
            return _revoke_request

        request_token = _revoke_request["token"]
        _resp = self.response_cls()
        _context = self.upstream_get("endpoint_context")
        logger.debug("Token Revocation")

        try:
            _session_info = _context.session_manager.get_session_info_by_token(
                request_token, grant=True
            )
        except (UnknownToken, WrongTokenClass):
            return {"response_args": _resp}

        client_id = _session_info["client_id"]
        if client_id != _revoke_request["client_id"]:
            logger.debug("{} owner of token".format(client_id))
            logger.warning("Client using token it was not given")
            return self.error_cls(error="invalid_grant", error_description="Wrong client")

        grant = _session_info["grant"]
        _token = grant.get_token(request_token)

        try:
            self.token_types_supported = _context.cdb[client_id]["token_revocation"][
                "token_types_supported"]
        except:
            self.token_types_supported = self.token_revocation_kwargs.get("token_types_supported",
                                                                          self.token_types_supported)

        try:
            self.policy = _context.cdb[client_id]["token_revocation"]["policy"]
        except:
            self.policy = self.token_revocation_kwargs.get("policy", {
                "": {"callable": validate_token_revocation_policy}})

        if _token.token_class not in self.token_types_supported:
            desc = (
                "The authorization server does not support the revocation of "
                "the presented token type. That is, the client tried to revoke an access "
                "token on a server not supporting this feature."
            )
            return self.error_cls(error="unsupported_token_type", error_description=desc)

        return self._revoke(_revoke_request, _session_info)

    def _revoke(self, request, session_info):
        _context = self.upstream_get("endpoint_context")
        _mngr = _context.session_manager
        _token = _mngr.find_token(session_info["branch_id"], request["token"])

        _cls = _token.token_class
        if _cls not in self.policy:
            _cls = ""

        temp_policy = self.policy[_cls]
        callable = temp_policy["callable"]
        kwargs = temp_policy.get("kwargs", {})

        if isinstance(callable, str):
            try:
                fn = importer(callable)
            except Exception:
                raise ImproperlyConfigured(f"Error importing {callable} policy callable")
        else:
            fn = callable

        try:
            return fn(_token, session_info=session_info, **kwargs)
        except Exception as e:
            logger.error(f"Error while executing the {fn} policy callable: {e}")
            return self.error_cls(error="server_error", error_description="Internal server error")


def validate_token_revocation_policy(token, session_info, **kwargs):
    _token = token
    _token.revoke()

    response_args = {"response_args": {}}
    return oauth2.TokenRevocationResponse(**response_args)
