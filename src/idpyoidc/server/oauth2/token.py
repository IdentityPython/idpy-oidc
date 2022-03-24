import logging
from typing import Optional
from typing import Union

from cryptojwt.jwe.exception import JWEException

from idpyoidc.message import Message
from idpyoidc.message.oauth2 import AccessTokenResponse
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.message.oidc import TokenErrorResponse
from idpyoidc.server.endpoint import Endpoint
from idpyoidc.server.exception import ProcessError
from idpyoidc.server.oauth2.token_helper import AccessTokenHelper
from idpyoidc.server.oauth2.token_helper import RefreshTokenHelper
from idpyoidc.util import importer

logger = logging.getLogger(__name__)


class Token(Endpoint):
    request_cls = Message
    response_cls = AccessTokenResponse
    error_cls = TokenErrorResponse
    request_format = "json"
    request_placement = "body"
    response_format = "json"
    response_placement = "body"
    endpoint_name = "token_endpoint"
    name = "token"
    default_capabilities = {"token_endpoint_auth_signing_alg_values_supported": None}
    helper_by_grant_type = {
        "authorization_code": AccessTokenHelper,
        "refresh_token": RefreshTokenHelper,
    }

    def __init__(self, server_get, new_refresh_token=False, **kwargs):
        Endpoint.__init__(self, server_get, **kwargs)
        self.post_parse_request.append(self._post_parse_request)
        self.allow_refresh = False
        self.new_refresh_token = new_refresh_token
        self.configure_grant_types(kwargs.get("grant_types_helpers"))
        self.grant_types_supported = kwargs.get("grant_types_supported", list(self.helper.keys()))
        self.revoke_refresh_on_issue = kwargs.get("revoke_refresh_on_issue", False)

    def configure_grant_types(self, grant_types_helpers):
        if grant_types_helpers is None:
            self.helper = {k: v(self) for k, v in self.helper_by_grant_type.items()}
            return

        self.helper = {}
        # TODO: do we want to allow any grant_type?
        for grant_type, grant_type_options in grant_types_helpers.items():
            _conf = grant_type_options.get("kwargs", {})
            if _conf is False:
                continue

            try:
                grant_class = grant_type_options["class"]
            except (KeyError, TypeError):
                raise ProcessError(
                    "Token Endpoint's grant types must be True, None or a dict with a"
                    " 'class' key."
                )

            if isinstance(grant_class, str):
                try:
                    grant_class = importer(grant_class)
                except (ValueError, AttributeError):
                    raise ProcessError(
                        f"Token Endpoint's grant type class {grant_class} can't" " be imported."
                    )

            try:
                self.helper[grant_type] = grant_class(self, _conf)
            except Exception as e:
                raise ProcessError(f"Failed to initialize class {grant_class}: {e}")

    def _post_parse_request(
            self, request: Union[Message, dict], client_id: Optional[str] = "", **kwargs
    ):
        grant_type = request["grant_type"]
        _helper = self.helper.get(grant_type)
        client = kwargs["endpoint_context"].cdb[client_id]
        grant_types_supported = client.get(
            "grant_types_supported", self.grant_types_supported
        )
        if grant_type not in grant_types_supported:
            return self.error_cls(
                error="invalid_request",
                error_description=f"Unsupported grant_type: {grant_type}",
            )
        if _helper:
            return _helper.post_parse_request(request, client_id, **kwargs)
        else:
            return self.error_cls(
                error="invalid_request",
                error_description=f"Unsupported grant_type: {grant_type}",
            )

    def process_request(self, request: Optional[Union[Message, dict]] = None, **kwargs):
        """

        :param request:
        :param kwargs:
        :return: Dictionary with response information
        """
        if isinstance(request, self.error_cls):
            return request

        if request is None:
            return self.error_cls(error="invalid_request")

        try:
            _helper = self.helper.get(request["grant_type"])
            if _helper:
                response_args = _helper.process_request(request, **kwargs)
            else:
                return self.error_cls(
                    error="invalid_request",
                    error_description=f"Unsupported grant_type: {request['grant_type']}",
                )
        except JWEException as err:
            return self.error_cls(error="invalid_request", error_description="%s" % err)

        if isinstance(response_args, ResponseMessage):
            return response_args

        _access_token = response_args["access_token"]
        _context = self.server_get("endpoint_context")
        _session_info = _context.session_manager.get_session_info_by_token(
            _access_token, grant=True
        )

        _cookie = _context.new_cookie(
            name=_context.cookie_handler.name["session"],
            sub=_session_info["grant"].sub,
            sid=_context.session_manager.session_key(
                _session_info["user_id"],
                _session_info["client_id"],
                _session_info["grant"].id,
            ),
        )

        _headers = [("Content-type", "application/json")]
        resp = {"response_args": response_args, "http_headers": _headers}
        if _cookie:
            resp["cookie"] = [_cookie]
        return resp
