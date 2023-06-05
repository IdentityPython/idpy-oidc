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
from idpyoidc.server.oauth2.token_helper import TokenEndpointHelper
from idpyoidc.server.session import MintingNotAllowed
from idpyoidc.util import importer

from .token_helper.access_token import AccessTokenHelper
from .token_helper.client_credentials import ClientCredentials
from .token_helper.refresh_token import RefreshTokenHelper
from .token_helper.resource_owner_password_credentials import ResourceOwnerPasswordCredentials
from .token_helper.token_exchange import TokenExchangeHelper

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
    token_exchange_helper = TokenExchangeHelper

    helper_by_grant_type = {
        "authorization_code": AccessTokenHelper,
        "refresh_token": RefreshTokenHelper,
        "urn:ietf:params:oauth:grant-type:token-exchange": TokenExchangeHelper,
        "client_credentials": ClientCredentials,
        "password": ResourceOwnerPasswordCredentials,
    }

    _supports = {
        "grant_types_supported": list(helper_by_grant_type.keys())
    }

    def __init__(self, upstream_get, new_refresh_token=False, **kwargs):
        Endpoint.__init__(self, upstream_get, **kwargs)
        self.post_parse_request.append(self._post_parse_request)
        self.allow_refresh = False
        self.new_refresh_token = new_refresh_token
        self.grant_type_helper = self.configure_types(kwargs.get("grant_types_helpers"),
                                                      self.helper_by_grant_type)
        # self.grant_types_supported = kwargs.get("grant_types_supported",
        #                                         list(self.grant_type_helper.keys()))
        self.revoke_refresh_on_issue = kwargs.get("revoke_refresh_on_issue", False)
        self.resource_indicators_config = kwargs.get('resource_indicators', None)

    def configure_types(self, helpers, default_helpers):
        if helpers is None:
            return {k: v(self) for k, v in default_helpers.items()}

        _helper = {}
        for type, args in helpers.items():
            _kwargs = args.get("kwargs", {})
            if _kwargs is False:
                continue

            try:
                _class = args["class"]
            except (KeyError, TypeError):
                raise ProcessError(
                    "Token Endpoint's grant types must be True, None or a dict with a"
                    " 'class' key."
                )

            if isinstance(_class, str):
                try:
                    _class = importer(_class)
                except (ValueError, AttributeError):
                    raise ProcessError(
                        f"Token Endpoint's helper class {_class} can't" " be imported."
                    )

            try:
                _helper[type] = _class(self, _kwargs)
            except Exception as e:
                raise ProcessError(f"Failed to initialize class {_class}: {e}")

        return _helper

    def _get_helper(self,
                    request: Union[Message, dict],
                    client_id: Optional[str] = "") -> Optional[Union[Message, TokenEndpointHelper]]:
        grant_type = request.get('grant_type')
        if grant_type:
            _client_id = client_id or request.get('client_id')
            if client_id:
                client = self.upstream_get('context').cdb[client_id]
                _grant_types_supported = client.get("grant_types_supported",
                                                    self.upstream_get('context').claims.get_claim(
                                                        "grant_types_supported", [])
                                                    )
                if grant_type not in _grant_types_supported:
                    return self.error_cls(
                        error="invalid_request",
                        error_description=f"Unsupported grant_type: {grant_type}",
                    )

            return self.grant_type_helper.get(grant_type)
        else:
            return self.error_cls(
                error="invalid_request",
                error_description=f"Do not know how to handle this type of request",
            )

    def _post_parse_request(
            self, request: Union[Message, dict], client_id: Optional[str] = "", **kwargs
    ):
        _resp = self._get_helper(request, client_id)
        if isinstance(_resp, TokenEndpointHelper):
            return _resp.post_parse_request(request, client_id, **kwargs)
        elif _resp:
            return _resp
        else:
            return self.error_cls(
                error="invalid_request",
                error_description=f"Do not know how to handle this type of request",
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
            _helper = self._get_helper(request)
            if _helper:
                response_args = _helper.process_request(request, **kwargs)
            else:
                return self.error_cls(
                    error="invalid_request",
                    error_description=f"Unsupported grant_type: {request['grant_type']}",
                )
        except JWEException as err:
            return self.error_cls(error="invalid_request", error_description="%s" % err)
        except MintingNotAllowed as err:
            return self.error_cls(error="invalid_request", error_description="%s" % err)

        if isinstance(response_args, ResponseMessage):
            return response_args

        _access_token = response_args["access_token"]
        _context = self.upstream_get("context")

        if isinstance(_helper, self.token_exchange_helper):
            _handler_key = _helper.get_handler_key(request, _context)
        else:
            _handler_key = "access_token"

        _session_info = _context.session_manager.get_session_info_by_token(
            _access_token, grant=True, handler_key=_handler_key
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

    def supports(self):
        return {'grant_types_supported': list(self.grant_type_helper.keys())}
