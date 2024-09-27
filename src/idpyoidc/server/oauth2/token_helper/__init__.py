import logging
from typing import Optional
from typing import Union

from idpyoidc.message import Message
from idpyoidc.message.oidc import TokenErrorResponse
from idpyoidc.server.constant import DEFAULT_TOKEN_LIFETIME
from idpyoidc.server.session.grant import Grant
from idpyoidc.server.session.token import SessionToken
from idpyoidc.time_util import utc_time_sans_frac

logger = logging.getLogger(__name__)


class TokenEndpointHelper(object):
    def __init__(self, endpoint, config=None):
        self.endpoint = endpoint
        self.config = config or {}
        self.error_cls = self.endpoint.error_cls

    def post_parse_request(
        self, request: Union[Message, dict], client_id: Optional[str] = "", **kwargs
    ):
        """Context specific parsing of the request.
        This is done after general request parsing and before processing
        the request.
        """
        raise NotImplementedError

    def process_request(self, req: Union[Message, dict], **kwargs):
        """Acts on a process request."""
        raise NotImplementedError

    def _mint_token(
        self,
        token_class: str,
        grant: Grant,
        session_id: str,
        client_id: str,
        based_on: Optional[SessionToken] = None,
        scope: Optional[list] = None,
        token_args: Optional[dict] = None,
        token_type: Optional[str] = "",
    ) -> SessionToken:
        _context = self.endpoint.upstream_get("context")
        _mngr = _context.session_manager
        usage_rules = grant.usage_rules.get(token_class)
        if usage_rules:
            _exp_in = usage_rules.get("expires_in")
        else:
            _token_handler = _mngr.token_handler[token_class]
            _exp_in = _token_handler.lifetime

        token_args = token_args or {}
        for meth in _context.token_args_methods:
            token_args = meth(_context, client_id, token_args)

        if token_args:
            _args = token_args
        else:
            _args = {}

        token = grant.mint_token(
            session_id,
            context=_context,
            token_class=token_class,
            token_handler=_mngr.token_handler[token_class],
            based_on=based_on,
            usage_rules=usage_rules,
            scope=scope,
            token_type=token_type,
            **_args,
        )

        if _exp_in:
            if isinstance(_exp_in, str):
                _exp_in = int(_exp_in)

            if _exp_in:
                token.expires_at = utc_time_sans_frac() + _exp_in

        _context.session_manager.set(_context.session_manager.unpack_session_key(session_id), grant)

        return token


def validate_resource_indicators_policy(request, context, **kwargs):
    if "resource" not in request:
        return TokenErrorResponse(
            error="invalid_target",
            error_description="Missing resource parameter",
        )

    client_id = request["client_id"]

    resource_servers_per_client = kwargs.get("resource_servers_per_client", [])

    if (
        isinstance(resource_servers_per_client, dict)
        and client_id not in resource_servers_per_client
    ):
        return TokenErrorResponse(
            error="invalid_target",
            error_description=f"Resources for client {client_id} not found",
        )

    if isinstance(resource_servers_per_client, dict):
        permitted_resources = [res for res in resource_servers_per_client[client_id]]
    else:
        permitted_resources = [res for res in resource_servers_per_client]

    common_resources = list(set(request["resource"]).intersection(set(permitted_resources)))
    if not common_resources:
        return TokenErrorResponse(
            error="invalid_target",
            error_description=f"Invalid resource requested by client {client_id}",
        )

    common_resources = [r for r in common_resources if r in context.cdb.keys()]
    if not common_resources:
        return TokenErrorResponse(
            error="invalid_target",
            error_description=f"Invalid resource requested by client {client_id}",
        )

    if client_id not in common_resources:
        common_resources.append(client_id)

    request["resource"] = common_resources

    permitted_scopes = [context.cdb[r]["allowed_scopes"] for r in common_resources]
    permitted_scopes = [r for res in permitted_scopes for r in res]
    scopes = list(set(request.get("scope", [])).intersection(set(permitted_scopes)))
    request["scope"] = scopes
    return request


def validate_token_exchange_policy(request, context, subject_token, **kwargs):
    if "resource" in request:
        resource = kwargs.get("resource", [])
        if not set(request["resource"]).issubset(set(resource)):
            return TokenErrorResponse(error="invalid_target", error_description="Unknown resource")

    if "audience" in request:
        if request["subject_token_type"] == "urn:ietf:params:oauth:token-type:refresh_token":
            return TokenErrorResponse(
                error="invalid_target", error_description="Refresh token has single owner"
            )
        audience = kwargs.get("audience", [])
        if audience and not set(request["audience"]).issubset(set(audience)):
            return TokenErrorResponse(error="invalid_target", error_description="Unknown audience")

    if "actor_token" in request or "actor_token_type" in request:
        return TokenErrorResponse(
            error="invalid_request", error_description="Actor token not supported"
        )

    if (
        "requested_token_type" in request
        and request["requested_token_type"] == "urn:ietf:params:oauth:token-type:refresh_token"
    ):
        if "offline_access" not in subject_token.scope:
            return TokenErrorResponse(
                error="invalid_request",
                error_description=f"Exchange {request['subject_token_type']} to refresh token "
                f"forbidden",
            )

    scopes = request.get("scope", subject_token.scope)
    scopes = list(set(scopes).intersection(subject_token.scope))
    if kwargs.get("scope"):
        scopes = list(set(scopes).intersection(kwargs.get("scope")))
    if scopes:
        request["scope"] = scopes
    elif "scope" in request:
        del request["scope"]

    return request
