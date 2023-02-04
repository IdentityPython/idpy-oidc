import logging
from typing import Optional
from typing import Union

from cryptojwt import BadSyntax
from cryptojwt.exception import JWKESTException

from idpyoidc.exception import ImproperlyConfigured
from idpyoidc.exception import MissingRequiredAttribute
from idpyoidc.exception import MissingRequiredValue
from idpyoidc.message import Message
from idpyoidc.message.oauth2 import TokenExchangeRequest
from idpyoidc.message.oauth2 import TokenExchangeResponse
from idpyoidc.message.oidc import RefreshAccessTokenRequest
from idpyoidc.message.oidc import TokenErrorResponse
from idpyoidc.server.constant import DEFAULT_REQUESTED_TOKEN_TYPE
from idpyoidc.server.constant import DEFAULT_TOKEN_LIFETIME
from idpyoidc.server.exception import ToOld
from idpyoidc.server.exception import UnAuthorizedClientScope
from idpyoidc.server.oauth2.authorization import check_unknown_scopes_policy
from idpyoidc.server.session.grant import Grant
from idpyoidc.server.session.token import AuthorizationCode
from idpyoidc.server.session.token import MintingNotAllowed
from idpyoidc.server.session.token import RefreshToken
from idpyoidc.server.session.token import SessionToken
from idpyoidc.server.session.token import TOKEN_TYPES_MAPPING
from idpyoidc.server.token.exception import UnknownToken
from idpyoidc.time_util import utc_time_sans_frac
from idpyoidc.util import importer
from idpyoidc.util import sanitize

logger = logging.getLogger(__name__)


class TokenEndpointHelper(object):
    def __init__(self, endpoint, config=None):
        self.endpoint = endpoint
        self.config = config
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
            _exp_in = DEFAULT_TOKEN_LIFETIME

        token_args = token_args or {}
        for meth in _context.token_args_methods:
            token_args = meth(_context, client_id, token_args)

        if token_args:
            _args = {"token_args": token_args}
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

    resource_servers_per_client = kwargs["resource_servers_per_client"]
    client_id = request["client_id"]

    resource_servers_per_client = kwargs.get("resource_servers_per_client", None)

    if isinstance(resource_servers_per_client, dict) and client_id not in resource_servers_per_client:
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

        if ("resource_indicators" in _cinfo
            and "access_token" in _cinfo["resource_indicators"]):
            resource_indicators_config = _cinfo["resource_indicators"]["access_token"]
        else:
            resource_indicators_config = self.endpoint.kwargs.get("resource_indicators", None)

        if resource_indicators_config is not None:
            if "policy" not in resource_indicators_config:
                policy = {"policy": {"callable": validate_resource_indicators_policy}}
                resource_indicators_config.update(policy)

            req = self._enforce_resource_indicators_policy(req, resource_indicators_config)

            if isinstance(req, TokenErrorResponse):
                return req

        if "grant_types_supported" in _context.cdb[client_id]:
            grant_types_supported = _context.cdb[client_id].get("grant_types_supported")
        else:
            grant_types_supported = _context.provider_info["grant_types_supported"]
        grant = _session_info["grant"]

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

        issue_refresh = kwargs.get("issue_refresh", False)

        if resource_indicators_config is not None:
            scope = req["scope"]
        else:
            scope = grant.scope

        _response = {
            "token_type": "Bearer",
            "scope": scope,
        }

        if "access_token" in _supports_minting:

            resources = req.get("resource", None)
            if resources:
                token_args = {"resources": resources}
            else:
                token_args = None

            try:
                token = self._mint_token(
                    token_class="access_token",
                    grant=grant,
                    session_id=_session_info["branch_id"],
                    client_id=_session_info["client_id"],
                    based_on=_based_on,
                    token_args=token_args
                )
            except MintingNotAllowed as err:
                logger.warning(err)
            else:
                _response["access_token"] = token.value
                if token.expires_at:
                    _response["expires_in"] = token.expires_at - utc_time_sans_frac()

        if (
                issue_refresh
                and "refresh_token" in _supports_minting
                and "refresh_token" in grant_types_supported
        ):
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
        callable = policy["callable"]
        kwargs = policy.get("kwargs", {})

        if isinstance(callable, str):
            try:
                fn = importer(callable)
            except Exception:
                raise ImproperlyConfigured(f"Error importing {callable} policy callable")
        else:
            fn = callable
        try:
            return fn(request, context=_context, **kwargs)
        except Exception as e:
            logger.error(f"Error while executing the {fn} policy callable: {e}")
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


class RefreshTokenHelper(TokenEndpointHelper):
    def process_request(self, req: Union[Message, dict], **kwargs):
        _context = self.endpoint.upstream_get("context")
        _mngr = _context.session_manager
        logger.debug("Refresh Token")

        if req["grant_type"] != "refresh_token":
            return self.error_cls(error="invalid_request", error_description="Wrong grant_type")

        token_value = req["refresh_token"]
        _session_info = _mngr.get_session_info_by_token(
            token_value, grant=True, handler_key="refresh_token"
        )
        logger.debug("Session info: {}".format(_session_info))

        if _session_info["client_id"] != req["client_id"]:
            logger.debug("{} owner of token".format(_session_info["client_id"]))
            logger.warning("Client using token it was not given")
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
            "token_type": access_token.token_type,
            "scope": scope,
        }

        if access_token.expires_at:
            _resp["expires_in"] = access_token.expires_at - utc_time_sans_frac()

        _mints = token.usage_rules.get("supports_minting")
        issue_refresh = kwargs.get("issue_refresh", False)
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

        request.verify(
            keyjar=self.endpoint.upstream_get('sttribute', 'keyjar'),
            opponent_id=client_id)

        _mngr = _context.session_manager
        try:
            _session_info = _mngr.get_session_info_by_token(
                request["refresh_token"], grant=True, handler_key="refresh_token"
            )
        except (KeyError, UnknownToken):
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


class TokenExchangeHelper(TokenEndpointHelper):
    """Implements Token Exchange a.k.a. RFC8693"""

    token_types_mapping = {
        "urn:ietf:params:oauth:token-type:access_token": "access_token",
        "urn:ietf:params:oauth:token-type:refresh_token": "refresh_token",
    }

    def __init__(self, endpoint, config=None):
        TokenEndpointHelper.__init__(self, endpoint=endpoint, config=config)
        if config is None:
            self.config = {
                "requested_token_types_supported": [
                    "urn:ietf:params:oauth:token-type:access_token",
                    "urn:ietf:params:oauth:token-type:refresh_token",
                ],
                "default_requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "policy": {"": {"callable": validate_token_exchange_policy}},
            }
        else:
            self.config = config

    def post_parse_request(self, request, client_id="", **kwargs):
        request = TokenExchangeRequest(**request.to_dict())

        _context = self.endpoint.upstream_get("context")
        if "token_exchange" in _context.cdb[request["client_id"]]:
            config = _context.cdb[request["client_id"]]["token_exchange"]
        else:
            config = self.config

        try:
            request.verify(
                keyjar=self.endpoint.upstream_get('attribute', 'keyjar'),
                opponent_id=client_id
            )
        except (
                MissingRequiredAttribute,
                ValueError,
                MissingRequiredValue,
                JWKESTException,
        ) as err:
            return self.endpoint.error_cls(error="invalid_request", error_description="%s" % err)

        self._validate_configuration(config)

        _mngr = _context.session_manager
        try:
            # token exchange is about minting one token based on another
            _handler_key = self.token_types_mapping[request["subject_token_type"]]
            _session_info = _mngr.get_session_info_by_token(
                request["subject_token"], grant=True, handler_key=_handler_key
            )
        except (KeyError, UnknownToken, BadSyntax) as err:
            logger.error(f"Subject token invalid ({err}).")
            return self.error_cls(
                error="invalid_request", error_description="Subject token invalid"
            )

        # Find the token instance based on the token value
        token = _mngr.find_token(_session_info["branch_id"], request["subject_token"])
        if token.is_active() is False:
            return self.error_cls(
                error="invalid_request", error_description="Subject token inactive"
            )

        resp = self._enforce_policy(request, token, config)

        return resp

    def _enforce_policy(self, request, token, config):
        _context = self.endpoint.upstream_get("context")
        subject_token_types_supported = config.get(
            "subject_token_types_supported", self.token_types_mapping.keys()
        )
        subject_token_type = request["subject_token_type"]
        if subject_token_type not in subject_token_types_supported:
            return TokenErrorResponse(
                error="invalid_request",
                error_description="Unsupported subject token type",
            )
        if self.token_types_mapping[subject_token_type] != token.token_class:
            return TokenErrorResponse(
                error="invalid_request",
                error_description="Wrong token type",
            )

        if (
                "requested_token_type" in request
                and request["requested_token_type"] not in config["requested_token_types_supported"]
        ):
            return TokenErrorResponse(
                error="invalid_request",
                error_description="Unsupported requested token type",
            )

        request_info = dict(scope=request.get("scope", []))
        try:
            check_unknown_scopes_policy(request_info, request["client_id"], _context)
        except UnAuthorizedClientScope:
            return self.error_cls(
                error="invalid_grant",
                error_description="Unauthorized scope requested",
            )

        if subject_token_type not in config["policy"]:
            subject_token_type = ""

        policy = config["policy"][subject_token_type]
        callable = policy["callable"]
        kwargs = policy.get("kwargs", {})

        if isinstance(callable, str):
            try:
                fn = importer(callable)
            except Exception:
                raise ImproperlyConfigured(f"Error importing {callable} policy callable")
        else:
            fn = callable

        try:
            return fn(request, context=_context, subject_token=token, **kwargs)
        except Exception as e:
            logger.error(f"Error while executing the {fn} policy callable: {e}")
            return self.error_cls(error="server_error", error_description="Internal server error")

    def token_exchange_response(self, token):
        response_args = {}
        response_args["access_token"] = token.value
        response_args["scope"] = token.scope
        response_args["issued_token_type"] = token.token_class

        if token.expires_at:
            response_args["expires_in"] = token.expires_at - utc_time_sans_frac()
        if hasattr(token, "token_type"):
            response_args["token_type"] = token.token_type
        else:
            response_args["token_type"] = "N_A"

        return TokenExchangeResponse(**response_args)

    def process_request(self, request, **kwargs):
        _context = self.endpoint.upstream_get("context")
        _mngr = _context.session_manager
        try:
            _handler_key = self.token_types_mapping[request["subject_token_type"]]
            _session_info = _mngr.get_session_info_by_token(
                request["subject_token"], grant=True, handler_key=_handler_key
            )
        except ToOld:
            logger.error("Subject token has expired.")
            return self.error_cls(
                error="invalid_request", error_description="Subject token has expired"
            )
        except (KeyError, UnknownToken):
            logger.error("Subject token invalid.")
            return self.error_cls(
                error="invalid_request", error_description="Subject token invalid"
            )

        token = _mngr.find_token(_session_info["branch_id"], request["subject_token"])
        _requested_token_type = request.get(
            "requested_token_type", "urn:ietf:params:oauth:token-type:access_token"
        )

        _token_class = self.token_types_mapping[_requested_token_type]

        sid = _session_info["branch_id"]

        _token_type = "Bearer"
        # Is DPOP supported
        if "dpop_signing_alg_values_supported" in _context.provider_info:
            if request.get("dpop_jkt"):
                _token_type = "DPoP"

        if request["client_id"] != _session_info["client_id"]:
            _token_usage_rules = _context.authz.usage_rules(request["client_id"])

            sid = _mngr.create_exchange_session(
                exchange_request=request,
                original_session_id=sid,
                user_id=_session_info["user_id"],
                client_id=request["client_id"],
                token_usage_rules=_token_usage_rules,
            )

            try:
                _session_info = _mngr.get_session_info(session_id=sid, grant=True)
            except Exception:
                logger.error("Error retrieving token exchange session information")
                return self.error_cls(
                    error="server_error", error_description="Internal server error"
                )

        resources = request.get("resource")
        if resources and request.get("audience"):
            resources = list(set(resources + request.get("audience")))
        else:
            resources = request.get("audience")

        try:
            new_token = self._mint_token(
                token_class=_token_class,
                grant=_session_info["grant"],
                session_id=sid,
                client_id=request["client_id"],
                based_on=token,
                scope=request.get("scope"),
                token_args={"resources": resources},
                token_type=_token_type,
            )
        except MintingNotAllowed:
            logger.error(f"Minting not allowed for {_token_class}")
            return self.error_cls(
                error="invalid_grant",
                error_description="Token Exchange not allowed with that token",
            )

        return self.token_exchange_response(token=new_token)

    def _validate_configuration(self, config):
        if "requested_token_types_supported" not in config:
            raise ImproperlyConfigured(
                "Missing 'requested_token_types_supported' from Token Exchange configuration"
            )
        if "policy" not in config:
            raise ImproperlyConfigured("Missing 'policy' from Token Exchange configuration")
        if "" not in config["policy"]:
            raise ImproperlyConfigured(
                "Default Token Exchange policy configuration is not defined"
            )
        if "callable" not in config["policy"][""]:
            raise ImproperlyConfigured(
                "Missing 'callable' from default Token Exchange policy configuration"
            )

        _default_requested_token_type = config.get("default_requested_token_type",
                                                   DEFAULT_REQUESTED_TOKEN_TYPE)
        if _default_requested_token_type not in config["requested_token_types_supported"]:
            raise ImproperlyConfigured(
                f"Unsupported default requested_token_type {_default_requested_token_type}"
            )

    def get_handler_key(self, request, endpoint_context):
        client_info = endpoint_context.cdb.get(request["client_id"], {})

        default_requested_token_type = (
                client_info.get("token_exchange", {}).get("default_requested_token_type", None)
                or
                self.config.get("default_requested_token_type", DEFAULT_REQUESTED_TOKEN_TYPE)
        )

        requested_token_type = request.get("requested_token_type", default_requested_token_type)
        return TOKEN_TYPES_MAPPING[requested_token_type]


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

    if "scope" in request:
        scopes = list(set(request.get("scope")).intersection(kwargs.get("scope")))
        if scopes:
            request["scope"] = scopes
        else:
            return TokenErrorResponse(
                error="invalid_request",
                error_description="No supported scope requested",
            )

    return request
