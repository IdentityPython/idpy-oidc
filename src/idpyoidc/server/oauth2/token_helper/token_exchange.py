import logging

from cryptojwt import BadSyntax
from cryptojwt.exception import JWKESTException

from idpyoidc.exception import ImproperlyConfigured
from idpyoidc.exception import MissingRequiredAttribute
from idpyoidc.exception import MissingRequiredValue
from idpyoidc.message.oauth2 import TokenExchangeRequest
from idpyoidc.message.oauth2 import TokenExchangeResponse
from idpyoidc.message.oidc import TokenErrorResponse
from idpyoidc.server.constant import DEFAULT_REQUESTED_TOKEN_TYPE
from idpyoidc.server.exception import ToOld
from idpyoidc.server.exception import UnAuthorizedClientScope
from idpyoidc.server.oauth2.authorization import check_unknown_scopes_policy
from idpyoidc.server.session.token import MintingNotAllowed
from idpyoidc.server.session.token import TOKEN_TYPES_MAPPING
from idpyoidc.server.token.exception import UnknownToken
from idpyoidc.time_util import utc_time_sans_frac
from idpyoidc.util import importer
from . import TokenEndpointHelper
from . import validate_token_exchange_policy

logger = logging.getLogger(__name__)


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
                "policy": {"": {"function": validate_token_exchange_policy}},
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
                keyjar=self.endpoint.upstream_get("attribute", "keyjar"), opponent_id=client_id
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
        if isinstance(resp, TokenErrorResponse):
            return resp

        scopes = resp.get("scope", [])
        scopes = _context.scopes_handler.filter_scopes(scopes, client_id=resp["client_id"])

        if not scopes:
            logger.error("All requested scopes have been filtered out.")
            return self.error_cls(
                error="invalid_scope", error_description="Invalid requested scopes"
            )

        _requested_token_type = resp.get(
            "requested_token_type", "urn:ietf:params:oauth:token-type:access_token"
        )
        _token_class = self.token_types_mapping[_requested_token_type]
        if _token_class == "refresh_token" and "offline_access" not in scopes:
            return TokenErrorResponse(
                error="invalid_request",
                error_description="Exchanging this subject token to refresh token forbidden",
            )

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

        request_info = dict(scope=request.get("scope", token.scope))
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
            return fn(request, context=_context, subject_token=token, **kwargs)
        except Exception as e:
            logger.error(f"Error while executing the {fn} policy function: {e}")
            return self.error_cls(error="server_error", error_description="Internal server error")

    def token_exchange_response(self, token, issued_token_type):
        response_args = {}
        response_args["access_token"] = token.value
        response_args["scope"] = token.scope
        response_args["issued_token_type"] = issued_token_type

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

        grant = _session_info["grant"]
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
        scopes = request.get("scope", [])

        if request["client_id"] != _session_info["client_id"]:
            _token_usage_rules = _context.authz.usage_rules(request["client_id"])

            sid = _mngr.create_exchange_session(
                exchange_request=request,
                original_grant=grant,
                original_session_id=sid,
                user_id=_session_info["user_id"],
                client_id=request["client_id"],
                token_usage_rules=_token_usage_rules,
                scopes=scopes,
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

        _token_args = None
        if resources:
            _token_args = {"resources": resources}

        try:
            new_token = self._mint_token(
                token_class=_token_class,
                grant=_session_info["grant"],
                session_id=sid,
                client_id=request["client_id"],
                based_on=token,
                scope=scopes,
                token_args=_token_args,
                token_type=_token_type,
            )
            new_token.expires_at = token.expires_at
        except MintingNotAllowed:
            logger.error(f"Minting not allowed for {_token_class}")
            return self.error_cls(
                error="invalid_grant",
                error_description="Token Exchange not allowed with that token",
            )

        return self.token_exchange_response(new_token, _requested_token_type)

    def _validate_configuration(self, config):
        if "requested_token_types_supported" not in config:
            raise ImproperlyConfigured(
                "Missing 'requested_token_types_supported' from Token Exchange configuration"
            )
        if "policy" not in config:
            raise ImproperlyConfigured("Missing 'policy' from Token Exchange configuration")
        if "" not in config["policy"]:
            raise ImproperlyConfigured("Default Token Exchange policy configuration is not defined")
        if "function" not in config["policy"][""]:
            raise ImproperlyConfigured(
                "Missing 'function' from default Token Exchange policy configuration"
            )

        _default_requested_token_type = config.get(
            "default_requested_token_type", DEFAULT_REQUESTED_TOKEN_TYPE
        )
        if _default_requested_token_type not in config["requested_token_types_supported"]:
            raise ImproperlyConfigured(
                f"Unsupported default requested_token_type {_default_requested_token_type}"
            )

    def get_handler_key(self, request, endpoint_context):
        client_info = endpoint_context.cdb.get(request["client_id"], {})

        default_requested_token_type = client_info.get("token_exchange", {}).get(
            "default_requested_token_type", None
        ) or self.config.get("default_requested_token_type", DEFAULT_REQUESTED_TOKEN_TYPE)

        requested_token_type = request.get("requested_token_type", default_requested_token_type)
        return TOKEN_TYPES_MAPPING[requested_token_type]
