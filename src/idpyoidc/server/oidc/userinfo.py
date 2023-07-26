import json
import logging
from datetime import datetime
from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt.exception import MissingValue
from cryptojwt.jwt import JWT
from cryptojwt.jwt import utc_time_sans_frac

from idpyoidc import metadata
from idpyoidc.exception import ImproperlyConfigured
from idpyoidc.message import Message
from idpyoidc.message import oidc
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.server.endpoint import Endpoint
from idpyoidc.server.exception import ClientAuthenticationError
from idpyoidc.server.util import OAUTH2_NOCACHE_HEADERS
from idpyoidc.util import importer

logger = logging.getLogger(__name__)


class UserInfo(Endpoint):
    request_cls = Message
    response_cls = oidc.OpenIDSchema
    request_format = "json"
    response_format = "jose"
    response_placement = "body"
    endpoint_name = "userinfo_endpoint"
    name = "userinfo"
    endpoint_type = "oidc"

    _supports = {
        "claim_types_supported": ["normal", "aggregated", "distributed"],
        "encrypt_userinfo_supported": True,
        "userinfo_signing_alg_values_supported": metadata.get_signing_algs(),
        "userinfo_encryption_alg_values_supported": metadata.get_encryption_algs(),
        "userinfo_encryption_enc_values_supported": metadata.get_encryption_encs(),
    }

    def __init__(
        self, upstream_get: Callable, add_claims_by_scope: Optional[bool] = True, **kwargs
    ):
        Endpoint.__init__(
            self,
            upstream_get,
            add_claims_by_scope=add_claims_by_scope,
            **kwargs,
        )
        # Add the issuer ID as an allowed JWT target
        self.allowed_targets.append("")
        self.config = kwargs or {}

    def get_client_id_from_token(self, context, token, request=None):
        _info = context.session_manager.get_session_info_by_token(token, handler_key="access_token")
        return _info["client_id"]

    def do_response(
        self,
        response_args: Optional[Union[Message, dict]] = None,
        request: Optional[Union[Message, dict]] = None,
        client_id: Optional[str] = "",
        **kwargs,
    ) -> dict:
        if "error" in kwargs and kwargs["error"]:
            return Endpoint.do_response(self, response_args, request, **kwargs)

        _context = self.upstream_get("context")
        if not client_id:
            raise MissingValue("client_id")

        # Should I return a JSON or a JWT ?
        _cinfo = _context.cdb[client_id]

        # default is not to sign or encrypt
        try:
            sign_alg = _cinfo["userinfo_signed_response_alg"]
            sign = True
        except KeyError:
            sign_alg = ""
            sign = False

        try:
            enc_enc = _cinfo["userinfo_encrypted_response_enc"]
            enc_alg = _cinfo["userinfo_encrypted_response_alg"]
            encrypt = True
        except KeyError:
            encrypt = False
            enc_alg = enc_enc = ""

        if encrypt or sign:
            _jwt = JWT(
                self.upstream_get("attribute", "keyjar"),
                iss=_context.issuer,
                sign=sign,
                sign_alg=sign_alg,
                encrypt=encrypt,
                enc_enc=enc_enc,
                enc_alg=enc_alg,
            )

            resp = _jwt.pack(response_args, recv=client_id)
            content_type = "application/jwt"
        else:
            if isinstance(response_args, dict):
                resp = json.dumps(response_args)
            else:
                resp = response_args.to_json()
            content_type = "application/json"

        http_headers = [("Content-type", content_type)]
        http_headers.extend(OAUTH2_NOCACHE_HEADERS)

        return {"response": resp, "http_headers": http_headers}

    def process_request(self, request=None, **kwargs):
        _mngr = self.upstream_get("context").session_manager
        try:
            _session_info = _mngr.get_session_info_by_token(
                request["access_token"], grant=True, handler_key="access_token"
            )
        except (KeyError, ValueError):
            return self.error_cls(error="invalid_token", error_description="Invalid Token")

        _grant = _session_info["grant"]
        token = _grant.get_token(request["access_token"])
        # should be an access token
        if token and token.token_class != "access_token":
            return self.error_cls(error="invalid_token", error_description="Wrong type of token")

        # And it should be valid
        if token.is_active() is False:
            return self.error_cls(error="invalid_token", error_description="Invalid Token")

        _cntxt = self.upstream_get("context")
        _claims_restriction = _cntxt.claims_interface.get_claims(
            _session_info["branch_id"], scopes=token.scope, claims_release_point="userinfo"
        )
        info = _cntxt.claims_interface.get_user_claims(
            _session_info["user_id"], claims_restriction=_claims_restriction
        )
        info["sub"] = _grant.sub
        if _grant.add_acr_value("userinfo"):
            info["acr"] = _grant.authentication_event["authn_info"]

            extra_claims = kwargs.get("extra_claims")
            if extra_claims:
                info.update(extra_claims)

        if "userinfo" in _cntxt.cdb[request["client_id"]]:
            self.config["policy"] = _cntxt.cdb[request["client_id"]]["userinfo"]["policy"]

        if "policy" in self.config:
            info = self._enforce_policy(request, info, token, self.config)

        return {"response_args": info, "client_id": _session_info["client_id"]}

    def parse_request(self, request, http_info=None, **kwargs):
        """

        :param request:
        :param auth:
        :param kwargs:
        :return:
        """

        if not request:
            request = {}

        # Verify that the client is allowed to do this
        try:
            auth_info = self.client_authentication(request, http_info, **kwargs)
        except ClientAuthenticationError:
            return self.error_cls(error="invalid_token", error_description="Invalid token")

        if isinstance(auth_info, ResponseMessage):
            return auth_info
        else:
            request["client_id"] = auth_info["client_id"]
            request["access_token"] = auth_info["token"]

        # Do any endpoint specific parsing
        return self.do_post_parse_request(
            request=request,
            client_id=auth_info["client_id"],
            http_info=http_info,
            auth_info=auth_info,
            **kwargs,
        )

    def _enforce_policy(self, request, response_info, token, config):
        policy = config["policy"]
        callable = policy["function"]
        kwargs = policy.get("kwargs") or {}

        if isinstance(callable, str):
            try:
                fn = importer(callable)
            except Exception:
                raise ImproperlyConfigured(f"Error importing {callable} policy callable")
        else:
            fn = callable

        try:
            return fn(request, token, response_info, **kwargs)
        except Exception as e:
            logger.error(f"Error while executing the {fn} policy callable: {e}")
            return self.error_cls(error="server_error", error_description="Internal server error")


def validate_userinfo_policy(request, token, response_info, **kwargs):
    return response_info
