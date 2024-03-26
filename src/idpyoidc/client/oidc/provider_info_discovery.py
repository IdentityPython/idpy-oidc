import logging
from typing import Optional

from idpyoidc.client.defaults import OIDCONF_PATTERN
from idpyoidc.client.oauth2 import server_metadata
from idpyoidc.message import oidc
from idpyoidc.message.oauth2 import ResponseMessage

__author__ = "Roland Hedberg"

logger = logging.getLogger(__name__)

PROVIDER_DEFAULT = {
    "token_endpoint_auth_method": "client_secret_basic",
    "id_token_signed_response_alg": "RS256",
}


def add_redirect_uris(request_args, service=None, **kwargs):
    """
    Add redirect_uris to the request arguments.

    :param request_args: Incoming request arguments
    :param service: A link to the service
    :param kwargs: Possible extra keyword arguments
    :return: A possibly augmented set of request arguments.
    """
    _work_environment = service.upstream_get("attribute", "claims")
    if "redirect_uris" not in request_args:
        # Callbacks is a dictionary with callback type 'code', 'implicit',
        # 'form_post' as keys.
        _callback = _work_environment.get_preference("callback")
        if _callback:
            # Filter out local additions.
            _uris = [v for k, v in _callback.items() if not k.startswith("__")]
            request_args["redirect_uris"] = _uris
        else:
            request_args["redirect_uris"] = _work_environment.get_preference(
                "redirect_uris", _work_environment.supports.get("redirect_uris")
            )

    return request_args, {}


class ProviderInfoDiscovery(server_metadata.ServerMetadata):
    msg_type = oidc.Message
    response_cls = oidc.ProviderConfigurationResponse
    error_msg = ResponseMessage
    service_name = "provider_info"
    url_pattern = OIDCONF_PATTERN

    _include = {}
    _supports = {}

    def __init__(self, upstream_get, conf=None):
        server_metadata.ServerMetadata.__init__(self, upstream_get, conf=conf)

    def update_service_context(self, resp, key: Optional[str] = "", **kwargs):
        _context = self.upstream_get("context")
        self._update_service_context(resp)
        _context.map_supported_to_preferred(resp)
        if "pre_load_keys" in self.conf and self.conf["pre_load_keys"]:
            _jwks = self.upstream_get("attribute", "keyjar").export_jwks_as_json(
                issuer=resp["issuer"]
            )
            logger.info("Preloaded keys for {}: {}".format(resp["issuer"], _jwks))

    def match_preferences(self, pcr=None, issuer=None):
        """
        Match the clients supports against what the provider can do.
        This is to prepare for later client registration and/or what
        functionality the client actually will use.
        In the client configuration the client preferences are expressed.
        These are then compared with the Provider Configuration information.
        If the Provider has left some claims out, defaults specified in the
        standard will be used.

        :param pcr: Provider configuration response if available
        :param issuer: The issuer identifier
        """
        _context = self.upstream_get("context")
        if not pcr:
            pcr = _context.provider_info

        prefers = _context.map_supported_to_preferred(pcr)

        logger.debug("Entity prefers: {}".format(prefers))
