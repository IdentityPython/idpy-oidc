import logging

from idpyoidc.message import oidc
from idpyoidc.server.endpoint import Endpoint

logger = logging.getLogger(__name__)


class ProviderConfiguration(Endpoint):
    request_cls = oidc.Message
    response_cls = oidc.ProviderConfigurationResponse
    request_format = ""
    response_format = "json"
    name = "provider_config"
    # _supports = {"require_request_uri_registration": None}

    def __init__(self, upstream_get, **kwargs):
        Endpoint.__init__(self, upstream_get=upstream_get, **kwargs)
        self.pre_construct.append(self.add_endpoints)

    def add_endpoints(self, request, client_id, context, **kwargs):
        for endpoint in [
            "authorization",
            "provider_config",
            "token",
            "userinfo",
            "session",
        ]:
            endp_instance = self.upstream_get("endpoint", endpoint)
            if endp_instance:
                request[endp_instance.endpoint_name] = endp_instance.full_path

        return request

    def process_request(self, request=None, **kwargs):
        return {"response_args": self.upstream_get("context").provider_info}
