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
    endpoint_type = "oidc"

    def __init__(self, upstream_get, **kwargs):
        Endpoint.__init__(self, upstream_get=upstream_get, **kwargs)
        self.pre_construct.append(self.add_endpoints)

    def add_endpoints(self, request, client_id, context, **kwargs):
        for endpoint in [
            "authorization",
            # "provider_config",
            "token",
            "userinfo",
            "session",
        ]:
            endp_instance = self.upstream_get("endpoint", endpoint)
            if endp_instance:
                request[endp_instance.endpoint_name] = endp_instance.full_path

        return request

    def process_request(self, request=None, **kwargs):
        # return {"response_args": self.upstream_get("context").provider_info}
        _schema = self.upstream_get("attribute", "metadata_schema")
        _args = self.upstream_get("context").claims.get_server_metadata(metadata_schema=_schema)
        # add issuer
        _args["issuer"] = self.upstream_get("attribute", "entity_id")
        # add endpoints
        for name, endpoint in self.upstream_get("unit").endpoint.items():
            if endpoint.endpoint_name:
                _args[endpoint.endpoint_name] = endpoint.full_path

        return {"response_args": _args}
