# Server specific defaults and a basic Server class
import logging
from typing import Any
from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt import KeyJar

from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.node import Unit
# from idpyoidc.server import authz
# from idpyoidc.server.client_authn import client_auth_setup
from idpyoidc.server.configure import ASConfiguration
from idpyoidc.server.configure import OPConfiguration
from idpyoidc.server.endpoint import Endpoint
from idpyoidc.server.endpoint_context import EndpointContext
# from idpyoidc.server.session.manager import create_session_manager
# from idpyoidc.server.user_authn.authn_context import populate_authn_broker
from idpyoidc.server.util import allow_refresh_token
from idpyoidc.server.util import build_endpoints

logger = logging.getLogger(__name__)


def do_endpoints(conf, upstream_get):
    _endpoints = conf.get("endpoint")
    if _endpoints:
        return build_endpoints(_endpoints, upstream_get=upstream_get, issuer=conf["issuer"])
    else:
        return {}


class Server(Unit):
    parameter = {"endpoint": [Endpoint], "context": EndpointContext}

    def __init__(
            self,
            conf: Union[dict, OPConfiguration, ASConfiguration],
            keyjar: Optional[KeyJar] = None,
            cwd: Optional[str] = "",
            cookie_handler: Optional[Any] = None,
            httpc: Optional[Callable] = None,
            upstream_get: Optional[Callable] = None,
            httpc_params: Optional[dict] = None,
            entity_id: Optional[str] = "",
            key_conf: Optional[dict] = None,
            server_type: Optional[str] = ""
    ):
        self.entity_id = entity_id or conf.get("entity_id")
        self.issuer = conf.get("issuer", self.entity_id)
        self.persistence = None

        if upstream_get is None:
            if key_conf is None:
                _conf = conf.get("key_conf")
                if _conf is None:
                    key_conf = {"key_defs": DEFAULT_KEY_DEFS}

        Unit.__init__(
            self,
            config=conf,
            keyjar=keyjar,
            httpc=httpc,
            upstream_get=upstream_get,
            httpc_params=httpc_params,
            key_conf=key_conf,
            issuer_id=self.issuer,
        )

        self.upstream_get = upstream_get
        if isinstance(conf, OPConfiguration) :
            if server_type == "":
                self.server_type = "oidc"
            elif server_type != "oidc":
                raise ValueError("server_type 'oidc' MUST be combined with configuration type OPConfiguration")
            self.conf = conf
        elif isinstance(conf, ASConfiguration):
            if server_type == "":
                self.server_type = "oauth2"
            elif server_type != "oauth2":
                raise ValueError("server_type 'oauth2' MUST be combined with configuration type ASConfiguration")
            self.conf = conf
        else:
            if server_type == "oidc" or server_type == "":
                self.conf = OPConfiguration(conf)
                self.server_type = "oidc"
            elif server_type == "oauth2":
                self.conf = ASConfiguration(conf)
                self.server_type = "oauth2"
            else:
                raise ValueError("Only allow 'oidc' and 'oauth2' as server types")

        self.endpoint = do_endpoints(self.conf, self.unit_get)

        self.context = EndpointContext(
            conf=self.conf,
            upstream_get=self.unit_get,  # points to me
            cwd=cwd,
            cookie_handler=cookie_handler,
            keyjar=self.keyjar,
        )

        # Need to have context in place before doing this
        self.context.do_add_on(endpoints=self.endpoint)

        for endpoint_name, _ in self.endpoint.items():
            self.endpoint[endpoint_name].upstream_get = self.unit_get

        _token_endp = self.endpoint.get("token")

        self.context.map_supported_to_preferred()
        if _token_endp:
            _token_endp.allow_refresh = allow_refresh_token(self.context)

    def get_endpoints(self, *arg):
        return self.endpoint

    def get_endpoint(self, endpoint_name, *arg):
        try:
            return self.endpoint[endpoint_name]
        except KeyError:
            return None

    def get_context(self, *arg):
        return self.context

    def get_endpoint_context(self, *arg):
        return self.context

    def get_server(self, *args):
        return self

    def get_entity(self, *args):
        return self

    def get_context_attribute(self, attr, *args):
        _val = getattr(self.context, attr)
        if not _val and self.upstream_get:
            return self.upstream_get("context_attribute", attr)

    def get_metadata(self):
        metadata = self.get_context().claims.prefer
        # collect endpoints
        metadata.update(self.get_endpoint_claims())
        # _issuer = getattr(self.server.context, "trust_mark_server", None)
        return metadata

    def get_endpoint_claims(self):
        _info = {}
        for endp in self.endpoint.values():
            if endp.endpoint_name:
                _info[endp.endpoint_name] = endp.full_path
                for arg, claim in [("client_authn_method", "auth_methods"),
                                   ("auth_signing_alg_values", "auth_signing_alg_values")]:
                    _val = getattr(endp, arg, None)
                    if _val:
                        # trust_mark_status_endpoint_auth_methods_supported
                        md_param = f"{endp.endpoint_name}_{claim}"
                        _info[md_param] = _val
        return _info
