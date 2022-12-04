# Server specific defaults and a basic Server class
import logging
from typing import Any
from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt import KeyJar

from idpyoidc.impexp import ImpExp
from idpyoidc.message.oidc import RegistrationRequest
from idpyoidc.node import Unit
from idpyoidc.server import authz
from idpyoidc.server.client_authn import client_auth_setup
from idpyoidc.server.configure import ASConfiguration
from idpyoidc.server.configure import OPConfiguration
from idpyoidc.server.endpoint import Endpoint
from idpyoidc.server.endpoint_context import EndpointContext
from idpyoidc.server.endpoint_context import get_provider_capabilities
from idpyoidc.server.endpoint_context import init_service
from idpyoidc.server.endpoint_context import init_user_info
from idpyoidc.server.session.manager import create_session_manager
from idpyoidc.server.user_authn.authn_context import populate_authn_broker
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
            key_conf: Optional[dict] = None
    ):
        Unit.__init__(self, config=conf, keyjar=keyjar, httpc=httpc, upstream_get=upstream_get,
                      httpc_params=httpc_params, entity_id=entity_id, key_conf=key_conf)

        self.upstream_get = upstream_get
        self.conf = conf
        self.endpoint_context = EndpointContext(
            conf=conf,
            upstream_get=self.server_get, # points to me
            cwd=cwd,
            cookie_handler=cookie_handler
        )

        self.endpoint_context.authz = self.setup_authz()

        self.setup_authentication(self.endpoint_context)

        self.endpoint = do_endpoints(conf, self.server_get)
        _cap = get_provider_capabilities(conf, self.endpoint)

        self.endpoint_context.provider_info = self.endpoint_context.create_providerinfo(_cap)
        self.endpoint_context.do_add_on(endpoints=self.endpoint)

        self.endpoint_context.session_manager = create_session_manager(
            self.server_get,
            self.endpoint_context.th_args,
            sub_func=self.endpoint_context._sub_func,
            conf=self.conf,
        )
        self.endpoint_context.do_userinfo()
        # Must be done after userinfo
        self.setup_login_hint_lookup()
        self.endpoint_context.set_remember_token()

        self.setup_client_authn_methods()
        for endpoint_name, _ in self.endpoint.items():
            self.endpoint[endpoint_name].upstream_get = self.server_get

        _token_endp = self.endpoint.get("token")
        if _token_endp:
            _token_endp.allow_refresh = allow_refresh_token(self.endpoint_context)

        self.endpoint_context.claims_interface = init_service(
            conf["claims_interface"], self.server_get
        )

        _id_token_handler = self.endpoint_context.session_manager.token_handler.handler.get(
            "id_token"
        )
        if _id_token_handler:
            self.endpoint_context.provider_info.update(_id_token_handler.provider_info)

    def server_get(self, what, *arg):
        _func = getattr(self, "get_{}".format(what), None)
        if _func:
            return _func(*arg)
        return None

    def get_attribute(self, attribute, *args):
        try:
            getattr(self, attribute)
        except AttributeError:
            if self.upstream_get:
                return self.upstream_get(attribute)
            else:
                return None

    def get_endpoints(self, *arg):
        return self.endpoint

    def get_endpoint(self, endpoint_name, *arg):
        try:
            return self.endpoint[endpoint_name]
        except KeyError:
            return None

    def get_context(self, *arg):
        return self.endpoint_context

    def get_endpoint_context(self, *arg):
        return self.endpoint_context

    def get_server(self, *args):
        return self

    def get_entity(self, *args):
        return self

    def setup_authz(self):
        authz_spec = self.conf.get("authz")
        if authz_spec:
            return init_service(authz_spec, self.server_get)
        else:
            return authz.Implicit(self.server_get)

    def setup_authentication(self, target):
        _conf = self.conf.get("authentication")
        if _conf:
            target.authn_broker = populate_authn_broker(
                _conf, self.server_get, target.template_handler
            )
        else:
            target.authn_broker = {}

        target.endpoint_to_authn_method = {}
        for method in target.authn_broker:
            try:
                target.endpoint_to_authn_method[method.action] = method
            except AttributeError:
                pass

    def setup_login_hint_lookup(self):
        _conf = self.conf.get("login_hint_lookup")
        if _conf:
            _userinfo = None
            _kwargs = _conf.get("kwargs")
            if _kwargs:
                _userinfo_conf = _kwargs.get("userinfo")
                if _userinfo_conf:
                    _userinfo = init_user_info(_userinfo_conf, self.endpoint_context.cwd)

            if _userinfo is None:
                _userinfo = self.endpoint_context.userinfo

            self.endpoint_context.login_hint_lookup = init_service(_conf)
            self.endpoint_context.login_hint_lookup.userinfo = _userinfo

    def setup_client_authn_methods(self):
        self.endpoint_context.client_authn_method = client_auth_setup(
            self.server_get, self.conf.get("client_authn_methods")
        )
