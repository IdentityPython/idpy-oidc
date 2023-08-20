import copy
import inspect
import logging
import sys
from typing import Optional
from typing import Union

from idpyoidc.message import Message
from idpyoidc.server.session.grant import Grant

logger = logging.getLogger(__name__)


class AuthzHandling(object):
    """Class that allow an entity to manage authorization"""

    def __init__(self, upstream_get, grant_config=None, **kwargs):
        self.upstream_get = upstream_get
        self.grant_config = grant_config or {}
        self.kwargs = kwargs

    def usage_rules(self, client_id: Optional[str] = ""):
        if "usage_rules" in self.grant_config:
            _usage_rules = copy.deepcopy(self.grant_config["usage_rules"])
        else:
            _usage_rules = {}

        if not client_id:
            return _usage_rules

        try:
            _per_client = self.upstream_get("context").cdb[client_id]["token_usage_rules"]
        except KeyError:
            pass
        else:
            if _usage_rules:
                for _token_type, _rule in _usage_rules.items():
                    _pc = _per_client.get(_token_type)
                    if _pc:
                        _rule.update(_pc)
                    elif _pc == {}:
                        _usage_rules[_token_type] = {}
                for _token_type, _rule in _per_client.items():
                    if _token_type not in _usage_rules:
                        _usage_rules[_token_type] = _rule
            else:
                _usage_rules = _per_client

        return _usage_rules

    def usage_rules_for(self, client_id, token_type):
        _token_usage = self.usage_rules(client_id=client_id)
        try:
            return _token_usage[token_type]
        except KeyError:
            return {}

    def __call__(
        self,
        session_id: str,
        request: Union[dict, Message],
        resources: Optional[list] = None,
    ) -> Grant:
        _context = self.upstream_get("context")
        session_info = _context.session_manager.get_session_info(session_id=session_id, grant=True)
        grant = session_info["grant"]
        _client_id = session_info["client_id"]

        args = self.grant_config.copy()

        for key, val in args.items():
            if key == "expires_in":
                grant.set_expires_at(val)
            elif key == "usage_rules":
                setattr(grant, key, self.usage_rules(_client_id))
            else:
                setattr(grant, key, val)

        if resources is None:
            grant.resources = [_client_id]
        else:
            grant.resources = resources

        # Scope handling. If allowed scopes are defined for the client filter using that
        scopes = grant.scope
        if not scopes:
            scopes = request.get("scope", [])
        else:
            scopes = _context.scopes_handler.filter_scopes(scopes, client_id=_client_id)
        grant.scope = scopes

        # After this is where user consent should be handled
        grant.claims = self.upstream_get("context").claims_interface.get_claims_all_usage(
            session_id=session_id, scopes=scopes
        )

        return grant


class Implicit(AuthzHandling):
    def __call__(
        self,
        session_id: str,
        request: Union[dict, Message],
        resources: Optional[list] = None,
    ) -> Grant:
        args = self.grant_config.copy()
        grant = self.upstream_get("context").session_manager.get_grant(session_id=session_id)
        for arg, val in args:
            setattr(grant, arg, val)
        return grant


def factory(msgtype, upstream_get, **kwargs):
    """
    Factory method that can be used to easily instantiate a class instance

    :param msgtype: The name of the class
    :param kwargs: Keyword arguments
    :return: An instance of the class or None if the name doesn't match any
        known class.
    """
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj) and issubclass(obj, AuthzHandling):
            try:
                if obj.__name__ == msgtype:
                    return obj(upstream_get, **kwargs)
            except AttributeError:
                pass
