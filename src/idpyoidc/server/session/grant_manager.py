"""
Implements a database with branches with N nodes (SessionInstance instances)
that ends in a Grant instances.
"""
import logging
from typing import Callable
from typing import List
from typing import Optional
from typing import Union

from idpyoidc.encrypter import default_crypt_config
from idpyoidc.encrypter import get_crypt_config
from idpyoidc.message.oauth2 import TokenExchangeRequest
from idpyoidc.server.token import handler
from .database import Database
from .grant import ExchangeGrant
from .grant import Grant
from .info import SessionInfo
from ..token.handler import TokenHandler

logger = logging.getLogger(__name__)


class GrantManager(Database):
    parameter = Database.parameter.copy()
    init_args = ["handler"]

    def __init__(
            self,
            handler: TokenHandler,
            conf: Optional[dict] = None,
            remember_token: Optional[Callable] = None,
            remove_inactive_token: Optional[bool] = False,
    ):
        self.conf = conf or {
            "session_params": {
                "encrypter": default_crypt_config(),
                "node_map": ["client", "grant"]
            }
        }

        session_params = self.conf.get("session_params") or {}
        _crypt_config = get_crypt_config(session_params)
        super(GrantManager, self).__init__(_crypt_config)

        self.node_map = session_params.get("node_map", {"client": 0, "grant": 1})
        self.token_handler = handler
        self.remember_token = remember_token
        self.remove_inactive_token = remove_inactive_token

    def get_salt(self):
        """returns the original salt assigned in init"""
        return self.crypt_config["kwargs"]["salt"]

    def __setattr__(self, key, value):
        if key in ("_key", "_salt"):
            if hasattr(self, key):
                # not first time we configure it!
                raise AttributeError(f"{key} is a ReadOnly attribute that can't be overwritten!")
        super().__setattr__(key, value)

    def __getitem__(self, branch_id: str):
        return self.get(self.decrypt_branch_id(branch_id))

    def __setitem__(self, branch_id: str, value):
        return self.set(self.decrypt_branch_id(branch_id), value)

    def _setup_branch(self, path):
        for i in range(len(path)):
            _id = path[0:i + 1]

            try:
                _si = self.get(_id)
            except KeyError:
                _si = SessionInfo()
                self.set(_id, _si)

    def _get_nodes(self, path):
        res = []
        for i in range(len(path)):
            _id = path[0:i + 1]
            res.append(self.get(_id))
        return res

    def add_grant(
            self,
            path: List[str],
            token_usage_rules: Optional[dict] = None,
            scope: Optional[list] = None,
            **grant_args
    ) -> str:
        """
        Creates a Grant instance and adds it as a leaf to a branch

        :param path: The nodes in a branch
        :param token_usage_rules:
        :return: A branch ID
        :param scope:
        """

        self._setup_branch(path)

        grant = Grant(
            usage_rules=token_usage_rules,
            remember_token=self.remember_token,
            remove_inactive_token=self.remove_inactive_token,
            scope=scope
        )

        if grant_args:
            for key, val in grant_args.items():
                setattr(grant, key, val)

        _id = path[:]
        _id.append(grant.id)
        self.set(_id, grant)

        return self.encrypted_branch_id(*_id)

    def add_exchange_grant(
            self,
            exchange_request: TokenExchangeRequest,
            original_branch_id: str,
            path: List[str],
            token_usage_rules: Optional[dict] = None,
            **grant_args
    ) -> str:
        """

        :param scopes: Scopes
        :param exchange_request:
        :param original_branch_id:
        :param path: list of strings identifying the nodes in the branch
        :param token_usage_rules:
        :return:
        """

        self._setup_branch(path)

        grant = ExchangeGrant(
            original_branch_id=original_branch_id,
            exchange_request=exchange_request,
            usage_rules=token_usage_rules,
        )

        if grant_args:
            for key, val in grant_args.items():
                setattr(grant, key, val)

        _id = path[:]
        _id.append(grant.id)
        self.set(_id, grant)

        return self.encrypted_branch_id(*_id)

    def get_node_info(self, branch_id: str, level: Optional[int] = None,
                      node_id: Optional[str] = None) -> (str, SessionInfo):
        """
        Return session information for a specific node in the grant path.

        :param branch_id: Session identifier
        :param level:
        :param node_id: Identifier for a node, MUST appear in the node_map
        :return: SessionInfo instance
        """
        _path = self.decrypt_branch_id(branch_id)
        if level is None:
            if node_id:
                level = self.node_map.index(node_id)
            else:
                raise ValueError("One of level or node_id MUST be defined")

        return _path[level], self.get(_path[0:level + 1])

    def branch_info(self, branch_id: str, *args) -> dict:
        """
        Returns information about the branch

        :param branch_id: Session identifier
        :return: dict with node identifiers as keys and SessionInfo instances as values
        """
        _path = self.decrypt_branch_id(branch_id)
        _nodes = self._get_nodes(_path)

        _res = {}
        for i in range(len(self.node_map)):
            if args and self.node_map[i] not in args:
                continue
            _res[self.node_map[i]] = _nodes[i]
            _res[f"{self.node_map[i]}_id"] = _path[i]
        return _res

    def get_grant(self, branch_id: str) -> Grant:
        """
        Return client connected information for a user session.

        :param branch_id: Session identifier
        :return: ClientSessionInfo instance
        """
        return self.get(self.decrypt_branch_id(branch_id))

    def get_subordinates(
            self,
            path: List[str],
            session_info: Optional[SessionInfo] = None) -> List[Union[SessionInfo, Grant]]:
        """
        Return all subordinates to a specific node

        :param path:
        :param session_info:
        :return:
        """
        if session_info is None:
            session_info = self.get(path)

        _subs = []
        for gid in session_info.subordinate:
            _tmp = path[:]
            _tmp.append(gid)
            _subs.append(self.get(_tmp))

        return _subs

    def get_grant_argument(self, branch_id: str, arg: str):
        grant = self.get_grant(branch_id=branch_id)
        return getattr(grant, arg)

    def get_info_by_argument(
            self,
            arg: str,
            branch_id: Optional[str] = "",
            path: Optional[List[str]] = None,
    ) -> list:
        """
        Return the authentication events that exists for a user/client combination.

        :param path:
        :param branch_id: A session identifier
        :return: None if no authentication event could be found or an AuthnEvent instance.
        """
        if branch_id:
            _id = self.decrypt_branch_id(branch_id)
        elif path:
            _id = path
        else:
            raise AttributeError("Must have branch_id or user_id and client_id")

        _grants = self.get_subordinates(_id)
        return [getattr(g, arg) for g in _grants]

    def _revoke_tree(self, node):
        node.revoke()
        for _sub in node.subordinate:
            self._revoke_tree(_sub)

    def revoke_sub_tree(self, branch_id: str, level: Optional[int] = None):
        """
        Revokes a node and all nodes below that node.

        :param branch_id: Session identifier
        :param level: the node number
        """
        _path = self.decrypt_branch_id(branch_id)
        if level is None:
            _node = self.get(_path)
        else:
            if level > len(_path):
                raise ValueError("Looking for level beyond what is available")
            _node = self.get(_path[0:level])
        self._revoke_tree(_node)

    def revoke_grant(self, branch_id: str):
        self.revoke_sub_tree(branch_id=branch_id)

    def grants(
            self,
            branch_id: Optional[str] = "",
            path: Optional[List[str]] = "",
    ) -> List[Grant]:
        """
        Find all grants connected to a branch

        :param path:
        :param branch_id: A session identifier
        :return: A list of grants
        """
        if branch_id:
            _path = self.decrypt_branch_id(branch_id)
        elif path:
            _path = path[:]
        else:
            raise AttributeError("Must have branch_id or user_id and client_id")

        return [s for s in self.get_subordinates(_path) if isinstance(s, Grant)]

    def _compatible_sid(self, sid):
        # To be backward compatible is this an old time sid
        p = self.unpack_branch_key(sid)
        if len(p) == 3:
            sid = self.encrypted_branch_id(*p)
        return sid

    def remove_branch(self, branch_id: str):
        _path = self.decrypt_branch_id(branch_id)
        self.delete(_path)

    def flush(self):
        super().flush()

    # def get_branch_id_by_token(self, token_value: str) -> str:
    #     _token_info = self.token_handler.info(token_value)
    #     sid = _token_info.get("sid")
    #     return self._compatible_sid(sid)
    #
    # def find_token(self, branch_id: str, token_value: str) -> Optional[SessionToken]:
    #     """
    #
    #     :param branch_id: A n-tuple
    #     :param token_value:
    #     :return: A SessionToken instance
    #     """
    #     return self.get_grant(branch_id).get_token(token_value)
    #
    # def revoke_token(self, branch_id: str, token_value: str, recursive: bool = False):
    #     """
    #     Revoke a specific token that belongs to a specific Grant.
    #
    #     :param branch_id: Branch identifier
    #     :param token_value: SessionToken value
    #     :param recursive: Revoke all tokens that was minted using this token or
    #         tokens minted by this token. Recursively.
    #     """
    #     _grant = self.get_grant(branch_id)
    #     token = _grant.get_token(token_value)
    #     if token is None:  # pragma: no cover
    #         raise UnknownToken()
    #
    #     token.revoked = True
    #     if recursive:  # TODO: not covered yet!
    #         _grant.revoke_token(value=token.value)


def create_grant_manager(server_get, token_handler_args, conf=None, **kwargs):
    _token_handler = handler.factory(server_get, **token_handler_args)
    return GrantManager(_token_handler, conf=conf)
