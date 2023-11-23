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
from idpyoidc.server.session.info import ClientSessionInfo
from idpyoidc.server.token import handler

from ..exception import InvalidBranchID
from ..token.handler import TokenHandler
from .database import Database
from .grant import ExchangeGrant
from .grant import Grant
from .info import NodeInfo

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
                "node_type": ["client", "grant"],
                "node_info_class": {"client": ClientSessionInfo, "grant": Grant},
            }
        }

        session_params = self.conf.get("session_params") or {}
        _crypt_config = get_crypt_config(session_params)
        super(GrantManager, self).__init__(_crypt_config, **self.conf)

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
            _id = path[0 : i + 1]

            try:
                _si = self.get(_id)
            except KeyError:
                _info_class = self.node_info_class[self.node_type[i]]
                _si = _info_class(id=_id[i])
                self.set(_id, _si)

    def _get_nodes(self, path):
        res = []
        for i in range(len(path)):
            _id = path[0 : i + 1]
            res.append(self.get(_id))
        return res

    def add_grant(
        self,
        path: List[str],
        token_usage_rules: Optional[dict] = None,
        scope: Optional[list] = None,
        **kwargs,
    ) -> str:
        """
        Creates a Grant instance and adds it as a leaf to a branch

        :param path: The nodes in a branch
        :param token_usage_rules:
        :return: A branch ID
        :param scope:
        """

        self._setup_branch(path)

        grant_args = {k: v for k, v in kwargs.items() if k in Grant.parameter}
        if "usage_rules" not in grant_args and token_usage_rules:
            grant_args["usage_rules"] = token_usage_rules

        grant = Grant(
            remember_token=self.remember_token,
            remove_inactive_token=self.remove_inactive_token,
            scope=scope,
            **grant_args,
        )

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
        **grant_args,
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

    def get_node_info(
        self, branch_id: str, level: Optional[int] = None, node_type: Optional[str] = None
    ) -> (str, NodeInfo):
        """
        Return session information for a specific node in the grant path.

        :param branch_id: Session identifier
        :param level:
        :param node_type: Type of node, MUST appear in the node_type
        :return: NodeInfo instance
        """
        _path = self.decrypt_branch_id(branch_id)
        if level is None:
            if node_type:
                level = self.node_type.index(node_type)
            else:
                raise ValueError("One of level or node_type MUST be defined")

        return _path[level], self.get(_path[0 : level + 1])

    def branch_info(self, branch_id: str, *args) -> dict:
        """
        Returns information about the branch

        :param branch_id: Session identifier
        :return: dict with node identifiers as keys and NodeInfo instances as values
        """
        _path = self.decrypt_branch_id(branch_id)
        try:
            _nodes = self._get_nodes(_path)
        except KeyError:
            raise InvalidBranchID(branch_id)

        _res = {"branch_id": branch_id}
        for i in range(len(self.node_type)):
            if args and self.node_type[i] not in args:
                continue
            _res[self.node_type[i]] = _nodes[i]
            _res[f"{self.node_type[i]}_id"] = _path[i]
        return _res

    def get_subordinates(self, path: List[str]) -> List[Union[NodeInfo, Grant]]:
        """
        Return all subordinates to a specific node

        :param path:
        :return:
        """
        session_info = self.get(path)
        return [self.db[gid] for gid in session_info.subordinate if gid in self.db]

    def get_grant_argument(self, branch_id: str, arg: str):
        grant = self[branch_id]
        return getattr(grant, arg)

    def _revoke_tree(self, node):
        node.revoke()
        if isinstance(node, NodeInfo):
            for _sub in node.subordinate:
                _sub_node = self.db[_sub]
                self._revoke_tree(_sub_node)

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
            _node = self.get(_path[0 : level + 1])
        self._revoke_tree(_node)

    def _grants(self, path):
        _res = []
        for s in self.get_subordinates(path):
            if isinstance(s, Grant):
                _res.append(s)
            else:
                _res.extend(self._grants(self.unpack_branch_key(s)))
        return _res

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
            if len(_path) == len(self.node_type):
                # take one step back
                _path = _path[0:-1]
        elif path:
            _path = path[:]
        else:
            raise AttributeError("Must have branch_id or branch path")

        return self._grants(_path)

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


def create_grant_manager(upstream_get, token_handler_args, conf=None, **kwargs):
    _token_handler = handler.factory(upstream_get, **token_handler_args)
    return GrantManager(_token_handler, conf=conf)
