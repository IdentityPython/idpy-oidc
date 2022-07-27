import hashlib
import logging
import os
from typing import Callable
from typing import List
from typing import Optional
import uuid

from idpyoidc.server.exception import NoSuchClientSession

from idpyoidc.message.oauth2 import AuthorizationRequest
from idpyoidc.message.oauth2 import TokenExchangeRequest
from idpyoidc.server.authn_event import AuthnEvent
from idpyoidc.server.exception import ConfigurationError
from idpyoidc.util import rndstr
from .database import Database
from .grant import ExchangeGrant
from .grant import Grant
from .grant import SessionToken
from .grant_manager import GrantManager
from .info import ClientSessionInfo
from .info import UserSessionInfo
from ..token import UnknownToken
from ..token import WrongTokenClass
from ..token import handler
from ..token.handler import TokenHandler

logger = logging.getLogger(__name__)


class RawID(object):
    def __init__(self, *args, **kwargs):
        pass

    def __call__(self, uid, *args, **kwargs):
        return uid


def pairwise_id(uid, sector_identifier, salt="", **kwargs):
    return hashlib.sha256(
        ("{}{}{}".format(uid, sector_identifier, salt)).encode("utf-8")
    ).hexdigest()


class PairWiseID(object):
    def __init__(self, salt: Optional[str] = "", filename: Optional[str] = ""):
        if salt:
            self.salt = salt
        elif filename:
            if os.path.isfile(filename):
                self.salt = open(filename).read()
            elif not os.path.isfile(filename) and os.path.exists(
                    filename
            ):  # Not a file, Something else
                raise ConfigurationError("Salt filename points to something that is not a file")
            else:
                self.salt = rndstr(24)
                # May raise an exception
                fp = open(filename, "w")
                fp.write(self.salt)
                fp.close()
        else:
            self.salt = rndstr(24)

    def __call__(self, uid, sector_identifier, *args, **kwargs):
        return pairwise_id(uid, sector_identifier, self.salt)


def public_id(uid, salt="", **kwargs):
    return hashlib.sha256("{}{}".format(uid, salt).encode("utf-8")).hexdigest()


class PublicID(PairWiseID):
    def __call__(self, uid, sector_identifier, *args, **kwargs):
        return public_id(uid, self.salt)


def ephemeral_id(*args, **kwargs):
    return uuid.uuid4().hex


class SessionManager(GrantManager):
    parameter = Database.parameter.copy()
    # parameter.update({"salt": ""})
    init_args = ["handler"]

    def __init__(
            self,
            handler: TokenHandler,
            conf: Optional[dict] = None,
            remember_token: Optional[Callable] = None,
            remove_inactive_token: Optional[bool] = False,
            sub_func: Optional[dict] = None
    ):
        super(SessionManager, self).__init__(handler=handler, conf=conf,
                                             remember_token=remember_token,
                                             remove_inactive_token=remove_inactive_token)

        self.node_type = ["user", "client", "grant"]
        self.node_info_class = {"user": UserSessionInfo,
                                "client": ClientSessionInfo,
                                "grant": Grant}
        # this allows the subject identifier minters to be defined by someone
        # else then me.
        if sub_func is None:
            self.sub_func = {
                "public": public_id,
                "pairwise": pairwise_id,
                "ephemeral": ephemeral_id,
            }
        else:
            self.sub_func = sub_func
            if "public" not in sub_func:
                self.sub_func["public"] = public_id
            if "pairwise" not in sub_func:
                self.sub_func["pairwise"] = pairwise_id
            if "ephemeral" not in sub_func:
                self.sub_func["ephemeral"] = ephemeral_id

        self.auth_req_id_map = {}

    def find_token(self, branch_id: str, token_value: str) -> Optional[SessionToken]:
        """

        :param branch_id: Based on 3-tuple, user_id, client_id and grant_id
        :param token_value:
        :return:
        """
        grant = self.get(self.decrypt_branch_id(branch_id))
        for token in grant.issued_token:
            if token.value == token_value:
                return token

        return None  # pragma: no cover

    def create_session(
            self,
            authentication_event: AuthnEvent,
            authorization_request: AuthorizationRequest,
            user_id: str,
            client_id: Optional[str] = "",
            sub_type: Optional[str] = "public",
            token_usage_rules: Optional[dict] = None,
            scope: Optional[list] = None,
    ) -> str:
        """
        Create part of a user session. The parts added are user- and client
        information and a grant.

        :param scope:
        :param authentication_event: Authentication Event information
        :param authorization_request: Authorization Request
        :param client_id: Client ID
        :param user_id: User ID
        :param sub_type: What kind of subject will be assigned
        :param token_usage_rules: Rules for how tokens can be used
        :return: Session key
        """

        if authorization_request:
            sector_identifier = authorization_request.get("sector_identifier_uri", "")
        else:
            sector_identifier = ""
        sub=self.sub_func[sub_type](user_id, salt=self.get_salt(),
                                    sector_identifier=sector_identifier),

        return self.add_grant(
            path=[user_id, client_id],
            token_usage_rules=token_usage_rules,
            scope=scope,
            authorization_request=authorization_request,
            authentication_event=authentication_event,
            sub=sub
        )

    def create_exchange_session(
            self,
            exchange_request: TokenExchangeRequest,
            original_branch_id: str,
            user_id: str,
            client_id: Optional[str] = "",
            sub_type: Optional[str] = "public",
            token_usage_rules: Optional[dict] = None,
            scope: Optional[list] = None,
    ) -> str:
        """
        Create part of a user session. The parts added are user- and client
        information and a grant.

        :param scope:
        :param authn_event: Authentication Event information
        :param auth_req: Authorization Request
        :param client_id: Client ID
        :param user_id: User ID
        :param sub_type: What kind of subject will be assigned
        :param token_usage_rules: Rules for how tokens can be used
        :return: Session key
        """

        try:
            _usi = self.get([user_id])
        except KeyError:
            _usi = UserSessionInfo(user_id=user_id)
            self.set([user_id], _usi)

        if not client_id:
            client_id = exchange_request["client_id"]

        try:
            self.get([user_id, client_id])
        except (NoSuchClientSession, ValueError):
            client_info = ClientSessionInfo(client_id=client_id)
            self.set([user_id, client_id], client_info)

        return self.add_exchange_grant(
            exchange_request=exchange_request,
            original_branch_id=original_branch_id,
            path=[user_id, client_id],
            token_usage_rules=token_usage_rules,
            sub_type=sub_type,
            scope=scope,
        )

    def get_user_info(self, branch_id: str) -> UserSessionInfo:
        """
        Return user connected information for a session.

        :param branch_id: Session identifier
        :return: ClientSessionInfo instance
        """
        return self.get_node_info(branch_id, node_type="user")[1]

    def get_client_session_info(self, branch_id: str) -> ClientSessionInfo:
        """
        Return client connected information for a session.

        :param branch_id: Session identifier
        :return: ClientSessionInfo instance
        """
        return self.get_node_info(branch_id, node_type="client")[1]

    def get_grant(self, branch_id: str) -> Grant:
        """
        Return client connected information for a session.

        :param branch_id: Session identifier
        :return: ClientSessionInfo instance
        """
        return self.get_node_info(branch_id, node_type="grant")[1]

    def get_authentication_events(self, branch_id: Optional[str] = "") -> List[AuthnEvent]:
        """
        Return the authentication events that exists for a user/client combination.

        :param path:
        :param branch_id: A session identifier
        :return: None if no authentication event could be found or an AuthnEvent instance.
        """
        _path = self.decrypt_branch_id(branch_id)

        c_info = self.get(_path[0:2])

        _grants = [self.get(gid) for gid in c_info.subordinate]
        return [g.authentication_event for g in _grants]

    def get_authorization_request(self, branch_id):
        _grant = self.get(self.decrypt_branch_id(branch_id))
        return _grant.authorization_request

    def get_authentication_event(self, branch_id):
        _grant = self.get(self.decrypt_branch_id(branch_id))
        return _grant.authentication_event

    def revoke_client_session(self, branch_id: str):
        """
        Revokes a client session

        :param branch_id: Session identifier
        """
        _path = self.decrypt_branch_id(branch_id)
        _info = self.get(_path[0:2])
        logger.debug(f"revoke_client_session: {_path[0]}:{_path[1]}")
        # revoke client session and all grants
        self._revoke_tree(_info)

    def client_session_is_revoked(self, branch_id: str):
        _path = self.decrypt_branch_id(branch_id)
        _client_inst = self.get(_path[0:2])
        return _client_inst.revoked

    def revoke_grant(self, branch_id: str):
        """
        Revokes the grant pointed to by a session identifier.

        :param branch_id: A session identifier
        """
        self.revoke_sub_tree(branch_id)

    def get_branch_info_by_token(
            self,
            token_value: str,
            handler_key: Optional[str] = "",
    ) -> dict:
        if handler_key:
            _token_info = self.token_handler.handler[handler_key].info(token_value)
        else:
            _token_info = self.token_handler.info(token_value)

        sid = _token_info.get("sid")
        # If the token is an ID Token then the sid will not be in the
        # _token_info
        if not sid:
            raise WrongTokenClass

        # To be backward compatible is this an old time sid
        sid = self._compatible_sid(sid)

        return self.branch_info(sid, *self.node_type)

    def get_branch_id_by_token(self, token_value: str) -> str:
        _token_info = self.token_handler.info(token_value)
        sid = _token_info.get("sid")
        return self._compatible_sid(sid)


def create_session_manager(server_get, token_handler_args, sub_func=None, conf=None):
    _token_handler = handler.factory(server_get, **token_handler_args)
    return SessionManager(_token_handler, sub_func=sub_func, conf=conf)
