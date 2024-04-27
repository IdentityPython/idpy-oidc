import hashlib
import logging
import os
import uuid
from typing import Callable
from typing import List
from typing import Optional

from idpyoidc.encrypter import default_crypt_config
from idpyoidc.message.oauth2 import AuthorizationRequest
from idpyoidc.message.oauth2 import TokenExchangeRequest
from idpyoidc.server.authn_event import AuthnEvent
from idpyoidc.server.exception import ConfigurationError
from idpyoidc.server.session.grant_manager import GrantManager
from idpyoidc.util import rndstr

from ..token import UnknownToken
from ..token import WrongTokenClass
from ..token import handler
from ..token.handler import TokenHandler
from .database import Database
from .grant import Grant
from .grant import SessionToken
from .info import ClientSessionInfo
from .info import UserSessionInfo

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
    init_args = ["token_handler_args", "upstream_get"]

    def __init__(
        self,
        token_handler_args: dict,
        conf: Optional[dict] = None,
        sub_func: Optional[dict] = None,
        remember_token: Optional[Callable] = None,
        remove_inactive_token: Optional[bool] = False,
        upstream_get: Optional[Callable] = None,
    ):
        self.conf = conf or {"session_params": {"encrypter": default_crypt_config()}}
        session_params = self.conf.get("session_params") or {}
        self.token_handler = self.create_token_handler(upstream_get, token_handler_args)

        super(SessionManager, self).__init__(self.token_handler, self.conf)

        self.node_type = session_params.get("node_type", ["user", "client", "grant"])
        # Make sure node_type is a list and must contain at least one element.
        if not isinstance(self.node_type, list):
            raise ValueError("Wrong type of value for SessionManager node_type")
        if len(self.node_type) == 0:
            raise ValueError("SessionManager node_type must at least contain one value")

        self.node_info_class = session_params.get(
            "node_info_class",
            {"user": UserSessionInfo, "client": ClientSessionInfo, "grant": Grant},
        )

        self.remember_token = remember_token
        self.remove_inactive_token = remove_inactive_token

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

    def create_token_handler(self, upstream_get, token_handler_args) -> TokenHandler:
        return handler.factory(upstream_get, **token_handler_args)

    def get_user_info(self, uid: str) -> UserSessionInfo:
        usi = self.get([uid])
        if isinstance(usi, UserSessionInfo):
            return usi
        else:  # pragma: no cover
            raise ValueError("Not UserSessionInfo")

    def find_token(self, session_id: str, token_value: str) -> Optional[SessionToken]:
        """

        :param session_id: Based on 3-tuple, user_id, client_id and grant_id
        :param token_value:
        :return:
        """
        grant = self.get(self.decrypt_branch_id(session_id))
        for token in grant.issued_token:
            if token.value == token_value:
                return token

        return None  # pragma: no cover

    def make_path(self, **kwargs):
        _path = []
        for typ in self.node_type[:-1]:
            _id_type = f"{typ}_id"
            _path.append(kwargs[_id_type])
        return _path

    def create_grant(
        self,
        authn_event: AuthnEvent,
        auth_req: AuthorizationRequest,
        user_id: Optional[str] = "",
        client_id: Optional[str] = "",
        sub_type: Optional[str] = "public",
        token_usage_rules: Optional[dict] = None,
        scopes: Optional[list] = None,
    ) -> str:
        """

        :param scopes: Scopes
        :param authn_event: AuthnEvent instance
        :param auth_req:
        :param user_id:
        :param client_id:
        :param sub_type:
        :param token_usage_rules:
        :return:
        """
        if auth_req:
            sector_identifier = auth_req.get("sector_identifier_uri", "")
            _claims = auth_req.get("claims", {})
            if scopes is None:
                scopes = auth_req.get("scope")
        else:
            sector_identifier = ""
            _claims = {}

        resources = []
        if "resource" in auth_req:
            resources = auth_req["resource"]

        return self.add_grant(
            path=self.make_path(user_id=user_id, client_id=client_id),
            token_usage_rules=token_usage_rules,
            authorization_request=auth_req,
            authentication_event=authn_event,
            sub=self.sub_func[sub_type](
                user_id, salt=self.get_salt(), sector_identifier=sector_identifier
            ),
            usage_rules=token_usage_rules,
            scope=scopes,
            claims=_claims,
            remember_token=self.remember_token,
            remove_inactive_token=self.remove_inactive_token,
            resources=resources,
        )

    def create_exchange_grant(
        self,
        exchange_request: TokenExchangeRequest,
        original_grant: Grant,
        original_session_id: str,
        user_id: str,
        client_id: Optional[str] = "",
        sub_type: Optional[str] = "public",
        token_usage_rules: Optional[dict] = None,
        scopes: Optional[list] = None,
    ) -> str:
        """

        :param scopes: Scopes
        :param exchange_req:
        :param user_id:
        :param client_id:
        :param sub_type:
        :return:
        """

        return self.add_exchange_grant(
            authentication_event=original_grant.authentication_event,
            authorization_request=original_grant.authorization_request,
            exchange_request=exchange_request,
            original_branch_id=original_session_id,
            path=self.make_path(user_id=user_id, client_id=client_id),
            sub=original_grant.sub,
            token_usage_rules=token_usage_rules,
            scope=scopes,
        )

    def create_session(
        self,
        authn_event: AuthnEvent,
        auth_req: AuthorizationRequest,
        user_id: Optional[str] = "",
        client_id: Optional[str] = "",
        sub_type: Optional[str] = "public",
        token_usage_rules: Optional[dict] = None,
        scopes: Optional[list] = None,
    ) -> str:
        """
        Create part of a user session. The parts added are user- and client
        information and a grant.

        :param scopes:
        :param authn_event: Authentication Event information
        :param auth_req: Authorization Request
        :param client_id: Client ID
        :param user_id: User ID
        :param sub_type: What kind of subject will be assigned
        :param token_usage_rules: Rules for how tokens can be used
        :return: Session key
        """

        return self.create_grant(
            auth_req=auth_req,
            authn_event=authn_event,
            user_id=user_id,
            client_id=client_id,
            sub_type=sub_type,
            token_usage_rules=token_usage_rules,
            scopes=scopes,
        )

    def create_exchange_session(
        self,
        exchange_request: TokenExchangeRequest,
        original_grant: Grant,
        original_session_id: str,
        user_id: str,
        client_id: Optional[str] = "",
        sub_type: Optional[str] = "public",
        token_usage_rules: Optional[dict] = None,
        scopes: Optional[list] = None,
    ) -> str:
        """
        Create part of a user session. The parts added are user- and client
        information and a grant.

        :param scopes:
        :param authn_event: Authentication Event information
        :param auth_req: Authorization Request
        :param client_id: Client ID
        :param user_id: User ID
        :param sub_type: What kind of subject will be assigned
        :param token_usage_rules: Rules for how tokens can be used
        :return: Session key
        """

        return self.create_exchange_grant(
            exchange_request=exchange_request,
            original_grant=original_grant,
            original_session_id=original_session_id,
            user_id=user_id,
            client_id=client_id,
            sub_type=sub_type,
            token_usage_rules=token_usage_rules,
            scopes=scopes,
        )

    def get_client_session_info(self, session_id: str) -> ClientSessionInfo:
        """
        Return client connected information for a user session.

        :param session_id: Session identifier
        :return: ClientSessionInfo instance
        """
        _id, csi = self.get_node_info(session_id, node_type="client")

        if isinstance(csi, ClientSessionInfo):
            return csi
        else:  # pragma: no cover
            raise ValueError("Wrong type of session info")

    def get_user_session_info(self, session_id: str) -> UserSessionInfo:
        """
        Return client connected information for a user session.

        :param session_id: Session identifier
        :return: ClientSessionInfo instance
        """
        _id, usi = self.get_node_info(session_id, node_type="user")

        if isinstance(usi, UserSessionInfo):
            return usi
        else:  # pragma: no cover
            raise ValueError("Wrong type of session info")

    def get_grant(self, session_id: str) -> Grant:
        """
        Return client connected information for a user session.

        :param session_id: Session identifier
        :return: ClientSessionInfo instance
        """
        _id, grant = self.get_node_info(session_id, node_type="grant")

        if isinstance(grant, Grant):
            return grant
        else:  # pragma: no cover
            raise ValueError("Wrong type of item")

    def revoke_token(self, session_id: str, token_value: str, recursive: bool = False):
        """
        Revoke a specific token that belongs to a specific user session.

        :param session_id: Session identifier
        :param token_value: SessionToken value
        :param recursive: Revoke all tokens that was minted using this token or
            tokens minted by this token. Recursively.
        """
        token = self.find_token(session_id, token_value)
        if token is None:  # pragma: no cover
            raise UnknownToken()

        token.revoked = True
        if recursive:  # TODO: not covered yet!
            grant = self[session_id]
            grant.revoke_token(value=token.value)

    def get_authentication_events(
        self,
        session_id: Optional[str] = "",
        user_id: Optional[str] = "",
        client_id: Optional[str] = "",
    ) -> List[AuthnEvent]:
        """
        Return the authentication events that exists for a user/client combination.

        :param client_id:
        :param user_id:
        :param session_id: A session identifier
        :return: None if no authentication event could be found or an AuthnEvent instance.
        """
        if session_id:
            cid, c_info = self.get_node_info(session_id, node_type="client")
        elif user_id and client_id:
            c_info = self.get([user_id, client_id])
        else:
            raise AttributeError("Must have session_id or user_id and client_id")

        _grants = [self.get(self.unpack_branch_key(gid)) for gid in c_info.subordinate]
        return [g.authentication_event for g in _grants]

    def get_authorization_request(self, session_id):
        res = self.get_session_info(session_id=session_id, authorization_request=True)
        return res["authorization_request"]

    def get_authentication_event(self, session_id):
        res = self.get_session_info(session_id=session_id, authentication_event=True)
        return res["authentication_event"]

    def revoke_client_session(self, session_id: str):
        """
        Revokes a client session

        :param session_id: Session identifier
        """

        self.revoke_sub_tree(session_id, 1)

    def client_session_is_revoked(self, session_id: str):
        _c_info = self.get_client_session_info(session_id)
        return _c_info.revoked

    def revoke_grant(self, session_id: str):
        """
        Revokes the grant pointed to by a session identifier.

        :param session_id: A session identifier
        """
        self._revoke_tree(self.get_grant(session_id))

    # def grants(
    #         self,
    #         session_id: Optional[str] = "",
    #         user_id: Optional[str] = "",
    #         client_id: Optional[str] = "",
    # ) -> List[Grant]:
    #     """
    #     Find all grant connected to a user session
    #
    #     :param client_id:
    #     :param user_id:
    #     :param session_id: A session identifier
    #     :return: A list of grants
    #     """
    #     if session_id:
    #         user_id, client_id, _ = self.decrypt_session_id(session_id)
    #     elif user_id and client_id:
    #         pass
    #     else:
    #         raise AttributeError("Must have session_id or user_id and client_id")
    #
    #     _csi = self.get([user_id, client_id])
    #     return [self.get([user_id, client_id, gid]) for gid in _csi.subordinate]

    def get_session_info(
        self,
        session_id: str,
        user_session_info: bool = False,
        client_session_info: bool = False,
        grant: bool = False,
        authentication_event: bool = False,
        authorization_request: bool = False,
    ) -> dict:
        """
        Returns information connected to a session.

        :param session_id: The identifier of the session
        :param user_session_info: Whether user session info should part of the response
        :param client_session_info: Whether client session info should part of the response
        :param grant: Whether the grant should part of the response
        :param authentication_event: Whether the authentication event information should part of
            the response
        :param authorization_request: Whether the authorization_request should part of the response
        :return: A dictionary with session information
        """
        res = self.branch_info(session_id)

        if authentication_event:
            res["authentication_event"] = res["grant"].authentication_event

        if authorization_request:
            res["authorization_request"] = res["grant"].authorization_request

        return res

    def get_session_info_by_token(
        self,
        token_value: str,
        user_session_info: Optional[bool] = False,
        client_session_info: Optional[bool] = False,
        grant: Optional[bool] = False,
        authentication_event: Optional[bool] = False,
        authorization_request: Optional[bool] = False,
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

        return self.get_session_info(
            sid,
            user_session_info=user_session_info,
            client_session_info=client_session_info,
            grant=grant,
            authentication_event=authentication_event,
            authorization_request=authorization_request,
        )

    def get_session_id_by_token(self, token_value: str) -> str:
        _token_info = self.token_handler.info(token_value)
        sid = _token_info.get("sid")
        return self._compatible_sid(sid)

    def remove_session(self, session_id: str):
        self.remove_branch(session_id)

    def session_key(self, *args):
        return self.branch_key(*args)

    def decrypt_session_id(self, key):
        return self.decrypt_branch_id(key)

    def encrypted_session_id(self, *args):
        return self.encrypted_branch_id(*args)

    def unpack_session_key(self, key):
        return self.unpack_branch_key(key)



def create_session_manager(upstream_get, token_handler_args, sub_func=None, conf=None):
    return SessionManager(token_handler_args, sub_func=sub_func, conf=conf, upstream_get=upstream_get)
