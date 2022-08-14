from typing import List
from typing import Optional

from idpyoidc.impexp import ImpExp


class SessionInfo(ImpExp):
    parameter = {"subordinate": [], "revoked": bool, "type": "", "extra_args": {}, "id": ""}

    def __init__(
        self,
        id: Optional[str] = "",
        subordinate: Optional[List[str]] = None,
        revoked: Optional[bool] = False,
        type: Optional[str] = "",
        **kwargs
    ):
        ImpExp.__init__(self)
        self.id = id
        self.subordinate = subordinate or []
        self.revoked = revoked
        self.type = type
        self.extra_args = {}

    def add_subordinate(self, value: str) -> "SessionInfo":
        if value not in self.subordinate:
            self.subordinate.append(value)
        return self

    def remove_subordinate(self, value: str) -> "SessionInfo":
        self.subordinate.remove(value)
        return self

    def revoke(self) -> "SessionInfo":
        self.revoked = True
        return self

    def is_revoked(self) -> bool:
        return self.revoked

    def keys(self):
        return self.parameter.keys()


class UserSessionInfo(SessionInfo):
    def __init__(self, id: Optional[str] = "", **kwargs):
        SessionInfo.__init__(self, id, **kwargs)
        self.type = "UserSessionInfo"
        self.extra_args = {k: v for k, v in kwargs.items() if k not in self.parameter}


class ClientSessionInfo(SessionInfo):
    def __init__(self, id: Optional[str] = "", **kwargs):
        SessionInfo.__init__(self, id, **kwargs)
        self.type = "ClientSessionInfo"
        self.extra_args = {k: v for k, v in kwargs.items() if k not in self.parameter}

    def find_grant_and_token(self, val: str):
        for grant in self.subordinate:
            token = grant.get_token(val)
            if token:
                return grant, token
