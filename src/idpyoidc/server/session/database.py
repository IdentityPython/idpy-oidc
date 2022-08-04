import base64
import logging
from typing import List
from typing import Optional
from typing import Union

import cryptography
from cryptojwt import as_unicode

from idpyoidc.encrypter import default_crypt_config
from idpyoidc.encrypter import init_encrypter
from idpyoidc.impexp import ImpExp
from idpyoidc.item import DLDict
from idpyoidc.server.constant import DIVIDER
from idpyoidc.server.util import lv_pack
from idpyoidc.server.util import lv_unpack
from idpyoidc.util import rndstr
from .grant import Grant
from .info import SessionInfo

logger = logging.getLogger(__name__)


class Database(ImpExp):
    parameter = {"db": DLDict, "crypt_config": {}}

    def __init__(self, crypt_config: Optional[dict] = None, **kwargs):
        ImpExp.__init__(self)
        self.db = DLDict()

        for k, v in kwargs.items():
            setattr(self, k, v)

        if crypt_config is None:
            crypt_config = default_crypt_config()

        _crypt = init_encrypter(crypt_config)
        self.crypt = _crypt["encrypter"]
        self.crypt_config = _crypt["conf"]

    @staticmethod
    def branch_key(*args):
        return DIVIDER.join(args)

    @staticmethod
    def unpack_branch_key(key):
        return key.split(DIVIDER)

    def encrypted_branch_id(self, *args) -> str:
        rnd = rndstr(32)
        return base64.b64encode(
            self.crypt.encrypt(lv_pack(rnd, self.branch_key(*args)).encode())
        ).decode("utf-8")

    def decrypt_branch_id(self, key: str) -> List[str]:
        try:
            plain = self.crypt.decrypt(base64.b64decode(key))
        except cryptography.fernet.InvalidToken as err:
            logger.error(f"cryptography.fernet.InvalidToken: {key}")
            raise ValueError(err)
        except Exception as err:
            raise ValueError(err)
        # order: rnd, type, sid
        return self.unpack_branch_key(lv_unpack(as_unicode(plain))[1])

    def set(self, path: List[str], value: Union[SessionInfo, Grant]):
        """

        :param path: a list of identifiers. root -> .. -> leaf
        :param value: Class instance to be stored
        """

        _inv_path = path[:]
        _inv_path.reverse()
        _len = len(path)

        _superior = None
        for i in range(_len):
            _key = self.branch_key(*path[0:i+1])
            _info = self.db.get(_key)
            if _info is None:
                if i == _len - 1:
                    _info = value
                else:
                    _info = SessionInfo()
            else:
                if i == _len - 1:
                    _info = value  # overwrite old value

            if _superior:
                if hasattr(_superior, "subordinate"):
                    if _key not in _superior.subordinate:
                        _superior.add_subordinate(_key)

            self.db[_key] = _info
            _superior = _info

    def get(self, path: List[str]) -> Union[SessionInfo, Grant]:
        _key = self.branch_key(*path)
        return self.db[_key]

    def delete_sub_tree(self, key: str):
        """
        Removes all a node and all its subordinates

        @param path:
        @return:
        """
        _node = self.db[key]
        if hasattr(_node, "subordinate"):
            for _sub in _node.subordinate:
                self.delete_sub_tree(_sub)

        self.db.__delitem__(key)


    def delete(self, path: List[str]):
        """
        Deletes a branch all the way from the root to the leaf. If a node in the branch has a
        subordinate that is not listed in the path then it and the nodes above are not
        removed.

        @param path:
        @return:
        """
        if path[0] not in self.db:
            return

        if len(path) == 1:
            self.db.__delitem__(path[0])
            return

        # start at leaf and work our way upwards
        _inv_path = path[:]
        _inv_path.reverse()
        _len = len(path)

        _sub = None
        for i in range(0, len(path)):
            _key = self.branch_key(*path[0:_len - i])
            if _key in self.db:
                _node = self.db[_key]
                if _sub:
                    if _sub in _node.subordinate:
                        _node.subordinate.remove(_sub)
                        if _node.subordinate == []:
                            self.db.__delitem__(_key)
                        else:
                            return
                else:
                    if isinstance(_node, SessionInfo) and _node.subordinate:
                        for _s in _node.subordinate:
                            self.delete_sub_tree(_s)
                    self.db.__delitem__(_key)
            _sub = _key

    def update(self, path: List[str], new_info: dict):
        _info = self.get(path)
        for key, val in new_info.items():
            setattr(_info, key, val)
        self.set(path, _info)

    def flush(self):
        self.db = DLDict()

    def local_load_adjustments(self, **kwargs):
        _crypt = init_encrypter(self.crypt_config)
        self.crypt = _crypt["encrypter"]
