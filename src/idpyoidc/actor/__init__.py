from typing import Optional
from typing import Union

from cryptojwt.key_jar import KeyJar
from idpyoidc.client.entity import Entity
from idpyoidc.server import Server


class Actor(object):
    def __init__(
            self,
            keyjar: Optional[KeyJar] = None,
    ):
        self.keyjar = keyjar
        self._db = {}

    def __setitem__(self, key: str, value: Union[Server, Entity]):
        self._db[key] = value

    def __getitem__(self, item):
        return self._db[item]

    def roles(self):
        return self._db.keys()
