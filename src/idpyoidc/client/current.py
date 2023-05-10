from typing import Optional
from typing import Union

from idpyoidc.impexp import ImpExp
from idpyoidc.message import Message
from idpyoidc.util import rndstr


class Current(ImpExp):
    """A more powerful interface to a state DB."""

    parameter = {"_db": None, "_map": None}

    def __init__(self):
        ImpExp.__init__(self)
        self._db = {}
        self._map = {}

    def get(self, key: str) -> dict:
        """
        Get the currently used claims connected to a given key.

        :param key: Key into the state database
        :return: A dictionary with the currently used claims
        """
        _data = self._db.get(key)
        if not _data:
            raise KeyError(key)

        return _data

    def update(self, key: str, info: Union[Message, dict]) -> dict:
        if isinstance(info, Message):
            info = info.to_dict()

        _current = self._db.get(key)
        if _current is None:
            self._db[key] = info
            return info
        else:
            _current.update(info)
            self._db[key] = _current
            return _current

    def set(self, key: str, info: Union[Message, dict]):
        if isinstance(info, Message):
            self._db[key] = info.to_dict()
        else:
            self._db[key] = info

    def get_claim(self, key: str, claim: str) -> Union[str, None]:
        return self.get(key).get(claim)

    def get_set(
        self, key: str, message: Optional[type(Message)] = None, claim: Optional[list] = None
    ) -> dict:
        """

        @param key: The key to a seet of current claims
        @param message: A message class
        @param claim: A list of claims
        @return: Dictionary
        """

        try:
            _current = self.get(key)
        except KeyError:
            return {}

        if message:
            _res = {k: _current[k] for k in message.c_param.keys() if k in _current}
        else:
            _res = {}

        if claim:
            _res.update({k: _current[k] for k in claim if k in _current})

        return _res

    def rm_claim(self, key, claim):
        try:
            del self._db[key][claim]
        except KeyError:
            pass

    def remove_state(self, key):
        try:
            del self._db[key]
        except KeyError:
            pass
        else:
            _mkeys = list(self._map.keys())
            for k in _mkeys:
                if self._map[k] == key:
                    del self._map[k]

    def bind_key(self, fro, to):
        self._map[fro] = to

    def get_base_key(self, key):
        return self._map[key]

    def create_key(self):
        return rndstr(32)

    def create_state(self, **kwargs):
        _key = self.create_key()
        self._db[_key] = kwargs
        return _key
