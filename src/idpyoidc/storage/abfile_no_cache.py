import logging
import os
import time
from typing import Optional

from cryptojwt.utils import importer
from filelock import FileLock

from idpyoidc.storage import DictType
from idpyoidc.util import PassThru
from idpyoidc.util import QPKey

logger = logging.getLogger(__name__)


class AbstractFileSystemNoCache(DictType):
    """
    FileSystem implements a simple file based database.
    It has a dictionary like interface.
    Each key maps one-to-one to a file on disc, where the content of the
    file is the value.
    ONLY goes one level deep.
    Not directories in directories.
    """

    def __init__(
            self,
            fdir: Optional[str] = "",
            key_conv: Optional[str] = "",
            value_conv: Optional[str] = "",
            read_only: Optional[bool] = False,
            **kwargs
    ):
        """
        items = FileSystem(
            {
                'fdir': fdir,
                'key_conv':{'to': quote_plus, 'from': unquote_plus},
                'value_conv':{'to': keyjar_to_jwks, 'from': jwks_to_keyjar}
            })

        :param fdir: The root of the directory
        :param key_conv: Converts to/from the key displayed by this class to
            users of it to something that can be used as a file name.
            The value of key_conv is a class that has the methods 'serialize'/'deserialize'.
        :param value_conv: As with key_conv you can convert/translate
            the value bound to a key in the database to something that can easily
            be stored in a file. Like with key_conv the value of this parameter
            is a class that has the methods 'serialize'/'deserialize'.
        """
        super(AbstractFileSystemNoCache, self).__init__(
            fdir=fdir, key_conv=key_conv, value_conv=value_conv
        )

        self.fdir = fdir
        self.read_only = read_only

        if key_conv:
            self.key_conv = importer(key_conv)()
        else:
            self.key_conv = QPKey()

        if value_conv:
            self.value_conv = importer(value_conv)()
        else:
            self.value_conv = PassThru()

        if not os.path.isdir(self.fdir):
            os.makedirs(self.fdir)

    def get(self, item, default=None):
        try:
            return self[item]
        except KeyError:
            return default

    def __getitem__(self, item):
        """
        Return the value bound to an identifier.

        :param item: The identifier.
        :return:
        """
        _file_name = self.key_conv.serialize(item)
        logger.debug(f'Read from "{_file_name}"')
        return self._read_info(_file_name)

    def __setitem__(self, key, value):
        """
        Binds a value to a specific key. If the file that the key maps to
        does not exist it will be created. The content of the file will be
        set to the value given.

        :param key: Identifier
        :param value: Value that should be bound to the identifier.
        :return:
        """

        if self.read_only:
            return

        if not os.path.isdir(self.fdir):
            os.makedirs(self.fdir, exist_ok=True)

        try:
            _file_name = self.key_conv.serialize(key)
        except KeyError:
            _file_name = key

        fname = os.path.join(self.fdir, _file_name)
        lock = FileLock(f"{fname}.lock")
        with lock:
            with open(fname, "w") as fp:
                fp.write(self.value_conv.serialize(value))

        logger.debug(f'Wrote to "{_file_name}"')

    def __delitem__(self, key):
        if self.read_only:
            return

        fname = os.path.join(self.fdir, key)
        if fname.endswith(".lock"):
            if os.path.isfile(fname):
                os.unlink(fname)
        else:
            if os.path.isfile(fname):
                lock = FileLock(f"{fname}.lock")
                with lock:
                    os.unlink(fname)
                    os.unlink(f"{fname}.lock")
    def _keys(self):
        """
        Implements the dict.keys() method
        """
        keys = []
        for f in os.listdir(self.fdir):
            fname = os.path.join(self.fdir, f)

            if not os.path.isfile(fname):
                continue
            if fname.endswith(".lock"):
                continue

            keys.append(f)

        return keys

    def keys(self):
        return [self.key_conv.deserialize(k) for k in self._keys()]

    def _read_info(self, key):
        file_name = os.path.join(self.fdir, key)
        if os.path.isfile(file_name):
            try:
                lock = FileLock(f"{file_name}.lock")
                with lock:
                    info = open(file_name, "r").read().strip()
                lock.release()
                return self.value_conv.deserialize(info)
            except Exception as err:
                logger.error(err)
                raise
        else:
            _msg = f"No such file: '{file_name}'"
            logger.error(_msg)
        return None

    def items(self):
        """
        Implements the dict.items() method
        """
        for k in self._keys():
            v = self._read_info(k)
            yield self.key_conv.deserialize(k), v

    def clear(self):
        """
        Completely resets the database. This means that all information in
        the local cache and on disc will be erased.
        """
        if self.read_only:
            return

        if not os.path.isdir(self.fdir):
            os.makedirs(self.fdir, exist_ok=True)
            return

        for f in os.listdir(self.fdir):
            del self[f]

    def __contains__(self, item):
        file_name = os.path.join(self.fdir, self.key_conv.serialize(item))
        if os.path.isfile(file_name):
            return True
        else:
            return False

    def __iter__(self):
        for k in self._keys():
            yield self.key_conv.deserialize(k)

    def __call__(self, *args, **kwargs):
        return [self.key_conv.deserialize(k) for k in self._keys()]

    def __len__(self):
        if not os.path.isdir(self.fdir):
            return 0

        return len(self._keys())