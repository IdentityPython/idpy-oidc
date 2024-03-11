import logging
import os
import time
from copy import copy

from filelock import FileLock

logger = logging.getLogger(__name__)


class ReadOnlyListFileMtime(object):

    def __init__(self, file_name):
        self.file_name = file_name
        self.mtime = 0
        self.size = 0
        self.inode = 0

        if not os.path.exists(file_name):
            fp = open(file_name, "x")
            fp.close()
            self._lst = []
        else:
            self._lst = self._read_info(self.file_name)

    def __getitem__(self, item):
        if self.is_changed(self.file_name):
            self._lst = self._read_info(self.file_name)

        if self._lst:
            return self._lst[item]
        else:
            return None

    def __len__(self):
        if self.is_changed(self.file_name):
            self._lst = self._read_info(self.file_name)
        if self._lst is None or self._lst == []:
            return 0

        return len(self._lst)

    @staticmethod
    def get_mtime(fname):
        """
        Find the time this file was last modified.

        :param fname: File name
        :return: The last time the file was modified.
        """
        try:
            mtime = os.path.getmtime(fname)
        except OSError:
            # The file might be right in the middle of being created
            # so sleep
            time.sleep(1)
            mtime = os.path.getmtime(fname)

        return mtime

    def is_changed(self, fname):
        """
        Find out if this file has been modified since last

        :param fname: A file name
        :return: True/False
        """

        if os.path.isfile(fname):
            inode = os.stat(fname).st_ino
            mtime = self.get_mtime(fname)
            size = os.stat(fname).st_size

            if inode != self.inode or mtime != self.mtime or size != self.size:
                self.inode = copy(inode)
                self.mtime = copy(mtime)
                self.size = copy(size)
                return True
            else:
                return False
        else:
            logger.error("Could not access {}".format(fname))
            raise FileNotFoundError()

    def _read_info(self, fname):
        if os.path.isfile(fname):
            try:
                lock = FileLock(f"{fname}.lock")
                with lock:
                    fp = open(fname, "r")
                    info = [x.strip() for x in fp.readlines()]
                lock.release()
                return info or None
            except Exception as err:
                logger.error(err)
                raise
        else:
            _msg = f"No such file: '{fname}'"
            logger.error(_msg)
        return None


class ReadOnlyListFile(object):

    def __init__(self, file_name):
        self.file_name = file_name

        if not os.path.exists(file_name):
            fp = open(file_name, "x")
            fp.close()

    def __getitem__(self, item):
        _lst = self._read_info(self.file_name)
        if _lst:
            return _lst[item]
        else:
            return None

    def __len__(self):
        _lst = self._read_info(self.file_name)
        if _lst is None or _lst == []:
            return 0

        return len(_lst)

    def _read_info(self, fname):
        if os.path.isfile(fname):
            try:
                lock = FileLock(f"{fname}.lock")
                with lock:
                    fp = open(fname, "r")
                    info = [x.strip() for x in fp.readlines()]
                lock.release()
                return info or None
            except Exception as err:
                logger.error(err)
                raise
        else:
            _msg = f"No such file: '{fname}'"
            logger.error(_msg)
        return None
