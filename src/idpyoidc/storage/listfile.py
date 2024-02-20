import logging
import os
from pathlib import Path
import time

from filelock import FileLock

logger = logging.getLogger(__name__)


class ReadOnlyListFile(object):

    def __init__(self, file_name):
        self.file_name = file_name
        self.fmtime = 0
        self.lst = None

        if not os.path.exists(file_name):
            fp = open(file_name, "x")
            fp.close()

    def __getitem__(self, item):
        if self.is_changed(self.file_name):
            self.lst = self._read_info(self.file_name)
        return self.lst[item]

    def __len__(self):
        if self.is_changed(self.file_name):
            self.lst = self._read_info(self.file_name)
        if self.lst is None or self.lst == []:
            return 0

        return len(self.lst)

    @staticmethod
    def get_mtime(fname):
        """
        Find the time this file was last modified.

        :param fname: File name
        :return: The last time the file was modified.
        """
        try:
            target = Path(fname)
            mtime = target.stat().st_mtime
            # mtime = os.stat(fname).st_mtime_ns
        except OSError:
            # The file might be right in the middle of being written to
            # so sleep
            time.sleep(1)
            target = Path(fname)
            mtime = target.stat().st_mtime
            # mtime = os.stat(fname).st_mtime_ns

        return mtime

    def is_changed(self, fname):
        """
        Find out if this file has been modified since last

        :param fname: A file name
        :return: True/False
        """
        if os.path.isfile(fname):
            mtime = self.get_mtime(fname)

            if self.fmtime == 0:
                self.fmtime = mtime
                return True

            if mtime > self.fmtime:  # has changed
                self.fmtime = mtime
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
