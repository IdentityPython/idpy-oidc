import os
from time import sleep

from idpyoidc.storage.listfile import ReadOnlyListFile

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)

FILE_NAME = full_path("read_only")
def test_read_only_list_file():
    if os.path.exists(FILE_NAME):
        os.unlink(FILE_NAME)
    if os.path.exists(f"{FILE_NAME}.lock"):
        os.unlink(f"{FILE_NAME}.lock")

    _read_only = ReadOnlyListFile(FILE_NAME)
    assert len(_read_only) == 0

    with open(FILE_NAME, "w") as fp:
        for line in ["one", "two", "three"]:
            fp.write(line + '\n')

    sleep(2)
    assert len(_read_only) == 3
    assert set(_read_only) == {"one", "two", "three"}
    assert _read_only[-1] == "three"