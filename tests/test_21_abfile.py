import os
import shutil

import pytest

from idpyoidc.impexp import ImpExp
from idpyoidc.storage.abfile import AbstractFileSystem

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


CLIENT_1 = {
    "client_secret": 'hemligtkodord',
    "redirect_uris": [['https://example.com/cb', '']],
    "client_salt": "salted",
    'token_endpoint_auth_method': 'client_secret_post',
    'response_types': ['code', 'token']
}

CLIENT_2 = {
    "client_secret": "spraket",
    "redirect_uris": [['https://app1.example.net/foo', ''],
                      ['https://app2.example.net/bar', '']],
    "response_types": ["code"]
}


class ImpExpTest(ImpExp):
    parameter = {
        "string": "",
        "list": [],
        "dict": "DICT_TYPE",
    }


class TestAFS(object):
    @pytest.fixture(autouse=True)
    def setup(self):
        filename = full_path("afs")
        if os.path.isdir(filename):
            shutil.rmtree(filename)

    def test_create_cdb(self):
        abf = AbstractFileSystem(fdir=full_path("afs"), value_conv='idpyoidc.util.JSON')

        # add a client

        abf['client_1'] = CLIENT_1

        assert list(abf.keys()) == ["client_1"]

        # add another one

        abf['client_2'] = CLIENT_2

        assert set(abf.keys()) == {"client_1", "client_2"}

    def test_read_cdb(self):
        abf = AbstractFileSystem(fdir=full_path("afs"), value_conv='idpyoidc.util.JSON')
        # add a client
        abf['client_1'] = CLIENT_1
        # add another one
        abf['client_2'] = CLIENT_2

        afs_2 = AbstractFileSystem(fdir=full_path("afs"), value_conv='idpyoidc.util.JSON')
        assert set(afs_2.keys()) == {"client_1", "client_2"}

    def test_dump(self):
        abf = AbstractFileSystem(fdir=full_path("afs"), value_conv='idpyoidc.util.JSON')
        # add a client
        abf['client_1'] = CLIENT_1
        # add another one
        abf['client_2'] = CLIENT_2

        _dict = abf.dump()
        assert _dict["client_1"]["client_secret"] == "hemligtkodord"
        assert _dict["client_2"]["client_secret"] == "spraket"

    def test_dump_load(self):
        abf = AbstractFileSystem(fdir=full_path("afs"), value_conv='idpyoidc.util.JSON')
        # add a client
        abf['client_1'] = CLIENT_1
        # add another one
        abf['client_2'] = CLIENT_2

        _dict = abf.dump()
        afs_2 = AbstractFileSystem(fdir=full_path("afs"), value_conv='idpyoidc.util.JSON')
        afs_2.load(_dict)
        assert set(afs_2.keys()) == {"client_1", "client_2"}

    def test_dump_load_afs(self):
        b = ImpExpTest()
        b.string = "foo"
        b.list = ["a", "b", "c"]
        b.dict = AbstractFileSystem(fdir=full_path("afs"), value_conv='idpyoidc.util.JSON')

        # add a client
        b.dict['client_1'] = CLIENT_1
        # add another one
        b.dict['client_2'] = CLIENT_2

        dump = b.dump()

        b_copy = ImpExpTest().load(dump)
        assert b_copy
        assert isinstance(b_copy.dict, AbstractFileSystem)
        assert set(b_copy.dict.keys()) == {"client_1", "client_2"}

    def test_dump_load_dict(self):
        b = ImpExpTest()
        b.string = "foo"
        b.list = ["a", "b", "c"]
        b.dict = {"a": 1, "b": 2, "c": 3}

        dump = b.dump()

        b_copy = ImpExpTest().load(dump)
        assert b_copy
        assert isinstance(b_copy.dict, dict)

    def test_get(self):
        abf = AbstractFileSystem(fdir=full_path("afs"), value_conv='idpyoidc.util.JSON')
        # add a client
        abf['client_1'] = CLIENT_1
        # add another one
        abf['client_2'] = CLIENT_2

        val = abf['client_2']
        assert val == CLIENT_2

        del abf['client_2']

        assert set(abf.keys()) == {"client_1"}

        abf.clear()
        assert set(abf.keys()) == set()

