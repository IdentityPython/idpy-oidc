# Database is organized in 3 layers. User-session-grant.
import pytest

from idpyoidc.message.oauth2 import AuthorizationRequest
from idpyoidc.server.authn_event import create_authn_event
from idpyoidc.server.exception import NoSuchClientSession
from idpyoidc.server.exception import NoSuchGrant
from idpyoidc.server.session.database import Database
from idpyoidc.server.session.grant import Grant
from idpyoidc.server.session.info import ClientSessionInfo
from idpyoidc.server.session.info import UserSessionInfo
from idpyoidc.server.session.manager import public_id
from idpyoidc.server.session.token import SessionToken
from tests import CRYPT_CONFIG

AUTHZ_REQ = AuthorizationRequest(
    "client_1",
    redirect_uri="https://example.com/cb",
    scope=["openid"],
    state="STATE",
    response_type="code",
)


class TestDB:
    @pytest.fixture(autouse=True)
    def setup_environment(self):
        self.db = Database(crypt_config=CRYPT_CONFIG,
                           session_params={"node_type": ["user", "client", "grant"],
                                           "node_info_class": {
                                               "user": UserSessionInfo,
                                               "client": ClientSessionInfo,
                                               "grant": Grant}
                                           })

    def test_user_info(self):
        with pytest.raises(KeyError):
            self.db.get(["diana"])

        user_info = UserSessionInfo("diana", foo="bar")
        self.db.set(["diana"], user_info)
        stored_user_info = self.db.get(["diana"])
        assert stored_user_info.extra_args["foo"] == "bar"

    def test_client_info(self):
        user_info = UserSessionInfo("diana", foo="bar")
        self.db.set(["diana"], user_info)
        client_info = ClientSessionInfo("client_1")
        self.db.set(["diana", "client_1"], client_info)

        stored_user_info = self.db.get(["diana"])
        assert stored_user_info.subordinate == ["diana;;client_1"]
        stored_client_info = self.db.get(["diana", "client_1"])
        assert stored_client_info.id == "client_1"

    def test_client_info_change(self):
        user_info = UserSessionInfo("diana", foo="bar")
        self.db.set(["diana"], user_info)
        client_info = ClientSessionInfo("client_1", falling="snow")
        self.db.set(["diana", "client_1"], client_info)

        user_info = self.db.get(["diana"])
        assert user_info.subordinate == ["diana;;client_1"]
        client_info = self.db.get(["diana", "client_1"])
        assert client_info.id == "client_1"
        assert client_info.extra_args["falling"] == "snow"

        client_info = ClientSessionInfo("client_1", falling="ice")
        self.db.set(["diana", "client_1"], client_info)

        stored_client_info = self.db.get(["diana", "client_1"])
        assert stored_client_info.extra_args["falling"] == "ice"

    def test_client_info_add1(self):
        user_info = UserSessionInfo("diana")
        self.db.set(["diana"], user_info)
        client_info = ClientSessionInfo("client_1")
        self.db.set(["diana", "client_1"], client_info)

        # The reference is there but not the value
        del self.db.db[self.db.branch_key("diana", "client_1")]

        client_info = ClientSessionInfo("client_1", extra="ice")
        self.db.set(["diana", "client_1"], client_info)

        stored_client_info = self.db.get(["diana", "client_1"])
        assert stored_client_info.extra_args["extra"] == "ice"

    def test_client_info_add2(self):
        user_info = UserSessionInfo(foo="bar")
        self.db.set(["diana"], user_info)
        client_info = ClientSessionInfo(sid="abcdef")
        self.db.set(["diana", "client_1"], client_info)

        # The reference is there but not the value
        del self.db.db[self.db.branch_key("diana", "client_1")]

        authn_event = create_authn_event(uid="diana", expires_in=10, authn_info="authn_class_ref")

        grant = Grant(authentication_event=authn_event, authorization_request=AUTHZ_REQ)

        access_code = SessionToken("access_code", value="1234567890")
        grant.issued_token.append(access_code)

        self.db.set(["diana", "client_1", "G1"], grant)
        stored_client_info = self.db.get(["diana", "client_1"])
        assert isinstance(stored_client_info,ClientSessionInfo)
        assert set(stored_client_info.keys()) == {
            "subordinate",
            "revoked",
            "type",
            "extra_args",
            "id"
        }

        stored_grant_info = self.db.get(["diana", "client_1", "G1"])
        assert stored_grant_info.issued_at

    def test_jump_ahead(self):
        grant = Grant()
        access_code = SessionToken("access_code", value="1234567890")
        grant.issued_token.append(access_code)

        self.db.set(["diana", "client_1", "G1"], grant)

        user_info = self.db.get(["diana"])
        assert user_info.subordinate == ["diana;;client_1"]
        client_info = self.db.get(["diana", "client_1"])
        assert client_info.subordinate == ['diana;;client_1;;G1']
        grant_info = self.db.get(["diana", "client_1", "G1"])
        assert grant_info.issued_at
        assert len(grant_info.issued_token) == 1
        token = grant_info.issued_token[0]
        assert token.value == "1234567890"
        assert token.token_class == "access_code"

    def test_replace_grant_info_not_there(self):
        grant = Grant()
        access_code = SessionToken("access_code", value="1234567890")
        grant.issued_token.append(access_code)

        self.db.set(["diana", "client_1", "G1"], grant)

        # The reference is there but not the value
        del self.db.db[self.db.branch_key("diana", "client_1", "G1")]

        grant = Grant()
        access_code = SessionToken("access_code", value="aaaaaaaaa")
        grant.issued_token.append(access_code)

        self.db.set(["diana", "client_1", "G1"], grant)

        stored_grant_info = self.db.get(["diana", "client_1", "G1"])
        assert stored_grant_info.issued_at
        assert len(stored_grant_info.issued_token) == 1
        token = stored_grant_info.issued_token[0]
        assert token.value == "aaaaaaaaa"

    def test_replace_user_info(self):
        # store user info
        self.db.set(["diana"], UserSessionInfo("diana"))

        stored_user_info = self.db.get(["diana"])
        assert stored_user_info.id == "diana"

    def test_add_client_info(self):
        client_info = ClientSessionInfo("abcdef")
        self.db.set(["diana", "client_1"], client_info)

        stored_client_info = self.db.get(["diana", "client_1"])
        assert stored_client_info.id == "abcdef"

    def test_half_way(self):
        # store user info
        self.db.set(["diana"], UserSessionInfo("diana"))

        grant = Grant()
        access_code = SessionToken("access_code", value="1234567890")
        grant.issued_token.append(access_code)

        self.db.set(["diana", "client_1", "G1"], grant)

        stored_grant_info = self.db.get(["diana", "client_1", "G1"])
        assert stored_grant_info.issued_at
        assert len(stored_grant_info.issued_token) == 1

    def test_step_wise(self):
        salt = "natriumklorid"
        # store user info
        self.db.set(["diana"], UserSessionInfo("diana"))
        # Client specific information
        self.db.set(["diana", "client_1"], ClientSessionInfo(sub=public_id("diana", salt)))
        # Grant
        grant = Grant()
        access_code = SessionToken("access_code", value="1234567890")
        grant.issued_token.append(access_code)

        self.db.set(["diana", "client_1", "G1"], grant)

    def test_removed(self):
        grant = Grant()
        access_code = SessionToken("access_code", value="1234567890")
        grant.issued_token.append(access_code)

        self.db.set(["diana", "client_1", "G1"], grant)
        self.db.delete(["diana", "client_1"])
        with pytest.raises(KeyError):
            self.db.get(["diana", "client_1", "G1"])

    def test_client_info_removed(self):
        user_info = UserSessionInfo(foo="bar")
        self.db.set(["diana"], user_info)
        client_info = ClientSessionInfo(sid="abcdef")
        self.db.set(["diana", "client_1"], client_info)

        # The reference is there but not the value
        del self.db.db[self.db.branch_key("diana", "client_1")]

        with pytest.raises(KeyError):
            self.db.get(["diana", "client_1"])

    def test_grant_info(self):
        user_info = UserSessionInfo(foo="bar")
        self.db.set(["diana"], user_info)
        client_info = ClientSessionInfo(sid="abcdef")
        self.db.set(["diana", "client_1"], client_info)

        with pytest.raises(KeyError):
            self.db.get(["diana", "client_1", "G1"])

        grant = Grant()
        access_code = SessionToken("access_code", value="1234567890")
        grant.issued_token.append(access_code)

        self.db.set(["diana", "client_1", "G1"], grant)

        # removed value
        del self.db.db[self.db.branch_key("diana", "client_1", "G1")]

        with pytest.raises(KeyError):
            self.db.get(["diana", "client_1", "G1"])

    def test_delete_non_existent_info(self):
        # Does nothing
        self.db.delete(["diana"])

        user_info = UserSessionInfo(foo="bar")
        user_info.add_subordinate("client")
        self.db.set(["diana"], user_info)

        # again silently does nothing
        self.db.delete(["diana", "client"])

        client_info = ClientSessionInfo(sid="abcdef")
        client_info.add_subordinate("G1")
        self.db.set(["diana", "client_1"], client_info)

        # and finally
        self.db.delete(["diana", "client_1", "G1"])

    def test_delete_user_info(self):
        user_info = UserSessionInfo(foo="bar")
        self.db.set(["diana"], user_info)
        self.db.delete(["diana"])
        with pytest.raises(KeyError):
            self.db.get(["diana"])
