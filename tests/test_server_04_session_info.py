from idpyoidc.message.oauth2 import AuthorizationRequest
from idpyoidc.server.session.info import ClientSessionInfo
from idpyoidc.server.session.info import NodeInfo
from idpyoidc.server.session.info import UserSessionInfo

AUTH_REQ = AuthorizationRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    scope=["openid"],
    state="STATE",
    response_type=["code"],
)


def test_session_info_subordinate():
    si = NodeInfo()
    si.add_subordinate("subordinate_1")
    si.add_subordinate("subordinate_2")
    assert set(si.subordinate) == {"subordinate_1", "subordinate_2"}
    assert set(si.subordinate) == {"subordinate_1", "subordinate_2"}
    assert si.is_revoked() is False

    si.remove_subordinate("subordinate_1")
    assert si.subordinate == ["subordinate_2"]

    si.revoke()
    assert si.is_revoked() is True


def test_session_info_no_subordinate():
    si = NodeInfo()
    assert si.subordinate == []


def test_user_session_info_to_json():
    usi = UserSessionInfo("uid")

    _jstr = usi.dump()

    usi2 = UserSessionInfo().load(_jstr)

    assert usi2.id == "uid"


def test_user_session_info_to_json_with_sub():
    usi = UserSessionInfo("uid")
    usi.add_subordinate("client_id")

    _jstr = usi.dump()

    usi2 = UserSessionInfo().load(_jstr)

    assert usi2.subordinate == ["client_id"]


def test_client_session_info():
    csi = ClientSessionInfo("clientID")

    _jstr = csi.dump()

    _csi2 = ClientSessionInfo().load(_jstr)
    assert _csi2.id == "clientID"
