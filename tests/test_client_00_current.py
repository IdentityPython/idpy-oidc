import pytest

from idpyoidc.client.current import Current
from idpyoidc.message import Message

ISSUER = "https://example.com"


class TestCurrent:
    @pytest.fixture(autouse=True)
    def test_setup(self):
        self.current = Current()

    def test_create_key_no_key(self):
        state_key = self.current.create_key()
        self.current.set(state_key, {"iss": ISSUER})
        _iss = self.current.get(state_key)["iss"]
        assert _iss == ISSUER
        _item = self.current.get_set(state_key, claim=["iss"])
        assert _item["iss"] == ISSUER

    def test_store_and_retrieve_state_item(self):
        state_key = self.current.create_key()
        item = Message(foo="bar", issuer=ISSUER)
        self.current.set(state_key, item)
        _state = self.current.get(state_key)
        assert set(_state.keys()) == {"issuer", "foo"}
        _item = self.current.get_set(state_key, Message)
        assert set(_item.keys()) == set()  # since Message has no attribute definitions

    def test_nonce(self):
        state_key = self.current.create_key()
        self.current.bind_key("nonce", state_key)
        _state_key = self.current.get_base_key("nonce")
        assert _state_key == state_key

    def test_other_id(self):
        state_key = self.current.create_key()
        self.current.bind_key("subject_id", state_key)
        self.current.bind_key("nonce", state_key)
        self.current.bind_key("session_id", state_key)
        self.current.bind_key("logout_id", state_key)

        _state_key = self.current.get_base_key("nonce")
        assert _state_key == state_key
        _state_key = self.current.get_base_key("subject_id")
        assert _state_key == state_key
        _state_key = self.current.get_base_key("session_id")
        assert _state_key == state_key
        _state_key = self.current.get_base_key("logout_id")
        assert _state_key == state_key

    def test_remove(self):
        state_key = self.current.create_state(iss="foo")
        self.current.bind_key("subject_id", state_key)
        self.current.bind_key("nonce", state_key)
        self.current.bind_key("session_id", state_key)
        self.current.bind_key("logout_id", state_key)

        _state_key = self.current.get_base_key("nonce")
        assert _state_key == state_key
        _state_key = self.current.get_base_key("subject_id")
        assert _state_key == state_key
        _state_key = self.current.get_base_key("session_id")
        assert _state_key == state_key
        _state_key = self.current.get_base_key("logout_id")
        assert _state_key == state_key

        self.current.remove_state(state_key)
        with pytest.raises(KeyError):
            self.current.get_base_key(state_key)
        with pytest.raises(KeyError):
            self.current.get_base_key("subject_id")
        with pytest.raises(KeyError):
            self.current.get_base_key("nonce")
        with pytest.raises(KeyError):
            self.current.get_base_key("session_id")
        with pytest.raises(KeyError):
            self.current.get_base_key("logout_id")

    def test_extend_request_args(self):
        state_key = self.current.create_key()

        item = Message(foo="bar")
        self.current.set(state_key, item)

        args = self.current.get_set(state_key, claim=["foo"])
        assert args == {"foo": "bar"}

        # unknown attribute
        args = self.current.get_set(state_key, claim=["fox"])
        assert args == {}
