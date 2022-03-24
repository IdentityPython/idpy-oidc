import pytest

from idpyoidc.client.state_interface import StateInterface
from idpyoidc.message import Message

ISSUER = "https://example.com"

class TestStateInterface:
    @pytest.fixture(autouse=True)
    def test_setup(self):
        self.state_interface = StateInterface()

    def test_create_state_no_key(self):
        state_key = self.state_interface.create_state(ISSUER)
        _iss = self.state_interface.get_iss(state_key)
        assert _iss == ISSUER

    def test_create_state_with_key(self):
        state_key = self.state_interface.create_state(ISSUER, key="state_key")
        assert state_key == "state_key"
        _iss = self.state_interface.get_iss(state_key)
        assert _iss == ISSUER

    def test_create_state(self):
        state_key = self.state_interface.create_state(ISSUER)
        _state = self.state_interface.get_state(state_key)
        assert set(_state.keys()) == {"iss"}

    def test_store_and_retrieve_state_item(self):
        state_key = self.state_interface.create_state(ISSUER)
        item = Message(foo="bar")
        self.state_interface.store_item(item, "info", state_key)
        _state = self.state_interface.get_state(state_key)
        assert set(_state.keys()) == {"iss", 'info'}
        _item = self.state_interface.get_item(Message, 'info', state_key)
        assert isinstance(_item, Message)
        assert set(_item.keys()) == {'foo'}

    def test_nonce(self):
        state_key = self.state_interface.create_state(ISSUER)
        self.state_interface.store_nonce2state('nonce', state_key)
        _state_key = self.state_interface.get_state_by_nonce('nonce')
        assert _state_key == state_key

    def test_other_id(self):
        state_key = self.state_interface.create_state(ISSUER)
        self.state_interface.store_sub2state('subject_id', state_key)
        self.state_interface.store_nonce2state('nonce', state_key)
        self.state_interface.store_sid2state('session_id', state_key)
        self.state_interface.store_logout_state2state('logout_id', state_key)

        with pytest.raises(KeyError):
            _state_key = self.state_interface.get_state_by_sub('nonce')

        with pytest.raises(KeyError):
            _state_key = self.state_interface.get_state_by_nonce('subject_id')

        with pytest.raises(KeyError):
            _state_key = self.state_interface.get_state_by_sid('subject_id')

        _state_key = self.state_interface.get_state_by_nonce('nonce')
        assert _state_key == state_key
        _state_key = self.state_interface.get_state_by_sub('subject_id')
        assert _state_key == state_key
        _state_key = self.state_interface.get_state_by_sid('session_id')
        assert _state_key == state_key
        _state_key = self.state_interface.get_state_by_logout_state('logout_id')
        assert _state_key == state_key

    def test_remove(self):
        state_key = self.state_interface.create_state(ISSUER)
        self.state_interface.store_sub2state('subject_id', state_key)
        self.state_interface.store_nonce2state('nonce', state_key)
        self.state_interface.store_sid2state('session_id', state_key)
        self.state_interface.store_logout_state2state('logout_id', state_key)

        _state_key = self.state_interface.get_state_by_nonce('nonce')
        assert _state_key == state_key
        _state_key = self.state_interface.get_state_by_sub('subject_id')
        assert _state_key == state_key
        _state_key = self.state_interface.get_state_by_sid('session_id')
        assert _state_key == state_key
        _state_key = self.state_interface.get_state_by_logout_state('logout_id')
        assert _state_key == state_key

        self.state_interface.remove_state(state_key)
        with pytest.raises(KeyError):
            self.state_interface.get_state(state_key)
        with pytest.raises(KeyError):
            self.state_interface.get_state_by_sub('subject_id')
        with pytest.raises(KeyError):
            self.state_interface.get_state_by_nonce('nonce')
        with pytest.raises(KeyError):
            self.state_interface.get_state_by_sid('session_id')
        with pytest.raises(KeyError):
            self.state_interface.get_state_by_logout_state('logout_id')

    def test_extend_request_args(self):
        state_key = self.state_interface.create_state(ISSUER)

        item = Message(foo="bar")
        self.state_interface.store_item(item, "info", state_key)

        args = self.state_interface.extend_request_args({}, Message, 'info', state_key, ["foo"])
        assert args == {"foo": "bar"}

        # unknown attribute
        args = self.state_interface.extend_request_args({}, Message, 'info', state_key, ["fox"])
        assert args == {}

        # unknown item
        args = self.state_interface.extend_request_args({}, Message, 'other', state_key, ["fox"])
        assert args == {}