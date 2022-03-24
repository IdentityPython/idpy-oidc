import logging

from cryptojwt.exception import UnsupportedAlgorithm

from idpyoidc.exception import MessageException
from idpyoidc.exception import NotForMe
from idpyoidc.message import OPTIONAL_LIST_OF_SP_SEP_STRINGS
from idpyoidc.message import REQUIRED_LIST_OF_STRINGS
from idpyoidc.message import SINGLE_OPTIONAL_STRING
from idpyoidc.message import SINGLE_REQUIRED_INT
from idpyoidc.message import SINGLE_REQUIRED_JSON
from idpyoidc.message import SINGLE_REQUIRED_STRING
from idpyoidc.message import Message
from idpyoidc.time_util import utc_time_sans_frac

from ..oauth2 import ResponseMessage
from ..oidc import ID_TOKEN_VERIFY_ARGS
from ..oidc import SINGLE_OPTIONAL_IDTOKEN
from ..oidc import IdToken
from ..oidc import MessageWithIdToken
from ..oidc import clear_verified_claims
from ..oidc import verified_claim_name
from ..oidc import verify_id_token

logger = logging.getLogger(__name__)


class RefreshSessionRequest(MessageWithIdToken):
    c_param = MessageWithIdToken.c_param.copy()
    c_param.update({"redirect_url": SINGLE_REQUIRED_STRING, "state": SINGLE_REQUIRED_STRING})


class RefreshSessionResponse(MessageWithIdToken, ResponseMessage):
    c_param = MessageWithIdToken.c_param.copy()
    c_param.update(ResponseMessage.c_param.copy())
    c_param.update({"state": SINGLE_REQUIRED_STRING})


class CheckSessionRequest(MessageWithIdToken):
    pass


class CheckIDRequest(Message):
    c_param = {"access_token": SINGLE_REQUIRED_STRING}


class EndSessionRequest(Message):
    c_param = {
        "id_token_hint": SINGLE_OPTIONAL_IDTOKEN,
        "post_logout_redirect_uri": SINGLE_OPTIONAL_STRING,
        "state": SINGLE_OPTIONAL_STRING,
        "ui_locales": OPTIONAL_LIST_OF_SP_SEP_STRINGS,
    }

    def verify(self, **kwargs):
        super(EndSessionRequest, self).verify(**kwargs)
        clear_verified_claims(self)

        if "post_logout_redirect_uri" in self:
            if "id_token_hint" not in self:
                return False

        if "id_token_hint" in self:
            # Try to decode the JWT, checks the signature
            args = {}
            for arg in ID_TOKEN_VERIFY_ARGS:
                try:
                    args[arg] = kwargs[arg]
                except KeyError:
                    pass
            idt = IdToken().from_jwt(str(self["id_token_hint"]), **args)
            if not verify_id_token(self, claim="id_token_hint", **kwargs):
                return False
            # Add the verified ID Token to the message instance
            self[verified_claim_name("id_token_hint")] = idt

        return True


class EndSessionResponse(ResponseMessage):
    c_param = ResponseMessage.c_param.copy()
    c_param.update({"state": SINGLE_OPTIONAL_STRING})


class LogoutToken(Message):
    """
    Defined in
    https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken
    """

    c_param = {
        "iss": SINGLE_REQUIRED_STRING,
        "sub": SINGLE_OPTIONAL_STRING,
        "aud": REQUIRED_LIST_OF_STRINGS,  # Array of strings or string
        "iat": SINGLE_REQUIRED_INT,
        "jti": SINGLE_REQUIRED_STRING,
        "events": SINGLE_REQUIRED_JSON,
        "sid": SINGLE_OPTIONAL_STRING,
    }

    def verify(self, **kwargs):
        super(LogoutToken, self).verify(**kwargs)

        if "nonce" in self:
            raise MessageException('"nonce" is prohibited from appearing in ' "a LogoutToken.")

        # Check the 'events' JSON
        _keys = list(self["events"].keys())
        if len(_keys) != 1:
            raise ValueError('Must only be one member in "events"')
        if _keys[0] != "http://schemas.openid.net/event/backchannel-logout":
            raise ValueError('Wrong member in "events"')
        if self["events"][_keys[0]] != {}:
            raise ValueError('Wrong member value in "events"')

        # There must be either a 'sub' or a 'sid', and may contain both
        if not ("sub" in self or "sid" in self):
            raise ValueError('There MUST be either a "sub" or a "sid"')

        try:
            if kwargs["aud"] not in self["aud"]:
                raise NotForMe("Not among intended audience")
        except KeyError:
            pass

        try:
            if kwargs["iss"] != self["iss"]:
                raise NotForMe("Wrong issuer")
        except KeyError:
            pass

        _now = utc_time_sans_frac()

        try:
            _skew = kwargs["skew"]
        except KeyError:
            _skew = 0

        try:
            _exp = self["iat"]
        except KeyError:
            pass
        else:
            if self["iat"] > (_now + _skew):
                raise ValueError("Invalid issued_at time")

        _allowed = kwargs.get("allowed_sign_alg")
        if _allowed and self.jws_header["alg"] != _allowed:
            _msg = "Wrong token signing algorithm, {} != {}".format(
                self.jws_header["alg"], kwargs["allowed_sign_alg"]
            )
            raise UnsupportedAlgorithm(_msg)

        return True


BACK_CHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"


class BackChannelLogoutRequest(Message):
    """
    Defined in
    https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken
    """

    c_param = {"logout_token": SINGLE_REQUIRED_STRING}

    def verify(self, **kwargs):
        super(BackChannelLogoutRequest, self).verify(**kwargs)

        args = {}
        for arg in ID_TOKEN_VERIFY_ARGS:
            try:
                args[arg] = kwargs[arg]
            except KeyError:
                pass
        idt = LogoutToken().from_jwt(str(self["logout_token"]), **args)
        if not idt.verify(**kwargs):
            return False

        self[verified_claim_name("logout_token")] = idt
        logger.info("Verified Logout Token: {}".format(idt.to_dict()))

        return True
