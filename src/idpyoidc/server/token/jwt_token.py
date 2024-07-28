import logging
from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt import JWT
from cryptojwt.jws.exception import JWSException
from cryptojwt.utils import importer

from idpyoidc.server.exception import ToOld
from . import is_expired
from . import Token
from .exception import UnknownToken
from .exception import WrongTokenClass
from ..constant import DEFAULT_TOKEN_LIFETIME
from ...message import Message
from ...message.oauth2 import JWTAccessToken

logger = logging.getLogger(__name__)


class JWTToken(Token):

    def __init__(
            self,
            token_class,
            # keyjar: KeyJar = None,
            issuer: str = None,
            aud: Optional[list] = None,
            alg: str = "ES256",
            lifetime: int = DEFAULT_TOKEN_LIFETIME,
            upstream_get: Callable = None,
            token_type: str = "Bearer",
            profile: Optional[Union[Message, str]] = JWTAccessToken,
            with_jti: Optional[bool] = False,
            **kwargs
    ):
        Token.__init__(self, token_class, **kwargs)
        self.token_type = token_type
        self.lifetime = lifetime

        self.kwargs = kwargs
        _context = upstream_get("context")
        # self.key_jar = keyjar or upstream_get('attribute','keyjar')
        self.issuer = issuer or _context.issuer
        self.cdb = _context.cdb
        self.upstream_get = upstream_get

        self.def_aud = aud or []
        self.alg = alg
        if isinstance(profile, str):
            self.profile = importer(profile)
        else:
            self.profile = profile
        self.with_jti = with_jti

        if self.with_jti is False and profile == JWTAccessToken:
            self.with_jti = True

    def load_custom_claims(self, payload: dict = None):
        # inherit me and do your things here
        return payload

    def __call__(
            self,
            session_id: Optional[str] = "",
            token_class: Optional[str] = "",
            usage_rules: Optional[dict] = None,
            profile: Optional[Message] = None,
            with_jti: Optional[bool] = None,
            **payload
    ) -> str:
        """
        Return a token.

        :param session_id: Session id
        :param token_class: Token class
        :param payload: A dictionary with information that is part of the payload of the JWT.
        :return: Signed JSON Web Token
        """
        if not token_class:
            if self.token_class:
                token_class = self.token_class
            else:
                token_class = "authorization_code"

        payload.update({"sid": session_id, "token_class": token_class})
        payload = self.load_custom_claims(payload)

        # payload.update(kwargs)
        if usage_rules and "expires_in" in usage_rules:
            lifetime = usage_rules.get("expires_in")
        else:
            lifetime = self.lifetime
        _keyjar = self.upstream_get("attribute", "keyjar")
        logger.info(f"Key owners in the keyjar: {_keyjar.owners()}")
        signer = JWT(
            key_jar=_keyjar,
            iss=self.issuer,
            lifetime=lifetime,
            sign_alg=self.alg,
        )
        if isinstance(payload, Message):  # don't mess with it.
            pass
        else:
            if profile:
                payload = profile(**payload).to_dict()
            elif self.profile:
                payload = self.profile(**payload).to_dict()

        if with_jti:
            signer.with_jti = True
        elif with_jti is None:
            signer.with_jti = self.with_jti

        return signer.pack(payload)

    def get_payload(self, token):
        verifier = JWT(
            key_jar=self.upstream_get("attribute", "keyjar"), allowed_sign_algs=[self.alg]
        )
        try:
            _payload = verifier.unpack(token)
        except JWSException:
            raise UnknownToken()

        return _payload

    def info(self, token):
        """
        Return token information

        :param token: A token
        :return: dictionary with token information
        """
        _payload = self.get_payload(token)

        _class = _payload.get("ttype")
        if _class is None:
            _class = _payload.get("token_class")

        if _class not in [self.token_class, self.alt_token_name]:
            raise WrongTokenClass(_payload["token_class"])
        else:
            _payload["token_class"] = self.token_class

        if is_expired(_payload["exp"]):
            raise ToOld("Token has expired")
        # All the token claims
        _res = {
            "sid": _payload["sid"],
            "token_class": _payload["token_class"],
            "exp": _payload["exp"],
            "handler": self,
        }
        return _res

    def is_expired(self, token, when=0):
        """
        Evaluate whether the token has expired or not

        :param token: The token
        :param when: The time against which to check the expiration. 0 means now.
        :return: True/False
        """
        _payload = self.get_payload(token)
        return is_expired(_payload["exp"], when)

    def gather_args(self, sid, sdb, udb):
        # sdb[sid]
        return {}
