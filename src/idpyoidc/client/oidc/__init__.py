import json
import logging

from idpyoidc.client import oauth2
from idpyoidc.client.client_auth import BearerHeader
from idpyoidc.client.defaults import DEFAULT_OIDC_SERVICES
from idpyoidc.configure import Configuration

try:
    from json import JSONDecodeError
except ImportError:  # Only works for >= 3.5
    _decode_err = ValueError
else:
    _decode_err = JSONDecodeError

__author__ = "Roland Hedberg"

logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
#

WF_URL = "https://{}/.well-known/webfinger"
OIC_ISSUER = "http://openid.net/specs/connect/1.0/issuer"

IDT2REG = {
    "sigalg": "id_token_signed_response_alg",
    "encalg": "id_token_encrypted_response_alg",
    "encenc": "id_token_encrypted_response_enc",
}

ENDPOINT2SERVICE = {
    "authorization": ["authorization"],
    "token": ["accesstoken", "refresh_token"],
    "userinfo": ["userinfo"],
    "registration": ["registration"],
    "end_sesssion": ["end_session"],
}

# This should probably be part of the configuration
MAX_AUTHENTICATION_AGE = 86400


PROVIDER_DEFAULT = {
    "token_endpoint_auth_method": "client_secret_basic",
    "id_token_signed_response_alg": "RS256",
}


class FetchException(Exception):
    pass


class RP(oauth2.Client):
    def __init__(
        self,
        keyjar=None,
        verify_ssl=True,
        config=None,
        httplib=None,
        services=None,
        httpc_params=None,
    ):

        if isinstance(config, Configuration):
            _srvs = services or config.conf.get("services", DEFAULT_OIDC_SERVICES)
        else:
            _srvs = services or config.get("services", DEFAULT_OIDC_SERVICES)

        oauth2.Client.__init__(
            self,
            keyjar=keyjar,
            verify_ssl=verify_ssl,
            config=config,
            httplib=httplib,
            services=_srvs,
            httpc_params=httpc_params,
            client_type="oidc"
        )

        _context = self.get_service_context()
        if _context.callback is None:
            _context.callback = {}

    def fetch_distributed_claims(self, userinfo, callback=None):
        """

        :param userinfo: A :py:class:`idpyoidc.message.Message` sub class
            instance
        :param callback: A function that can be used to fetch things
        :return: Updated userinfo instance
        """
        try:
            _csrc = userinfo["_claim_sources"]
        except KeyError:
            pass
        else:
            for csrc, spec in _csrc.items():
                if "endpoint" in spec:
                    if "access_token" in spec:
                        cauth = BearerHeader()
                        httpc_params = cauth.construct(
                            service=self.client_get("service", "userinfo"),
                            access_token=spec["access_token"],
                        )
                        _resp = self.http.send(spec["endpoint"], "GET", **httpc_params)
                    else:
                        if callback:
                            token = callback(spec["endpoint"])
                            cauth = BearerHeader()
                            httpc_params = cauth.construct(
                                service=self.client_get("service", "userinfo"), access_token=token
                            )
                            _resp = self.http.send(spec["endpoint"], "GET", **httpc_params)
                        else:
                            _resp = self.http.send(spec["endpoint"], "GET")

                    if _resp.status_code == 200:
                        _uinfo = json.loads(_resp.text)
                    else:  # There shouldn't be any redirect
                        raise FetchException(
                            "HTTP error {}: {}".format(_resp.status_code, _resp.reason)
                        )

                    claims = [
                        value for value, src in userinfo["_claim_names"].items() if src == csrc
                    ]

                    if set(claims) != set(_uinfo.keys()):
                        logger.warning(
                            "Claims from claim source doesn't match what's in " "the userinfo"
                        )

                    # only add those I expected
                    for key in claims:
                        userinfo[key] = _uinfo[key]

        return userinfo
