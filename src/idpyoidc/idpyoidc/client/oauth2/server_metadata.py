"""The service that talks to the OAuth2 provider info discovery endpoint."""
import logging
from typing import Optional

from cryptojwt.key_jar import KeyJar

from idpyoidc.client.defaults import OAUTH2_SERVER_METADATA_URL
from idpyoidc.client.defaults import OIDCONF_PATTERN
from idpyoidc.client.exception import OidcServiceError
from idpyoidc.client.service import Service
from idpyoidc.message import Message
from idpyoidc.message import oauth2
from idpyoidc.message.oauth2 import ResponseMessage

LOGGER = logging.getLogger(__name__)


class ServerMetadata(Service):
    """The service that talks to the OAuth2 server claims endpoint."""

    msg_type = oauth2.Message
    response_cls = oauth2.ASConfigurationResponse
    error_msg = ResponseMessage
    synchronous = True
    service_name = "server_metadata"
    http_method = "GET"
    url_pattern = OAUTH2_SERVER_METADATA_URL

    _supports = {}

    def __init__(self, upstream_get, conf=None):
        Service.__init__(self, upstream_get, conf=conf)

    def get_endpoint(self):
        """
        Find the issuer ID and from it construct the service endpoint

        :return: Service endpoint
        """
        try:
            _iss = self.upstream_get("context").issuer
        except AttributeError:
            _iss = self.endpoint

        if _iss.endswith("/"):
            return self.url_pattern.format(_iss[:-1])

        return self.url_pattern.format(_iss)

    def get_request_parameters(self, method="GET", **kwargs):
        """
        The Provider info discovery version of get_request_parameters()

        :param method:
        :param kwargs:
        :return:
        """
        return {"url": self.get_endpoint(), "method": method}

    def _verify_issuer(self, resp, issuer):
        _pcr_issuer = resp["issuer"]
        if resp["issuer"].endswith("/"):
            if issuer.endswith("/"):
                _issuer = issuer
            else:
                _issuer = issuer + "/"
        else:
            if issuer.endswith("/"):
                _issuer = issuer[:-1]
            else:
                _issuer = issuer

        # In some cases we can live with the two URLs not being
        # the same. But this is an excepted that has to be explicit
        try:
            self.upstream_get("context").allow["issuer_mismatch"]
        except KeyError:
            if _issuer != _pcr_issuer:
                raise OidcServiceError(
                    "provider info issuer mismatch '%s' != '%s'" % (_issuer, _pcr_issuer)
                )
        return _issuer

    def _set_endpoints(self, resp):
        """
        If there are services defined set the service endpoint to be
        the URLs specified in the provider information."""
        for key, val in resp.items():
            # All service endpoint parameters in the provider info has
            # a name ending in '_endpoint' so I can look specifically
            # for those
            if key.endswith("_endpoint"):
                _srv = self.upstream_get("service_by_endpoint_name", key)
                if _srv:
                    _srv.endpoint = val

    def _update_service_context(self, resp):
        """
        Deal with Provider Config Response. Based on the provider info
        response a set of parameters in different places needs to be set.

        :param resp: The provider info response
        :param service_context: Information collected/used by services
        """

        _context = self.upstream_get("context")
        # Verify that the issuer value received is the same as the
        # url that was used as service endpoint (without the .well-known part)
        if "issuer" in resp:
            _pcr_issuer = self._verify_issuer(resp, _context.issuer)
        else:  # No prior knowledge
            _pcr_issuer = _context.issuer

        _context.issuer = _pcr_issuer
        _context.provider_info = resp

        self._set_endpoints(resp)

        # If I already have a Key Jar then I'll add then provider keys to
        # that. Otherwise, a new Key Jar is minted
        try:
            _keyjar = self.upstream_get("attribute", "keyjar")
            if _keyjar is None:
                _keyjar = KeyJar()
        except KeyError:
            _keyjar = KeyJar()

        # Load the keys. Note that this only means that the key specification
        # is loaded not necessarily that any keys are fetched.
        if "jwks_uri" in resp:
            _keyjar.load_keys(_pcr_issuer, jwks_uri=resp["jwks_uri"])
        elif "jwks" in resp:
            _keyjar.load_keys(_pcr_issuer, jwks=resp["jwks"])

        # Combine what I prefer/supports with what the Provider supports
        if isinstance(resp, Message):
            _info = resp.to_dict()
        else:
            _info = resp
        _context.map_service_against_endpoint(_info)

    def update_service_context(self, resp, key: Optional[str] = "", **kwargs):
        return self._update_service_context(resp)
