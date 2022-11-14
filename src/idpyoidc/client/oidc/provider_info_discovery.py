import logging

from idpyoidc.client.exception import ConfigurationError
from idpyoidc.client.oauth2 import server_metadata
from idpyoidc.message import oidc
from idpyoidc.message.oauth2 import ResponseMessage

__author__ = "Roland Hedberg"

logger = logging.getLogger(__name__)

PREFERENCE2PROVIDER = {
    # "require_signed_request_object": "request_object_algs_supported",
    "request_object_signing_alg": "request_object_signing_alg_values_supported",
    "request_object_encryption_alg": "request_object_encryption_alg_values_supported",
    "request_object_encryption_enc": "request_object_encryption_enc_values_supported",
    "userinfo_signed_response_alg": "userinfo_signing_alg_values_supported",
    "userinfo_encrypted_response_alg": "userinfo_encryption_alg_values_supported",
    "userinfo_encrypted_response_enc": "userinfo_encryption_enc_values_supported",
    "id_token_signed_response_alg": "id_token_signing_alg_values_supported",
    "id_token_encrypted_response_alg": "id_token_encryption_alg_values_supported",
    "id_token_encrypted_response_enc": "id_token_encryption_enc_values_supported",
    "default_acr_values": "acr_values_supported",
    "subject_type": "subject_types_supported",
    "token_endpoint_auth_method": "token_endpoint_auth_methods_supported",
    "token_endpoint_auth_signing_alg": "token_endpoint_auth_signing_alg_values_supported",
    "response_types": "response_types_supported",
    "grant_types": "grant_types_supported",
    "scope": "scopes_supported",
}

PROVIDER2PREFERENCE = dict([(v, k) for k, v in PREFERENCE2PROVIDER.items()])

PROVIDER_DEFAULT = {
    "token_endpoint_auth_method": "client_secret_basic",
    "id_token_signed_response_alg": "RS256",
}


def add_redirect_uris(request_args, service=None, **kwargs):
    """
    Add redirect_uris to the request arguments.

    :param request_args: Incoming request arguments
    :param service: A link to the service
    :param kwargs: Possible extra keyword arguments
    :return: A possibly augmented set of request arguments.
    """
    _work_condition = service.client_get("service_context").work_condition
    if "redirect_uris" not in request_args:
        # Callbacks is a dictionary with callback type 'code', 'implicit',
        # 'form_post' as keys.
        _callback = _work_condition.get_preference('callback')
        if _callback:
            # Filter out local additions.
            _uris = [v for k, v in _callback.items() if not k.startswith("__")]
            request_args["redirect_uris"] = _uris
        else:
            request_args["redirect_uris"] = _work_condition.get_preference(
                "redirect_uris", _work_condition.supports.get('redirect_uris'))

    return request_args, {}


class ProviderInfoDiscovery(server_metadata.ServerMetadata):
    msg_type = oidc.Message
    response_cls = oidc.ProviderConfigurationResponse
    error_msg = ResponseMessage
    service_name = "provider_info"

    _supports = {}

    def __init__(self, client_get, conf=None):
        server_metadata.ServerMetadata.__init__(self, client_get, conf=conf)

    def update_service_context(self, resp, **kwargs):
        _context = self.client_get("service_context")
        self._update_service_context(resp)  # set endpoints and import keys
        self.match_preferences(resp, _context.issuer)
        if "pre_load_keys" in self.conf and self.conf["pre_load_keys"]:
            _jwks = _context.keyjar.export_jwks_as_json(issuer=resp["issuer"])
            logger.info("Preloaded keys for {}: {}".format(resp["issuer"], _jwks))

    def match_preferences(self, pcr=None, issuer=None):
        """
        Match the clients supports against what the provider can do.
        This is to prepare for later client registration and/or what
        functionality the client actually will use.
        In the client configuration the client preferences are expressed.
        These are then compared with the Provider Configuration information.
        If the Provider has left some claims out, defaults specified in the
        standard will be used.

        :param pcr: Provider configuration response if available
        :param issuer: The issuer identifier
        """
        _context = self.client_get("service_context")
        _entity = self.client_get("entity")
        _work_condition = _context.work_condition

        _supports = _context.supports()
        _prefers = _context.prefers()

        if not pcr:
            pcr = _context.provider_info

        regreq = oidc.RegistrationRequest
        prefers = {}

        for _pref, _prov in PREFERENCE2PROVIDER.items():
            _supported_values = _supports.get(_pref)
            _preferred_value = _prefers.get(_pref)

            if not _preferred_value:
                if not _supported_values:
                    continue
            else:
                _supported_values = _preferred_value

            try:
                _provider_vals = pcr[_prov]
            except KeyError:
                try:
                    # If the provider have not specified use what the
                    # standard says is mandatory if at all.
                    _provider_vals = PROVIDER_DEFAULT[_pref]
                except KeyError:
                    logger.info("No info from provider on {} and no default".format(_pref))
                    _provider_vals = _supported_values

            if not isinstance(_supported_values, list):
                if isinstance(_provider_vals, list):
                    if _supported_values in _provider_vals:
                        prefers[_pref] = _supported_values
                elif _provider_vals == _supported_values:
                    prefers[_pref] = _supported_values
            else:  # _supported_values is a list
                try:
                    vtyp = regreq.c_param[_pref]
                except KeyError:
                    # Allow non standard claims
                    if isinstance(_supported_values, list) and isinstance(_provider_vals, list):
                        prefers[_pref] = [v for v in _supported_values if v in _provider_vals]
                    elif isinstance(_provider_vals, list):
                        if _supported_values in _provider_vals:
                            prefers[_pref] = _supported_values
                    elif type(_supported_values) == type(_provider_vals):
                        if _supported_values == _provider_vals:
                            prefers[_pref] = _supported_values
                else:
                    if isinstance(vtyp[0], list):
                        prefers[_pref] = []
                        for val in _supported_values:
                            if val in _provider_vals:
                                prefers[_pref].append(_supported_values)
                    else:
                        for val in _supported_values:
                            if val in _provider_vals:
                                prefers[_pref] = val
                                break

            if _pref not in prefers:
                raise ConfigurationError("OP couldn't match preference:%s" % _pref, pcr)

        for key, val in _supports:
            if key in prefers:
                continue
            if key in ["jwks", "jwks_uri"]:
                continue

            try:
                vtyp = regreq.c_param[key]
                if isinstance(vtyp[0], list):
                    pass
                elif isinstance(val, list) and not isinstance(val, str):
                    val = val[0]
            except KeyError:
                pass
            if key not in PREFERENCE2PROVIDER:
                prefers[key] = val

        # stores it all in one place
        _context.work_condition.prefer = prefers
        logger.debug("Entity prefers: {}".format(prefers))
