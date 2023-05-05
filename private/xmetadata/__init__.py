import logging
from typing import Optional

from cryptojwt.exception import IssuerNotFound
from cryptojwt.jwk.hmac import SYMKey

from idpyoidc import metadata
from idpyoidc.message import Message
from idpyoidc.metadata import array_or_singleton
from idpyoidc.metadata import is_subset

logger = logging.getLogger(__name__)


class Metadata(metadata.Metadata):
    register2preferred = {}
    registration_response = Message
    registration_request = Message

    def get_base_url(self, configuration: dict):
        _base = configuration.get('base_url')
        if not _base:
            _base = configuration.get('client_id')

        return _base

    def get_id(self, configuration: dict):
        return self.get_preference('client_id')

    def add_extra_keys(self, keyjar, id):
        _secret = self.get_preference('client_secret')
        if _secret:
            _new = SYMKey(key=_secret)
            try:
                _id_keys = keyjar.get_issuer_keys(id)
            except IssuerNotFound:
                keyjar.add_symmetric(issuer_id=id, key=_secret)
            else:
                if _new not in _id_keys:
                    keyjar.add_symmetric(issuer_id=id, key=_secret)

            try:
                _own_keys = keyjar.get_issuer_keys('')
            except IssuerNotFound:
                keyjar.add_symmetric(issuer_id='', key=_secret)
            else:
                if _new not in _own_keys:
                    keyjar.add_symmetric(issuer_id='', key=_secret)

    def get_jwks(self, keyjar):
        _jwks = None
        try:
            _own_keys = keyjar.get_issuer_keys('')
        except IssuerNotFound:
            pass
        else:
            if len(_own_keys) == 1 and isinstance(_own_keys[0], SYMKey):
                pass
            else:
                _jwks = keyjar.export_jwks()

        return _jwks

    def supported_to_preferred(self,
                               supported: dict,
                               base_url: str,
                               info: Optional[dict] = None):
        if info:  # The provider info
            for key, val in supported.items():
                if key in self.prefer:
                    _pref_val = self.prefer.get(key)  # defined in configuration
                    _info_val = info.get(key)
                    if _info_val:
                        # Only use provider setting if less or equal to what I support
                        if key.endswith('supported'):  # list
                            self.prefer[key] = [x for x in _pref_val if x in _info_val]
                        else:
                            pass
                elif val is None:  # No default, means the RP does not have a self.prefer
                    # if key not in ['jwks_uri', 'jwks']:
                    pass
                else:
                    # there is a default
                    _info_val = info.get(key)
                    if _info_val:  # The OP has an opinion
                        if key.endswith('supported'):  # list
                            self.prefer[key] = [x for x in val if x in _info_val]
                        else:
                            pass
                    else:
                        self.prefer[key] = val

            # special case -> must have a request_uris value
            if 'require_request_uri_registration' in info:
                # only makes sense if I want to use request_uri
                if self.prefer.get('request_parameter') == 'request_uri':
                    if 'request_uri' not in self.prefer:
                        self.prefer['request_uris'] = [f'{base_url}/requests']
                else:  # just ignore
                    logger.info('Asked for "request_uri" which it did not plan to use')
        else:
            # Add defaults
            for key, val in supported.items():
                if val is None:
                    continue
                if key not in self.prefer:
                    self.prefer[key] = val

    def preferred_to_registered(self,
                                supported: dict,
                                response: Optional[dict] = None):
        """
        The claims with values that are returned from the OP is what goes unless (!!)
        the values returned are not within the supported values.

        @param registration_response:
        @return:
        """
        registered = {}

        if response:
            for key, val in response.items():
                if key in self.register2preferred:
                    if is_subset(val, supported.get(self.register2preferred[key])):
                        registered[key] = val
                    else:
                        logger.warning(
                            f'OP tells me to do something I do not support: {key} = {val}')
                else:
                    registered[key] = val  # Should I just accept with the OP says ??

        for key, spec in self.registration_response.c_param.items():
            if key in registered:
                continue
            _pref_key = self.register2preferred.get(key, key)

            _preferred_values = self.prefer.get(_pref_key, self.prefer.get(key))
            if not _preferred_values:
                continue

            registered[key] = array_or_singleton(spec, _preferred_values)

        # transfer those claims that are not part of the registration request
        _rr_keys = list(self.registration_response.c_param.keys())
        for key, val in self.prefer.items():
            _reg_key = self.register2preferred.get(key, key)
            if _reg_key not in _rr_keys:
                # If they are not part of the registration request I do not know if it is 
                # supposed to be a singleton or an array. So just add it as is.
                registered[_reg_key] = val

        # all those others
        _filtered_registered = {k: v for k, v in registered.items() if k not in
                                self.register2preferred.keys() and k not in
                                self.register2preferred.values()}

        # Removed supported if value chosen
        for key, val in self.register2preferred.items():
            if val in registered:
                if key in registered:
                    _filtered_registered[key] = registered[key]
                elif registered[val] != []:
                    _filtered_registered[val] = registered[val]
            elif key in registered:
                _filtered_registered[key] = registered[key]

        logger.debug(f"Entity registered: {_filtered_registered}")
        self.use = _filtered_registered
        return _filtered_registered

    def create_registration_request(self, supported):
        _request = {}
        for key, spec in self.registration_request.c_param.items():
            _pref_key = self.register2preferred.get(key, key)
            if _pref_key in self.prefer:
                value = self.prefer[_pref_key]
            elif _pref_key in supported:
                value = supported[_pref_key]
            else:
                continue

            if not value:
                continue

            _request[key] = array_or_singleton(spec, value)
        return _request
