import json
import os

import pytest
from cryptojwt import JWT
from cryptojwt.key_jar import init_key_jar

from idpyoidc.client.defaults import DEFAULT_OIDC_SERVICES
from idpyoidc.client.entity import Entity
from idpyoidc.message.oidc import AuthorizationRequest
from idpyoidc.message.oidc import AuthorizationResponse

KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

_dirname = os.path.dirname(os.path.abspath(__file__))


class TestUserInfo(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self._iss = 'https://server.otherop.com'
        client_config = {
            'client_id': 'client_id',
            'client_secret': 'a longesh password',
            'redirect_uris': ['https://example.com/cli/authz_cb'],
            'issuer': self._iss,
            'base_url': 'https://example.com/cli/'
        }

        KEYS = init_key_jar(key_defs=KEYSPEC)

        entity = Entity(config=client_config, services=DEFAULT_OIDC_SERVICES, keyjar=KEYS)
        entity.client_get("service_context").issuer = 'https://server.otherop.com'
        self.service = entity.client_get("service", 'userinfo')

        entity.client_get("service_context").behaviour = {
            'userinfo_signed_response_alg': 'RS256',
            "userinfo_encrypted_response_alg": "RSA-OAEP",
            "userinfo_encrypted_response_enc": "A256GCM"
        }

    def test_unpack_aggregated_response(self):
        _state_interface = self.service.client_get("service_context").state
        # Add history
        auth_request = AuthorizationRequest(
            redirect_uri='https://example.com/cli/authz_cb',
            claims={
                "userinfo": {
                    "verified_claims": {
                        "verification": {
                            "trust_framework": None
                        },
                        "claims": {
                            "given_name": None,
                            "family_name": None,
                            "birthdate": None
                        }
                    }
                }
            }
        )
        _state = _state_interface.create_state('issuer')
        auth_request["state"] = _state
        _state_interface.store_item(auth_request, 'auth_request', _state)

        auth_response = AuthorizationResponse(code='access_code').to_json()
        _state_interface.store_item(auth_response, 'auth_response', 'abcde')

        _distributed_respone = {
            "iss": "https://server.otherop.com",
            "sub": "e8148603-8934-4245-825b-c108b8b6b945",
            "verified_claims": {
                "verification": {
                    "trust_framework": "ial_example_gold"
                },
                "claims": {
                    "given_name": "Max",
                    "family_name": "Meier",
                    "birthdate": "1956-01-28"
                }
            }
        }

        _jwt = JWT(key_jar=self.service.client_get("service_context").keyjar)
        _jws = _jwt.pack(payload=_distributed_respone)

        resp = {
            "iss": "https://server.example.com",
            "sub": "248289761001",
            "email": "janedoe@example.com",
            "email_verified": True,
            "_claim_names": {
                "verified_claims": "src1"
            },
            "_claim_sources": {
                "src1": {
                    "JWT": _jws
                }
            }
        }

        _resp = self.service.parse_response(json.dumps(resp), state='abcde')
        _resp = self.service.post_parse_response(_resp, state='abcde')
        assert set(_resp.keys()) == {'sub', 'iss', 'email',
                                     '_claim_names', '_claim_sources',
                                     'verified_claims', 'email_verified'}
