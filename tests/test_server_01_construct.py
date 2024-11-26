import pytest

from idpyoidc.server.construct import construct_provider_info


def test_construct():
    default_capabilities = {
        "claims_parameter_supported": True,
        "request_parameter_supported": True,
        "response_types_supported": ["code", "token", "code token"],
        "response_modes_supported": ["query", "fragment", "form_post"],
        "request_object_signing_alg_values_supported": None,
        "request_object_encryption_alg_values_supported": None,
        "request_object_encryption_enc_values_supported": None,
        "grant_types_supported": ["authorization_code", "implicit"],
        "scopes_supported": [],
    }
    _info = construct_provider_info(
        default_capabilities,
        request_object_signing_alg_values_supported=["RS256", "RS384", "RS512"],
        grant_types_supported=["authorization_code"],
    )
    assert _info["request_object_signing_alg_values_supported"] == ["RS256", "RS384", "RS512"]
    assert _info["grant_types_supported"] == ["authorization_code"]
    assert "A128KW" in _info["request_object_encryption_alg_values_supported"]

    with pytest.raises(ValueError):
        _info = construct_provider_info(
            default_capabilities,
            request_object_encryption_alg_values_supported=["X"],
        )
