from idpyoidc.resource import ResourceEntity

ENTITY_ID = "https://entity.example.com"
KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]


def test_resource_server():
    CONF = {
        "preference": {
            "organization_name": "The example federation FTP operator",
            "organization_uri": "https://rp.example.com",
            "contacts": "operations@ftp.example.com"
        }
    }
    server = ResourceEntity(
        config=CONF,
        entity_id=ENTITY_ID,
    )

    metadata = server.get_metadata()
    assert set(metadata.keys()) == {"jwks"}
