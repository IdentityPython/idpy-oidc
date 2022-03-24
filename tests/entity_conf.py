CONFIG = {
  "port": 8090,
  "domain": "127.0.0.1",
  "base_url": "https://{domain}:{port}",
  "httpc_params": {
    "verify": False
  },
  "keys": {
    "private_path": "private/jwks.json",
    "key_defs": [
      {
        "type": "RSA",
        "key": "",
        "use": [
          "sig"
        ]
      },
      {
        "type": "EC",
        "crv": "P-256",
        "use": [
          "sig"
        ]
      }
    ],
    "public_path": "static/jwks.json",
    "read_only": False
  }
}
