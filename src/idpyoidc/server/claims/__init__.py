from typing import Optional

from idpyoidc import claims


class Claims(claims.Claims):
    def get_base_url(self, configuration: dict, entity_id: Optional[str] = ""):
        _base = configuration.get("base_url")
        if not _base:
            if entity_id:
                _base = entity_id
            else:
                _base = configuration.get("issuer")

        return _base

    def get_id(self, configuration: dict):
        return configuration.get("issuer")

    def supported_to_preferred(
        self, supported: dict, base_url: Optional[str] = "", info: Optional[dict] = None
    ):
        # Add defaults
        for key, val in supported.items():
            if val is None:
                continue
            if key not in self.prefer:
                self.prefer[key] = val
