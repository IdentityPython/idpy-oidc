# default set can be changed by configuration
import logging

LOGGER = logging.getLogger(__name__)

SCOPE2CLAIMS = {
    "openid": ["sub"],
    "profile": [
        "name",
        "given_name",
        "family_name",
        "middle_name",
        "nickname",
        "profile",
        "picture",
        "website",
        "gender",
        "birthdate",
        "zoneinfo",
        "locale",
        "updated_at",
        "preferred_username",
    ],
    "email": ["email", "email_verified"],
    "address": ["address"],
    "phone": ["phone_number", "phone_number_verified"],
    "offline_access": [],
}


def convert_scopes2claims(scopes, allowed_claims=None, scope2claim_map=None):
    scope2claim_map = scope2claim_map or SCOPE2CLAIMS

    res = {}
    if allowed_claims is None:
        for scope in scopes:
            claims = {name: None for name in scope2claim_map.get(scope, [])}
            res.update(claims)
    else:
        for scope in scopes:
            try:
                claims = {
                    name: None for name in scope2claim_map.get(scope, []) if name in allowed_claims
                }
                res.update(claims)
            except KeyError:
                continue

    return res


class Scopes:

    def __init__(self, upstream_get, allowed_scopes=None, scopes_to_claims=None):
        self.upstream_get = upstream_get
        if not scopes_to_claims:
            scopes_to_claims = dict(SCOPE2CLAIMS)
        self._scopes_to_claims = scopes_to_claims
        self.allowed_scopes = list(scopes_to_claims.keys())

    def get_allowed_scopes(self, client_id=None):
        """
        Returns the set of scopes that a specific client can use.

        :param client_id: The client identifier
        :returns: List of scope names. Can be empty.
        """
        allowed_scopes = self.allowed_scopes
        if client_id:
            client_info = self.upstream_get("context").cdb.get(client_id)
            if client_info is not None:
                client_scopes = client_info.get("allowed_scopes")
                if client_scopes:
                    allowed_scopes = client_scopes
                else:
                    # if there is client specific scopes_to_claims definition use the keys as
                    # allowed_scopes
                    client_scopes = list(client_info.get("scopes_to_claims", {}).keys())
                    if client_scopes:
                        allowed_scopes = client_scopes
                    else:
                        LOGGER.warning("No `allowed_scopes` are defined for client: %s" % client_id)
        return allowed_scopes

    def get_scopes_mapping(self, client_id=None):
        """
        Returns the mapping of scopes to claims fora specific client.

        :param client_id: The client identifier
        :returns: Dict of scopes to claims. Can be empty.
        """
        scopes_to_claims = self._scopes_to_claims
        if client_id:
            client = self.upstream_get("context").cdb.get(client_id)
            if client is not None:
                scopes_to_claims = client.get("scopes_to_claims", scopes_to_claims)
        return scopes_to_claims

    def filter_scopes(self, scopes, client_id=None):
        allowed_scopes = self.get_allowed_scopes(client_id)
        return [s for s in scopes if s in allowed_scopes]

    def scopes_to_claims(self, scopes, scopes_to_claims=None, client_id=None):
        if not scopes_to_claims:
            scopes_to_claims = self.get_scopes_mapping(client_id)

        scopes = self.filter_scopes(scopes, client_id)

        return convert_scopes2claims(scopes, scope2claim_map=scopes_to_claims)

    def set_scopes_mapping(self, scopes_to_claims):
        self._scopes_to_claims = scopes_to_claims
