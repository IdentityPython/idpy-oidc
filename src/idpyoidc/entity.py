from typing import List
from typing import Optional

from idpyoidc.server import Server


def make_entity(entity_id: str,
                key_config: Optional[dict] = None,
                preference: Optional[dict] = None,
                endpoints: Optional[List[str]] = None,
                httpc_params: Optional[dict] = None,
                persistence: Optional[dict] = None,
                client_authn_methods: Optional[list] = None
                ):
    _config = build_entity_config(
        entity_id=entity_id,
        key_config=key_config,
        authority_hints=authority_hints,
        preference=preference,
        endpoints=endpoints,
        services=services,
        functions=functions,
        init_kwargs=init_kwargs,
        item_args=item_args,
        httpc_params=httpc_params,
        persistence=persistence
    )

    fe = Server(client_authn_methods=client_authn_methods, **_config)
