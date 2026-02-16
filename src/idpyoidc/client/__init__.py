import logging

from idpyoidc.util import conf_get

LOGGER = logging.getLogger(__name__)


def get_base_url(base_url, config) -> str:
    base_url = base_url or conf_get(config, "base_url", '')
    if not base_url:
        base_url = conf_get(config, "entity_id", '') or conf_get(config, "client_id", '')
        if not base_url.startswith('https://'):
            if not base_url.startswith('http://'):
                LOGGER.warning('You are using HTTP not HTTPS is that correct?')
            else:
                raise ValueError
    return base_url
