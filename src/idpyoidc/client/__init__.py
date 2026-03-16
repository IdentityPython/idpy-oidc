import logging

LOGGER = logging.getLogger(__name__)


def get_base_url(base_url, config) -> str:
    base_url = base_url or config.getarg("base_url", '')
    if not base_url:
        base_url = config.getarg( "entity_id", '') or config.getarg("client_id", '')
        if not base_url.startswith('https://'):
            if not base_url.startswith('http://'):
                LOGGER.warning('You are using HTTP not HTTPS is that correct?')
            else:
                raise ValueError
    return base_url
