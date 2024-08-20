from typing import Optional


class EntityMetadata(object):

    def __init__(self, metadata: Optional[dict] = None):
        if metadata is None:
            self.metadata = {}
        else:
            self.metadata = metadata

    def __getitem__(self, item):
        for _type, _dict in self.metadata.items():
            _val = _dict.get(item, None)
            if _val:
                return _val
        raise KeyError(item)

    def __setitem__(self, key, value):
        # Assumes not multiple entity types
        self.metadata[key] = value

    def entity_types(self):
        return list(self.metadata.keys())

    def entity_type(self, etype):
        return self.metadata[etype]

    def items(self):
        return self.metadata.items()

    def get_entity_type_claim(self, entity_type, claim):
        return self.metadata[entity_type][claim]

    def __contains__(self, item):
        return item in self.metadata

    def get(self, item, default=None):
        return self.metadata.get(item, default)
