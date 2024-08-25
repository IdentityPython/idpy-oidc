from typing import Optional

from idpyoidc.impexp import ImpExp


class EntityMetadata(ImpExp):
    parameter = {"metadata": {}}
    def __init__(self, metadata: Optional[dict] = None):
        ImpExp.__init__(self)
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

    def items(self):
        return self.metadata.items()

    def __contains__(self, item):
        return item in self.metadata

    def get(self, item, default=None):
        return self.metadata.get(item, default)

    def to_dict(self):
        return self.metadata
