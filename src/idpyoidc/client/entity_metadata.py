from typing import Optional
from typing import Union

from idpyoidc.impexp import ImpExp


class EntityMetadata(ImpExp):
    # two levels deep metadata store
    # first level is entity types, second layer is metadata per entity type
    parameter = {"metadata": {}}

    def __init__(self, metadata: Optional[dict] = None):
        ImpExp.__init__(self)
        if metadata is None:
            self.metadata = {}
        else:
            self.metadata = metadata

    def __getitem__(self, entity_type):
        _metadata = self.metadata.get(entity_type, None)
        if _metadata is None:
            raise KeyError(entity_type)
        else:
            return _metadata

    def set_entity_type_metadata(self, entity_type: str, info: dict):
        # Info is metadata connected to an entity type
        self.metadata[entity_type] = info

    def items(self):
        return self.metadata.items()

    def __contains__(self, entity_type):
        return entity_type in self.metadata

    def get(self, entity_type, default=None):
        return self.metadata.get(entity_type, default)

    def to_dict(self):
        return self.metadata

    def get_claim_by_entity_type(self,
                                 claim:str,
                                 entity_type: Optional[str] = '') -> Union[dict, str]:
        if entity_type:
            entity_type_metadata = self.metadata.get(entity_type, {})
            if claim in entity_type_metadata:
                claim_value = entity_type_metadata.get(claim, None)
                return claim_value
            else:
                raise KeyError(entity_type)
        else:
            res = {}
            for entity_type, entity_type_metadata in self.metadata.items():
                if claim in entity_type_metadata:
                    claim_value = entity_type_metadata.get(claim, None)
                    res[entity_type] = claim_value
            return res