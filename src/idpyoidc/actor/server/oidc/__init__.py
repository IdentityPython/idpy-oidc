from typing import Optional

from cryptojwt.key_jar import KeyJar

from idpyoidc.impexp import ImpExp


class CIBAServer(ImpExp):
    parameter = {"context": {}}

    def __init__(
            self,
            keyjar: Optional[KeyJar] = None,
    ):
        ImpExp.__init__(self)
        self.keyjar = keyjar
        self.server = None
        self.client = None
        self.context = {}
