#
from typing import List
from typing import Optional
from typing import Union

from idpyoidc.client.oauth2 import Client
from idpyoidc.configure import Configuration
from idpyoidc.impexp import ImpExp
from idpyoidc.server import OPConfiguration
from idpyoidc.server import Server


class Actor(ImpExp):
    def __init__(self,
                 conf: Union[Configuration, dict],
                 domain: str,
                 port: int,
                 base_path: str = "",
                 file_attributes: Optional[List[str]] = None,
                 dir_attributes: Optional[List[str]] = None
                 ):
        ImpExp.__init__(self)

        server_config = conf.get("server")
        if server_config:
            if isinstance(server_config, dict):
                server_config = OPConfiguration(conf=server_config, port=port, domain=domain,
                                                file_attributes=file_attributes,
                                                dir_attributes=dir_attributes,
                                                base_path=base_path)
            self.server = Server(conf=server_config)
        client_config = conf.get("client")
        if client_config:
            if isinstance(client_config, dict):
                client_config = Configuration(conf=client_config, port=port, domain=domain,
                                              file_attributes=file_attributes,
                                              dir_attributes=dir_attributes,
                                              base_path=base_path)
            self.client = Client(config=client_config)
