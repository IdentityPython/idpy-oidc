from idpyoidc import work_environment


class WorkEnvironment(work_environment.WorkEnvironment):

    def get_base_url(self, configuration: dict):
        _base = configuration.get('base_url')
        if not _base:
            _base = configuration.get('issuer')

        return _base

    def get_id(self, configuration: dict):
        return configuration.get('issuer')
