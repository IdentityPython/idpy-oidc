import json


class DummyResponse():
    def __init__(self, status_code, text):
        self.text = text
        self.status_code = status_code

class EmulatePARCall():
    def __init__(self, server=None):
        self.server = server

    def __call__(self, method, url, data):
        # I can ignore the method and url. Only interested in the data
        _endp = self.server.endpoint['pushed_authorization']
        _resp = _endp.process_request(request=data)
        return DummyResponse(text=json.dumps(_resp['http_response']), status_code=200)

