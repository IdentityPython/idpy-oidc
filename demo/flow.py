import responses

from idpyoidc.message.oauth2 import is_error_message
from idpyoidc.util import rndstr


class Flow(object):

    def __init__(self, client, server):
        self.client = client
        self.server = server

    def do_query(self, service_type, endpoint_type, request_args=None, msg=None):
        if request_args is None:
            request_args = {}
        if msg is None:
            msg = {}

        _client_service = self.client.get_service(service_type)
        req_info = _client_service.get_request_parameters(request_args=request_args)

        areq = req_info.get("request")
        headers = req_info.get("headers")

        _server_endpoint = self.server.get_endpoint(endpoint_type)
        if headers:
            argv = {"http_info": {"headers": headers}}
        else:
            argv = {}

        if areq:
            if _server_endpoint.request_format == 'json':
                _pr_req = _server_endpoint.parse_request(areq.to_json(), **argv)
            else:
                _pr_req = _server_endpoint.parse_request(areq.to_urlencoded(), **argv)
        else:
            if areq is None:
                _pr_req = _server_endpoint.parse_request(areq)
            else:
                _pr_req = _server_endpoint.parse_request(areq, **argv)

        if is_error_message(_pr_req):
            return areq, _pr_req

        _resp = _server_endpoint.process_request(_pr_req)
        if is_error_message(_resp):
            return areq, _resp

        _response = _server_endpoint.do_response(**_resp)

        resp = _client_service.parse_response(_response["response"])
        _state = msg.get('state', '')

        if _client_service.service_name in ['server_metadata', 'provider_info']:
            if 'server_jwks_uri' in msg and 'server_jwks' in msg:
                with responses.RequestsMock() as rsps:
                    rsps.add(
                        "GET",
                        msg["server_jwks_uri"],
                        json=msg["server_jwks"],
                        content_type="application/json",
                        status=200,
                    )

                    _client_service.update_service_context(_resp["response_args"], key=_state)
            else:
                _client_service.update_service_context(_resp["response_args"], key=_state)
        else:
            _client_service.update_service_context(_resp["response_args"], key=_state)
        return {'request': areq, 'response': resp}

    def server_metadata_request(self, msg):
        return {}

    def authorization_request(self, msg):
        # ***** Authorization Request **********
        _nonce = rndstr(24)
        _context = self.client.get_service_context()
        # Need a new state for a new authorization request
        _state = _context.cstate.create_state(iss=_context.get("issuer"))
        _context.cstate.bind_key(_nonce, _state)

        req_args = {
            "response_type": ["code"],
            "nonce": _nonce,
            "state": _state
        }

        scope = msg.get('scope')
        if scope:
            _scope = scope
        else:
            _scope = ["openid"]

        req_args["scope"] = _scope

        return req_args

    def accesstoken_request(self, msg):
        # ***** Token Request **********
        _context = self.client.get_service_context()

        auth_resp = msg['authorization']['response']
        req_args = {
            "code": auth_resp["code"],
            "state": auth_resp["state"],
            "redirect_uri": msg['authorization']['request']["redirect_uri"],
            "grant_type": "authorization_code",
            "client_id": self.client.get_client_id(),
            "client_secret": _context.get_usage("client_secret"),
        }

        return req_args

    def __call__(self, request_responses: list[list], **kwargs):
        msg = kwargs
        for request, response in request_responses:
            func = getattr(self, f"{request}_request")
            req_args = func(msg)
            msg[request] = self.do_query(request, response, req_args, msg)
        return msg
