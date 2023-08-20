import json

import responses

from idpyoidc.message import Message
from idpyoidc.message.oauth2 import is_error_message
from idpyoidc.util import rndstr


class Flow(object):

    def __init__(self, client, server):
        self.client = client
        self.server = server

    def print(self, proc, msg):
        print(30 * '=' + f' {proc} ' + 30 * '=')
        print("-- REQUEST --")
        print(f"    METHOD: {msg['method']}")
        if 'url' in msg:
            print(f"    URL: {msg['url']}")
        if msg['headers']:
            print('    HEADERS')
            for line in json.dumps(msg['headers'], sort_keys=True, indent=4).split('\n'):
                print('    ' + line)
        if not msg['request']:
            print('{}')
        else:
            print(json.dumps(msg['request'].to_dict(), sort_keys=True, indent=4))
        print('-- RESPONSE --')
        _resp = msg['response']
        if isinstance(_resp, Message):
            print(json.dumps(_resp.to_dict(), sort_keys=True, indent=4))
        else:
            print(json.dumps(_resp, sort_keys=True, indent=4))
        print()

    def do_query(self, service_type, endpoint_type, request_args=None, msg=None):
        if request_args is None:
            request_args = {}
        if msg is None:
            msg = {}

        _client_service = self.client.get_service(service_type)

        _additions = msg.get('request_additions')
        if _additions:
            _info = _additions.get(service_type)
            if _info:
                request_args.update(_info)

        _args = msg.get('get_request_parameters', {})
        kwargs = _args.get(service_type, {})

        if service_type in ["userinfo", 'refresh_token']:
            kwargs['state'] = msg['authorization']['request']['state']

        _mock_resp = msg.get('mock_response')
        if _mock_resp:
            _func = _mock_resp.get(service_type)
            _info = _func(_client_service)
            with responses.RequestsMock() as rsps:
                rsps.add(
                    "GET",
                    _info["uri"],
                    json=_info["data"],
                    content_type="application/json",
                    status=200,
                )
                req_info = _client_service.get_request_parameters(request_args=request_args,
                                                                  **kwargs)
        else:
            req_info = _client_service.get_request_parameters(request_args=request_args, **kwargs)

        areq = req_info.get("request")
        headers = req_info.get("headers")

        _server_endpoint = self.server.get_endpoint(endpoint_type)
        if headers:
            argv = {"http_info": {"headers": headers}}
            argv['http_info']['url'] = req_info['url']
            argv['http_info']['method'] = req_info['method']
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
            result = {'request': _pr_req, 'headers': headers,
                      'method': req_info['method'], 'url': req_info['url']}
            self.print(f"{service_type} - ERROR", result)
            return result

        args = msg.get('process_request_args', {})
        _resp = _server_endpoint.process_request(_pr_req, **args.get(endpoint_type, {}))
        if is_error_message(_resp):
            result = {'request': areq, 'response': _resp, 'headers': headers,
                      'method': req_info['method'], 'url': req_info['url']}
            self.print(f"{service_type} - ERROR", result)
            return result

        _response = _server_endpoint.do_response(**_resp)

        # resp = _client_service.parse_response(_response["response"])
        _state = ''
        if service_type == 'authorization':
            _state = areq.get('state', _pr_req.get('state'))
        else:
            _authz = msg.get('authorization')
            if _authz:
                _state = _authz['request']['state']

        if 'response_args' in _resp:
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

        _response = _resp.get('response_args', _resp.get('response', _resp.get('response_msg')))
        result = {'request': areq, 'response': _response, 'headers': headers,
                  'method': req_info['method'], 'url': req_info['url']}
        self.print(service_type, result)
        return result

    def server_metadata_request(self, msg):
        return {}

    def provider_info_request(self, msg):
        return {}

    def authorization_request(self, msg):
        # ***** Authorization Request **********
        _nonce = rndstr(24)
        _context = self.client.get_service_context()
        # Need a new state for a new authorization request
        _state = _context.cstate.create_state(iss=_context.get("issuer"))
        _context.cstate.bind_key(_nonce, _state)
        _response_type = msg.get('response_type', ['code'])

        req_args = {
            "response_type": _response_type,
            "nonce": _nonce,
            "state": _state
        }

        scope = msg.get('scope')
        if scope:
            if 'openid' not in scope:
                scope.append('openid')
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

    def introspection_request(self, msg):
        _context = self.client.get_context()
        auth_resp = msg['authorization']['response']
        _state = _context.cstate.get(auth_resp["state"])

        return {
            "token": _state['access_token'],
            "token_type_hint": 'access_token'
        }

    def token_revocation_request(self, msg):
        _context = self.client.get_context()
        auth_resp = msg['authorization']['response']
        _state = _context.cstate.get(auth_resp["state"])

        return {
            "token": _state['access_token'],
            "token_type_hint": 'access_token'
        }

    def token_exchange_request(self, msg):
        _token = msg['accesstoken']['response']['access_token']
        _state = msg['authorization']['request']['state']

        return {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "requested_token_type": 'urn:ietf:params:oauth:token-type:access_token',
            "subject_token": _token,
            "subject_token_type": 'urn:ietf:params:oauth:token-type:access_token',
            "state": _state
        }

    def refresh_token_request(self, msg):
        _state = msg['authorization']['request']['state']

        return {
            "grant_type": "refresh_token",
            "state": _state,
        }

    def registration_request(self, msg):
        return {}

    def userinfo_request(self, msg):
        return {}

    def client_credentials_request(self, msg):
        return {}

    def resource_owner_password_credentials_request(self, msg):
        return {}

    def __call__(self, request_responses, **kwargs):
        msg = kwargs
        for request, response in request_responses:
            func = getattr(self, f"{request}_request")
            req_args = func(msg)
            msg[request] = self.do_query(request, response, req_args, msg)
        return msg
