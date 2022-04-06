from idpyoidc.client.client_auth import ClientAuthnMethod
from idpyoidc.client.service import Service
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.message.oidc.backchannel_authentication import AuthenticationRequest
from idpyoidc.message.oidc.backchannel_authentication import AuthenticationResponse
from idpyoidc.message.oidc.backchannel_authentication import NotificationRequest


class BackChannelAuthentication(Service):
    """The service that talks to the Backchannel Authentication endpoint."""
    msg_type = AuthenticationRequest
    response_cls = AuthenticationResponse
    error_msg = ResponseMessage
    endpoint_name = 'backchannel_authentication_endpoint'
    synchronous = True
    service_name = 'backchannel_authentication'
    response_body_type = 'json'

    def __init__(self, client_get, client_authn_factory=None, conf=None, **kwargs):
        super().__init__(client_get=client_get, conf=conf,
                         client_authn_factory=client_authn_factory, **kwargs)
        self.default_request_args = {'scope': ['openid']}
        self.pre_construct = []
        self.post_construct = []


class ClientNotification(Service):
    """The service that talks to the Client Notification endpoint."""
    msg_type = NotificationRequest
    response_cls = None
    error_msg = None
    endpoint_name = 'client_notification_endpoint'
    synchronous = True
    request_body_type = 'json'
    service_name = 'client_notification'
    response_body_type = ''
    http_method = 'POST'

    def __init__(self, client_get, client_authn_factory=None, conf=None, **kwargs):
        super().__init__(client_get=client_get, client_authn_factory=client_authn_factory,
                         conf=conf, **kwargs)
        self.pre_construct = []
        self.post_construct = []


class ClientNotificationAuthn(ClientAuthnMethod):
    """The bearer header authentication method."""

    def construct(self, request=None, service=None, http_args=None,
                  **kwargs):
        """
        Constructing the Authorization header. The value of
        the Authorization header is "Bearer <access_token>".

        :param request: Request class instance
        :param service: Service
        :param http_args: HTTP header arguments
        :param kwargs: extra keyword arguments
        :return:
        """

        _token = request.get('client_notification_token')
        if not _token:
            raise KeyError('No client_notification_token token available')
        del request["client_notification_token"]

        # The authorization value starts with 'Bearer' when bearer tokens
        # are used
        _bearer = "Bearer {}".format(_token)

        # Add 'Authorization' to the headers
        if http_args is None:
            http_args = {"headers": {}}
            http_args["headers"]["Authorization"] = _bearer
        else:
            try:
                http_args["headers"]["Authorization"] = _bearer
            except KeyError:
                http_args["headers"] = {"Authorization": _bearer}

        return http_args
