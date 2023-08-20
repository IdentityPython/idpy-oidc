from idpyoidc.message.oauth2 import AccessTokenResponse
from idpyoidc.message.oauth2 import AuthorizationResponse
from idpyoidc.message.oauth2 import TokenExchangeResponse
from idpyoidc.message.oauth2 import TokenIntrospectionResponse
from idpyoidc.message.oidc import OpenIDSchema


def pre_construct(response_args, request, context, **kwargs):
    """
    Add extra arguments to the request.

    :param response_args:
    :param request:
    :param context:
    :param kwargs:
    :return:
    """

    _extra = context.add_on.get("extra_args")
    if _extra:
        if isinstance(response_args, AuthorizationResponse):
            _args = _extra.get("authorization", {})
        elif isinstance(response_args, AccessTokenResponse):
            _args = _extra.get("accesstoken", {})
        elif isinstance(response_args, TokenExchangeResponse):
            _args = _extra.get("token_exchange", {})
        elif isinstance(response_args, TokenIntrospectionResponse):
            _args = _extra.get("token_introspection", {})
        elif isinstance(response_args, OpenIDSchema):
            _args = _extra.get("userinfo", {})
        else:
            _args = {}

        for arg, _param in _args.items():
            _val = getattr(context, _param)
            if _val:
                response_args[arg] = _val

    return response_args


def add_support(endpoint, **kwargs):
    #
    _added = False
    for endpoint_name in list(kwargs.keys()):
        _endp = endpoint[endpoint_name]
        _endp.pre_construct.append(pre_construct)

        if _added is False:
            _endp.upstream_get("context").add_on["extra_args"] = kwargs
            _added = True
