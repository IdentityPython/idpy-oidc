import logging
from typing import List
from typing import Optional
from typing import Union

from idpyoidc.client.service import Service
from idpyoidc.exception import MissingParameter
from idpyoidc.exception import MissingRequiredAttribute
from idpyoidc.message import Message

logger = logging.getLogger(__name__)


def get_state_parameter(request_args, kwargs):
    """Find a state value from a set of possible places."""
    try:
        _state = kwargs["state"]
    except KeyError:
        try:
            _state = request_args["state"]
        except KeyError:
            raise MissingParameter("state")

    return _state


def pick_redirect_uri(
        context,
        entity,
        request_args: Optional[Union[Message, dict]] = None,
        response_type: Optional[str] = "",
):
    if request_args is None:
        request_args = {}

    if "redirect_uri" in request_args:
        return request_args["redirect_uri"]

    if context.specs.callback:
        if not response_type:
            _conf_resp_types = context.specs.behaviour.get("response_types", [])
            response_type = request_args.get("response_type")
            if not response_type and _conf_resp_types:
                response_type = _conf_resp_types[0]

        _response_mode = request_args.get("response_mode")

        if _response_mode == "form_post" or response_type == ["form_post"]:
            redirect_uri = context.specs.callback["form_post"]
        elif response_type == "code" or response_type == ["code"]:
            redirect_uri = context.specs.callback["code"]
        else:
            redirect_uri = context.specs.callback["implicit"]

        logger.debug(
            f"pick_redirect_uris: response_type={response_type}, response_mode={_response_mode}, "
            f"redirect_uri={redirect_uri}"
        )
    else:
        redirect_uris = entity.get_metadata_value("redirect_uris", [])
        if redirect_uris:
            redirect_uri = redirect_uris[0]
        else:
            logger.error("No redirect_uri")
            raise MissingRequiredAttribute("redirect_uri")

    return redirect_uri


def pre_construct_pick_redirect_uri(
        request_args: Optional[Union[Message, dict]] = None, service: Optional[Service] = None,
        **kwargs
):
    request_args["redirect_uri"] = pick_redirect_uri(service.client_get("service_context"),
                                                     entity=service.client_get("entity"),
                                                     request_args=request_args)
    return request_args, {}


def set_state_parameter(request_args=None, **kwargs):
    """Assigned a state value."""
    request_args["state"] = get_state_parameter(request_args, kwargs)
    return request_args, {"state": request_args["state"]}
