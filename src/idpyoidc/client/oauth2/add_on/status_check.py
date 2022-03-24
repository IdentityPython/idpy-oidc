from cryptojwt.utils import as_bytes


def get_session_status_page(service_context, looked_for_state):
    """
    Constructs the session status check page

    :param service_context: The relying party's service context
    :param looked_for_state: Expecting state to be ? (changed/unchanged)
    """
    _msg = open(service_context.add_on['status_check']['template_file']).read()
    _csi = service_context.provider_info['check_session_iframe']
    _mod_msg = _msg.replace("{check_session_iframe}", _csi)
    if looked_for_state == "changed":
        _mod_msg = _mod_msg.replace(
            "{status_check_iframe}",
            service_context.add_on['status_check']['session_changed_iframe'])
    else:
        _mod_msg = _mod_msg.replace(
            "{status_check_iframe}",
            service_context.add_on['status_check']['session_unchanged_iframe'])

    return as_bytes(_mod_msg)


def add_support(service, rp_iframe_path, template_file="",
                session_changed_iframe_path="", session_unchanged_iframe_path=""):
    """
    Setup status check support.

    :param service: Dictionary of services
    :param template_file: Name of template file
    """
    # Arbitrary which service is used, just want a link to the service context
    authn_service = service["authorization"]
    authn_service.service_context.add_on['status_check'] = {
        "template_file": template_file,
        "rp_iframe_path": rp_iframe_path,
        "session_changed_iframe": session_changed_iframe_path,
        "session_unchanged_iframe": session_unchanged_iframe_path,
        # below are functions
        # "rp_iframe": rp_iframe,
        "get_session_status_page": get_session_status_page
    }
