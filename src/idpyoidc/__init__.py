__author__ = "Roland Hedberg"
__version__ = "6.0.1"

import inspect

VERIFIED_CLAIM_PREFIX = "__verified"


def verified_claim_name(claim):
    return "{}_{}".format(VERIFIED_CLAIM_PREFIX, claim)


def proper_path(path):
    """
    Clean up the path specification such that it looks like something I could use.
    "./" <path> "/"
    """
    if path.startswith("./"):
        pass
    elif path.startswith("/"):
        path = ".%s" % path
    elif path.startswith("."):
        while path.startswith("."):
            path = path[1:]
        if path.startswith("/"):
            path = ".%s" % path
    else:
        path = "./%s" % path

    if not path.endswith("/"):
        path += "/"

    return path

def init_args_from_source(cls):
    """
    Based on https://www.geeksforgeeks.org/python/get-the-number-of-explicit-arguments-in-the
    -init-of-a-class/
    """
    init_method = cls.__init__

    # Get the signature of the __init__ method
    sig = inspect.signature(init_method)

    # Get the parameters from the signature, excluding 'self'
    params = [k for k in sig.parameters.keys() if k not in ['self', 'kwargs']]
    if 'kwargs' in sig.parameters.keys():
        return params, True
    else:
        return params, False
