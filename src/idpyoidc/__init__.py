__author__ = "Roland Hedberg"
__version__ = "1.0.4"

import os
from typing import Dict

VERIFIED_CLAIM_PREFIX = "__verified"


def verified_claim_name(claim):
    return "{}_{}".format(VERIFIED_CLAIM_PREFIX, claim)


def proper_path(path):
    """
    Clean up the path specification so it looks like something I could use.
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
