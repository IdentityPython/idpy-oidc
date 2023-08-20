import logging
from urllib.parse import urlsplit
from urllib.parse import urlunsplit

from idpyoidc.client.oidc import OIC_ISSUER
from idpyoidc.client.oidc import WF_URL
from idpyoidc.client.service import Service
from idpyoidc.exception import MissingRequiredAttribute
from idpyoidc.message import oidc
from idpyoidc.message.oauth2 import Message
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.message.oidc import JRD

__author__ = "Roland Hedberg"

logger = logging.getLogger(__name__)

SCHEME = 0
NETLOC = 1
PATH = 2
QUERY = 3
FRAGMENT = 4


class WebFinger(Service):
    """
    Implements RFC 7033
    """

    msg_type = Message
    response_cls = JRD
    error_msg = ResponseMessage
    synchronous = True
    service_name = "webfinger"
    http_method = "GET"
    response_body_type = "json"

    def __init__(self, upstream_get, conf=None, rel="", **kwargs):
        Service.__init__(self, upstream_get, conf=conf, **kwargs)

        self.rel = rel or OIC_ISSUER

    def update_service_context(self, resp, key="", **kwargs):
        try:
            links = resp["links"]
        except KeyError:
            raise MissingRequiredAttribute("links")
        else:
            for link in links:
                if link["rel"] == self.rel:
                    _href = link["href"]
                    _context = self.upstream_get("service_context")
                    _http_allowed = "http_links" in _context.get("allow", default={})

                    if _href.startswith("http://") and not _http_allowed:
                        raise ValueError("http link not allowed ({})".format(_href))

                    self.upstream_get("context").issuer = link["href"]
                    break
        return resp

    @staticmethod
    def create_url(part, ignore):
        res = []
        for a in range(0, 5):
            if a in ignore:
                res.append("")
            else:
                res.append(part[a])
        return urlunsplit(tuple(res))

    def query(self, resource):
        """
        Given a resource identifier find the domain specifier and then
        construct the webfinger request. Implements
        http://openid.net/specs/openid-connect-discovery-1_0.html#NormalizationSteps

        :param resource:
        """
        if resource[0] in ["=", "@", "!"]:  # Have no process for handling these
            raise ValueError("Not allowed resource identifier")

        try:
            part = urlsplit(resource)
        except Exception:
            raise ValueError("Unparsable resource")
        else:
            if not part[SCHEME]:
                if not part[NETLOC]:
                    _path = part[PATH]
                    if not part[QUERY] and not part[FRAGMENT]:
                        if "/" in _path or ":" in _path:
                            resource = "https://{}".format(resource)
                            part = urlsplit(resource)
                            authority = part[NETLOC]
                        else:
                            if "@" in _path:
                                authority = _path.split("@")[1]
                            else:
                                authority = _path
                            resource = "acct:{}".format(_path)
                    elif part[QUERY]:
                        resource = "https://{}?{}".format(_path, part[QUERY])
                        parts = urlsplit(resource)
                        authority = parts[NETLOC]
                    else:
                        resource = "https://{}".format(_path)
                        part = urlsplit(resource)
                        authority = part[NETLOC]
                else:
                    raise ValueError("Missing netloc")
            else:
                _scheme = part[SCHEME]
                if _scheme not in ["http", "https", "acct"]:
                    # assume it to be a hostname port combo,
                    # eg. example.com:8080
                    resource = "https://{}".format(resource)
                    part = urlsplit(resource)
                    authority = part[NETLOC]
                    resource = self.create_url(part, [FRAGMENT])
                elif _scheme in ["http", "https"] and not part[NETLOC]:
                    raise ValueError("No authority part in the resource specification")
                elif _scheme == "acct":
                    _path = part[PATH]
                    for c in ["/", "?"]:
                        _path = _path.split(c)[0]

                    if "@" in _path:
                        authority = _path.split("@")[1]
                    else:
                        raise ValueError("No authority part in the resource specification")
                    authority = authority.split("#")[0]
                    resource = self.create_url(part, [FRAGMENT])
                else:
                    authority = part[NETLOC]
                    resource = self.create_url(part, [FRAGMENT])

        location = WF_URL.format(authority)
        return oidc.WebFingerRequest(resource=resource, rel=OIC_ISSUER).request(location)

    def get_request_parameters(self, request_args=None, **kwargs):

        if request_args is None:
            request_args = {}

        try:
            _resource = request_args["resource"]
        except KeyError:
            try:
                _resource = kwargs["resource"]
            except KeyError:
                try:
                    _resource = self.upstream_get("context").config["resource"]
                except KeyError:
                    raise MissingRequiredAttribute("resource")

        return {"url": self.query(_resource), "method": "GET"}
