import logging
import sys
import traceback
from typing import List
from typing import Optional

from cryptojwt import KeyJar
from cryptojwt.key_jar import init_key_jar
from cryptojwt.utils import as_bytes
from cryptojwt.utils import importer

from idpyoidc.client.defaults import DEFAULT_CLIENT_CONFIGS
from idpyoidc.client.defaults import DEFAULT_OIDC_SERVICES
from idpyoidc.client.defaults import DEFAULT_RP_KEY_DEFS
from idpyoidc.client.oauth2.stand_alone_client import StandAloneClient
from idpyoidc.util import add_path
from idpyoidc.util import rndstr
from .oauth2 import Client
from ..message import Message

logger = logging.getLogger(__name__)


class RPHandler(object):

    def __init__(
            self,
            base_url: Optional[str] = "",
            client_configs=None,
            services=None,
            keyjar=None,
            hash_seed="",
            verify_ssl=True,
            state_db=None,
            httpc=None,
            httpc_params=None,
            config=None,
            **kwargs,
    ):
        self.base_url = base_url

        if keyjar is None:
            keyjar_defs = {}
            if config:
                keyjar_defs = getattr(config, "key_conf", None)

            if not keyjar_defs:
                keyjar_defs = kwargs.get("key_conf", DEFAULT_RP_KEY_DEFS)

            _jwks_path = kwargs.get("jwks_path", keyjar_defs.get("uri_path", keyjar_defs.get("public_path", "")))
            if "uri_path" in keyjar_defs:
                del keyjar_defs["uri_path"]
            self.keyjar = init_key_jar(**keyjar_defs, issuer_id="")
            self.keyjar.import_jwks_as_json(self.keyjar.export_jwks_as_json(True, ""), base_url)
        else:
            self.keyjar = keyjar
            _jwks_path = kwargs.get("jwks_path", "")

        if _jwks_path:
            self.jwks_uri = add_path(base_url, _jwks_path)
        else:
            self.jwks_uri = ""
            if len(self.keyjar):
                self.jwks = self.keyjar.export_jwks()
            else:
                self.jwks = {}

        if config:
            if not hash_seed:
                self.hash_seed = config.hash_seed
            if not keyjar:
                self.keyjar = init_key_jar(**config.key_conf, issuer_id="")
            if not client_configs:
                self.client_configs = config.clients

            if "client_class" in config:
                if isinstance(config["client_class"], str):
                    self.client_cls = importer(config["client_class"])
                else:  # assume it's a class
                    self.client_cls = config["client_class"]
            else:
                self.client_cls = StandAloneClient
        else:
            if hash_seed:
                self.hash_seed = as_bytes(hash_seed)
            else:
                self.hash_seed = as_bytes(rndstr(32))

            if client_configs is None:
                self.client_configs = DEFAULT_CLIENT_CONFIGS
                for param in ["client_type", "preference", "add_ons"]:
                    val = kwargs.get(param, None)
                    if val:
                        self.client_configs[""][param] = val
            else:
                self.client_configs = client_configs

            _cc = kwargs.get("client_class", None)
            if _cc:
                if isinstance(_cc, str):
                    _cc = importer(_cc)
                self.client_cls =_cc
            else:
                self.client_cls = StandAloneClient


        if state_db:
            self.state_db = state_db
        else:
            self.state_db = {}

        self.extra = kwargs

        if services is None:
            self.services = DEFAULT_OIDC_SERVICES
        else:
            self.services = services

        # keep track on which RP instance that serves which OP
        self.issuer2rp = {}
        self.hash2issuer = {}
        self.httpc = httpc

        if not httpc_params:
            self.httpc_params = {"verify": verify_ssl}
        else:
            self.httpc_params = httpc_params

        if not self.keyjar.httpc_params:
            self.keyjar.httpc_params = self.httpc_params

        self.upstream_get = kwargs.get("upstream_get", None)

    def state2issuer(self, state):
        """
        Given the state value find the Issuer ID of the OP/AS that state value
        was used against.
        Will raise a KeyError if the state is unknown.

        :param state: The state value
        :return: An Issuer ID
        """
        for _rp in self.issuer2rp.values():
            try:
                _set = _rp.get_context().cstate.get_set(state, claim=["iss"])
            except KeyError:
                continue

            _iss = _set.get("iss")
            if _iss:
                return _iss
        return None

    def pick_config(self, issuer):
        """
        From the set of client configurations pick one based on the issuer ID.
        Will raise a KeyError if issuer is unknown.

        :param issuer: Issuer ID
        :return: A client configuration
        """
        return self.client_configs[issuer]

    def get_session_information(self, key, client=None):
        """
        This is the second of the methods users of this class should know about.
        It will return the complete session information as an
        :py:class:`idpyoidc.client.current.Current` instance.

        :param key: The session key (state)
        :return: A State instance
        """
        if not client:
            client = self.get_client_from_session_key(key)

        return client.get_session_information(key)

    def init_client(self, issuer):
        """
        Initiate a Client instance. Specifically which Client class is used
        is decided by configuration.

        :param issuer: An issuer ID
        :return: A Client instance
        """

        logger.debug(20 * "*" + " init_client " + 20 * "*")

        try:
            _cnf = self.pick_config(issuer)
        except KeyError:
            _cnf = self.pick_config("")
            _cnf["issuer"] = issuer

        try:
            _services = _cnf["services"]
        except KeyError:
            _services = self.services

        if "base_url" not in _cnf:
            _cnf["base_url"] = self.base_url

        if self.jwks_uri:
            _cnf["jwks_uri"] = self.jwks_uri

        logger.debug(f"config: {_cnf}")
        try:
            client = self.client_cls(
                services=_services,
                config=_cnf,
                httpc=self.httpc,
                httpc_params=self.httpc_params,
                upstream_get=self.upstream_get
            )
        except Exception as err:
            logger.error("Failed initiating client: {}".format(err))
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            raise

        _context = client.get_context()
        if _context.iss_hash:
            self.hash2issuer[_context.iss_hash] = issuer
        # If non persistent
        _keyjar = client.keyjar
        if not _keyjar:
            _keyjar = KeyJar()
            _keyjar.httpc_params.update(self.httpc_params)

        for iss in self.keyjar.owners():
            _keyjar.import_jwks(self.keyjar.export_jwks(issuer_id=iss, private=True), iss)

        client.keyjar = _keyjar
        # If persistent nothing has to be copied

        _context.base_url = self.base_url
        _context.jwks_uri = self.jwks_uri
        return client

    def do_provider_info(
            self,
            client: Optional[Client] = None,
            state: Optional[str] = "",
            behaviour_args: Optional[dict] = None,
    ) -> str:
        """
        Either get the provider info from configuration or through dynamic
        discovery.

        :param behaviour_args:
        :param client: A Client instance
        :param state: A key by which the state of the session can be
            retrieved
        :return: issuer ID
        """
        if not client:
            if state:
                client = self.get_client_from_session_key(state)
            else:
                raise ValueError("Missing state/session key")

        return client.do_provider_info(behaviour_args=behaviour_args)

    def do_client_registration(
            self,
            client=None,
            iss_id: Optional[str] = "",
            state: Optional[str] = "",
            request_args: Optional[dict] = None,
            behaviour_args: Optional[dict] = None,
    ):
        """
        Prepare for and do client registration if configured to do so

        :param iss_id: Issuer ID
        :param behaviour_args: To fine tune behaviour
        :param client: A Client instance
        :param state: A key by which the state of the session can be
            retrieved
        """

        if not client:
            if state:
                client = self.get_client_from_session_key(state)
            else:
                raise ValueError("Missing state/session key")

        _context = client.get_context()
        _iss = _context.get("issuer")
        self.hash2issuer[iss_id] = _iss

        return client.do_client_registration(
            request_args=request_args, behaviour_args=behaviour_args
        )

    def do_webfinger(self, user: str) -> Client:
        """
        Does OpenID Provider Issuer discovery using webfinger.

        :param user: Identifier for the target End-User that is the subject of the discovery
            request.
        :return: A Client instance
        """

        logger.debug(20 * "*" + " do_webfinger " + 20 * "*")

        temporary_client = self.init_client("")
        temporary_client.do_request("webfinger", resource=user)
        return temporary_client

    def client_setup(
            self,
            iss_id: Optional[str] = "",
            user: Optional[str] = "",
            behaviour_args: Optional[dict] = None,
    ) -> StandAloneClient:
        """
        First if no issuer ID is given then the identifier for the user is
        used by the webfinger service to try to find the issuer ID.
        Once the method has an issuer ID if no client is bound to this issuer
        one is created and initiated with
        the necessary information for the client to be able to communicate
        with the OP/AS that has the provided issuer ID.

        :param behaviour_args: To fine tune behaviour
        :param iss_id: The issuer ID
        :param user: A user identifier
        :return: A :py:class:`idpyoidc.client.oidc.Client` instance
        """

        logger.debug(20 * "*" + " client_setup " + 20 * "*")

        logger.info("client_setup: iss_id={}, user={}".format(iss_id, user))

        if not iss_id:
            if not user:
                raise ValueError("Need issuer or user")

            logger.debug("Connecting to previously unknown OP")
            temporary_client = self.do_webfinger(user)
        else:
            temporary_client = None

        try:
            client = self.issuer2rp[iss_id]
        except KeyError:
            if temporary_client:
                client = temporary_client
            else:
                logger.debug("Creating new client: %s", iss_id)
                client = self.init_client(iss_id)
        else:
            return client

        logger.debug("Get provider info")
        issuer = client.do_provider_info(behaviour_args=behaviour_args)

        logger.debug("Do client registration")
        client.do_client_registration(behaviour_args=behaviour_args)

        self.issuer2rp[issuer] = client
        return client

    def _get_response_type(self, context, req_args: Optional[dict] = None):
        if req_args:
            return req_args.get("response_type", context.claims.get_usage("response_types")[0])
        else:
            return context.claims.get_usage("response_types")[0]

    def init_authorization(
            self,
            client: Optional[Client] = None,
            state: Optional[str] = "",
            req_args: Optional[dict] = None,
            behaviour_args: Optional[dict] = None,
    ) -> str:
        """
        Constructs the URL that will redirect the user to the authorization
        endpoint of the OP/AS.

        :param behaviour_args:
        :param state:
        :param client: A Client instance
        :param req_args: Non-default Request arguments
        :return: A dictionary with 2 keys: **url** The authorization redirect
            URL and **state** the key to the session information in the
            state data store.
        """

        logger.debug(20 * "*" + " init_authorization " + 20 * "*")
        if not client:
            if state:
                client = self.get_client_from_session_key(state)
            else:
                raise ValueError("Missing state/session key")

        return client.init_authorization(req_args=req_args, behaviour_args=behaviour_args)

    def begin(self, issuer_id="", user_id="", req_args=None, behaviour_args=None):
        """
        This is the first of the 3 high level methods that most users of this
        library should confine them self to use.
        It will use client_setup to produce a Client instance ready to be used
        against the OP/AS the user wants to use.
        Once it has the client it will construct an Authorization
        request.

        :param behaviour_args:
        :param req_args:
        :param issuer_id: Issuer ID
        :param user_id: A user identifier
        :return: A dictionary containing **url** the URL that will redirect the
            user to the OP/AS and **state** the session key which will
            allow higher level code to access session information.
        """

        # Get the client instance that has been assigned to this issuer
        client = self.client_setup(issuer_id, user_id, behaviour_args=behaviour_args)

        try:
            res = client.init_authorization(req_args=req_args, behaviour_args=behaviour_args)
        except Exception:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            raise
        else:
            return res

    # ----------------------------------------------------------------------

    def get_client_from_session_key(self, state):
        return self.issuer2rp[self.state2issuer(state)]

    @staticmethod
    def get_response_type(client):
        """
        Return the response_type a specific client wants to use.

        :param client: A Client instance
        :return: The response_type
        """
        return client.service_context.claims.get_usage("response_types")[0]

    @staticmethod
    def get_client_authn_method(client, endpoint):
        """
        Return the client authentication method a client wants to use a
        specific endpoint

        :param client: A Client instance
        :param endpoint: The endpoint at which the client has to authenticate
        :return: The client authentication method
        """
        if endpoint == "token_endpoint":
            am = client.get_context().get_usage("token_endpoint_auth_method")
            if not am:
                return ""
            else:
                if isinstance(am, str):
                    return am
                else:  # a list
                    return am[0]

    def get_tokens(self, state, client: Optional[Client] = None):
        """
        Use the 'accesstoken' service to get an access token from the OP/AS.

        :param state: The state key (the state parameter in the
            authorization request)
        :param client: A Client instance
        :return: A :py:class:`idpyoidc.message.oidc.AccessTokenResponse` or
            :py:class:`idpyoidc.message.oauth2.AuthorizationResponse`
        """
        if client is None:
            client = self.get_client_from_session_key(state)

        return client.get_tokens(state)

    def refresh_access_token(self, state, client=None, scope=""):
        """
        Refresh an access token using a refresh_token. When asking for a new
        access token the RP can ask for another scope for the new token.

        :param client: A Client instance
        :param state: The state key (the state parameter in the
            authorization request)
        :param scope: What the returned token should be valid for.
        :return: A :py:class:`idpyoidc.message.oidc.AccessTokenResponse` instance
        """

        if client is None:
            client = self.get_client_from_session_key(state)

        return client.refresh_access_token(state, scope="")

    def get_user_info(self, state, client=None, access_token="", **kwargs):
        """
        use the access token previously acquired to get some userinfo

        :param client: A Client instance
        :param state: The state value, this is the key into the session
            data store
        :param access_token: An access token
        :param kwargs: Extra keyword arguments
        :return: A :py:class:`idpyoidc.message.oidc.OpenIDSchema` instance
        """

        if client is None:
            client = self.get_client_from_session_key(state)

        return client.get_user_info(state, access_token=access_token, **kwargs)

    @staticmethod
    def userinfo_in_id_token(id_token: Message, user_info_claims: Optional[List] = None) -> dict:
        """
        Given a verified ID token return all the claims that may be user
        information.

        :param id_token: An :py:class:`idpyoidc.message.oidc.IDToken` instance
        :return: A dictionary with user information
        """
        return StandAloneClient.userinfo_in_id_token(id_token, user_info_claims)

    def finalize_auth(
            self, client, issuer: str, response: dict, behaviour_args: Optional[dict] = None
    ):
        """
        Given the response returned to the redirect_uri, parse and verify it.

        :param behaviour_args: For fine tuning behaviour
        :param client: A Client instance
        :param issuer: An Issuer ID
        :param response: The authorization response as a dictionary
        :return: An :py:class:`idpyoidc.message.oidc.AuthorizationResponse` or
            :py:class:`idpyoidc.message.oauth2.AuthorizationResponse` instance.
        """

        if not client:
            client = self.issuer2rp[issuer]

        return client.finalize_auth(response, behaviour_args=behaviour_args)

    def get_access_and_id_token(
            self,
            authorization_response=None,
            state: Optional[str] = "",
            client: Optional[object] = None,
            behaviour_args: Optional[dict] = None,
    ):
        """
        There are a number of services where access tokens and ID tokens can
        occur in the response. This method goes through the possible places
        based on the response_type the client uses.

        :param behaviour_args: For fine tuning behaviour
        :param authorization_response: The Authorization response
        :param state: The state key (the state parameter in the
            authorization request)
        :return: A dictionary with 2 keys: **access_token** with the access
            token as value and **id_token** with a verified ID Token if one
            was returned otherwise None.
        """

        if client is None:
            client = self.get_client_from_session_key(state)

        return client.get_access_and_id_token(
            authorization_response=authorization_response,
            state=state,
            behaviour_args=behaviour_args,
        )

    # noinspection PyUnusedLocal
    def finalize(self, issuer, response, behaviour_args: Optional[dict] = None):
        """
        The third of the high level methods that a user of this Class should
        know about.
        Once the consumer has redirected the user back to the
        callback URL there might be a number of services that the client should
        use. Which one those are defined by the client configuration.

        :param behaviour_args: For finetuning
        :param issuer: Who sent the response
        :param response: The Authorization response as a dictionary
        :returns: A dictionary with two claims:
            **state** The key under which the session information is
            stored in the data store and
            **error** and encountered error or
            **userinfo** The collected user information
        """

        client = self.issuer2rp[issuer]

        return client.finalize(response, behaviour_args)

    def has_active_authentication(self, state):
        """
        Find out if the user has an active authentication

        :param state:
        :return: True/False
        """

        client = self.get_client_from_session_key(state)
        return client.has_active_authentication(state)

    def get_valid_access_token(self, state):
        """
        Find a valid access token.

        :param state:
        :return: An access token if a valid one exists and when it
            expires. Other wise raise exception.
        """

        client = self.get_client_from_session_key(state)
        return client.get_valid_access_token(state)

    def logout(
            self,
            state: str,
            client: Optional[Client] = None,
            post_logout_redirect_uri: Optional[str] = "",
    ) -> dict:
        """
        Does an RP initiated logout from an OP. After logout the user will be
        redirected by the OP to a URL of choice (post_logout_redirect_uri).

        :param state: Key to an active session
        :param client: Which client to use
        :param post_logout_redirect_uri: If a special post_logout_redirect_uri
            should be used
        :return: Request arguments
        """

        if client is None:
            client = self.get_client_from_session_key(state)

        return client.logout(state, post_logout_redirect_uri=post_logout_redirect_uri)

    def close(
            self, state: str, issuer: Optional[str] = "", post_logout_redirect_uri: Optional[str] = ""
    ) -> dict:

        if issuer:
            client = self.issuer2rp[issuer]
        else:
            client = self.get_client_from_session_key(state)

        return client.logout(state=state, post_logout_redirect_uri=post_logout_redirect_uri)

    def clear_session(self, state):
        client = self.get_client_from_session_key(state)
        client.get_context().cstate.remove_state(state)
