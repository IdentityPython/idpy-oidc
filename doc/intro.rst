.. _intro:

*************************
Introduction to IdPy-OIDC
*************************

This package will try to implement all things OAuth2 and OIDC.
Not just the basic standards but also as soon as we can the
extensions that appear on the horizon.

IdpyOIDC implements the following standards:

* `The OAuth 2.0 Authorization Framework <https://tools.ietf.org/html/rfc6749>`_
* `The OAuth 2.0 Authorization Framework: Bearer Token Usage <https://tools.ietf.org/html/rfc6750>`_
* `OpenID Connect Core 1.0 incorporating errata set 1 <https://openid.net/specs/openid-connect-core-1_0.html>`_
* `Web Finger <https://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery>`_
* `OpenID Connect Discovery 1.0 incorporating errata set 1 <https://openid.net/specs/openid-connect-discovery-1_0.html>`_
* `OpenID Connect Dynamic Client Registration 1.0 incorporating errata set 1 <https://openid.net/specs/openid-connect-registration-1_0.html>`_
* `OpenID Connect Session Management 1.0 <https://openid.net/specs/openid-connect-session-1_0.html>`_
* `OpenID Connect Back-Channel Logout 1.0 <https://openid.net/specs/openid-connect-backchannel-1_0.html>`_
* `OpenID Connect Front-Channel Logout 1.0 <https://openid.net/specs/openid-connect-frontchannel-1_0.html>`_
* `OAuth2 Token introspection <https://tools.ietf.org/html/rfc7662>`_
* `OAuth2 Token exchange <https://datatracker.ietf.org/doc/html/rfc8693>`_
* `OAuth2 Resource Indicators <https://datatracker.ietf.org/doc/rfc8707/>`_
* `The OAuth 2.0 Authorization Framework: JWT-Secured Authorization Request (JAR) <https://datatracker.ietf.org/doc/html/rfc9101>`_

It also comes with the following `add_on` modules.

* Custom scopes, that extends `[OIDC standard ScopeClaims] <https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims>`_
* `Proof Key for Code Exchange by OAuth Public Clients (PKCE) <https://tools.ietf.org/html/rfc7636>`_
* `OAuth2 PAR <https://datatracker.ietf.org/doc/html/rfc9126>`_
* `OAuth2 RAR <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rar>`_
* `OAuth2 DPoP <https://tools.ietf.org/id/draft-fett-oauth-dpop-04.html>`_

The entire project code is open sourced and therefore licensed
under the `Apache 2.0 <https://en.wikipedia.org/wiki/Apache_License>`_.
