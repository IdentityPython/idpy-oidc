# Claims

This is where claims that specifies how the instance should behave is kept.

The claims are calculated based on:
* preferences noted in the configuration
* what the instance supports (depends on which services are included, possible addon ...)
* If dynamic provider information discovery is used then that is added to the mix and lastly
* If dynamic client registration is used, then the registration response is also used.

What the package supports are expressed in idpyoidc.client.claims.Claims, in loaded service instances and possible add ons.

The claims names are the ones defined in [discovery](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata)

Added to this are the following:

* request_uris - whether a request uri should be used or not
* request_parameter - whether the request patameter should be used
* encrypt\_request_object\_supported - if the request object should be encrypted