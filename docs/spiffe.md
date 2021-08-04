# Keyhouse SPIFFE Integration

## Required SPIFFE ID Schema

Keyhouse requires all SPIFFE ids to be of the form:
```
spiffe://<trust-domain>(/<key>:<value>)*
```

This is used to support powerful and cheap indexing on SPIFFE ID matchers, and also set a standard for identity matching.

## Outgoing Connections

Keyhouse supports outgoing SPIFFE authorized mTLS to:
* ETCD/other backend stores
* Implementation-defined services (i.e. a master key host)

It uses the internal identity for outgoing connections, which *may* or *may not* be the same as the primary identity.

## Incoming connections

Keyhouses uses SPIFFE bundles to authenticate and SPIFFE IDs to authorize requests. SPIFFE identity is integral to how Keyhouse represents authorization.

The control plane can be configured to use TLS, in which case it accepts clients with a SPIFFE-sourced bundle.

The data plane always uses TLS, and will always use a SPIFFE-sourced bundle to accept clients.
If an alternate authentication mode is defined, then the client->server certificate requirement is relaxed, and each gRPC call MUST have a string based token to authenticate with, which *may* be a SPIFFE JWT token.
