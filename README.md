<img src="TOS-SERVICE.png" alt="TOS Service Protocol" width="220">

# TOS Service Gateway

This repository implements the stateless public gateway for `tos_service_v1`.
Finalized TOS Network state is the sole authority for Agent and Capability
state. The gateway authenticates transport access and forwards Native actions
and resolution requests; it does not keep a canonical business database or
define alternate trust modes.

The product and protocol specification lives in
[`tosnetwork/tos-service-spec`](https://github.com/tosnetwork/tos-service-spec).

## Runtime surface

- `tos.service.v1.NativeService/SubmitNativeAction` requires the
  `TOS_SERVICE_RELAY_TOKEN`.
- `tos.service.v1.NativeService/ResolveNativeState` accepts the read or relay
  token.
- `tos.service.v1.CapabilityDiscoveryService/ListCapabilities`,
  `SearchCapabilities`, and `GetSoftwareWorkManifest` accept the read or relay
  token.
- `tos.service.v1.CapabilityDiscoveryService/PublishSoftwareWorkManifest`
  requires the relay token.
- `tos.service.v1.CapabilityDiscoveryService/RequestQuoteProposal` accepts a
  read or relay token and proxies only a provider-supplied complete-preimage
  package. The gateway validates the non-canonical proposal but cannot accept
  terms for the buyer.
- `GET /livez` reports process liveness.
- `GET /readyz` verifies that the authoritative `tos-service-protocol` boundary is
  reachable.

These tokens grant transport permissions only. They cannot create or change
canonical state without a valid signed Native action accepted by TOS.

## Run locally

The module uses Go 1.26.5. Start a configured Native-only `tos-service-protocol` RPC
server, then run:

```bash
export TOS_SERVICE_READ_TOKEN='<read-token>'
export TOS_SERVICE_RELAY_TOKEN='<distinct-relay-token>'
export TOS_SERVICE_ADDR='127.0.0.1:8080' # loopback backend behind the TLS terminator
export TOS_SERVICE_PUBLIC_BASE_URL='https://gateway.example'
export TOS_SERVICE_TOS_RPC_URL='http://127.0.0.1:8090'
export TOS_SERVICE_TOS_RPC_TOKEN='<private-backend-token>'
export TOS_SERVICE_TOS_RPC_INSECURE=true
install -d -m 0700 /absolute/private/catalog
export TOS_SERVICE_CAPABILITY_CATALOG_DIRECTORY='/absolute/private/catalog'
export TOS_SERVICE_NETWORK_ID='<network-id>'
export TOS_SERVICE_GENESIS_ROOT_HASH='sha256:<64 lowercase hex>'
export TOS_SERVICE_GENESIS_FILE_HASH='sha256:<64 lowercase hex>'
export TOS_SERVICE_REGISTRY_CODE_HASH='tvm-cell-sha256:<64 lowercase hex>'
# Optional: enables provider Quote construction. Both this profile and its
# manifest_cbor_file must be owner-owned regular files with mode 0600.
export TOS_SERVICE_PROVIDER_QUOTE_PROFILE_FILE='/absolute/private/provider/quote-profile.json'

GOWORK=off go run ./cmd/api
```

The Quote profile schema is illustrated in
[`docs/provider-quote-profile.example.json`](docs/provider-quote-profile.example.json).
It binds the provider Agent/address, exact TOS-network stablecoin identity,
atomic price, transport policy, canonical manifest file, and bounded timing.
Every request re-resolves the Capability from finalized Native state before a
proposal is returned.

Plaintext backend RPC is rejected unless `TOS_SERVICE_TOS_RPC_INSECURE=true`. Use
HTTPS outside local development. Optional TLS settings are:

```text
TOS_SERVICE_TOS_RPC_SERVER_NAME
TOS_SERVICE_TOS_RPC_CA_FILE
TOS_SERVICE_TOS_RPC_CLIENT_CERT_FILE
TOS_SERVICE_TOS_RPC_CLIENT_KEY_FILE
TOS_SERVICE_TOS_RPC_TIMEOUT
TOS_SERVICE_TOS_RPC_MAX_MESSAGE_BYTES
TOS_SERVICE_CAPABILITY_CATALOG_MAX_ENTRIES
```

Client certificate and key must be configured together. Startup and readiness
fail closed when `tos-service-protocol` is unavailable; there is no mock or Managed
fallback.

Capability discovery is derived and explicitly incomplete. The gateway keeps
only bounded discovery IDs, immutable canonical manifest bytes, and rollback
fences in the owner-private catalog directory. Every listed Capability is
freshly resolved from finalized TOS state. Clients must compare a retrieved
manifest digest with that fresh state or an Accepted Quote; catalog inclusion,
ordering, and availability have no semantic authority.

Search scans that same bounded local set in Capability-ID order. Each result
keeps the freshly finalized Capability/version/digest separate from the
`gateway_local` name, description, operation, and match score. Those local
fields are digest-authenticated manifest projections for discovery only; they
are not chain state or consensus ranking.

## Repository layout

```text
cmd/api/                              Native gateway process
internal/adapters/serviceprotocol/        private Native Connect client
internal/config/                      Native-only configuration
internal/nativegateway/               transport auth and pass-through service
```

Run the test suite with:

```bash
GOWORK=off go test ./...
```
