## ADDED Requirements

### Requirement: Proxy logic decoupled from HTTP connector

Proxy selection, authentication, and tunnel establishment SHALL live in a dedicated proxy module rather than being inlined in the HTTP connector. The connector MUST interact with proxies only through this module's abstraction.

#### Scenario: Connector uses proxy abstraction

- **WHEN** the connector establishes a connection that is routed through a proxy
- **THEN** it delegates proxy selection and tunnel establishment to the proxy module rather than implementing the CONNECT/tunnel logic inline

#### Scenario: Behavior parity after extraction

- **WHEN** the proxy logic is moved into the dedicated module
- **THEN** all existing proxy scenarios (HTTP proxy, HTTPS-target tunneling, basic auth, no-proxy matching) produce the same observable behavior as before extraction

### Requirement: Extensible proxy protocol abstraction

The proxy module SHALL define an abstraction (e.g. a connect/tunnel trait) that allows new proxy protocols to be added without modifying the HTTP connector.

#### Scenario: Add a new proxy protocol

- **WHEN** a developer adds a new proxy scheme by implementing the proxy abstraction
- **THEN** the connector can route through it without changes to the connector's connection-establishment code

#### Scenario: Existing schemes implemented via the abstraction

- **WHEN** the module is in place
- **THEN** the existing plaintext HTTP proxy and the new TLS-secured proxy are both expressed as implementations of the common proxy abstraction

### Requirement: Proxy selection and no-proxy rules preserved

The extracted module SHALL preserve proxy matching by request scheme, the no-proxy exclusion list (including wildcard/domain matching), and proxy basic authentication.

#### Scenario: No-proxy host bypasses proxy

- **WHEN** a request targets a host listed in the no-proxy rules
- **THEN** the proxy module reports no proxy match and the connection is made directly

#### Scenario: Scheme-based proxy matching

- **WHEN** proxies are configured for specific schemes (HTTP-only, HTTPS-only, or all)
- **THEN** the proxy module selects the correct proxy based on the request scheme exactly as the prior implementation did

### Requirement: Proxy module available without TLS

The proxy module SHALL compile and function for plaintext HTTP proxies even when the TLS feature is disabled, with TLS-secured proxy implementations gated behind the TLS feature.

#### Scenario: Module builds without TLS feature

- **WHEN** the crate is built without the TLS feature
- **THEN** the proxy module and its plaintext HTTP proxy implementation compile and work, and the TLS-secured proxy implementation is excluded
