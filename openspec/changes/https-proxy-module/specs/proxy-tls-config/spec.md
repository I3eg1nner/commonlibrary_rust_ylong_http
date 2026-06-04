## ADDED Requirements

### Requirement: Configure proxy-server TLS independently of origin TLS

The public client/proxy builder API SHALL allow configuring TLS settings that apply specifically to the proxy connection, independent of the TLS settings used for the origin server.

#### Scenario: Proxy TLS distinct from origin TLS

- **WHEN** a user sets a proxy TLS configuration and a separate origin TLS configuration on the client builder
- **THEN** the proxy handshake uses the proxy TLS configuration and the origin handshake uses the origin TLS configuration, with neither overriding the other

#### Scenario: Additive builder API

- **WHEN** a user upgrades to this version without adding any proxy TLS configuration
- **THEN** existing builder code continues to compile and behave unchanged (the new methods are additive)

### Requirement: One-way proxy certificate verification

The client SHALL support one-way verification of the proxy server's certificate, allowing the user to supply CA root certificates used to validate the proxy server.

#### Scenario: Trusted proxy certificate accepted

- **WHEN** the proxy presents a certificate chaining to a configured/trusted CA
- **THEN** the proxy TLS handshake succeeds

#### Scenario: Untrusted proxy certificate rejected

- **WHEN** the proxy presents a certificate that does not chain to any trusted CA and invalid certs are not explicitly accepted
- **THEN** the proxy TLS handshake fails with a certificate verification error

### Requirement: Two-way (mutual) proxy certificate verification

The client SHALL support mutual TLS to the proxy by presenting a client certificate and private key when the proxy requests client authentication.

#### Scenario: Client certificate presented to proxy

- **WHEN** a client certificate and matching private key are configured for the proxy and the proxy requests client authentication
- **THEN** the client presents the configured certificate and the mutual TLS handshake completes

#### Scenario: Missing client certificate for mTLS proxy

- **WHEN** the proxy requires client authentication but no client certificate is configured for the proxy
- **THEN** the proxy TLS handshake fails and the error indicates the proxy connection could not be established

### Requirement: Proxy TLS protocol and cipher configuration

The proxy TLS configuration SHALL expose controls for minimum/maximum TLS protocol version and cipher suite selection, mirroring the origin TLS configuration surface.

#### Scenario: Restrict proxy TLS version

- **WHEN** a minimum proxy TLS protocol version is configured and the proxy only offers a lower version
- **THEN** the proxy handshake fails due to version mismatch

#### Scenario: Restrict proxy cipher suites

- **WHEN** a cipher suite list is configured for the proxy
- **THEN** the proxy handshake negotiates only from the configured cipher suites

### Requirement: Proxy TLS verification escape hatches and SNI

The proxy TLS configuration SHALL provide explicit controls to accept invalid certificates, accept invalid hostnames, and toggle SNI / hostname verification for the proxy connection, scoped so they do not affect the origin connection.

#### Scenario: Accept invalid proxy certificate when explicitly allowed

- **WHEN** the user explicitly enables accept-invalid-certificates for the proxy
- **THEN** the proxy handshake succeeds even with an otherwise-untrusted proxy certificate, while origin verification remains governed by the origin TLS settings

#### Scenario: SNI controlled per proxy

- **WHEN** SNI is configured for the proxy connection
- **THEN** the proxy handshake sends (or omits) the server name accordingly, independent of the origin SNI behavior
