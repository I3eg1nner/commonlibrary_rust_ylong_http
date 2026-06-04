## ADDED Requirements

### Requirement: Establish TLS session to proxy server

The client SHALL support proxy servers that require a TLS-secured connection ("HTTPS proxy"). When a request is routed through a proxy configured as TLS-secured, the client MUST complete a TLS handshake with the proxy server before sending any proxy request line, headers, or credentials.

#### Scenario: TLS handshake with HTTPS proxy precedes CONNECT

- **WHEN** a request targets an HTTPS origin and is routed through a TLS-secured proxy
- **THEN** the client establishes a TCP connection to the proxy, completes a TLS handshake with the proxy using the proxy TLS configuration, and only afterwards transmits the `CONNECT` request and any proxy credentials over the encrypted channel

#### Scenario: Proxy credentials are not sent in plaintext

- **WHEN** the proxy is TLS-secured and basic-auth credentials are configured
- **THEN** the `Proxy-Authorization` header is transmitted only inside the TLS session to the proxy and never over an unencrypted socket

### Requirement: Tunnel target TLS over the proxy TLS session (TLS-in-TLS)

For an HTTPS origin reached through a TLS-secured proxy, after the `CONNECT` tunnel is accepted the client SHALL perform the origin-server TLS handshake nested inside the established proxy TLS session.

#### Scenario: Nested TLS to origin after successful CONNECT

- **WHEN** the proxy returns `200` to the `CONNECT` request over the proxy TLS session
- **THEN** the client performs the origin-server TLS handshake over that same proxy TLS stream and uses the resulting nested TLS stream for the HTTP exchange with the origin

#### Scenario: CONNECT rejected by HTTPS proxy

- **WHEN** the proxy returns a non-`200` status (e.g. `407 Proxy Authentication Required`) to the `CONNECT` request over the proxy TLS session
- **THEN** the client surfaces a connection error that identifies it as a proxy/tunnel failure and does not attempt the origin TLS handshake

### Requirement: HTTPS proxy support in async and sync clients

Both the asynchronous and synchronous client implementations SHALL support the TLS-secured proxy connection flow.

#### Scenario: Async client through HTTPS proxy

- **WHEN** the asynchronous client is configured with a TLS-secured proxy and makes an HTTPS request
- **THEN** the request completes successfully through the proxy TLS-in-TLS path

#### Scenario: Sync client through HTTPS proxy

- **WHEN** the synchronous client is configured with a TLS-secured proxy and makes an HTTPS request
- **THEN** the request completes successfully through the proxy TLS-in-TLS path

### Requirement: HTTPS proxy gated behind TLS feature

TLS-secured proxy capability SHALL be available only when the TLS feature (`__tls`) is enabled, and the existing plaintext HTTP proxy behavior MUST remain functional when TLS is disabled.

#### Scenario: TLS feature disabled

- **WHEN** the crate is built without the TLS feature
- **THEN** plaintext HTTP proxy support continues to work and the HTTPS-proxy configuration API is not compiled in

### Requirement: Existing proxy behavior preserved

Introducing HTTPS proxy support MUST NOT change the behavior of existing plaintext HTTP proxy connections or direct (non-proxied) HTTPS connections.

#### Scenario: Plaintext HTTP proxy unchanged

- **WHEN** a proxy is configured without TLS (the existing behavior)
- **THEN** the client connects to the proxy over plaintext TCP and tunnels exactly as before this change
