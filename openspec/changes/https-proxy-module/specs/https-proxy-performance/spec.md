## ADDED Requirements

### Requirement: Reproducible HTTPS-proxy benchmark harness

The change SHALL provide a reproducible benchmark that exercises the HTTPS-proxy scenario (client → TLS-secured proxy → HTTPS origin) and measures throughput and latency under a documented, fixed configuration.

#### Scenario: Benchmark runs deterministically

- **WHEN** the benchmark is executed against a fixed proxy + origin setup with documented parameters (payload size, concurrency, request count)
- **THEN** it reports throughput and latency metrics for the HTTPS-proxy path in a repeatable manner

#### Scenario: Documented methodology

- **WHEN** a reviewer inspects the benchmark
- **THEN** the configuration (TLS versions, cipher, keep-alive, concurrency, payload, warm-up) and measurement method are documented so results can be reproduced

### Requirement: Performance comparison against libcurl

The benchmark SHALL compare `ylong_http_client` against `libcurl`/`curl` under the same HTTPS-proxy scenario and configuration.

#### Scenario: Side-by-side comparison

- **WHEN** the benchmark runs both `ylong_http_client` and `libcurl` against the identical proxy + origin and workload
- **THEN** it produces comparable metrics for both clients under the same conditions

### Requirement: HTTPS-proxy performance improvement target

In the HTTPS-proxy scenario, `ylong_http_client` SHALL achieve at least a 20% improvement over the measured `libcurl` baseline on the primary metric (throughput or equivalent latency reduction) for the documented configuration.

#### Scenario: Improvement target met

- **WHEN** the benchmark is run after optimization
- **THEN** the primary metric for `ylong_http_client` is at least 20% better than the `libcurl` baseline under the documented configuration

#### Scenario: Improvement target not met

- **WHEN** the measured improvement is below 20%
- **THEN** the result is recorded as not meeting the acceptance criterion, prompting further optimization rather than being reported as passing

### Requirement: No correctness or security regression from optimization

Performance optimizations on the HTTPS-proxy path MUST NOT weaken TLS verification, leak data across connections, or break the functional proxy scenarios.

#### Scenario: Optimizations preserve verification and isolation

- **WHEN** buffer reuse, connection reuse, or other optimizations are applied
- **THEN** proxy and origin certificate verification still behave per the proxy-tls-config requirements and no buffer/state is shared incorrectly across distinct connections
