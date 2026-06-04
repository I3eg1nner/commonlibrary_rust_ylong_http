// Copyright (c) 2023 Huawei Device Co., Ltd.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::io::{Read, Write};

use ylong_http::request::uri::Uri;

use crate::util::config::ConnectorConfig;

/// `Connector` trait used by `Client`. `Connector` provides synchronous
/// connection establishment interfaces.
pub trait Connector {
    /// The connection object established by `Connector::connect`.
    type Stream: Read + Write + 'static;
    /// Possible errors during connection establishment.
    type Error: Into<Box<dyn std::error::Error + Send + Sync>>;

    /// Attempts to establish a synchronous connection.
    fn connect(&self, uri: &Uri) -> Result<Self::Stream, Self::Error>;
}

/// Connector for creating HTTP connections synchronously.
///
/// `HttpConnector` implements `sync_impl::Connector` trait.
pub struct HttpConnector {
    config: ConnectorConfig,
}

impl HttpConnector {
    /// Creates a new `HttpConnector`.
    pub(crate) fn new(config: ConnectorConfig) -> HttpConnector {
        HttpConnector { config }
    }
}

impl Default for HttpConnector {
    fn default() -> Self {
        Self::new(ConnectorConfig::default())
    }
}

#[cfg(not(feature = "__tls"))]
pub mod no_tls {
    use std::io::Error;
    use std::net::TcpStream;

    use ylong_http::request::uri::Uri;

    use crate::sync_impl::Connector;

    impl Connector for super::HttpConnector {
        type Stream = TcpStream;
        type Error = Error;

        fn connect(&self, uri: &Uri) -> Result<Self::Stream, Self::Error> {
            let addr = if let Some(proxy) = self.config.proxies.match_proxy(uri) {
                proxy.via_proxy(uri).authority().unwrap().to_string()
            } else {
                uri.authority().unwrap().to_string()
            };
            TcpStream::connect(addr)
        }
    }
}

#[cfg(feature = "__tls")]
pub mod tls_conn {
    use std::net::TcpStream;

    use ylong_http::request::uri::{Scheme, Uri};

    use crate::sync_impl::proxy::{HttpProxyTunnel, HttpsProxyTunnel, ProxyTunnel, TunnelConnect};
    use crate::sync_impl::{Connector, MixStream};
    use crate::util::c_openssl::adapter::TlsConfig;
    use crate::{ErrorKind, HttpClientError};

    /// Describes the proxy hop for an HTTPS origin connection.
    enum ProxyKind {
        /// No proxy; connect directly to the origin.
        Direct,
        /// Plaintext (HTTP) proxy.
        Http,
        /// TLS-secured (HTTPS) proxy.
        Https {
            config: TlsConfig,
            proxy_host: String,
        },
    }

    impl Connector for super::HttpConnector {
        type Stream = MixStream<ProxyTunnel>;
        type Error = HttpClientError;

        fn connect(&self, uri: &Uri) -> Result<Self::Stream, Self::Error> {
            // Make sure all parts of uri is accurate.
            let mut addr = uri.authority().unwrap().to_string();
            let host = uri.host().unwrap().as_str().to_string();
            let port = uri.port().unwrap().as_u16().unwrap();
            let mut auth = None;
            let mut proxy_kind = ProxyKind::Direct;

            if let Some(proxy) = self.config.proxies.match_proxy(uri) {
                addr = proxy.via_proxy(uri).authority().unwrap().to_string();
                let info = proxy.intercept.proxy_info();
                auth = info.basic_auth.as_ref().and_then(|v| v.to_string().ok());
                proxy_kind = if info.is_tls() {
                    ProxyKind::Https {
                        config: info.proxy_tls_config(),
                        proxy_host: info.proxy_host(),
                    }
                } else {
                    ProxyKind::Http
                };
            }

            let host_name = match uri.host() {
                Some(host) => host.to_string(),
                None => "no host in uri".to_string(),
            };

            match *uri.scheme().unwrap() {
                Scheme::HTTP => {
                    let tcp = TcpStream::connect(addr)
                        .map_err(|e| HttpClientError::from_error(ErrorKind::Connect, e))?;
                    Ok(MixStream::Http(ProxyTunnel::Plain(tcp)))
                }
                Scheme::HTTPS => {
                    let tcp_stream = TcpStream::connect(addr)
                        .map_err(|e| HttpClientError::from_error(ErrorKind::Connect, e))?;

                    // Establish the transport to the origin: direct, plaintext-proxy
                    // tunnel, or TLS-secured-proxy tunnel (TLS-in-TLS).
                    let transport: ProxyTunnel = match proxy_kind {
                        ProxyKind::Direct => ProxyTunnel::Plain(tcp_stream),
                        ProxyKind::Http => HttpProxyTunnel.tunnel(tcp_stream, &host, port, auth)?,
                        ProxyKind::Https { config, proxy_host } => {
                            HttpsProxyTunnel { config, proxy_host }
                                .tunnel(tcp_stream, &host, port, auth)?
                        }
                    };

                    let tls_ssl = self
                        .config
                        .tls
                        .ssl_new(&host_name)
                        .map_err(|e| HttpClientError::from_error(ErrorKind::Connect, e))?;

                    let stream = tls_ssl
                        .into_inner()
                        .connect(transport)
                        .map_err(|e| HttpClientError::from_error(ErrorKind::Connect, e))?;
                    Ok(MixStream::Https(stream))
                }
            }
        }
    }
}
