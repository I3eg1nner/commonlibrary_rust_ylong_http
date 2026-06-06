// Copyright (c) 2024 Huawei Device Co., Ltd.
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

//! Client-side TLS session resumption support.
//!
//! Repeated TLS connections to the same host (as performed by the HTTPS-proxy
//! path for both the proxy hop and the origin hop) would otherwise each run a
//! full TLS handshake. libcurl resumes TLS sessions by default, giving it a
//! large advantage on cold-connection workloads. This module restores parity by
//! caching `SSL_SESSION`s keyed by host and offering them back to new `SSL`
//! objects before the handshake, enabling an abbreviated handshake.
//!
//! ## Mechanism
//!
//! 1. The owning `SSL_CTX` enables client-side session caching
//!    (`SSL_SESS_CACHE_CLIENT`) and registers a "new session" callback
//!    (`SSL_CTX_sess_set_new_cb`).
//! 2. When OpenSSL establishes a session (including each TLS 1.3 ticket), it
//!    invokes [`new_session_cb`]. The callback recovers the SNI host name from
//!    the `SSL` (via `SSL_get_servername`) and the owning `SSL_CTX` (via
//!    `SSL_get_SSL_CTX`) and stores the session in a global cache keyed by
//!    `(SSL_CTX pointer, host)`.
//! 3. Before each new handshake, `TlsConfig::ssl_new` (in `adapter.rs`, via
//!    `SslRef::try_resume_session`) calls [`try_set_cached_session`], which
//!    looks up a stored session for the same `(SSL_CTX, host)` key and, if
//!    present, hands it to the `SSL` via `SSL_set_session`.
//!
//! ## Why a single global cache (rather than per-`SslContext`)
//!
//! The new-session callback signature `(SSL*, SSL_SESSION*) -> int` carries no
//! user-data argument, so associating a per-context cache would require
//! threading the cache pointer through `SSL_CTX` ex-data — and the ex-data
//! index machinery (`SSL_CTX_get_ex_new_index`) is a version-fragile macro that
//! is not consistently exported. A process-wide map avoids all of that.
//!
//! ## Why this is safe across differing verification policies
//!
//! On a *resumed* handshake OpenSSL does NOT re-run certificate-chain
//! verification, the custom cert-verify callback, or hostname checks. A process
//! holds multiple `SSL_CTX`/`TlsConfig` with different policies, so a session
//! cached by a relaxed context must never be resumed by a stricter one for the
//! same host. Two measures prevent that:
//!
//! - The cache key is `(SSL_CTX pointer, host)`, not just `host`. Each
//!   `TlsConfig` owns a distinct `SSL_CTX`, so sessions are partitioned per
//!   context and can only ever be resumed by the exact context that cached
//!   them.
//! - Resumption is only enabled at all on contexts that use *standard*
//!   verification: `TlsConfigBuilder::build` (in `adapter.rs`) registers the
//!   cache mode and this callback only when the config has no custom cert
//!   verifier and no public-key pins. Pinning validates the peer chain, which
//!   is absent on resumption (so it must fail closed by never resuming), and a
//!   custom verifier is per-connection and would otherwise be skipped.
//!
//! ## Reference-count handling
//!
//! `SSL_SESSION` is reference-counted. We are careful to balance every
//! reference:
//! - In the callback we **return 1**, meaning we have taken ownership of the
//!   reference OpenSSL passed us; we therefore do NOT additionally up-ref and we
//!   ARE responsible for eventually calling `SSL_SESSION_free` (done by
//!   [`Session`]'s `Drop`, on eviction/replacement).
//! - `SSL_set_session` does not consume the reference we hold (it takes its own
//!   internal reference), so we keep our cached copy intact.
//! - `SSL_get1_session` (unused here, but available) would hand back an
//!   already-incremented reference.

#[cfg(feature = "__tls")]
use std::collections::HashMap;
#[cfg(feature = "__tls")]
use std::ffi::c_int;
#[cfg(feature = "__tls")]
use std::ffi::CStr;
#[cfg(feature = "__tls")]
use std::sync::{Mutex, OnceLock};

#[cfg(feature = "__tls")]
use crate::util::c_openssl::ffi::ssl::{
    SSL_SESSION, SSL_SESSION_free, SSL_get_SSL_CTX, SSL_get_servername, SSL_set_session, SSL,
};

/// `TLSEXT_NAMETYPE_host_name`: selector for the SNI host name in
/// `SSL_get_servername`.
#[cfg(feature = "__tls")]
const TLSEXT_NAMETYPE_HOST_NAME: c_int = 0;

/// An owned reference to an `SSL_SESSION`.
///
/// Wraps a raw `*mut SSL_SESSION` and frees (decrements the refcount of) it on
/// drop. OpenSSL sessions are internally synchronized, so it is sound to move
/// the pointer across threads and to free it from any thread; hence the manual
/// `Send`/`Sync` impls.
#[cfg(feature = "__tls")]
pub(crate) struct Session(*mut SSL_SESSION);

#[cfg(feature = "__tls")]
unsafe impl Send for Session {}
// Access is always mediated by the cache `Mutex`, and OpenSSL ref/free are
// thread-safe, so `Sync` is sound.
#[cfg(feature = "__tls")]
unsafe impl Sync for Session {}

#[cfg(feature = "__tls")]
impl Session {
    /// Wraps an owned (already-referenced) `*mut SSL_SESSION`.
    ///
    /// # Safety
    /// `ptr` must be non-null and the caller must transfer ownership of exactly
    /// one reference count to the returned `Session`.
    unsafe fn from_owned(ptr: *mut SSL_SESSION) -> Self {
        Session(ptr)
    }

    fn as_ptr(&self) -> *mut SSL_SESSION {
        self.0
    }
}

#[cfg(feature = "__tls")]
impl Drop for Session {
    fn drop(&mut self) {
        // Releases the one reference this `Session` owns.
        unsafe { SSL_SESSION_free(self.0) }
    }
}

/// The session-cache key: the owning `SSL_CTX` (as a `usize`) paired with the
/// SNI host name. Keying on the context partitions sessions per `TlsConfig`, so
/// a session cached under one verification policy can never be resumed by a
/// different context for the same host.
#[cfg(feature = "__tls")]
type SessionKey = (usize, String);

/// The process-wide client session cache, keyed by `(SSL_CTX pointer, host)`.
#[cfg(feature = "__tls")]
fn session_cache() -> &'static Mutex<HashMap<SessionKey, Session>> {
    static CACHE: OnceLock<Mutex<HashMap<SessionKey, Session>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The "new session" callback registered on the `SSL_CTX`.
///
/// Invoked by OpenSSL whenever a new session/ticket is established. We take
/// ownership of the passed reference (by returning 1) and store it keyed by the
/// connection's SNI host name. If the host name is unavailable (e.g. an IP-only
/// connection with no SNI) we cannot key it, so we decline the reference
/// (return 0) and let OpenSSL free it.
///
/// # Safety
/// Called by OpenSSL with valid `ssl`/`session` pointers; `session` carries one
/// reference that ownership of which is decided by the return value.
#[cfg(feature = "__tls")]
pub(crate) extern "C" fn new_session_cb(ssl: *mut SSL, session: *mut SSL_SESSION) -> c_int {
    if ssl.is_null() || session.is_null() {
        return 0;
    }

    // Recover the SNI host name set on this connection. On the client side this
    // is the value supplied via the SNI extension in `ssl_new`.
    let host_ptr = unsafe { SSL_get_servername(ssl, TLSEXT_NAMETYPE_HOST_NAME) };
    if host_ptr.is_null() {
        // No host to key by: decline ownership, OpenSSL will free it.
        return 0;
    }

    let host = match unsafe { CStr::from_ptr(host_ptr) }.to_str() {
        Ok(host) if !host.is_empty() => host.to_owned(),
        _ => return 0,
    };

    // Key by the owning `SSL_CTX` as well as the host, so the session can only
    // ever be resumed by the same context (verification policy) that cached it.
    let ctx = unsafe { SSL_get_SSL_CTX(ssl) };
    if ctx.is_null() {
        return 0;
    }
    let key: SessionKey = (ctx as usize, host);

    // Take ownership of the reference OpenSSL handed us (we return 1 below).
    let owned = unsafe { Session::from_owned(session) };

    if let Ok(mut cache) = session_cache().lock() {
        // Inserting replaces any previous session for this key; the displaced
        // `Session` is dropped here, freeing its reference.
        cache.insert(key, owned);
    } else {
        // Poisoned lock: don't leak — `owned` drops and frees the reference.
        // (We still return 1: we consumed the reference, OpenSSL must not.)
    }

    // 1 == we have retained the reference; OpenSSL must not free it.
    1
}

/// Before a handshake, looks up a cached session for `host` and, if present,
/// installs it on `ssl` to attempt an abbreviated (resumption) handshake.
///
/// Returns `true` if a session was installed. Best-effort: any failure simply
/// results in a normal full handshake.
///
/// # Safety
/// `ssl` must be a valid, not-yet-connected `*mut SSL`.
#[cfg(feature = "__tls")]
pub(crate) unsafe fn try_set_cached_session(ssl: *mut SSL, host: &str) -> bool {
    if ssl.is_null() || host.is_empty() {
        return false;
    }

    // Resume only from the entry cached by this same `SSL_CTX`, mirroring the
    // `(SSL_CTX, host)` key used in `new_session_cb`.
    let ctx = SSL_get_SSL_CTX(ssl);
    if ctx.is_null() {
        return false;
    }
    let key: SessionKey = (ctx as usize, host.to_owned());

    let cache = match session_cache().lock() {
        Ok(cache) => cache,
        Err(_) => return false,
    };

    if let Some(session) = cache.get(&key) {
        // `SSL_set_session` takes its own internal reference; it does NOT
        // consume the one held by our cached `Session`, so the cache entry
        // remains valid for future connections.
        return SSL_set_session(ssl, session.as_ptr()) == 1;
    }
    false
}
