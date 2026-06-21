// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
//
// Redis backend for the rate limiter engine.
//
// Holds a lazily-created multiplexed async Redis connection.
// Fires the same batch Lua scripts as the Python RedisBackend — one call per
// evaluate_many() invocation regardless of dimension count (REDIS-01/03).
// Uses EVALSHA with NOSCRIPT fallback to EVAL (REDIS-02).
//
// Key format: `{prefix}:{dimension_key}:{window_seconds}`
// This preserves the existing Redis counter namespace during rolling upgrades.

use std::cmp::max;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use parking_lot::Mutex;
use redis::aio::MultiplexedConnection;
use tokio::runtime::{Builder, Runtime};
use tokio::time::timeout;

use crate::config::Algorithm;
use crate::types::DimResult;

// ---------------------------------------------------------------------------
// Batch Lua scripts — identical to Python RedisBackend._LUA_BATCH_* constants
// ---------------------------------------------------------------------------

const LUA_BATCH_FIXED: &str = r#"
local results = {}
for i = 1, #KEYS do
    local current = redis.call('INCR', KEYS[i])
    if current == 1 then
        redis.call('EXPIRE', KEYS[i], ARGV[i])
    end
    local ttl = redis.call('TTL', KEYS[i])
    results[i] = {current, ttl}
end
return results
"#;

const LUA_BATCH_SLIDING: &str = r#"
local now = tonumber(ARGV[1])
local results = {}
for i = 1, #KEYS do
    local base = 1 + (i-1)*3 + 1
    local window = tonumber(ARGV[base])
    local limit  = tonumber(ARGV[base+1])
    local member = ARGV[base+2]
    local cutoff = now - window
    redis.call('ZREMRANGEBYSCORE', KEYS[i], '-inf', cutoff)
    local count = tonumber(redis.call('ZCARD', KEYS[i]))
    redis.call('EXPIRE', KEYS[i], window + 1)
    if count >= limit then
        local oldest = redis.call('ZRANGE', KEYS[i], 0, 0, 'WITHSCORES')
        local oldest_ts = 0
        if #oldest > 0 then oldest_ts = tonumber(oldest[2]) end
        results[i] = {0, count, oldest_ts}
    else
        redis.call('ZADD', KEYS[i], now, member)
        count = count + 1
        local oldest = redis.call('ZRANGE', KEYS[i], 0, 0, 'WITHSCORES')
        local oldest_ts = 0
        if #oldest > 0 then oldest_ts = tonumber(oldest[2]) end
        results[i] = {1, count, oldest_ts}
    end
end
return results
"#;

const LUA_BATCH_TOKEN_BUCKET: &str = r#"
local now = tonumber(ARGV[1])
local results = {}
for i = 1, #KEYS do
    local base = 1 + (i-1)*2 + 1
    local capacity = tonumber(ARGV[base])
    local rate = tonumber(ARGV[base+1])
    local data = redis.call('HMGET', KEYS[i], 'tokens', 'last_refill')
    local tokens = tonumber(data[1])
    local last_refill = tonumber(data[2])
    if tokens == nil then
        tokens = capacity - 1
        redis.call('HSET', KEYS[i], 'tokens', tokens, 'last_refill', now)
        local ttl = math.ceil(capacity / rate) + 1
        redis.call('EXPIRE', KEYS[i], ttl)
        results[i] = {1, math.floor(tokens), 0}
    else
        local elapsed = now - last_refill
        tokens = math.min(capacity, tokens + elapsed * rate)
        local allowed, time_to_next
        if tokens >= 1.0 then
            tokens = tokens - 1.0
            allowed = 1
            time_to_next = 0
        else
            allowed = 0
            time_to_next = math.ceil((1.0 - tokens) / rate)
        end
        redis.call('HSET', KEYS[i], 'tokens', tokens, 'last_refill', now)
        local ttl = math.ceil((capacity - tokens) / rate) + 1
        redis.call('EXPIRE', KEYS[i], ttl)
        results[i] = {allowed, math.floor(tokens), time_to_next}
    end
end
return results
"#;

// ---------------------------------------------------------------------------
// Unique member counter for sliding window sorted sets
// ---------------------------------------------------------------------------

static MEMBER_CTR: AtomicU64 = AtomicU64::new(0);

/// Process-unique PID, cached once.  Combined with the per-process atomic
/// counter this guarantees unique sorted-set members across gateway replicas,
/// preventing ZADD overwrites that would cause undercounting.
fn process_id() -> u32 {
    static PID: OnceLock<u32> = OnceLock::new();
    *PID.get_or_init(std::process::id)
}

fn unique_member(now: f64) -> String {
    let n = MEMBER_CTR.fetch_add(1, Ordering::Relaxed);
    format!("{:.9}:{}:{}", now, process_id(), n)
}

// ---------------------------------------------------------------------------
// Value extraction helpers
// ---------------------------------------------------------------------------

fn val_i64(v: &redis::Value) -> i64 {
    match v {
        redis::Value::Int(i) => *i,
        redis::Value::BulkString(b) => std::str::from_utf8(b)
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        _ => 0,
    }
}

fn val_f64(v: &redis::Value) -> f64 {
    match v {
        redis::Value::Int(i) => *i as f64,
        redis::Value::BulkString(b) => std::str::from_utf8(b)
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0.0),
        _ => 0.0,
    }
}

fn inner_array(outer: &redis::Value, i: usize) -> Option<&Vec<redis::Value>> {
    match outer {
        redis::Value::Array(a) => match a.get(i) {
            Some(redis::Value::Array(inner)) => Some(inner),
            _ => None,
        },
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// TLS configuration
// ---------------------------------------------------------------------------

/// TLS configuration knobs for the Redis backend.
///
/// All fields are optional/defaulted so that existing configs (no TLS knobs
/// set) take the unchanged fast path: `Client::open(redis_url)`.
///
/// Validated and materialised into a `redis::Client` at engine init time via
/// `validate_and_build` so misconfigurations surface before the first request.
pub struct RedisTlsConfig {
    /// Path to a PEM CA bundle. Overrides the OS trust store when set.
    /// Requires `rediss://` URL scheme.
    pub ca_certs_path: Option<String>,
    /// Path to a PEM client certificate for mTLS. Must be paired with
    /// `keyfile_path`.
    pub certfile_path: Option<String>,
    /// Path to a PEM private key for mTLS. Must be paired with
    /// `certfile_path`.
    pub keyfile_path: Option<String>,
    /// When `false`, ALL TLS certificate validation is disabled (both CA and
    /// hostname). Emits a WARN at init. Requires `rediss://` URL scheme.
    /// Note: due to the redis crate's public API surface, it is not possible
    /// to disable only hostname checking while keeping CA validation; setting
    /// this to `false` fully disables cert verification.
    pub check_hostname: bool,
}

impl Default for RedisTlsConfig {
    fn default() -> Self {
        Self {
            ca_certs_path: None,
            certfile_path: None,
            keyfile_path: None,
            check_hostname: true,
        }
    }
}

impl RedisTlsConfig {
    /// Validate the config and, if any TLS knob is active, build a
    /// `redis::Client` with the appropriate TLS settings.
    ///
    /// Returns `Ok(None)` when no TLS knobs are set — caller uses
    /// `Client::open(redis_url)` directly (zero behavioral change).
    /// Returns `Ok(Some(client))` on success.
    /// Returns `Err` on any misconfiguration detected at startup.
    pub fn validate_and_build(
        &self,
        redis_url: &str,
    ) -> Result<Option<redis::Client>, redis::RedisError> {
        let has_ca = self.ca_certs_path.is_some();
        let has_cert = self.certfile_path.is_some();
        let has_key = self.keyfile_path.is_some();
        let skip_hostname = !self.check_hostname;

        // Fast path — no TLS knobs active.
        if !has_ca && !has_cert && !has_key && !skip_hostname {
            return Ok(None);
        }

        // All TLS config requires the TLS URL scheme.
        if !redis_url.starts_with("rediss://") {
            return Err(redis::RedisError::from((
                redis::ErrorKind::InvalidClientConfig,
                "redis_ssl_* config keys require the rediss:// URL scheme",
                "update redis_url to start with rediss:// to enable TLS".to_string(),
            )));
        }

        // Validate file paths exist before reading them.
        for (path, key) in [
            (self.ca_certs_path.as_deref(), "redis_ssl_ca_certs"),
            (self.certfile_path.as_deref(), "redis_ssl_certfile"),
            (self.keyfile_path.as_deref(), "redis_ssl_keyfile"),
        ] {
            if let Some(p) = path
                && !std::path::Path::new(p).is_file()
            {
                return Err(redis::RedisError::from((
                    redis::ErrorKind::Io,
                    "TLS config file not found",
                    format!("{key}: file not found: {p:?}"),
                )));
            }
        }

        // mTLS cert and key must appear together.
        match (has_cert, has_key) {
            (true, false) => {
                return Err(redis::RedisError::from((
                    redis::ErrorKind::InvalidClientConfig,
                    "incomplete mTLS configuration",
                    "redis_ssl_certfile requires redis_ssl_keyfile to also be set".to_string(),
                )));
            }
            (false, true) => {
                return Err(redis::RedisError::from((
                    redis::ErrorKind::InvalidClientConfig,
                    "incomplete mTLS configuration",
                    "redis_ssl_keyfile requires redis_ssl_certfile to also be set".to_string(),
                )));
            }
            _ => {}
        }

        // check_hostname=false: build a fully insecure client.  The
        // `tls-rustls-insecure` feature enables `NoCertificateVerification` in
        // the rustls config so the `insecure: true` flag on `ConnectionAddr` is
        // actually honoured at connection time.
        //
        // CA certs are not loaded (cert pinning has no value without server-cert
        // verification).  mTLS client cert/key is still loaded and presented if
        // configured — the caller may need to authenticate even against a server
        // whose cert we don't verify.
        if skip_hostname {
            if has_ca {
                log::warn!(
                    "rate limiter: redis_ssl_check_hostname=false with redis_ssl_ca_certs: \
                     CA certificate is not loaded in insecure mode (all TLS validation \
                     is disabled); redis_ssl_ca_certs is ignored"
                );
            }
            log::warn!(
                "rate limiter: redis_ssl_check_hostname=false — ALL TLS certificate \
                 validation is disabled (server identity is not verified); \
                 use only in isolated environments"
            );

            // Still load and present client cert/key (mTLS) even in insecure mode.
            let client_tls = if let (Some(cert_path), Some(key_path)) =
                (&self.certfile_path, &self.keyfile_path)
            {
                let cert_data = std::fs::read(cert_path).map_err(|e| {
                    redis::RedisError::from((
                        redis::ErrorKind::Io,
                        "failed to read redis_ssl_certfile",
                        format!("{cert_path:?}: {e}"),
                    ))
                })?;
                let key_data = std::fs::read(key_path).map_err(|e| {
                    redis::RedisError::from((
                        redis::ErrorKind::Io,
                        "failed to read redis_ssl_keyfile",
                        format!("{key_path:?}: {e}"),
                    ))
                })?;
                Some(redis::ClientTlsConfig {
                    client_cert: cert_data,
                    client_key: key_data,
                })
            } else {
                None
            };

            use redis::IntoConnectionInfo;
            let conn_info = redis_url.into_connection_info().map_err(|e| {
                redis::RedisError::from((
                    redis::ErrorKind::InvalidClientConfig,
                    "failed to parse redis_url",
                    e.to_string(),
                ))
            })?;
            let new_addr = match conn_info.addr() {
                redis::ConnectionAddr::TcpTls {
                    host,
                    port,
                    tls_params,
                    ..
                } => redis::ConnectionAddr::TcpTls {
                    host: host.clone(),
                    port: *port,
                    insecure: true,
                    tls_params: tls_params.clone(),
                },
                _ => {
                    return Err(redis::RedisError::from((
                        redis::ErrorKind::InvalidClientConfig,
                        "redis_ssl_check_hostname=false requires a rediss:// URL",
                    )));
                }
            };
            let conn_info = conn_info.set_addr(new_addr);
            let client = if let Some(client_tls) = client_tls {
                redis::Client::build_with_tls(
                    conn_info,
                    redis::TlsCertificates {
                        client_tls: Some(client_tls),
                        root_cert: None,
                    },
                )?
            } else {
                redis::Client::open(conn_info)?
            };
            return Ok(Some(client));
        }

        // Standard TLS path: validate + read CA bundle if provided.
        let root_cert = if let Some(ca_path) = &self.ca_certs_path {
            let pem_data = std::fs::read(ca_path).map_err(|e| {
                redis::RedisError::from((
                    redis::ErrorKind::Io,
                    "failed to read redis_ssl_ca_certs",
                    format!("{ca_path:?}: {e}"),
                ))
            })?;
            use rustls_pki_types::pem::PemObject;
            let certs: Result<Vec<rustls_pki_types::CertificateDer<'static>>, _> =
                rustls_pki_types::CertificateDer::pem_slice_iter(&pem_data).collect();
            let certs = certs.map_err(|e| {
                redis::RedisError::from((
                    redis::ErrorKind::Io,
                    "PEM parse error in redis_ssl_ca_certs",
                    format!("{ca_path:?}: {e}"),
                ))
            })?;
            if certs.is_empty() {
                return Err(redis::RedisError::from((
                    redis::ErrorKind::InvalidClientConfig,
                    "no valid certificates found in redis_ssl_ca_certs",
                    format!("{ca_path:?}: file contains no parseable PEM certificates"),
                )));
            }
            Some(pem_data)
        } else {
            None
        };

        // Validate + read mTLS client cert and key if provided.
        let client_tls =
            if let (Some(cert_path), Some(key_path)) = (&self.certfile_path, &self.keyfile_path) {
                let cert_data = std::fs::read(cert_path).map_err(|e| {
                    redis::RedisError::from((
                        redis::ErrorKind::Io,
                        "failed to read redis_ssl_certfile",
                        format!("{cert_path:?}: {e}"),
                    ))
                })?;
                {
                    use rustls_pki_types::pem::PemObject;
                    let certs: Result<Vec<rustls_pki_types::CertificateDer<'static>>, _> =
                        rustls_pki_types::CertificateDer::pem_slice_iter(&cert_data).collect();
                    let certs = certs.map_err(|e| {
                        redis::RedisError::from((
                            redis::ErrorKind::Io,
                            "PEM parse error in redis_ssl_certfile",
                            format!("{cert_path:?}: {e}"),
                        ))
                    })?;
                    if certs.is_empty() {
                        return Err(redis::RedisError::from((
                            redis::ErrorKind::InvalidClientConfig,
                            "no valid certificates found in redis_ssl_certfile",
                            format!("{cert_path:?}: file contains no parseable PEM certificates"),
                        )));
                    }
                }
                let key_data = std::fs::read(key_path).map_err(|e| {
                    redis::RedisError::from((
                        redis::ErrorKind::Io,
                        "failed to read redis_ssl_keyfile",
                        format!("{key_path:?}: {e}"),
                    ))
                })?;
                {
                    use rustls_pki_types::pem::PemObject;
                    rustls_pki_types::PrivateKeyDer::from_pem_slice(&key_data).map_err(|e| {
                        redis::RedisError::from((
                            redis::ErrorKind::InvalidClientConfig,
                            "failed to parse redis_ssl_keyfile",
                            format!(
                                "{key_path:?}: {e} \
                                 (expected PEM-encoded PKCS#8, PKCS#1, or SEC1 private key)"
                            ),
                        ))
                    })?;
                }
                Some(redis::ClientTlsConfig {
                    client_cert: cert_data,
                    client_key: key_data,
                })
            } else {
                None
            };

        use redis::IntoConnectionInfo;
        let conn_info = redis_url.into_connection_info().map_err(|e| {
            redis::RedisError::from((
                redis::ErrorKind::InvalidClientConfig,
                "failed to parse redis_url",
                e.to_string(),
            ))
        })?;
        let client = redis::Client::build_with_tls(
            conn_info,
            redis::TlsCertificates {
                client_tls,
                root_cert,
            },
        )?;
        Ok(Some(client))
    }
}

// ---------------------------------------------------------------------------
// RedisRateLimiter
// ---------------------------------------------------------------------------

/// Per-endpoint state shared by every `RedisRateLimiter` pointing at the same
/// Redis URL: the one multiplexed connection plus the cached Lua script SHA
/// (server-side, so valid for any connection to that server).
///
/// Why share it: the gateway rebuilds its per-`(team, tool)` plugin manager on a
/// short TTL, so a fresh `RedisRateLimiter` is constructed frequently. Without
/// sharing, each one opened its own TLS+AUTH connection, turning a healthy
/// endpoint into a stream of short-lived connects. With sharing, all of them
/// reuse one warm connection — the way the gateway shares a single DB pool.
struct SharedEndpoint {
    conn: Mutex<Option<MultiplexedConnection>>,
    /// Single-flight gate: only one task establishes the connection at a time.
    /// Async mutex so it can be held across the connect `.await`; concurrent
    /// first-callers (cold start, or after a reset on error) wait here and then
    /// reuse the elected task's connection instead of each opening a socket.
    connect_gate: tokio::sync::Mutex<()>,
    /// Live `RedisRateLimiter` instances sharing this endpoint. The connection
    /// is closed when the last one is released (shutdown or drop), so it
    /// survives the gateway's overlapping manager rebuilds but is cleaned up on
    /// real teardown. The registry entry itself is process-lived.
    refs: AtomicUsize,
}

/// Look up (or create) the shared endpoint for a Redis URL.
///
/// The registry keeps each entry for the life of the process (so the gate and
/// refcount are stable), while the connection inside it is opened on first use
/// and closed once the last referencing instance is released. Keyed by the full
/// URL, so different endpoints (or DBs) get independent connections.
fn shared_endpoint(redis_url: &str) -> Arc<SharedEndpoint> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, Arc<SharedEndpoint>>>> = OnceLock::new();
    let registry = REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = registry.lock();
    map.entry(redis_url.to_string())
        .or_insert_with(|| {
            Arc::new(SharedEndpoint {
                conn: Mutex::new(None),
                connect_gate: tokio::sync::Mutex::new(()),
                refs: AtomicUsize::new(0),
            })
        })
        .clone()
}

pub struct RedisRateLimiter {
    client: redis::Client,
    /// Shared connection for this Redis URL, reused across instances.
    shared: Arc<SharedEndpoint>,
    algorithm: Algorithm,
    prefix: String,
    /// Cached SHA for THIS instance's algorithm script (REDIS-02). Per instance,
    /// not shared: the SHA is algorithm-specific (fixed/sliding/token) while the
    /// connection is shared across algorithms on the same URL.
    script_sha: Mutex<Option<String>>,
    /// Set once when this instance releases its endpoint reference, so
    /// `shutdown()` and `Drop` cannot double-release.
    released: AtomicBool,
}

impl Drop for RedisRateLimiter {
    fn drop(&mut self) {
        self.release();
    }
}

fn shared_runtime() -> Result<&'static Runtime, redis::RedisError> {
    static RUNTIME: OnceLock<Result<Runtime, String>> = OnceLock::new();
    let result = RUNTIME.get_or_init(|| {
        Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| e.to_string())
    });
    match result {
        Ok(rt) => Ok(rt),
        Err(msg) => Err(redis::RedisError::from((
            redis::ErrorKind::Io,
            "tokio runtime init failed",
            msg.clone(),
        ))),
    }
}

impl RedisRateLimiter {
    pub fn new(
        redis_url: &str,
        algorithm: Algorithm,
        prefix: String,
        tls_config: RedisTlsConfig,
    ) -> Result<Self, redis::RedisError> {
        let client = match tls_config.validate_and_build(redis_url)? {
            Some(client) => client,
            None => redis::Client::open(redis_url)?,
        };
        let shared = shared_endpoint(redis_url);
        shared.refs.fetch_add(1, Ordering::AcqRel);
        Ok(Self {
            client,
            shared,
            algorithm,
            prefix,
            script_sha: Mutex::new(None),
            released: AtomicBool::new(false),
        })
    }

    async fn connection_async(&self) -> Result<MultiplexedConnection, redis::RedisError> {
        // Fast path: a healthy connection already exists for this endpoint. This
        // never touches the single-flight gate, so a warm connection has zero
        // extra cost — the gate is only contended at cold start or after a reset.
        {
            let conn_guard = self.shared.conn.lock();
            if let Some(conn) = conn_guard.as_ref() {
                return Ok(conn.clone());
            }
        }

        // Single-flight: serialize connection establishment per endpoint so
        // concurrent first-callers don't each open a socket. Failures under the
        // gate serialize (intentional backpressure against a struggling backend);
        // fail_mode still decides the request outcome.
        let _gate = self.shared.connect_gate.lock().await;

        // Re-check: another task may have connected while we waited for the gate.
        {
            let conn_guard = self.shared.conn.lock();
            if let Some(conn) = conn_guard.as_ref() {
                return Ok(conn.clone());
            }
        }

        // Bound the connection-acquisition.  Without this, a Redis endpoint
        // that accepts TCP but never responds at the application layer
        // (plain ``redis://`` against a TLS-required server, a network ACL
        // dropping post-handshake bytes, etc.) hangs the call indefinitely;
        // the existing fail_mode path cannot engage because the call never
        // returns to surface an error.  Mapping the timeout into a
        // RedisError lets the caller's fail_mode logic route this exactly
        // like any other connection-side failure.
        //
        // Hardcoded rather than promoted to a config key to keep the
        // plugin's config surface small — operators rarely tune this knob
        // and adding it for the few who might need it expands the schema
        // for everyone else.  Two seconds is comfortable headroom for
        // typical production paths (intra-VPC and cross-AZ Redis well
        // under 100 ms; managed Redis with TLS handshake adds ~100-300 ms
        // on top).  If a deployment with deliberately slow networks
        // surfaces and 2 s becomes too tight, promote this into the
        // ``lib.rs`` defaults + the engine's KNOWN config-key list — the
        // existing config-validation machinery (defaults, unknown-key
        // warning) handles the rest cleanly.
        const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
        let conn = timeout(
            CONNECT_TIMEOUT,
            self.client.get_multiplexed_async_connection(),
        )
        .await
        .map_err(|_elapsed| {
            redis::RedisError::from((
                redis::ErrorKind::Io,
                "connection timeout",
                format!(
                    "redis connection acquisition exceeded {:?}",
                    CONNECT_TIMEOUT,
                ),
            ))
        })??;

        // We are the elected connector (we hold `_gate`), so no race to re-check.
        *self.shared.conn.lock() = Some(conn.clone());
        Ok(conn)
    }

    /// Drop the shared connection and this instance's script SHA so the next
    /// call reconnects. Invoked from the eval path on a connection-side error;
    /// the connection is rebuilt lazily by a single caller via `connect_gate`.
    fn reset_connection(&self) {
        *self.shared.conn.lock() = None;
        *self.script_sha.lock() = None;
    }

    /// Release this instance's reference to the shared endpoint, closing the
    /// connection only when the last instance is released. Idempotent across
    /// `shutdown()` and `Drop`. The connection therefore survives the gateway's
    /// overlapping manager rebuilds (which always hold another reference) but is
    /// cleaned up on real teardown.
    fn release(&self) {
        if self.released.swap(true, Ordering::AcqRel) {
            return;
        }
        if self.shared.refs.fetch_sub(1, Ordering::AcqRel) == 1 {
            *self.shared.conn.lock() = None;
        }
    }

    /// Plugin teardown — releases this instance's endpoint reference.
    pub fn shutdown(&self) {
        self.release();
    }

    /// Return the batch Lua script for the active algorithm.
    fn batch_script(&self) -> &'static str {
        match self.algorithm {
            Algorithm::FixedWindow => LUA_BATCH_FIXED,
            Algorithm::SlidingWindow => LUA_BATCH_SLIDING,
            Algorithm::TokenBucket => LUA_BATCH_TOKEN_BUCKET,
        }
    }

    /// REDIS-02: Load the active algorithm's script via SCRIPT LOAD and cache
    /// the SHA.  Returns the cached SHA on subsequent calls.
    async fn ensure_script_loaded(
        &self,
        conn: &mut MultiplexedConnection,
    ) -> Result<String, redis::RedisError> {
        {
            let guard = self.script_sha.lock();
            if let Some(sha) = guard.as_ref() {
                return Ok(sha.clone());
            }
        }
        let sha: String = redis::cmd("SCRIPT")
            .arg("LOAD")
            .arg(self.batch_script())
            .query_async(conn)
            .await?;
        *self.script_sha.lock() = Some(sha.clone());
        Ok(sha)
    }

    /// REDIS-02: Execute via EVALSHA when the SHA is cached; fall back to EVAL
    /// on NOSCRIPT (Redis restarted and flushed its script cache).
    #[mutants::skip] // Redis script-cache behavior needs a live Redis integration harness.
    async fn evalsha_or_eval(
        &self,
        conn: &mut MultiplexedConnection,
        num_keys: usize,
        keys: &[String],
        args: &[Vec<u8>],
    ) -> Result<redis::Value, redis::RedisError> {
        // Try EVALSHA if we have a cached SHA.
        if let Ok(sha) = self.ensure_script_loaded(conn).await {
            let mut cmd = redis::cmd("EVALSHA");
            cmd.arg(&sha).arg(num_keys);
            for k in keys {
                cmd.arg(k.as_bytes());
            }
            for a in args {
                cmd.arg(a.as_slice());
            }
            match cmd.query_async::<redis::Value>(conn).await {
                Ok(val) => return Ok(val),
                Err(e)
                    if e.kind() == redis::ErrorKind::Server(redis::ServerErrorKind::NoScript) =>
                {
                    // NOSCRIPT — clear cached SHA, fall through to EVAL.
                    *self.script_sha.lock() = None;
                }
                Err(e) => return Err(e),
            }
        }

        // Fallback: full EVAL (first call or after NOSCRIPT).
        let mut cmd = redis::cmd("EVAL");
        cmd.arg(self.batch_script()).arg(num_keys);
        for k in keys {
            cmd.arg(k.as_bytes());
        }
        for a in args {
            cmd.arg(a.as_slice());
        }
        let result: redis::Value = cmd.query_async(conn).await?;

        // EVAL caches the script server-side; the next call will lazily
        // re-populate our local SHA via ensure_script_loaded().
        Ok(result)
    }

    /// Evaluate all dimension checks in a single Redis call.
    ///
    /// `checks` is `(dimension_key, limit_count, window_nanos)` — same shape
    /// as the memory engine.  Returns one `DimResult` per check.
    pub fn evaluate_many(
        &self,
        checks: &[(String, u64, u64)],
        now_unix: i64,
    ) -> Result<Vec<DimResult>, redis::RedisError> {
        shared_runtime()?.block_on(self.evaluate_many_async(checks, now_unix))
    }

    pub async fn evaluate_many_async(
        &self,
        checks: &[(String, u64, u64)],
        now_unix: i64,
    ) -> Result<Vec<DimResult>, redis::RedisError> {
        if checks.is_empty() {
            return Ok(vec![]);
        }

        // Derive from the passed-in now_unix so Python time mocks propagate
        // to Redis Lua scripts (CORR-02).
        let now_float = now_unix as f64;

        let mut conn = self.connection_async().await?;
        let result = match self.algorithm {
            Algorithm::FixedWindow => self.eval_fixed(&mut conn, checks, now_unix).await,
            Algorithm::SlidingWindow => {
                self.eval_sliding(&mut conn, checks, now_float, now_unix)
                    .await
            }
            Algorithm::TokenBucket => {
                self.eval_token_bucket(&mut conn, checks, now_float, now_unix)
                    .await
            }
        };
        if result.is_err() {
            self.reset_connection();
        }
        result
    }

    fn redis_key(&self, dim_key: &str, window_nanos: u64) -> String {
        let window_secs = window_nanos / 1_000_000_000;
        format!("{}:{}:{}", self.prefix, dim_key, window_secs)
    }

    fn token_bucket_time_to_full(limit: u64, remaining: u64, window_nanos: u64) -> i64 {
        if remaining >= limit {
            return 0;
        }
        let window_secs = window_nanos as f64 / 1_000_000_000.0;
        let refill_rate = limit as f64 / window_secs;
        let tokens_needed = limit - remaining;
        let seconds_to_full = (tokens_needed as f64 / refill_rate).ceil() as i64;
        max(1, seconds_to_full)
    }

    // --- Fixed window ---

    #[mutants::skip] // Redis Lua response handling needs a live Redis integration harness.
    async fn eval_fixed(
        &self,
        conn: &mut MultiplexedConnection,
        checks: &[(String, u64, u64)],
        now_unix: i64,
    ) -> Result<Vec<DimResult>, redis::RedisError> {
        let keys: Vec<String> = checks
            .iter()
            .map(|(k, _, w)| self.redis_key(k, *w))
            .collect();
        let args: Vec<Vec<u8>> = checks
            .iter()
            .map(|(_, _, w)| format!("{}", w / 1_000_000_000).into_bytes())
            .collect();

        let raw = self.evalsha_or_eval(conn, keys.len(), &keys, &args).await?;
        let mut results = Vec::with_capacity(checks.len());

        for (i, (_, limit, _)) in checks.iter().enumerate() {
            let inner = inner_array(&raw, i).ok_or_else(|| {
                redis::RedisError::from((
                    redis::ErrorKind::UnexpectedReturnType,
                    "expected inner array",
                ))
            })?;
            let count = val_i64(inner.first().unwrap_or(&redis::Value::Int(0))) as u64;
            let ttl = val_i64(inner.get(1).unwrap_or(&redis::Value::Int(0)));
            let reset_timestamp = now_unix + ttl.max(0);

            if count > *limit {
                results.push(DimResult {
                    allowed: false,
                    limit: *limit,
                    remaining: 0,
                    reset_timestamp,
                    retry_after: Some(ttl.max(1)),
                });
            } else {
                results.push(DimResult {
                    allowed: true,
                    limit: *limit,
                    remaining: limit - count,
                    reset_timestamp,
                    retry_after: None,
                });
            }
        }
        Ok(results)
    }

    // --- Sliding window ---

    #[mutants::skip] // Redis Lua response handling needs a live Redis integration harness.
    async fn eval_sliding(
        &self,
        conn: &mut MultiplexedConnection,
        checks: &[(String, u64, u64)],
        now_float: f64,
        now_unix: i64,
    ) -> Result<Vec<DimResult>, redis::RedisError> {
        let keys: Vec<String> = checks
            .iter()
            .map(|(k, _, w)| self.redis_key(k, *w))
            .collect();

        let mut args: Vec<Vec<u8>> = vec![format!("{}", now_float).into_bytes()];
        for (_, limit, window_nanos) in checks {
            let window_secs = window_nanos / 1_000_000_000;
            args.push(format!("{}", window_secs).into_bytes());
            args.push(format!("{}", limit).into_bytes());
            args.push(unique_member(now_float).into_bytes());
        }

        let raw = self.evalsha_or_eval(conn, keys.len(), &keys, &args).await?;
        let mut results = Vec::with_capacity(checks.len());

        for (i, (_, limit, window_nanos)) in checks.iter().enumerate() {
            let inner = inner_array(&raw, i).ok_or_else(|| {
                redis::RedisError::from((
                    redis::ErrorKind::UnexpectedReturnType,
                    "expected inner array",
                ))
            })?;
            let allowed_int = val_i64(inner.first().unwrap_or(&redis::Value::Int(0)));
            let count = val_i64(inner.get(1).unwrap_or(&redis::Value::Int(0))) as u64;
            let oldest_ts = val_f64(inner.get(2).unwrap_or(&redis::Value::Int(0)));
            let window_secs = (window_nanos / 1_000_000_000) as f64;
            let reset_timestamp = (oldest_ts + window_secs) as i64;
            let reset_in = (reset_timestamp - now_unix).max(1);

            if allowed_int == 0 {
                results.push(DimResult {
                    allowed: false,
                    limit: *limit,
                    remaining: 0,
                    reset_timestamp,
                    retry_after: Some(reset_in),
                });
            } else {
                results.push(DimResult {
                    allowed: true,
                    limit: *limit,
                    remaining: limit.saturating_sub(count),
                    reset_timestamp,
                    retry_after: None,
                });
            }
        }
        Ok(results)
    }

    // --- Token bucket ---

    #[mutants::skip] // Redis Lua response handling needs a live Redis integration harness.
    async fn eval_token_bucket(
        &self,
        conn: &mut MultiplexedConnection,
        checks: &[(String, u64, u64)],
        now_float: f64,
        now_unix: i64,
    ) -> Result<Vec<DimResult>, redis::RedisError> {
        let keys: Vec<String> = checks
            .iter()
            .map(|(k, _, w)| self.redis_key(k, *w))
            .collect();

        let mut args: Vec<Vec<u8>> = vec![format!("{}", now_float).into_bytes()];
        for (_, limit, window_nanos) in checks {
            let window_secs = *window_nanos as f64 / 1_000_000_000.0;
            let rate = *limit as f64 / window_secs;
            args.push(format!("{}", limit).into_bytes());
            args.push(format!("{}", rate).into_bytes());
        }

        let raw = self.evalsha_or_eval(conn, keys.len(), &keys, &args).await?;
        let mut results = Vec::with_capacity(checks.len());

        for (i, (_, limit, window_nanos)) in checks.iter().enumerate() {
            let inner = inner_array(&raw, i).ok_or_else(|| {
                redis::RedisError::from((
                    redis::ErrorKind::UnexpectedReturnType,
                    "expected inner array",
                ))
            })?;
            let allowed_int = val_i64(inner.first().unwrap_or(&redis::Value::Int(0)));
            let remaining = val_i64(inner.get(1).unwrap_or(&redis::Value::Int(0))) as u64;
            let time_to_next = val_i64(inner.get(2).unwrap_or(&redis::Value::Int(0)));

            if allowed_int == 0 {
                let reset_timestamp = now_unix + time_to_next.max(1);
                results.push(DimResult {
                    allowed: false,
                    limit: *limit,
                    remaining: 0,
                    reset_timestamp,
                    retry_after: Some(time_to_next.max(1)),
                });
            } else {
                let time_to_full =
                    Self::token_bucket_time_to_full(*limit, remaining, *window_nanos);
                let reset_timestamp = now_unix + time_to_full;
                results.push(DimResult {
                    allowed: true,
                    limit: *limit,
                    remaining,
                    reset_timestamp,
                    retry_after: None,
                });
            }
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::{RedisRateLimiter, RedisTlsConfig};
    use crate::config::Algorithm;
    use std::io::Write;
    use std::time::{Duration, Instant};

    /// Write `content` to a uniquely-named temp file and return its path.
    /// The file is automatically deleted when the returned guard is dropped.
    struct TempFile(std::path::PathBuf);

    impl TempFile {
        fn with_content(content: &[u8]) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let name = format!(
                "rl_test_{}_{}.pem",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed),
            );
            let path = std::env::temp_dir().join(name);
            let mut f = std::fs::File::create(&path).expect("create temp test file");
            f.write_all(content).expect("write temp test file");
            Self(path)
        }

        fn path_str(&self) -> &str {
            self.0.to_str().unwrap()
        }
    }

    /// Two limiters pointing at the same Redis URL must share one endpoint
    /// (hence one connection); different URLs must not. This is what stops the
    /// gateway's per-(team, tool) manager rebuilds from each opening a fresh
    /// connection. `Client::open` is lazy, so this needs no live Redis.
    #[test]
    fn same_url_shares_one_endpoint() {
        let mk = |url: &str| {
            RedisRateLimiter::new(
                url,
                Algorithm::FixedWindow,
                "rl".to_string(),
                RedisTlsConfig::default(),
            )
            .expect("client should construct (lazy connection)")
        };
        let a = mk("redis://127.0.0.1:6379/0");
        let b = mk("redis://127.0.0.1:6379/0");
        let c = mk("redis://127.0.0.1:6380/0");
        assert!(
            std::sync::Arc::ptr_eq(&a.shared, &b.shared),
            "limiters with the same URL must share one endpoint",
        );
        assert!(
            !std::sync::Arc::ptr_eq(&a.shared, &c.shared),
            "limiters with different URLs must not share an endpoint",
        );
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// Generate a self-signed certificate PEM and its private key PEM using rcgen.
    #[cfg(test)]
    fn generate_test_cert_pem() -> (Vec<u8>, Vec<u8>) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("rcgen cert generation");
        (
            cert.serialize_pem()
                .expect("cert PEM serialize")
                .into_bytes(),
            cert.serialize_private_key_pem().into_bytes(),
        )
    }

    // ---------------------------------------------------------------------------
    // RedisTlsConfig tests
    // ---------------------------------------------------------------------------

    /// Regression guard: the rustls `tls12` feature must stay enabled.
    /// Without it rustls compiles TLS 1.3-only and cannot connect to a TLS-1.2-only
    /// managed Redis (e.g. AWS ElastiCache), failing with BACKEND_UNAVAILABLE.
    /// `rustls::version::TLS12` only exists when the feature is on, so removing it
    /// breaks this build.
    #[test]
    fn rustls_tls12_feature_is_enabled() {
        assert_eq!(
            rustls::version::TLS12.version,
            rustls::ProtocolVersion::TLSv1_2
        );
    }

    #[test]
    fn tls_no_knobs_returns_none() {
        // Default config (no TLS knobs) must take the fast path and return None
        // regardless of the URL scheme.
        let cfg = RedisTlsConfig::default();
        assert!(
            cfg.validate_and_build("redis://127.0.0.1:6379/0")
                .unwrap()
                .is_none()
        );
        assert!(
            cfg.validate_and_build("rediss://127.0.0.1:6379/0")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn tls_ca_certs_requires_rediss_scheme() {
        let (cert_pem, _) = generate_test_cert_pem();
        let tmp = TempFile::with_content(&cert_pem);
        let cfg = RedisTlsConfig {
            ca_certs_path: Some(tmp.path_str().to_string()),
            ..RedisTlsConfig::default()
        };
        let err = cfg
            .validate_and_build("redis://127.0.0.1:6379/0")
            .unwrap_err();
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("rediss://"),
            "error should mention rediss://; got: {err}"
        );
    }

    #[test]
    fn tls_ca_certs_missing_file_errors() {
        let cfg = RedisTlsConfig {
            ca_certs_path: Some("/nonexistent/path/ca.pem".to_string()),
            ..RedisTlsConfig::default()
        };
        let err = cfg
            .validate_and_build("rediss://127.0.0.1:6379/0")
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("redis_ssl_ca_certs"),
            "error should name the key; got: {err}"
        );
        assert!(
            msg.contains("nonexistent"),
            "error should name the path; got: {err}"
        );
    }

    #[test]
    fn tls_ca_certs_garbage_pem_errors() {
        let tmp = TempFile::with_content(b"this is not a valid PEM certificate");
        let cfg = RedisTlsConfig {
            ca_certs_path: Some(tmp.path_str().to_string()),
            ..RedisTlsConfig::default()
        };
        let err = cfg
            .validate_and_build("rediss://127.0.0.1:6379/0")
            .unwrap_err();
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("no valid certificates") || msg.contains("pem"),
            "error should describe the PEM problem; got: {err}"
        );
    }

    #[test]
    fn tls_ca_certs_valid_pem_builds_client() {
        let (cert_pem, _) = generate_test_cert_pem();
        let tmp = TempFile::with_content(&cert_pem);
        let cfg = RedisTlsConfig {
            ca_certs_path: Some(tmp.path_str().to_string()),
            ..RedisTlsConfig::default()
        };
        let client = cfg
            .validate_and_build("rediss://127.0.0.1:6379/0")
            .expect("should succeed")
            .expect("should return Some(client)");
        // Client is lazy — it's built successfully; no connection is made here.
        drop(client);
    }

    #[test]
    fn tls_certfile_without_keyfile_errors() {
        let (cert_pem, _) = generate_test_cert_pem();
        let tmp = TempFile::with_content(&cert_pem);
        let cfg = RedisTlsConfig {
            certfile_path: Some(tmp.path_str().to_string()),
            keyfile_path: None,
            ..RedisTlsConfig::default()
        };
        let err = cfg
            .validate_and_build("rediss://127.0.0.1:6379/0")
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("redis_ssl_keyfile"),
            "error should mention the missing key; got: {err}"
        );
    }

    #[test]
    fn tls_keyfile_without_certfile_errors() {
        let (_, key_pem) = generate_test_cert_pem();
        let tmp = TempFile::with_content(&key_pem);
        let cfg = RedisTlsConfig {
            certfile_path: None,
            keyfile_path: Some(tmp.path_str().to_string()),
            ..RedisTlsConfig::default()
        };
        let err = cfg
            .validate_and_build("rediss://127.0.0.1:6379/0")
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("redis_ssl_certfile"),
            "error should mention the missing cert; got: {err}"
        );
    }

    #[test]
    fn tls_mtls_valid_pair_builds_client() {
        let (cert_pem, key_pem) = generate_test_cert_pem();
        let cert_file = TempFile::with_content(&cert_pem);
        let key_file = TempFile::with_content(&key_pem);
        let cfg = RedisTlsConfig {
            certfile_path: Some(cert_file.path_str().to_string()),
            keyfile_path: Some(key_file.path_str().to_string()),
            ..RedisTlsConfig::default()
        };
        let client = cfg
            .validate_and_build("rediss://127.0.0.1:6379/0")
            .expect("should succeed")
            .expect("should return Some(client)");
        drop(client);
    }

    #[test]
    fn tls_check_hostname_false_requires_rediss_scheme() {
        let cfg = RedisTlsConfig {
            check_hostname: false,
            ..RedisTlsConfig::default()
        };
        let err = cfg
            .validate_and_build("redis://127.0.0.1:6379/0")
            .unwrap_err();
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("rediss://"),
            "error should mention rediss://; got: {err}"
        );
    }

    #[test]
    fn tls_check_hostname_false_builds_insecure_client() {
        // check_hostname=false should build an insecure (no cert validation) client.
        let cfg = RedisTlsConfig {
            check_hostname: false,
            ..RedisTlsConfig::default()
        };
        let client = cfg
            .validate_and_build("rediss://127.0.0.1:6379/0")
            .expect("should succeed")
            .expect("should return Some(client)");
        drop(client);
    }

    #[test]
    fn tls_check_hostname_false_with_mtls_builds_client() {
        // Insecure mode must still load and present the mTLS client cert/key
        // so the server can authenticate the client.
        let (cert_pem, key_pem) = generate_test_cert_pem();
        let cert_file = TempFile::with_content(&cert_pem);
        let key_file = TempFile::with_content(&key_pem);
        let cfg = RedisTlsConfig {
            check_hostname: false,
            certfile_path: Some(cert_file.path_str().to_string()),
            keyfile_path: Some(key_file.path_str().to_string()),
            ..RedisTlsConfig::default()
        };
        let client = cfg
            .validate_and_build("rediss://127.0.0.1:6379/0")
            .expect("should succeed")
            .expect("should return Some(client)");
        drop(client);
    }

    #[test]
    fn tls_check_hostname_false_with_ca_certs_builds_client() {
        // Insecure mode logs a warning and ignores the CA bundle; the build
        // still succeeds.
        let (cert_pem, _) = generate_test_cert_pem();
        let ca_file = TempFile::with_content(&cert_pem);
        let cfg = RedisTlsConfig {
            check_hostname: false,
            ca_certs_path: Some(ca_file.path_str().to_string()),
            ..RedisTlsConfig::default()
        };
        let client = cfg
            .validate_and_build("rediss://127.0.0.1:6379/0")
            .expect("should succeed")
            .expect("should return Some(client)");
        drop(client);
    }

    #[test]
    fn tls_mtls_garbage_certfile_pem_errors() {
        // Garbage content in redis_ssl_certfile must surface a PEM error
        // before any client is built.
        let (_, key_pem) = generate_test_cert_pem();
        let cert_file = TempFile::with_content(b"this is not a valid PEM certificate");
        let key_file = TempFile::with_content(&key_pem);
        let cfg = RedisTlsConfig {
            certfile_path: Some(cert_file.path_str().to_string()),
            keyfile_path: Some(key_file.path_str().to_string()),
            ..RedisTlsConfig::default()
        };
        let err = cfg
            .validate_and_build("rediss://127.0.0.1:6379/0")
            .unwrap_err();
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("redis_ssl_certfile") || msg.contains("no valid certificates"),
            "error should describe the PEM problem; got: {err}"
        );
    }

    #[test]
    fn tls_mtls_malformed_certfile_pem_errors() {
        // A PEM-shaped block with malformed body (invalid base64) must surface
        // a PEM parse error from pem_slice_iter (not the empty-cert branch).
        let (_, key_pem) = generate_test_cert_pem();
        let malformed =
            b"-----BEGIN CERTIFICATE-----\n!!!not valid base64!!!\n-----END CERTIFICATE-----\n";
        let cert_file = TempFile::with_content(malformed);
        let key_file = TempFile::with_content(&key_pem);
        let cfg = RedisTlsConfig {
            certfile_path: Some(cert_file.path_str().to_string()),
            keyfile_path: Some(key_file.path_str().to_string()),
            ..RedisTlsConfig::default()
        };
        let err = cfg
            .validate_and_build("rediss://127.0.0.1:6379/0")
            .unwrap_err();
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("redis_ssl_certfile") || msg.contains("pem"),
            "error should mention the certfile or PEM; got: {err}"
        );
    }

    #[test]
    fn tls_ca_certs_malformed_pem_errors() {
        // Malformed PEM in CA bundle must surface a PEM parse error.
        let malformed =
            b"-----BEGIN CERTIFICATE-----\n!!!not valid base64!!!\n-----END CERTIFICATE-----\n";
        let tmp = TempFile::with_content(malformed);
        let cfg = RedisTlsConfig {
            ca_certs_path: Some(tmp.path_str().to_string()),
            ..RedisTlsConfig::default()
        };
        let err = cfg
            .validate_and_build("rediss://127.0.0.1:6379/0")
            .unwrap_err();
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("redis_ssl_ca_certs") || msg.contains("pem"),
            "error should mention CA certs or PEM; got: {err}"
        );
    }

    #[test]
    fn tls_mtls_garbage_keyfile_pem_errors() {
        // Garbage content in redis_ssl_keyfile must surface a parse error.
        let (cert_pem, _) = generate_test_cert_pem();
        let cert_file = TempFile::with_content(&cert_pem);
        let key_file = TempFile::with_content(b"this is not a valid PEM private key");
        let cfg = RedisTlsConfig {
            certfile_path: Some(cert_file.path_str().to_string()),
            keyfile_path: Some(key_file.path_str().to_string()),
            ..RedisTlsConfig::default()
        };
        let err = cfg
            .validate_and_build("rediss://127.0.0.1:6379/0")
            .unwrap_err();
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("redis_ssl_keyfile"),
            "error should mention the keyfile; got: {err}"
        );
    }

    #[test]
    fn tls_mtls_with_ca_certs_builds_client() {
        // CA bundle + mTLS together must build a client successfully.
        let (cert_pem, key_pem) = generate_test_cert_pem();
        let ca_file = TempFile::with_content(&cert_pem);
        let cert_file = TempFile::with_content(&cert_pem);
        let key_file = TempFile::with_content(&key_pem);
        let cfg = RedisTlsConfig {
            ca_certs_path: Some(ca_file.path_str().to_string()),
            certfile_path: Some(cert_file.path_str().to_string()),
            keyfile_path: Some(key_file.path_str().to_string()),
            ..RedisTlsConfig::default()
        };
        let client = cfg
            .validate_and_build("rediss://127.0.0.1:6379/0")
            .expect("should succeed")
            .expect("should return Some(client)");
        drop(client);
    }

    /// `connection_async` must time out within a bounded window when the
    /// Redis endpoint accepts TCP but never speaks at the application layer.
    ///
    /// Test setup: bind a TCP listener but never call `accept()` to read or
    /// write any bytes.  The kernel completes the TCP three-way handshake
    /// into its accept queue; the redis crate's
    /// `get_multiplexed_async_connection` sends its initial handshake bytes
    /// and waits for a response that never comes.
    ///
    /// The outer `tokio::time::timeout(5s)` is the test's runaway-guard so
    /// a regression doesn't hang the test run.  Asserts:
    ///   * `connection_async` returns within ~3 seconds (well under the
    ///     5s guard).
    ///   * The returned error is `Io`-shaped, so the existing
    ///     `fail_mode` path can route it the same way as any other
    ///     connection-side failure.
    #[test]
    fn connection_async_fails_fast_against_hanging_redis() {
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let hang_addr = listener.local_addr().expect("local_addr").to_string();
        let url = format!("redis://{}/0", hang_addr);

        let limiter = RedisRateLimiter::new(
            &url,
            Algorithm::FixedWindow,
            "rl".to_string(),
            RedisTlsConfig::default(),
        )
        .expect("client should construct (lazy connection)");

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");

        let started = Instant::now();
        let result: Result<Result<_, redis::RedisError>, tokio::time::error::Elapsed> = runtime
            .block_on(async {
                tokio::time::timeout(Duration::from_secs(5), limiter.connection_async()).await
            });
        let elapsed = started.elapsed();

        // The outer 5s tokio::time::timeout is the test's runaway-guard.
        // It firing is the bug shape (hang).  We want the inner Result
        // to be available — i.e., connection_async must have returned of
        // its own accord well before 5s.
        let inner = result.expect(
            "connection_async hung against a TCP-accepted-but-app-hangs Redis — \
             expected an explicit connection timeout error from the redis client \
             well before the 5s test bound; instead the call never returned.",
        );

        assert!(
            elapsed < Duration::from_secs(3),
            "connection_async must fail fast on a hanging Redis (≤3s) — took {:?}. \
             Without a connection time-bound, the existing fail_mode path can't \
             trigger because the call never returns at all.",
            elapsed,
        );

        let err = inner.expect_err(
            "connection_async should error against a hanging Redis (server never \
             completes the redis handshake), not return Ok",
        );
        // Pin the exact contract: the connection-acquisition timeout maps
        // into ``redis::ErrorKind::Io``, the same shape the existing
        // ``fail_mode`` path routes for any other connection-side failure.
        // Anything else (ResponseError, ClientError, ...) would mean the
        // timeout is being surfaced through a different code path than
        // the rest of the fail-mode logic and would silently break the
        // operator's fail-open / fail-closed policy.
        assert_eq!(
            err.kind(),
            redis::ErrorKind::Io,
            "expected Io-shaped timeout error from connection_async; got {:?}: {}",
            err.kind(),
            err,
        );
    }

    #[test]
    fn token_bucket_success_reset_uses_time_to_full() {
        let window_nanos = 10_000_000_000_u64; // 10s
        let limit = 10_u64;
        let remaining = 9_u64;
        assert_eq!(
            RedisRateLimiter::token_bucket_time_to_full(limit, remaining, window_nanos),
            1
        );

        let remaining = 5_u64;
        assert_eq!(
            RedisRateLimiter::token_bucket_time_to_full(limit, remaining, window_nanos),
            5
        );
    }
}
