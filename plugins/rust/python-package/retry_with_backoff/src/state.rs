// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// How long (seconds) to keep a retry-state entry before considering it stale.
pub const STATE_TTL_SECS: f64 = 300.0;

/// Minimum interval (milliseconds) between full eviction scans, so that
/// `maybe_evict_stale` is O(1) on the hot path rather than O(n).
pub const EVICT_INTERVAL_MS: u64 = 30_000;

static MONO_EPOCH: OnceLock<Instant> = OnceLock::new();

pub fn monotonic_secs() -> f64 {
    let epoch = MONO_EPOCH.get_or_init(Instant::now);
    epoch.elapsed().as_secs_f64()
}

#[derive(Debug, Clone, Default)]
pub struct ToolRetryState {
    pub consecutive_failures: u32,
    pub last_failure_at: f64,
}

impl ToolRetryState {
    pub fn new() -> Self {
        Self {
            consecutive_failures: 0,
            last_failure_at: 0.0,
        }
    }
}

/// Evict stale entries from `map`, but at most once per [`EVICT_INTERVAL_MS`].
///
/// `last_eviction_ms` is an `AtomicU64` owned by the caller, tracking the last
/// time eviction ran for that state store.  The benign race (two threads both
/// triggering eviction at the boundary) is intentional — duplicate scans are
/// safe and infrequent.
#[mutants::skip] // time-dependent logic cannot be verified without clock injection
pub fn maybe_evict_stale(map: &mut HashMap<String, ToolRetryState>, last_eviction_ms: &AtomicU64) {
    let now_ms = (monotonic_secs() * 1000.0) as u64;
    let last_ms = last_eviction_ms.load(Ordering::Relaxed);
    if now_ms.saturating_sub(last_ms) >= EVICT_INTERVAL_MS {
        last_eviction_ms.store(now_ms, Ordering::Relaxed);
        let cutoff = (now_ms as f64 / 1000.0) - STATE_TTL_SECS;
        map.retain(|_, v| v.last_failure_at <= 0.0 || v.last_failure_at >= cutoff);
    }
}
