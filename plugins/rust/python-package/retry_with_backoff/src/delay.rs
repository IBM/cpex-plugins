// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

/// Compute the next retry delay in milliseconds using exponential backoff with
/// optional jitter.  The result is capped at `max_ms`.
pub fn compute_delay_ms(attempt: u32, base_ms: u64, max_ms: u64, jitter: bool) -> u64 {
    let ceiling = base_ms
        .saturating_mul(2u64.saturating_pow(attempt))
        .min(max_ms);
    if jitter {
        rand::random_range(0..=ceiling)
    } else {
        ceiling
    }
}
