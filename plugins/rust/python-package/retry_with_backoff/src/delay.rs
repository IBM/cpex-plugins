// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

use std::ops::RangeInclusive;

/// Compute the next retry delay in milliseconds using exponential backoff with
/// optional jitter.  The result is capped at `max_ms`.
pub fn compute_delay_ms(attempt: u32, base_ms: u64, max_ms: u64, jitter: bool) -> u64 {
    compute_delay_ms_with_jitter_sampler(attempt, base_ms, max_ms, jitter, rand::random_range)
}

fn compute_delay_ms_with_jitter_sampler(
    attempt: u32,
    base_ms: u64,
    max_ms: u64,
    jitter: bool,
    sample: impl FnOnce(RangeInclusive<u64>) -> u64,
) -> u64 {
    let ceiling = base_ms
        .saturating_mul(2u64.saturating_pow(attempt))
        .min(max_ms);
    if jitter { sample(0..=ceiling) } else { ceiling }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_samples_from_zero_to_capped_ceiling() {
        let delay = compute_delay_ms_with_jitter_sampler(10, 100, 500, true, |range| {
            assert_eq!(range, 0..=500);
            123
        });

        assert_eq!(delay, 123);
    }

    #[test]
    fn no_jitter_ignores_sampler() {
        let delay = compute_delay_ms_with_jitter_sampler(1, 100, 10_000, false, |_| {
            panic!("sampler should not be called when jitter is disabled");
        });

        assert_eq!(delay, 200);
    }
}
