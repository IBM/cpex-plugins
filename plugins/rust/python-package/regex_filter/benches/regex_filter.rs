// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

use criterion::{Criterion, criterion_group, criterion_main};
use regex::RegexSet;
use regex_filter_rust::{SearchReplace, SearchReplaceConfig, SearchReplacePluginRust};

fn bench_apply_patterns(c: &mut Criterion) {
    let config = SearchReplaceConfig {
        words: vec![
            SearchReplace {
                search: r"\bsecret\b".to_string(),
                replace: "[REDACTED]".to_string(),
                compiled: regex::Regex::new(r"\bsecret\b").unwrap(),
            },
            SearchReplace {
                search: r"\d{3}-\d{2}-\d{4}".to_string(),
                replace: "XXX-XX-XXXX".to_string(),
                compiled: regex::Regex::new(r"\d{3}-\d{2}-\d{4}").unwrap(),
            },
        ],
        pattern_set: RegexSet::new([r"\bsecret\b", r"\d{3}-\d{2}-\d{4}"]).ok(),
        max_text_bytes: 10 * 1024 * 1024,
        max_total_text_bytes: 10 * 1024 * 1024,
        max_nested_depth: 64,
        max_collection_items: 4096,
        max_total_items: 65_536,
        max_output_bytes: 10 * 1024 * 1024,
    };
    let plugin = SearchReplacePluginRust { config };
    let text = "The secret number is 123-45-6789";

    c.bench_function("regex_filter_apply_patterns", |b| {
        b.iter(|| plugin.apply_patterns(text).unwrap())
    });
}

criterion_group!(benches, bench_apply_patterns);
criterion_main!(benches);
