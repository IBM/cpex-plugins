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
    };
    let plugin = SearchReplacePluginRust { config };
    let text = "The secret number is 123-45-6789";

    c.bench_function("regex_filter_apply_patterns", |b| {
        b.iter(|| plugin.apply_patterns(text))
    });
}

criterion_group!(benches, bench_apply_patterns);
criterion_main!(benches);
