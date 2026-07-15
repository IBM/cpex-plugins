// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
//
// Benchmarks for SQL sanitizer hot paths.

use criterion::{Criterion, criterion_group, criterion_main};
use sql_sanitizer_rust::config::SqlSanitizerConfig;
use sql_sanitizer_rust::issues::find_issues;
use std::hint::black_box;

fn bench_safe_select(c: &mut Criterion) {
    let cfg = SqlSanitizerConfig::default();
    let sql = "SELECT id, name, email FROM users WHERE id = 1 AND active = true";
    c.bench_function("find_issues_safe_select", |b| {
        b.iter(|| find_issues(black_box(sql), &cfg))
    });
}

fn bench_multi_statement_violation(c: &mut Criterion) {
    let cfg = SqlSanitizerConfig::default();
    let sql = "UPDATE a SET x=1; UPDATE b SET x=2; UPDATE c SET x=3; UPDATE d SET x=4; SELECT * FROM e WHERE id=1";
    c.bench_function("find_issues_multi_stmt_violation", |b| {
        b.iter(|| find_issues(black_box(sql), &cfg))
    });
}

fn bench_comment_stripping(c: &mut Criterion) {
    let cfg = SqlSanitizerConfig::default();
    let sql = "SELECT /* secret */ id -- inline comment\nFROM users WHERE id = 1";
    c.bench_function("find_issues_with_comments", |b| {
        b.iter(|| find_issues(black_box(sql), &cfg))
    });
}

criterion_group!(
    benches,
    bench_safe_select,
    bench_multi_statement_violation,
    bench_comment_stripping
);
criterion_main!(benches);
