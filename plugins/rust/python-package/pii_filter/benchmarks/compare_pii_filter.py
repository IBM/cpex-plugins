#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Benchmark the Rust-backed PII detector."""

from __future__ import annotations

import argparse
import statistics
import time
from dataclasses import asdict, dataclass

from cpex_pii_filter import PIIDetectorRust


@dataclass
class BenchmarkResult:
    name: str
    duration_ms: float
    ops_per_sec: float
    text_size_bytes: int
    min_ms: float
    max_ms: float
    median_ms: float


def run_benchmark(detector: PIIDetectorRust, text: str, iterations: int) -> BenchmarkResult:
    for _ in range(10):
        detector.detect(text)

    latencies: list[float] = []
    for _ in range(iterations):
        start = time.perf_counter()
        detector.detect(text)
        latencies.append((time.perf_counter() - start) * 1000)

    avg_ms = statistics.mean(latencies)
    return BenchmarkResult(
        name=f"rust_detect_{len(text)}",
        duration_ms=avg_ms,
        ops_per_sec=1000 / avg_ms,
        text_size_bytes=len(text.encode("utf-8")),
        min_ms=min(latencies),
        max_ms=max(latencies),
        median_ms=statistics.median(latencies),
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=500)
    args = parser.parse_args()

    detector = PIIDetectorRust({})
    samples = [
        "alice@example.com",
        "My SSN is 123-45-6789 and email is alice@example.com",
        " ".join(["Contact alice@example.com or 123-45-6789"] * 100),
    ]

    for result in [run_benchmark(detector, sample, args.iterations) for sample in samples]:
        print(asdict(result))


if __name__ == "__main__":
    main()
