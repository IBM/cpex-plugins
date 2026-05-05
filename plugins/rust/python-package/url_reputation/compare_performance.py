import argparse
import asyncio
import json
import statistics
import sys
import time
from pathlib import Path

from cpex.framework import PluginConfig, ResourceHookType
from cpex_url_reputation.url_reputation import URLReputationPlugin
import cpex_url_reputation.url_reputation_rust  # noqa: F401


class Payload:
    def __init__(self, url):
        self.uri = url


def load_bench_config(config_path: str = "bench_config.json"):
    """Load benchmark configuration from JSON file."""
    config_file = Path(__file__).parent / config_path
    if not config_file.exists():
        raise FileNotFoundError(f"Benchmark config file not found: {config_file}")

    with open(config_file, "r") as handle:
        return json.load(handle)


def generate_payloads(size: int, urls: list[str], url_multiplier: int = 1):
    """Return a list of urls to be used in the benchmark."""
    expanded_urls = urls * url_multiplier
    url_count = len(expanded_urls)
    repeated = expanded_urls * (size // url_count)
    remaining = expanded_urls[: size % url_count]
    return [Payload(url) for url in repeated + remaining]


async def run_benchmark(
    config: PluginConfig,
    iterations: int,
    urls: list[str],
    url_multiplier: int = 1,
    warmup: int = 5,
):
    """Run benchmark for the Rust-backed plugin implementation."""
    plugin = URLReputationPlugin(config)

    for payload in generate_payloads(warmup, urls, url_multiplier):
        await plugin.resource_pre_fetch(payload, None)

    times = []
    for payload in generate_payloads(iterations, urls, url_multiplier):
        start = time.perf_counter()
        await plugin.resource_pre_fetch(payload, None)
        times.append(time.perf_counter() - start)

    return times


async def main():
    parser = argparse.ArgumentParser(description="Benchmark the URL reputation plugin")
    parser.add_argument("--iterations", type=int, default=500_000, help="Iterations per scenario")
    parser.add_argument("--warmup", type=int, default=1000, help="Warmup iterations")
    parser.add_argument("--config", type=str, default="bench_config.json", help="Path to benchmark config file")
    args = parser.parse_args()

    print("URL Reputation benchmark")
    print(f"Iterations: {args.iterations} (+ {args.warmup} warmup)")

    try:
        bench_config = load_bench_config(args.config)
    except FileNotFoundError as exc:
        print(f"Error: {exc}")
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(f"Error parsing config file: {exc}")
        sys.exit(1)

    urls = bench_config.get("urls", [])
    blocked_patterns = bench_config.get("blocked_patterns", [])
    blocked_domains = bench_config.get("blocked_domains", [])
    url_multiplier = bench_config.get("url_multiplier", 1)

    if not urls:
        print("Error: No URLs found in config file")
        sys.exit(1)

    plugin_config = PluginConfig(
        name="urlrep",
        kind="cpex_url_reputation.url_reputation.URLReputationPlugin",
        hooks=[ResourceHookType.RESOURCE_PRE_FETCH],
        config={
            "blocked_domains": blocked_domains,
            "blocked_patterns": blocked_patterns,
        },
    )

    times = await run_benchmark(
        plugin_config,
        args.iterations,
        urls,
        url_multiplier,
        args.warmup,
    )

    mean = statistics.mean(times) * 1_000_000
    median = statistics.median(times) * 1_000_000
    stdev = statistics.stdev(times) * 1_000_000 if len(times) > 1 else 0

    print("\nBenchmark results")
    print(f"{'Mean (us/iter)':<24} {mean:>12.2f}")
    print(f"{'Median (us/iter)':<24} {median:>12.2f}")
    print(f"{'Std Dev (us/iter)':<24} {stdev:>12.2f}")
    print(f"{'Iterations':<24} {len(times):>12}")


if __name__ == "__main__":
    asyncio.run(main())
