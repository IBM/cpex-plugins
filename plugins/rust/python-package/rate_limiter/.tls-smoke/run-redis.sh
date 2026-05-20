#!/usr/bin/env bash
# Starts a TLS-enabled Redis (in Docker) on port 6390 for the plugin-level
# smoke test.
#
# ``--tls-auth-clients optional`` lets a single instance serve both Combo 2
# (no client cert presented) and Combo 4 (client cert presented) in the same
# smoke run.  Strict mTLS (``yes``) would block Combo 2; ``no`` would let
# Combo 4's client cert through without actually verifying it.
#
# Plain ``redis://`` for Combo 1 expects a separate Redis on the default
# port 6379 -- the smoke script skips Combo 1 gracefully if nothing is
# listening there.  Either point an existing local Redis at 6379 or skip;
# the meaningful new-code coverage is in Combos 2 and 4.
#
# Run from the plugin directory:
#
#     ./.tls-smoke/run-redis.sh
#
# Ctrl-C to stop.  The container is named ``rl-smoke-tls-redis`` and is
# removed automatically on exit (``--rm``).  Counters persist only in
# memory; restarting the script wipes them.

set -euo pipefail

CERT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/certs" && pwd)"

exec docker run --rm -it \
    --name rl-smoke-tls-redis \
    -p 6390:6390 \
    -v "${CERT_DIR}:/certs:ro" \
    redis:7 \
    redis-server \
        --tls-port 6390 \
        --port 0 \
        --tls-cert-file /certs/redis.crt \
        --tls-key-file /certs/redis.key \
        --tls-ca-cert-file /certs/ca.crt \
        --tls-auth-clients optional \
        --loglevel notice
