#!/usr/bin/env bash
# Publish the workspace crates to crates.io in dependency order.
# Idempotent: versions already on crates.io are skipped, so a partial failure can simply be re-run.
# crates.io rate-limits *new* crate names (HTTP 429); on that we wait and retry.
set -euo pipefail

version=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
# ponytail: hard-coded dependency order; update when a crate is added.
crates=(capyshield-policy capyshield-reach capyshield-sync capyshield-scanner capyshield-vex capyshield-proxy capyshield)
ua="capyshield-release (https://github.com/capyshield-hq/capyshield)"

for crate in "${crates[@]}"; do
  if curl -sf -A "$ua" "https://crates.io/api/v1/crates/$crate/$version" >/dev/null; then
    echo "skip $crate@$version: already on crates.io"
    continue
  fi
  for attempt in 1 2 3 4 5 6 7 8; do
    if out=$(cargo publish --locked -p "$crate" 2>&1); then
      echo "$out" | tail -2
      continue 2
    fi
    echo "$out" | tail -4
    grep -q '429' <<<"$out" || exit 1
    # crates.io says exactly when to retry ("Please try again after Tue, 24 Nov 2026 21:31:37 GMT");
    # count down to that moment, falling back to 10 minutes if the message changes.
    retry_at=$(grep -oE 'try again after [A-Za-z]{3}, [0-9]{1,2} [A-Za-z]{3} [0-9]{4} [0-9:]{8} GMT' <<<"$out" | sed 's/try again after //' || true)
    wait=600
    if [ -n "$retry_at" ] && until_ts=$(date -u -d "$retry_at" +%s 2>/dev/null); then
      wait=$(( until_ts - $(date -u +%s) + 5 ))
    fi
    (( wait < 5 )) && wait=5
    echo "rate limited by crates.io (attempt $attempt/8); retrying $crate at ${retry_at:-+10 min}"
    while (( wait > 0 )); do
      echo "  $crate: retry in ${wait}s"
      step=$(( wait < 60 ? wait : 60 ))
      sleep "$step"
      wait=$(( wait - step ))
    done
  done
  echo "giving up on $crate after 8 rate-limited attempts" >&2
  exit 1
done
