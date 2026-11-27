#!/bin/sh
# Baseline for the confinement pack (confinement/README.md). plant runs it unplanted first and
# requires it to pass; each control replaces this file with one attack that must then fail.
#
# On the confined runner it must run under zwinger: ZWINGER_PROFILE and ZWINGER_GRANTS set.
# An unconfined run fails here, so every control goes red-baseline instead of passing. The
# stand-in manifest sets ZW_REQUIRE_CONFINED=0, because the stand-in runs unconfined on purpose.
set -eu
if [ "${ZW_REQUIRE_CONFINED:-1}" = 1 ]; then
  [ -n "${ZWINGER_PROFILE:-}" ] || { echo "not confined: ZWINGER_PROFILE unset" >&2; exit 1; }
  [ -n "${ZWINGER_GRANTS:-}" ] || { echo "not confined: ZWINGER_GRANTS unset" >&2; exit 1; }
fi
t="${RUNNER_TEMP:?RUNNER_TEMP unset}/zwinger-baseline-$$"
echo ok > "$t"
rm -f "$t"
echo "baseline: ok (profile ${ZWINGER_PROFILE:-none})"
