#!/usr/bin/env bash
# Gate for the AADL model (REQ-ZW-016, VER-ZW-007). Runs spar on the component type and on the
# reference mesh and fails unless:
#   1. spar reports no errors for either root;
#   2. fail-closed (DD-ZW-013): no ItemCommission propagates anywhere. spar's propagation pass
#      ignores sinks and over-approximates, so an absence it reports is an absence;
#   3. telemetry (DD-ZW-013): a lost event still reaches warte unflagged. This is a known gap
#      pinned on purpose: closing it flips this check, and the decision must be updated with it;
#   4. timing (DD-ZW-014): the Pi's event stream has a WCTT bound, at most WCTT_BUDGET_PS.
#   5. lifecycle (REQ-ZW-018): spar modes finds no dead transition, refused and exited are
#      terminal, and confined is entered only from preflight;
#   6. both roots instantiate with the expected number of components.
#
# Usage: architecture/check.sh [DIR]   (DIR holds zwinger.aadl, zwinger_profile.aadl and
#        reference_mesh.aadl)
# Needs spar and jq on PATH.
set -euo pipefail

dir="${1:-$(dirname "$0")}"
WCTT_BUDGET_PS=1000000000   # 1 ms: events are not real-time; a lost or 30x bound must fail
fail=0

analyze() {
  local out
  out="$(spar analyze --root "$1" --format json "${@:2}")" || {
    echo "spar analyze $1 exited non-zero" >&2
    exit 1
  }
  printf '%s' "$out"
}

node="$(analyze Zwinger::Node.Confined "$dir/zwinger.aadl")"
mesh="$(analyze Zwinger_Reference_Mesh::Mesh.TwoNodes "$dir/zwinger.aadl" "$dir/zwinger_profile.aadl" "$dir/reference_mesh.aadl")"

for pair in "node:$node" "mesh:$mesh"; do
  name="${pair%%:*}"
  json="${pair#*:}"
  n="$(jq '.diagnostics | length' <<<"$json")"
  errs="$(jq '[.diagnostics[] | select(.severity == "error")] | length' <<<"$json")"
  # Zero diagnostics means spar analysed nothing, not that the model is clean.
  if [ "$n" -eq 0 ]; then echo "FAIL $name: spar returned no diagnostics at all"; fail=1; fi
  comps="$(jq '[.instance | .. | objects | select(has("category"))] | length' <<<"$json")"
  want=7; [ "$name" = mesh ] && want=21   # 2 nodes x 7, warte, 2 NICs, LAN, 2 remote services, root
  if [ "$comps" -ne "$want" ]; then
    echo "FAIL $name: instance has $comps components, expected $want"; fail=1
  else
    echo "ok   $name: instance has $comps components"
  fi
  if [ "$errs" -ne 0 ]; then
    echo "FAIL $name: $errs spar error(s)"
    jq -r '.diagnostics[] | select(.severity == "error") | "  " + .message' <<<"$json"
    fail=1
  else
    echo "ok   $name: 0 errors in $n diagnostics"
  fi
  commission="$(jq '[.diagnostics[] | select(.data.error_type? == "ItemCommission")] | length' <<<"$json")"
  if [ "$commission" -ne 0 ]; then
    echo "FAIL $name: an ItemCommission propagates, so some fault becomes access the profile did not grant"
    jq -r '.diagnostics[] | select(.data.error_type? == "ItemCommission") | "  " + .data.origin + " -> " + (.data.downstream | join(", "))' <<<"$json"
    fail=1
  else
    echo "ok   $name: no ItemCommission propagates (fail-closed)"
  fi
done

# The device node's lost event crosses the NICs to warte: session -> probe -> pi_nic -> mac_nic -> warte.
lost="$(jq '[.diagnostics[] | .data? // {} | select(.error_type == "ServiceOmission" and .origin == "Mesh.TwoNodes.devices.session") | select([.downstream[]] | (index("Mesh.TwoNodes.pi_nic") != null) and (index("Mesh.TwoNodes.mac_nic") != null) and (index("Mesh.TwoNodes.warte") != null))] | length' <<<"$mesh")"
if [ "$lost" -eq 0 ]; then
  echo "FAIL mesh: a lost event no longer reaches warte unflagged; if that gap is closed, update DD-ZW-013 and this check"
  fail=1
else
  echo "ok   mesh: known gap pinned: a lost event reaches warte as a silent omission"
fi

bound="$(jq -r '[.diagnostics[] | select(.analysis == "wctt") | .data? // {} | select((.stream // "") | startswith("e_lan ")) | .bound_ps] | first // empty' <<<"$mesh")"
if [ -z "$bound" ]; then
  echo "FAIL mesh: no WCTT bound for the Pi's event stream (e_lan)"
  fail=1
elif [ "$bound" -gt "$WCTT_BUDGET_PS" ]; then
  echo "FAIL mesh: WCTT of e_lan is $bound ps, over the $WCTT_BUDGET_PS ps budget"
  fail=1
else
  echo "ok   mesh: WCTT of e_lan is $bound ps (budget $WCTT_BUDGET_PS ps)"
fi

# Lifecycle, from the SMV transition relation spar exports.
smv="$(spar modes --root Zwinger::Node.Confined --format smv "$dir/zwinger.aadl")" || { echo "spar modes exited non-zero" >&2; exit 1; }
trans="$(sed -n '/^  TRANS/,/esac/p' <<<"$smv" | grep ' : next(state)' | grep -v '^ *TRUE ' || true)"
if [ -z "$trans" ]; then
  echo "FAIL lifecycle: no transition relation for the session"; fail=1
else
  if grep -q 'DEAD TRANSITION' <<<"$smv"; then echo "FAIL lifecycle: dead transition"; grep 'DEAD TRANSITION' <<<"$smv"; fail=1; else echo "ok   lifecycle: no dead transition"; fi
  if grep -Eq 'state = (refused|exited) :' <<<"$trans"; then echo "FAIL lifecycle: a transition leaves refused or exited"; fail=1; else echo "ok   lifecycle: refused and exited are terminal"; fi
  into="$(grep -E 'next\(state\) (= confined|in \{[^}]*confined)' <<<"$trans" | sed -E 's/^ *state = ([a-z_]+) :.*/\1/' | sort -u | tr '\n' ' ')"
  if [ "$into" != "preflight " ]; then echo "FAIL lifecycle: confined entered from: ${into:-nothing}"; fail=1; else echo "ok   lifecycle: confined is entered only from preflight"; fi
fi

exit "$fail"
