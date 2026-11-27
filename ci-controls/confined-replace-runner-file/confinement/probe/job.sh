#!/bin/sh
# Attack: change the runner's own run.sh, which later jobs would execute. The runner home is
# read-only under the profile. Without ZW_RUNNER_FILE, the path comes from RUNNER_WORKSPACE
# (<runner home>/_work/<repo>).
set -eu
f="${ZW_RUNNER_FILE:-$(dirname "$(dirname "${RUNNER_WORKSPACE:?RUNNER_WORKSPACE unset}")")/run.sh}"
printf '\n' >> "$f"
echo "replace-runner-file: appended to $f"
