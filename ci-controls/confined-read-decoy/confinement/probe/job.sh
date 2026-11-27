#!/bin/sh
# Attack: read a file outside every grant, readable to the job's user by its mode.
set -eu
cat "${ZW_READ_TARGET:?ZW_READ_TARGET unset}" > /dev/null
echo "read-decoy: read $ZW_READ_TARGET"
