#!/bin/sh
# Attack: create a file outside every write grant, next to the decoy the deploy owns.
set -eu
echo planted > "${ZW_WRITE_TARGET:?ZW_WRITE_TARGET unset}"
echo "write-decoy: wrote $ZW_WRITE_TARGET"
