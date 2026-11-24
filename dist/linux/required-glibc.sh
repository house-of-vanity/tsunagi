#!/usr/bin/env bash
# Print the highest glibc symbol version imported by the Linux tray binary.
set -euo pipefail
export LC_ALL=C

minimum=$(objdump -T "$1" |
    sed -nE '/\*UND\*/s/.*GLIBC_([0-9]+(\.[0-9]+)+).*/\1/p' |
    sort -V | tail -n 1)
if [[ -z "$minimum" ]]; then
    echo "No versioned glibc imports found in $1" >&2
    exit 1
fi
printf '%s\n' "$minimum"
