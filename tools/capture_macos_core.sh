#!/bin/sh
# Copyright 2026 paundraP. Licensed under the Volatility Software License 1.0.
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 OUTPUT.core EXECUTABLE" >&2
    exit 2
fi

output=$1
shift
executable=$1

if [ ! -x "$executable" ]; then
    echo "not an executable: $executable" >&2
    exit 2
fi

# The target is launched as a child, so no third-party task_for_pid entitlement
# is needed.  Developer Tools approval is still required by macOS debugserver.
lldb --batch \
    -o "target create $executable" \
    -o "process launch --stop-at-entry" \
    -o "process save-core -s full $output" \
    -o "process kill"

echo "wrote $output"
shasum -a 256 "$output"
