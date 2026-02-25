#!/usr/bin/env bash
# Check that all Rust source files have a valid license header.
#
# Accepts two patterns:
#   1. Mysten Labs derivative:
#        // Copyright (c) Mysten Labs, Inc.
#        // Modifications Copyright (c) <YEAR> IOTA Stiftung
#        // SPDX-License-Identifier: Apache-2.0
#
#   2. IOTA Stiftung original:
#        // Copyright (c) <YEAR> IOTA Stiftung
#        // SPDX-License-Identifier: Apache-2.0

set -euo pipefail

failed=0
checked=0

while IFS= read -r file; do
    checked=$((checked + 1))

    line1=$(sed -n '1p' "$file")
    line2=$(sed -n '2p' "$file")
    line3=$(sed -n '3p' "$file")

    # Pattern 1: Mysten Labs derivative (3 lines)
    if [[ "$line1" == "// Copyright (c) Mysten Labs, Inc." ]] &&
        [[ "$line2" =~ ^//\ Modifications\ Copyright\ \(c\)\ [0-9]{4}\ IOTA\ Stiftung$ ]] &&
        [[ "$line3" == "// SPDX-License-Identifier: Apache-2.0" ]]; then
        continue
    fi

    # Pattern 2: IOTA original (2 lines)
    if [[ "$line1" =~ ^//\ Copyright\ \(c\)\ [0-9]{4}\ IOTA\ Stiftung$ ]] &&
        [[ "$line2" == "// SPDX-License-Identifier: Apache-2.0" ]]; then
        continue
    fi

    echo "  FAIL: $file"
    failed=$((failed + 1))
done < <(git ls-files '*.rs')

if [[ $failed -ne 0 ]]; then
    echo ""
    echo "$failed file(s) with missing or invalid license header."
    echo ""
    echo "Expected one of:"
    echo "  // Copyright (c) Mysten Labs, Inc."
    echo "  // Modifications Copyright (c) <YEAR> IOTA Stiftung"
    echo "  // SPDX-License-Identifier: Apache-2.0"
    echo ""
    echo "  // Copyright (c) <YEAR> IOTA Stiftung"
    echo "  // SPDX-License-Identifier: Apache-2.0"
    exit 1
fi

echo "All $checked files have valid license headers."
