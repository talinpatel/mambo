#!/usr/bin/env bash
# Print a main_trace.bin as hex offsets (pc - load base), one per line.
# Usage: plugins/main_trace_dump.sh [main_trace.bin]
set -euo pipefail

python3 - "${1:-main_trace.bin}" <<'EOF'
import struct, sys
d = open(sys.argv[1], 'rb').read()
b, *p = struct.unpack(f'<{len(d)//8}Q', d)
print('\n'.join(hex(x - b) for x in p))
EOF
