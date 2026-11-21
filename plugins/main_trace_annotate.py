#!/usr/bin/env python3
"""
Annotate a main_trace trace with full instructions from objdump.

Usage:
    plugins/main_trace_annotate.py <binary> [trace.txt] > annotated.txt

Each trace line (an offset such as 0x7a8) becomes:
    0x7a8      main+0x0             a9bd7bfd  stp x29, x30, [sp, #-48]!

Offsets that objdump didn't disassemble (e.g. inside shared libraries
such as libc) are printed with "?".

Set OBJDUMP to use a different objdump, e.g. OBJDUMP=aarch64-linux-gnu-objdump
when running on a non-ARM machine.
"""
import os
import re
import subprocess
import sys

# objdump lines look like:
#   00000000000007a8 <main>:
#    7a8:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
FUNC_LINE = re.compile(r"^([0-9a-f]+) <(.+)>:$")
INSN_LINE = re.compile(r"^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(.*)$")


def disassemble(binary):
    """Return {offset: (function+offset, encoding, instruction text)}."""
    objdump = os.environ.get("OBJDUMP", "objdump")
    out = subprocess.run([objdump, "-d", binary],
                         capture_output=True, text=True, check=True).stdout

    insns = {}
    func_name, func_start = "?", 0
    for line in out.splitlines():
        m = FUNC_LINE.match(line)
        if m:
            func_start, func_name = int(m.group(1), 16), m.group(2)
            continue
        m = INSN_LINE.match(line)
        if m:
            addr = int(m.group(1), 16)
            encoding = m.group(2)
            text = " ".join(m.group(3).split())   # collapse objdump's tabs
            where = f"{func_name}+{addr - func_start:#x}"
            insns[addr] = (where, encoding, text)
    return insns


def main():
    if len(sys.argv) not in (2, 3):
        sys.exit(__doc__.strip())

    binary = sys.argv[1]
    trace_path = sys.argv[2] if len(sys.argv) == 3 else "main_trace.txt"
    insns = disassemble(binary)

    with open(trace_path) as trace:
        for line in trace:
            line = line.strip()
            if not line:
                continue
            where, encoding, text = insns.get(int(line, 16), ("?", "?", "?"))
            print(f"{line:<10} {where:<20} {encoding:<9} {text}")


if __name__ == "__main__":
    main()
