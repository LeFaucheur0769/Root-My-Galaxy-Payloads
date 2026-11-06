#!/usr/bin/env python3
"""Flat-map AArch64 helper for raw Samsung bootloaders (sboot.bin and friends).

sboot.bin is a flat blob: it is copied to its load base and executed there, so
runtime VA = load_base + file_offset.  PC-relative addressing (adrp/adr/add)
therefore resolves identically whether we assume load_base 0 or not, which makes
file offsets directly usable as VMA for disassembly and cross-reference.

commands:
  xref <file> <target-file-offset>   find adrp+add pairs pointing at the offset
  dis <file> <start> <end>           flat disassembly (VMA == file offset)
  scan <file>                        report the branch/jump shape near a load
                                     constant, used for the physical-load proof
"""

import capstone as cs
import re
import struct
import sys

UM = cs.Cs(cs.CS_ARCH_ARM64, cs.CS_MODE_ARM)
UM.detail = True


def read(path):
    return open(path, "rb").read()


def disasm(data, start, end):
    out = []
    for ins in UM.disasm(data[start:end], start):
        out.append(f"{ins.address:#08x}: {ins.bytes.hex()} {ins.mnemonic}\t{ins.op_str}".rstrip())
    return out


def sign_ext(v, bits):
    if v >> (bits - 1):
        return v - (1 << bits)
    return v


def adrp_decode(word, pc):
    """Return (rd, page_target) for an adrp encoding, else None."""
    if (word & 0x9F00001F) != 0x90000000:
        return None
    immlo = (word >> 30) & 0x3
    imm20 = (word >> 5) & 0xFFFFF
    imm = sign_ext((imm20 << 2) | immlo, 21)
    page = (pc & ~0xFFF) + imm * 0x1000
    return word & 0x1F, page


def add_imm_decode(word):
    """Return (rd, rn, imm) for ADD (immediate) 64-bit with LSL #12, else None."""
    if (word & 0xFF800000) != 0x91000000:
        return None
    return (word & 0x1F), (word >> 5) & 0x1F, (word >> 10) & 0xFFF


def xref(data, target, limit=400):
    hits = []
    for off in range(0, len(data) - 8, 4):
        w = struct.unpack_from("<I", data, off)[0]
        a = adrp_decode(w, off)
        if a is None:
            continue
        rd, page = a
        w2 = struct.unpack_from("<I", data, off + 4)[0]
        ai = add_imm_decode(w2)
        if ai is not None and ai[0] == rd and (page + ai[2]) == target:
            hits.append(("adrp+add", off, target))
            continue
        if page == (target & ~0xFFF) and _branch_near(data, off, 12):
            hits.append(("adrp+ref", off, target))
    return hits[:limit]


def _branch_near(data, off, span):
    for i in range(off, min(off + span, len(data) - 4), 4):
        w = struct.unpack_from("<I", data, i)[0]
        if (w & 0xFC000000) in (0x14000000, 0x94000000) or (w & 0x3FE0FC00) == 0x2A000000:
            return True
    return False


def main():
    cmd = sys.argv[1]
    data = read(sys.argv[2])
    if cmd == "dis":
        start = int(sys.argv[3], 0)
        end = int(sys.argv[4], 0)
        for line in disasm(data, start, end):
            print(line)
    elif cmd == "xref":
        target = int(sys.argv[3], 0)
        for kind, off, tgt in xref(data, target):
            print(f"{kind} at {off:#08x} -> {tgt:#08x}")
    elif cmd == "find":
        pat = sys.argv[3].encode()
        for m in re.finditer(re.escape(pat), data):
            print(f"string {pat!r} at {m.start():#08x}")
    else:
        raise SystemExit("usage: sboot_disasm.py {dis|xref|find} file ...")


if __name__ == "__main__":
    main()
