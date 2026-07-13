#!/usr/bin/env python3
"""Enumerate call/jmp sites in .text that still target the Themida wrapper
section (missed imports unlicense failed to detect+patch).

In a correctly unpacked dump these are ~0: every wrapper call becomes
FF15/FF25 -> IAT. Remaining rel E8/E9 or indirect FF15/FF25 into the packer
wrapper section are undetected wrappers = missing imports.

Usage: python tools/find_missed_wrappers.py <dump.exe> <wrapper_sec> [--samples N]
"""
import sys
import argparse
from collections import Counter

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64


def run(path, wrap_name, samples):
    pe = pefile.PE(path, fast_load=True)
    ib = pe.OPTIONAL_HEADER.ImageBase
    is64 = pe.OPTIONAL_HEADER.Magic == 0x20b
    md = Cs(CS_ARCH_X86, CS_MODE_64 if is64 else CS_MODE_32)

    text = wlo = whi = None
    tbytes = None
    range_mode = "-" in wrap_name and wrap_name.startswith("0x")
    if range_mode:
        a, b = wrap_name.split("-")
        wlo, whi = int(a, 16), int(b, 16)
    for s in pe.sections:
        nm = s.Name.rstrip(b"\x00").decode("latin1")
        lo = s.VirtualAddress + ib
        hi = s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData) + ib
        if nm == ".text":
            text = (lo, hi); tbytes = s.get_data()
        if not range_mode and nm == wrap_name:
            wlo, whi = lo, hi
    assert text and wlo, f"sections not found (.text / {wrap_name})"
    tlo, thi = text

    hits = []
    enc = Counter()
    # Anchored scan: only decode where an opcode of interest starts, then verify
    # the decoded instruction's target lands in the wrapper section. A random
    # rel32 hitting the exact wrapper window is unlikely -> low false positives.
    n = len(tbytes)
    i = 0
    while i < n - 6:
        b = tbytes[i]
        b2 = tbytes[i + 1]
        cand = (b in (0xE8, 0xE9)) or (b == 0xFF and b2 in (0x15, 0x25)) \
            or (b == 0x0F) or (b2 == 0xE9 and b == 0x90)
        if not cand:
            i += 1
            continue
        try:
            ins = next(md.disasm(tbytes[i:i + 8], tlo + i))
        except StopIteration:
            i += 1
            continue
        if ins.mnemonic in ("call", "jmp"):
            op = ins.operands[0] if md.detail else None
            # capstone without detail: recompute target from bytes for rel forms
            tgt = None
            if ins.bytes[0] in (0xE8, 0xE9) and ins.size == 5:
                rel = int.from_bytes(ins.bytes[1:5], "little", signed=True)
                tgt = ins.address + 5 + rel
            elif ins.bytes[0] == 0xFF and ins.bytes[1] in (0x15, 0x25) and ins.size == 6:
                disp = int.from_bytes(ins.bytes[2:6], "little", signed=True)
                # rel form only meaningful on x64 (RIP); on x86 it's absolute
                if is64:
                    tgt = ins.address + 6 + disp
                else:
                    tgt = disp
            if tgt is not None and wlo <= tgt < whi:
                hits.append((ins.address, ins.mnemonic, ins.bytes.hex(), tgt))
                enc[f"{ins.mnemonic} {ins.bytes[:2].hex()}"] += 1
        i += 1

    print(f"\n=== {path} ({'x64' if is64 else 'x86'}) ===")
    print(f".text {hex(tlo)}-{hex(thi)}  wrapper[{wrap_name}] {hex(wlo)}-{hex(whi)}")
    print(f"MISSED wrapper call sites (.text -> {wrap_name}): {len(hits)}")
    for k, v in enc.most_common():
        print(f"   {v:6d}  {k}")
    for (a, m, by, t) in hits[:samples]:
        print(f"   0x{a:x}: {m} {by} -> 0x{t:x}")
    return hits


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("dump")
    ap.add_argument("wrapper_section")
    ap.add_argument("--samples", type=int, default=20)
    a = ap.parse_args()
    run(a.dump, a.wrapper_section, a.samples)
