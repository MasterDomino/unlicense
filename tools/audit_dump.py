#!/usr/bin/env python3
"""Static audit of an Unlicense dump: count former-import call sites that were
NOT redirected to the rebuilt IAT and still point into packer/other sections.

A correctly unpacked dump should have ~zero "dangling" call sites: every former
import call/jmp becomes `FF15/FF25 [rip+disp]` into the import table. Missed
wrappers stay as `E8/E9 rel` (or `FF15/FF25`) pointing into a packer code
section, which crashes at runtime and shows up as missing imports.

Usage: python tools/audit_dump.py <dump.exe> [--packer SEC1,SEC2] [--dump-samples N]

No Windows execution required. Pure pefile + capstone.
"""
import sys
import argparse
from collections import Counter

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP


def _sections(pe):
    out = []
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("latin1")
        out.append((name, s.VirtualAddress,
                    s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData)))
    return out


def audit(path, packer_names=None, dump_samples=0):
    pe = pefile.PE(path, fast_load=True)
    ib = pe.OPTIONAL_HEADER.ImageBase
    is64 = pe.OPTIONAL_HEADER.Magic == 0x20b
    md = Cs(CS_ARCH_X86, CS_MODE_64 if is64 else CS_MODE_32)
    md.detail = True

    secs = _sections(pe)
    text = next(s for s in secs if s[0] == ".text")
    tname, tlo, thi = text
    tdata = None
    for s in pe.sections:
        if s.Name.rstrip(b"\x00").decode("latin1") == ".text":
            tdata = s.get_data()
            break

    # IAT region = the import directory the rebuild produced.
    impdir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[1]
    iat_lo, iat_hi = impdir.VirtualAddress, impdir.VirtualAddress + impdir.Size

    # Auto-detect packer sections: executable, non-.text, non-resource.
    if packer_names is None:
        packer = [(n, lo, hi) for (n, lo, hi) in secs
                  if n not in (".text", ".rsrc", ".idata", ".pdata", ".SCY",
                               ".reloc") and not n.startswith(".")]
    else:
        want = set(packer_names)
        packer = [(n, lo, hi) for (n, lo, hi) in secs if n in want]

    def in_ranges(rva, ranges):
        return any(lo <= rva < hi for (_, lo, hi) in ranges)

    def which(rva):
        for (n, lo, hi) in secs:
            if lo <= rva < hi:
                return n
        return "<oob>"

    into_iat = 0
    into_packer = 0
    into_text = 0
    into_other = 0
    packer_samples = []
    enc_counter = Counter()

    # Linear sweep. Themida .text is huge; linear disasm is imperfect but the
    # ratio between dumps is what matters, and packer-targeted rel branches are
    # a strong, low-false-positive signal.
    for ins in md.disasm(tdata, tlo + ib):
        if ins.mnemonic not in ("call", "jmp"):
            continue
        op = ins.operands[0]
        tgt = None
        indirect = False
        if op.type == X86_OP_IMM:
            tgt = op.value.imm  # absolute VA (capstone resolves rel)
        elif op.type == X86_OP_MEM and op.value.mem.base == X86_REG_RIP:
            tgt = ins.address + ins.size + op.value.mem.disp
            indirect = True
        else:
            continue
        rva = tgt - ib
        if iat_lo <= rva < iat_hi:
            into_iat += 1
        elif in_ranges(rva, packer):
            into_packer += 1
            enc = ins.bytes[0] if not indirect else (ins.bytes[0] << 8 | ins.bytes[1])
            enc_counter[f"{ins.mnemonic} {'ind' if indirect else 'rel'} op={ins.bytes[:2].hex()}"] += 1
            if len(packer_samples) < dump_samples:
                packer_samples.append((ins.address, ins.mnemonic, ins.bytes.hex(), which(rva), tgt))
        elif tlo <= rva < thi:
            into_text += 1
        else:
            into_other += 1

    print(f"\n=== {path} ({'x64' if is64 else 'x86'}) base=0x{ib:x} ===")
    print(f".text: 0x{tlo+ib:x}-0x{thi+ib:x}  IAT(import dir): RVA 0x{iat_lo:x}-0x{iat_hi:x}")
    print(f"packer sections: {[n for (n,_,_) in packer]}")
    print(f"call/jmp -> IAT (redirected, good):     {into_iat}")
    print(f"call/jmp -> packer section (DANGLING):  {into_packer}   <-- primary metric")
    print(f"call/jmp -> within .text (intra-code):  {into_text}")
    print(f"call/jmp -> other/oob:                  {into_other}")
    if enc_counter:
        print("dangling encodings:")
        for k, v in enc_counter.most_common(10):
            print(f"   {v:6d}  {k}")
    for (a, m, b, sec, tgt) in packer_samples:
        print(f"   site 0x{a:x}: {m} {b}  -> 0x{tgt:x} ({sec})")
    return into_packer


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("dump")
    ap.add_argument("--packer", default=None,
                    help="comma-separated packer section names (else auto)")
    ap.add_argument("--dump-samples", type=int, default=0)
    args = ap.parse_args()
    packer = args.packer.split(",") if args.packer else None
    audit(args.dump, packer, args.dump_samples)
