#!/usr/bin/env python3
"""Find FF15/FF25 indirect call/jmp sites in .text whose cached target (read
from the referenced data cell) is a stale, low (<4GB) runtime pointer -- the
pattern behind the CRT-init crashes seen in unpacked_Client_x64: legit
resolved x64 imports live high (0x7ffXXXXXXXXX), so a cached target that fits
in 32 bits and isn't 0/sentinel is almost certainly a frozen, process-specific
address (e.g. into a non-ASLR legacy DLL like msvcr80.dll) that's invalid on a
fresh run.

Usage: python tools/find_stale_ptr_thunks.py <dump.exe>
"""
import sys
import pefile

def run(path):
    pe = pefile.PE(path, fast_load=True)
    ib = pe.OPTIONAL_HEADER.ImageBase
    soi = pe.OPTIONAL_HEADER.SizeOfImage

    tsec = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text")
    tdata = tsec.get_data()
    tbase = tsec.VirtualAddress + ib

    seen_cells = {}
    n = len(tdata)
    i = 0
    while i < n - 6:
        if tdata[i] == 0xFF and tdata[i + 1] in (0x15, 0x25):
            disp = int.from_bytes(tdata[i + 2:i + 6], "little", signed=True)
            cell_va = tbase + i + 6 + disp
            cell_rva = cell_va - ib
            if 0 <= cell_rva < soi:
                off = pe.get_offset_from_rva(cell_rva)
                raw = pe.__data__[off:off + 8]
                if len(raw) == 8:
                    target = int.from_bytes(raw, "little")
                    STALE_LO, STALE_HI = 0x10000000, 0x100000000
                    if STALE_LO <= target < STALE_HI:
                        seen_cells.setdefault(cell_va, (target, []))[1].append(
                            (tbase + i, "call" if tdata[i+1] == 0x15 else "jmp"))
            i += 6
            continue
        i += 1

    print(f"=== {path} ===")
    print(f"distinct stale-cache cells referenced by FF15/FF25 sites: {len(seen_cells)}")
    for cell, (target, sites) in sorted(seen_cells.items()):
        print(f"  cell 0x{cell:x} -> stale target 0x{target:x}  ({len(sites)} call site(s))")
        for (addr, kind) in sites[:3]:
            print(f"      {kind} site: 0x{addr:x}  (jmp qword [0x{cell:x}] resolves to sub_{addr:x})")
    return seen_cells

if __name__ == "__main__":
    run(sys.argv[1])
