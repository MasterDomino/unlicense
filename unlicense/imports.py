import bisect
import logging
import struct
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from capstone import Cs  # type: ignore
from capstone.x86 import X86_OP_MEM, X86_OP_IMM  # type: ignore

from .dump_utils import pointer_size_to_fmt
from .process_control import Architecture, MemoryRange, ProcessController, ProcessControllerException

LOG = logging.getLogger(__name__)

# Describes a map of API addresses to every call site that should point to it
# (instr_addr, call_size, instr_was_jmp)
ImportCallSiteInfo = Tuple[int, int, bool]
ImportToCallSiteDict = Dict[int, List[ImportCallSiteInfo]]
# Describes a set of all found call sites
# (instr_addr, call_size, instr_was_jmp, call_dest, ptr_addr)
ImportWrapperInfo = Tuple[int, int, bool, int, Optional[int]]
WrapperSet = Set[ImportWrapperInfo]
# Describes a map of API addresses to every raw data cell that holds their
# (process-instance-specific, live-only) address
DataCellDict = Dict[int, List[int]]
# Describes a set of data cells whose value points to an unresolved wrapper
# stub rather than directly to a named export: (cell_addr, wrapper_target_addr)
DataCellWrapperSet = Set[Tuple[int, int]]


def find_wrapped_imports(
    text_section_range: MemoryRange,
    exports_dict: Dict[int, Dict[str, Any]],  #
    md: Cs,
    process_controller: ProcessController
) -> Tuple[ImportToCallSiteDict, WrapperSet]:
    """
    Go through a code section and try to find wrapped (or not) import calls
    and jmps by disassembling instructions and using a few basic heuristics.
    """
    arch = process_controller.architecture
    ptr_size = process_controller.pointer_size
    ptr_format = pointer_size_to_fmt(ptr_size)

    # Not supposed to be None
    assert text_section_range.data is not None
    text_section_data = text_section_range.data

    wrapper_set: WrapperSet = set()
    api_to_calls: ImportToCallSiteDict = defaultdict(list)
    i = 0
    while i < text_section_range.size:
        # Quick pre-filter
        if not _is_wrapped_thunk_jmp(text_section_data, i) and \
                not _is_wrapped_call(text_section_data, i) and \
                not _is_wrapped_tail_call(text_section_data, i) and \
                not _is_indirect_call(text_section_data, i) and \
                not _is_indirect_jmp(text_section_data, i):
            i += 1
            continue

        # Check if the instruction is a jmp or should be replaced with a jmp.
        # This include checking for tail calls ("jmp X; int 3").
        if text_section_data[i] == 0xE9 or \
                text_section_data[i:i + 2] == bytes([0x90, 0xE9]) or \
                text_section_data[i:i + 2] == bytes([0xFF, 0x25]) or \
                _is_wrapped_tail_call(text_section_data, i):
            instr_was_jmp = True
        else:
            instr_was_jmp = False

        instr_addr = text_section_range.base + i
        instrs = md.disasm(text_section_data[i:i + 6], instr_addr)

        # Ensure the instructions are "call/jmp" or "nop; call/jmp"
        instruction = next(instrs)
        if instruction.mnemonic in ["call", "jmp"]:
            call_size = instruction.size
            op = instruction.operands[0]
        elif instruction.mnemonic == "nop":
            instruction = next(instrs)
            if instruction.mnemonic in ["call", "jmp"]:
                call_size = instruction.size
                op = instruction.operands[0]
            else:
                i += 1
                continue
        else:
            i += 1
            continue

        # Parse destination address or ignore in case of error
        if op.type == X86_OP_IMM:
            call_dest = op.value.imm
            ptr_addr = None
        elif op.type == X86_OP_MEM:
            try:
                if arch == Architecture.X86_32:
                    ptr_addr = op.value.mem.disp
                    data = process_controller.read_process_memory(
                        ptr_addr, ptr_size)
                    call_dest = struct.unpack(ptr_format, data)[0]
                elif arch == Architecture.X86_64:
                    ptr_addr = instruction.address + instruction.size + op.value.mem.disp
                    data = process_controller.read_process_memory(
                        ptr_addr, ptr_size)
                    call_dest = struct.unpack(ptr_format, data)[0]
                else:
                    raise NotImplementedError(
                        f"Unsupported architecture: {arch}")
            except ProcessControllerException:
                i += 1
                continue
        else:
            i += 1
            continue

        # Verify that the destination is outside of the .text section
        if not text_section_range.contains(call_dest):
            # Not wrapped, add it to list of "resolved wrappers"
            if call_dest in exports_dict:
                api_to_calls[call_dest].append(
                    (instr_addr, call_size, instr_was_jmp))
                i = _advance_past_wrapped_call(text_section_data, i, call_size)
                continue
            # Wrapped, add it to set of wrappers to resolve
            if _is_in_executable_range(call_dest, process_controller):
                wrapper_set.add((instr_addr, call_size, instr_was_jmp,
                                 call_dest, ptr_addr))
                i = _advance_past_wrapped_call(text_section_data, i, call_size)
                continue
        i += 1

    return api_to_calls, wrapper_set


def enumerate_executable_ranges(
        process_controller: ProcessController) -> List[MemoryRange]:
    """
    Fetch every executable memory range across all loaded modules in ONE bulk
    pass (a handful of RPC calls -- one per loaded module). Meant to be
    fetched once and reused for any number of local containment checks
    afterwards, instead of querying per-address via `find_range_by_address`
    (a fresh RPC round-trip every time), which is fine for the low call
    volume in `find_wrapped_imports` (gated by a narrow instruction-shape
    pre-filter) but would be ruinously slow for `find_stale_data_pointers`
    (which has no such pre-filter and checks every pointer-sized cell in the
    section -- millions of candidates, meaning millions of RPC round-trips
    if done one at a time).
    """
    ranges: List[MemoryRange] = []
    for module_name in process_controller.enumerate_modules():
        ranges += process_controller.enumerate_module_ranges(
            module_name, include_data=False)
    return [r for r in ranges if r.protection[2] == 'x']


# Sorted (non-overlapping) range bounds for O(log n) local containment
# checks: (sorted range-start addresses, matching range-end addresses)
SortedRanges = Tuple[List[int], List[int]]


def _sort_ranges(ranges: List[MemoryRange]) -> SortedRanges:
    """
    Precompute a sorted view of a range list for fast repeated containment
    checks. OS-reported memory ranges don't overlap, so bisecting on the
    start address alone is sufficient to find the one candidate range that
    could contain a given address.
    """
    ordered = sorted(ranges, key=lambda r: r.base)
    return [r.base for r in ordered], [r.base + r.size for r in ordered]


def _sorted_ranges_contains(sorted_ranges: SortedRanges, address: int) -> bool:
    """
    O(log n) containment check against a pre-sorted range list -- with
    millions of candidate addresses to check (see `find_stale_data_pointers`),
    even a fast local linear scan over every range would add up; this keeps
    each check to a handful of comparisons regardless of how many ranges
    there are.
    """
    bases, ends = sorted_ranges
    idx = bisect.bisect_right(bases, address) - 1
    return idx >= 0 and address < ends[idx]


def find_stale_data_pointers(
    text_section_range: MemoryRange,
    exports_dict: Dict[int, Dict[str, Any]],
    executable_ranges: List[MemoryRange],
    ptr_size: int,
) -> Tuple[DataCellDict, DataCellWrapperSet]:
    """
    Scan the section for pointer-sized, naturally-aligned data cells whose
    value (at scan time, while the target process is still alive) is a
    currently-resolved export address or points to an executable wrapper stub.

    Unlike `find_wrapped_imports`, this doesn't look for call/jmp instruction
    byte patterns -- it looks for raw pointer VALUES sitting inertly in data,
    e.g. a packer-maintained "resolved wrapper cache" table. Such tables are
    walked as plain data by legitimate CRT startup code (`_initterm`,
    `_initterm_e`, iterating their own C++ static-initializer arrays), not
    referenced via any call/jmp instruction in `.text` -- so
    `find_wrapped_imports`'s instruction-shaped pre-filter never considers
    them, regardless of how many indirect-call/jmp forms it recognizes. Left
    untouched, the dump keeps the ORIGINAL run's live (ASLR-randomized)
    absolute address baked in verbatim, which is only valid for that one
    process instance -- every subsequent run gets a different randomized base
    for the exporting DLL, so the frozen pointer dereferences into unmapped
    memory and crashes.

    `executable_ranges` must be pre-fetched (see `enumerate_executable_ranges`)
    -- with no instruction-shape pre-filter, this scans every pointer-sized
    cell in the section (millions, for a large `.text`), so classifying each
    candidate via a live RPC call would be far too slow.
    """
    ptr_format = pointer_size_to_fmt(ptr_size)
    sorted_ranges = _sort_ranges(executable_ranges)

    assert text_section_range.data is not None
    data = text_section_range.data

    api_to_cells: DataCellDict = defaultdict(list)
    wrapper_cells: DataCellWrapperSet = set()

    n = len(data)
    base = text_section_range.base
    i = 0
    while i + ptr_size <= n:
        cell_addr = base + i
        value = struct.unpack(ptr_format, data[i:i + ptr_size])[0]
        if not text_section_range.contains(value):
            if value in exports_dict:
                api_to_cells[value].append(cell_addr)
            elif _sorted_ranges_contains(sorted_ranges, value):
                wrapper_cells.add((cell_addr, value))
        i += ptr_size

    return api_to_cells, wrapper_cells


def _advance_past_wrapped_call(code_section_data: bytes, offset: int,
                               call_size: int) -> int:
    """
    Return the offset right after a matched wrapped call/jmp.

    The wrapped forms are padded by a single nop/int3 byte: either a leading
    `nop` (the `90 E8`/`90 E9` forms, where `offset` points at the nop) or a
    trailing `0x90`/`0xCC` (the `E8 rel32 90` / tail-call forms). Bare 6-byte
    `FF15`/`FF25` indirect calls have NO such padding, so blindly skipping an
    extra byte over-advances by one and drops the wrapped call that immediately
    follows (e.g. the very common `FF15 ...; E8 ...; 90` sequence) -- which is
    how import call sites (and whole imports) went missing on both x86 and x64.
    """
    pad = 0
    if code_section_data[offset] == 0x90:
        # Leading-nop form: `call_size` is the call length, the nop is extra.
        pad = 1
    elif offset + call_size < len(code_section_data) and \
            code_section_data[offset + call_size] in (0x90, 0xCC):
        # Trailing nop/int3 padding is part of the wrapped form.
        pad = 1
    return offset + call_size + pad


def _is_indirect_call(code_section_data: bytes, offset: int) -> bool:
    """
    Check if the instruction at `offset` is an `FF15` call.
    """
    return code_section_data[offset:offset + 2] == bytes([0xFF, 0x15])


def _is_indirect_jmp(code_section_data: bytes, offset: int) -> bool:
    """
    Check if the instruction at `offset` is a bare `FF25` jmp through a
    pointer cell (`jmp qword [rip+disp]`), e.g. a one-instruction import
    thunk. Unlike `_is_wrapped_thunk_jmp`, this doesn't require any specific
    trailing byte -- without it, a standalone `FF25` thunk that isn't
    immediately followed by 0x8B/0xC0 matches none of the wrapper predicates
    and is silently skipped, leaving its cached pointer (often a
    process-specific runtime address) unpatched.
    """
    return code_section_data[offset:offset + 2] == bytes([0xFF, 0x25])


def _is_wrapped_thunk_jmp(code_section_data: bytes, offset: int) -> bool:
    """
    Check if the instruction at `offset` is a wrapped jmp from a thunk table.
    """
    if offset > len(code_section_data) - 6:
        return False

    is_e9_jmp = code_section_data[offset] == 0xE9
    # Dirty trick to catch last elements of thunk tables
    if offset > 6:
        jmp_behind = code_section_data[offset - 5] == 0xE9 or \
                     code_section_data[offset - 6] == 0xE9
    else:
        jmp_behind = False

    return (is_e9_jmp and code_section_data[offset + 6] in [0xE9, 0x90]) or \
           (is_e9_jmp and code_section_data[offset + 5] in [0xCC, 0x90, 0xE9]) or \
           (code_section_data[offset:offset + 2] == bytes([0x90, 0xE9])) or \
           (is_e9_jmp and jmp_behind) or \
           (code_section_data[offset:offset + 2] == bytes([0xFF, 0x25]) and code_section_data[offset + 6] in [0x8B, 0xC0]) # Turbo delphi-style tuhnk


def _is_wrapped_call(code_section_data: bytes, offset: int) -> bool:
    """
    Check if the instruction at `offset` is a wrapped import call. Themida 2.x
    replaces `FF15` calls with `E8` calls followed or preceded by a `nop`.
    """
    return (code_section_data[offset] == 0xE8 and code_section_data[offset + 5] == 0x90) or \
           (code_section_data[offset:offset + 2] == bytes([0x90, 0xE8]))


def _is_wrapped_tail_call(code_section_data: bytes, offset: int) -> bool:
    """
    Check if the instruction at `offset` is a tail call (and thus should be
    transformed into a `jmp`).
    """
    is_call = code_section_data[offset] == 0xE8
    return (is_call and code_section_data[offset + 5] == 0xCC) or \
            (is_call and code_section_data[offset + 6] == 0xCC) or \
            (code_section_data[offset:offset + 2] == bytes([0x90, 0xE8])
            and code_section_data[offset + 6] == 0xCC) or (
                code_section_data[offset:offset + 2] == bytes([0xFF, 0x25])
                and code_section_data[offset + 6] == 0xCC)


def _is_in_executable_range(address: int,
                            process_controller: ProcessController) -> bool:
    """
    Check if an address is located in an executable memory range.
    """
    mem_range = process_controller.find_range_by_address(address)
    if mem_range is None:
        return False

    protection: str = mem_range.protection[2]
    return protection == 'x'
