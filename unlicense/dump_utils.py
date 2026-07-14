import gc
import logging
import os
import platform
import shutil
import struct
from tempfile import TemporaryDirectory
from typing import Dict, List, Optional, Tuple

import lief
import pyscylla  # type: ignore

from unlicense.lief_utils import lief_pe_data_directories, lief_pe_sections

from .process_control import MemoryRange, ProcessController

LOG = logging.getLogger(__name__)


def get_section_ranges(pe_file_path: str) -> List[MemoryRange]:
    section_ranges: List[MemoryRange] = []
    binary = lief.PE.parse(pe_file_path)
    if binary is None:
        LOG.error("Failed to parse PE '%s'", pe_file_path)
        return section_ranges

    for section in lief_pe_sections(binary):
        section_ranges += [
            MemoryRange(section.virtual_address, section.virtual_size, "r--")
        ]

    return section_ranges


def probe_text_sections(pe_file_path: str) -> Optional[List[MemoryRange]]:
    text_sections = []
    binary = lief.PE.parse(pe_file_path)
    if binary is None:
        LOG.error("Failed to parse PE '%s'", pe_file_path)
        return None

    # Find the potential original text sections (i.e., executable sections with
    # "empty" names or named '.text*').
    # Note(ergrelet): we thus do not want to include Themida/WinLicense's
    # sections in that list.
    for section in lief_pe_sections(binary):
        section_name = section.fullname
        stripped_section_name = section_name.replace(' ',
                                                     '').replace('\00', '')
        if len(stripped_section_name) > 0 and \
                stripped_section_name not in [".text", ".textbss", ".textidx"]:
            break

        if section.has_characteristic(
                lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE):
            LOG.debug("Probed .text section at (0x%x, 0x%x)",
                      section.virtual_address, section.virtual_size)
            text_sections += [
                MemoryRange(section.virtual_address, section.virtual_size,
                            "r-x")
            ]

    return None if len(text_sections) == 0 else text_sections


def dump_pe(
    process_controller: ProcessController,
    pe_file_path: str,
    image_base: int,
    oep: int,
    iat_addr: int,
    iat_size: int,
    add_new_iat: bool,
    stale_cell_entries: Optional[List[Tuple[List[str], List[int]]]] = None,
) -> bool:
    # Reclaim as much memory as possible. This is kind of a hack for 32-bit
    # interpreters not to run out of memory when dumping.
    # Idea: `pefile` might be less memory hungry than `lief` for our use case?
    process_controller.clear_cached_data()
    gc.collect()

    with TemporaryDirectory() as tmp_dir:
        TMP_FILE_PATH1 = os.path.join(tmp_dir, "unlicense.tmp2")
        TMP_FILE_PATH2 = os.path.join(tmp_dir, "unlicense.tmp2")
        try:
            pyscylla.dump_pe(process_controller.pid, image_base, oep,
                             TMP_FILE_PATH1, pe_file_path)
        except pyscylla.ScyllaException as scylla_exception:
            LOG.error("Failed to dump PE: %s", str(scylla_exception))
            return False

        LOG.info("Fixing dump ...")
        try:
            pyscylla.fix_iat(process_controller.pid, image_base, iat_addr,
                             iat_size, add_new_iat, TMP_FILE_PATH1,
                             TMP_FILE_PATH2)
        except pyscylla.ScyllaException as scylla_exception:
            LOG.error("Failed to fix IAT: %s", str(scylla_exception))
            return False

        try:
            pyscylla.rebuild_pe(TMP_FILE_PATH2, False, True, False)
        except pyscylla.ScyllaException as scylla_exception:
            LOG.error("Failed to rebuild PE: %s", str(scylla_exception))
            return False

        LOG.info("Rebuilding PE ...")
        output_file_name = f"unpacked_{process_controller.main_module_name}"
        _fix_pe(TMP_FILE_PATH2, output_file_name)

        # Re-point stale data-cell pointers (packer "resolved import cache"
        # cells walked as data by CRT init code) at freshly-built trampolines.
        # Must run on the FINAL file: it depends on where Scylla relocated the
        # IAT, and the trampoline section is appended after everything else.
        if stale_cell_entries:
            LOG.info("Injecting %d data-cell trampoline(s) ...",
                     sum(len(cells) for _, cells in stale_cell_entries))
            _inject_data_cell_trampolines(
                output_file_name, image_base, stale_cell_entries,
                process_controller.pointer_size)

        LOG.info("Output file has been saved at '%s'", output_file_name)

    return True


def dump_dotnet_assembly(
    process_controller: ProcessController,
    image_base: int,
) -> bool:
    output_file_name = f"unpacked_{process_controller.main_module_name}"
    try:
        pyscylla.dump_pe(process_controller.pid, image_base, image_base,
                         output_file_name, None)
    except pyscylla.ScyllaException as scylla_exception:
        LOG.error("Failed to dump PE: %s", str(scylla_exception))
        return False

    LOG.info("Output file has been saved at '%s'", output_file_name)

    return True


def _fix_pe(pe_file_path: str, output_file_path: str) -> None:
    with TemporaryDirectory() as tmp_dir:
        TMP_FILE_PATH = os.path.join(tmp_dir, "unlicense.tmp")
        _rebuild_pe(pe_file_path, TMP_FILE_PATH)
        _resize_pe(TMP_FILE_PATH, output_file_path)


def _rebuild_pe(pe_file_path: str, output_file_path: str) -> None:
    binary = lief.PE.parse(pe_file_path)
    if binary is None:
        LOG.error("Failed to parse PE '%s'", pe_file_path)
        return

    # Rename sections
    _resolve_section_names(binary)

    # Disable ASLR
    binary.header.add_characteristic(
        lief.PE.HEADER_CHARACTERISTICS.RELOCS_STRIPPED)
    binary.optional_header.remove(lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE)
    # Rebuild PE
    builder = lief.PE.Builder(binary)
    builder.build_dos_stub(True)
    builder.build_overlay(True)
    builder.build()
    builder.write(output_file_path)


def _resolve_section_names(binary: lief.PE.Binary) -> None:
    for data_dir in lief_pe_data_directories(binary):
        if data_dir.type == lief.PE.DATA_DIRECTORY.RESOURCE_TABLE and \
           data_dir.section is not None:
            LOG.debug(".rsrc section found (RVA=%s)",
                      hex(data_dir.section.virtual_address))
            data_dir.section.name = ".rsrc"

    ep_address = binary.optional_header.addressof_entrypoint
    for section in lief_pe_sections(binary):
        if section.virtual_address + section.virtual_size > ep_address >= section.virtual_address:
            LOG.debug(".text section found (RVA=%s)",
                      hex(section.virtual_address))
            section.name = ".text"


def _resize_pe(pe_file_path: str, output_file_path: str) -> None:
    pe_size = _get_pe_size(pe_file_path)
    if pe_size is None:
        return None

    # Copy file
    shutil.copy(pe_file_path, output_file_path)
    # Truncate file
    with open(output_file_path, "ab") as pe_file:
        pe_file.truncate(pe_size)


def _get_pe_size(pe_file_path: str) -> Optional[int]:
    binary = lief.PE.parse(pe_file_path)
    if binary is None:
        LOG.error("Failed to parse PE '%s'", pe_file_path)
        return None

    number_of_sections = len(binary.sections)
    if number_of_sections == 0:
        # Shouldn't happen but hey
        return None

    # Determine the actual PE raw size
    highest_section = binary.sections[0]
    for section in lief_pe_sections(binary):
        # Select section with the highest offset
        if section.offset > highest_section.offset:
            highest_section = section
        # If sections have the same offset, select the one with the biggest size
        elif section.offset == highest_section.offset and section.size > highest_section.size:
            highest_section = section
    pe_size = highest_section.offset + highest_section.size

    return pe_size


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _parse_import_name_to_iat_slot(data: bytes) -> Dict[str, int]:
    """
    Parse a PE's import directory and return {import name -> IAT slot RVA}.
    """
    return {name: slot for _, name, slot in _iter_import_names(data)}


def _parse_import_name_to_dll(data: bytes) -> Dict[str, str]:
    """Parse a PE's import directory and return {import name -> DLL name}."""
    return {name: dll for dll, name, _ in _iter_import_names(data)}


def _iter_import_names(data: bytes):
    """
    Yield (dll_name, import_name, IAT slot RVA) for every named import.

    Deterministic, dependency-free (plain struct) so it doesn't rely on a
    specific `lief` version's import-parsing API. Ordinal-only imports (no
    name) are skipped -- the packer's data cells reference named exports.
    """
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    magic = struct.unpack_from("<H", data, e_lfanew + 0x18)[0]
    is_64 = magic == 0x20B
    thunk_size = 8 if is_64 else 4
    thunk_fmt = "<Q" if is_64 else "<I"
    ordinal_flag = 1 << (63 if is_64 else 31)
    # Optional header size differs 32/64; import dir is entry #1 of the data
    # directory, which starts at a fixed offset within the optional header.
    dd_offset = e_lfanew + 0x18 + (0x70 if is_64 else 0x60)
    import_rva = struct.unpack_from("<I", data, dd_offset + 1 * 8)[0]
    if import_rva == 0:
        return

    sections = _read_section_headers(data)

    def rva_to_off(rva: int) -> Optional[int]:
        for s in sections:
            if s["va"] <= rva < s["va"] + max(s["vsize"], s["rawsize"]):
                return s["rawptr"] + (rva - s["va"])
        return None

    def read_cstr(rva: int) -> str:
        off = rva_to_off(rva)
        if off is None:
            return ""
        end = data.find(b"\x00", off)
        return data[off:end].decode("latin1") if end != -1 else ""

    desc_off = rva_to_off(import_rva)
    if desc_off is None:
        return
    # IMAGE_IMPORT_DESCRIPTOR is 20 bytes; array terminated by an all-zero one.
    while True:
        orig_first_thunk, _, _, name_rva, first_thunk = struct.unpack_from(
            "<IIIII", data, desc_off)
        if orig_first_thunk == 0 and first_thunk == 0 and name_rva == 0:
            break
        dll_name = read_cstr(name_rva)
        # ILT (OriginalFirstThunk) holds the names; fall back to IAT if absent.
        lookup_rva = orig_first_thunk or first_thunk
        lookup_off = rva_to_off(lookup_rva)
        if lookup_off is not None:
            idx = 0
            while True:
                thunk = struct.unpack_from(thunk_fmt, data, lookup_off +
                                           idx * thunk_size)[0]
                if thunk == 0:
                    break
                if not thunk & ordinal_flag:
                    # thunk = RVA to IMAGE_IMPORT_BY_NAME (2-byte hint + name)
                    name = read_cstr((thunk & (ordinal_flag - 1)) + 2)
                    if name:
                        yield dll_name, name, first_thunk + idx * thunk_size
                idx += 1
        desc_off += 20


def _read_section_headers(data: bytes) -> List[Dict[str, int]]:
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    num_sections = struct.unpack_from("<H", data, e_lfanew + 0x6)[0]
    size_opt_hdr = struct.unpack_from("<H", data, e_lfanew + 0x14)[0]
    sec_table = e_lfanew + 0x18 + size_opt_hdr
    sections = []
    for i in range(num_sections):
        off = sec_table + i * 40
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, off + 8)
        sections.append({"off": off, "vsize": vsize, "va": va,
                         "rawsize": rawsize, "rawptr": rawptr})
    return sections


# kernel32 forwards many exports to ntdll under a different name (e.g.
# EnterCriticalSection -> ntdll.RtlEnterCriticalSection). Themida resolves the
# app's calls straight to the ntdll target, so frida reports the ntdll name
# (RtlEnterCriticalSection), but Scylla imports it under the kernel32 name the
# app's PE actually references. The forwarder resolves to the same code, so
# matching to the kernel32 name is functionally identical.
_FORWARDER_ALIASES = {
    "RtlAllocateHeap": "HeapAlloc",
    "RtlReAllocateHeap": "HeapReAlloc",
    "RtlFreeHeap": "HeapFree",
    "RtlSizeHeap": "HeapSize",
}


# Plain-C CRT/kernel data exports (no `?` mangling, so the C++ rule below can't
# spot them). The packer hijacks their `__imp_` slots just like any import, but
# CRT startup reads them as DATA (`mov rax,[cell]; mov rbx,[rax]` -- a double
# deref), so they need a loader-bound cell, never a code trampoline. `_acmdln`
# is THE one that crashes __scrt_narrow_argv; the rest are the common CRT
# globals hijacked the same way (cheap insurance against the next such crash).
_KNOWN_DATA_EXPORTS = {
    "_acmdln", "_wcmdln", "_commode", "_fmode", "_environ", "_wenviron",
    "__initenv", "__winitenv", "_pgmptr", "_wpgmptr", "_osplatform", "_osver",
    "_winver", "_winmajor", "_winminor", "_pctype", "_pwctype", "_mbctype",
    "__mb_cur_max", "__argc", "__argv", "__wargv", "_HUGE", "_daylight",
    "_timezone", "_tzname", "_sys_errlist", "_sys_nerr",
}


def _is_data_export_name(name: str) -> bool:
    """
    True for names that denote DATA, not a function.

    C++ static data members (`?npos@...@2_K`), locale ids (`?id@...@2...A`),
    vtables (`??_7...@6B@`), RTTI (`??_R...`), string literals (`??_C...`):
    MSVC function mangling always ends in `Z` (`@Z` / `@XZ` from the signature),
    data symbols never do. Plain C names have no such rule, so the well-known
    CRT data globals are matched by an explicit set. Data cells can't be code
    trampolines (jmp to non-exec `.rdata`, and the CRT reads them as data
    anyway) -- they're bound as imports instead (see `_bind_data_cells_...`).
    """
    if name.startswith("?"):
        return not name.endswith("Z")
    return name in _KNOWN_DATA_EXPORTS


def _name_candidates(name: str):
    """Yield plausible import-table names for a resolved export name, most
    specific first: the name itself, a known forwarder alias, then the common
    kernel32-forwards-to-ntdll `Rtl` prefix strip (RtlEnterCriticalSection ->
    EnterCriticalSection)."""
    yield name
    alias = _FORWARDER_ALIASES.get(name)
    if alias is not None:
        yield alias
    if name.startswith("Rtl") and len(name) > 3:
        yield name[3:]


def _inject_data_cell_trampolines(
        pe_path: str, image_base: int,
        stale_cell_entries: List[Tuple[List[str], List[int]]],
        ptr_size: int) -> None:
    """
    Fix the packer's stale "resolved import cache" cells post-dump, routing
    each by kind: a CODE cell (a cached function pointer the CRT calls) gets an
    `FF25 jmp [import_slot]` trampoline (see `_append_trampoline_section`); a
    DATA cell (a cached `__imp_` data slot the CRT double-derefs, e.g.
    `_acmdln`) is rebound as a real named import (see
    `_bind_data_cells_as_imports`). Both indirect through the Windows-loader-
    populated import table, so they stay valid across runs. Done post-dump
    because it depends on where Scylla placed the rebuilt imports.

    `stale_cell_entries` is a list of (candidate import names, data cell VAs)
    per resolved API; the first candidate (incl. forwarder aliases) found in
    the rebuilt import table wins.
    """
    with open(pe_path, "rb") as f:
        data = bytearray(f.read())

    is_64 = ptr_size == 8
    ptr_fmt = "<Q" if is_64 else "<I"
    name_to_slot = _parse_import_name_to_iat_slot(bytes(data))
    name_to_dll = _parse_import_name_to_dll(bytes(data))

    # Split each entry into a code cell (trampoline through the IAT) or a data
    # cell (loader-bound import, see `_bind_data_cells_as_imports`). All aliases
    # of one address share its kind, so `any` data-looking alias => data cell.
    resolved: List[Tuple[int, List[int]]] = []  # (slot RVA, cell VAs)
    data_bindings: List[Tuple[str, str, List[int]]] = []  # (dll, sym, cell VAs)
    missing_names: List[str] = []
    missing_cells = 0
    for names, cells in stale_cell_entries:
        if any(_is_data_export_name(n) for n in names):
            # Data symbol: resolve its DLL + name from the rebuilt import table
            # (Scylla already imports it) so the loader can bind the cell too.
            dll_sym = next(
                ((name_to_dll[c], c)
                 for name in names for c in _name_candidates(name)
                 if c in name_to_dll), None)
            if dll_sym is None:
                missing_cells += len(cells)
                missing_names.append(names[0])
            else:
                data_bindings.append((dll_sym[0], dll_sym[1], cells))
            continue
        slot = next(
            (name_to_slot[c] for name in names
             for c in _name_candidates(name) if c in name_to_slot), None)
        if slot is None:
            missing_cells += len(cells)
            missing_names.append(names[0])
        else:
            resolved.append((slot, cells))
    if missing_names:
        LOG.warning("No import for %d data-cell API(s) / %d cell(s) "
                    "(e.g. %s); left unpatched", len(missing_names),
                    missing_cells, missing_names[:8])

    if resolved:
        _append_trampoline_section(pe_path, data, image_base, resolved,
                                   is_64, ptr_fmt, ptr_size)
    if data_bindings:
        _bind_data_cells_as_imports(pe_path, image_base, data_bindings,
                                    ptr_size)
    return


def _append_trampoline_section(
        pe_path: str, data: bytearray, image_base: int,
        resolved: List[Tuple[int, List[int]]], is_64: bool, ptr_fmt: str,
        ptr_size: int) -> None:
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    sect_align = struct.unpack_from("<I", data, e_lfanew + 0x38)[0]
    file_align = struct.unpack_from("<I", data, e_lfanew + 0x3C)[0]
    num_sections = struct.unpack_from("<H", data, e_lfanew + 0x6)[0]
    size_opt_hdr = struct.unpack_from("<H", data, e_lfanew + 0x14)[0]
    sec_table = e_lfanew + 0x18 + size_opt_hdr
    first_section_rawptr = min(
        s["rawptr"] for s in _read_section_headers(bytes(data)) if s["rawptr"])

    # Ensure there's room in the header for one more 40-byte section entry.
    if sec_table + (num_sections + 1) * 40 > first_section_rawptr:
        LOG.error("No room for a new section header; skipping trampolines")
        return

    sections = _read_section_headers(bytes(data))
    new_va = _align_up(max(s["va"] + s["vsize"] for s in sections), sect_align)
    new_rawptr = _align_up(len(data), file_align)

    def rva_to_off(rva: int) -> Optional[int]:
        for s in sections:
            if s["va"] <= rva < s["va"] + max(s["vsize"], s["rawsize"]):
                return s["rawptr"] + (rva - s["va"])
        return None

    # One trampoline per resolved entry; re-point that entry's cells at it.
    tramp_bytes = bytearray()
    patched = 0
    for j, (slot_rva, cells) in enumerate(resolved):
        tramp_va = image_base + new_va + j * 6
        slot_va = image_base + slot_rva
        if is_64:
            operand = struct.pack("<i", slot_va - (tramp_va + 6))
        else:
            operand = struct.pack("<I", slot_va)
        tramp_bytes += b"\xff\x25" + operand
        for cell_va in cells:
            off = rva_to_off(cell_va - image_base)
            if off is None or off + ptr_size > len(data):
                continue
            struct.pack_into(ptr_fmt, data, off, tramp_va)
            patched += 1

    vsize = len(tramp_bytes)
    rawsize = _align_up(vsize, file_align)

    # Append the section raw data (padded to file alignment).
    data += b"\x00" * (new_rawptr - len(data))
    data += tramp_bytes + b"\x00" * (rawsize - vsize)

    # Write the new section header (IMAGE_SECTION_HEADER, 40 bytes).
    CNT_CODE_EXEC_READ = 0x60000020
    header = struct.pack("<8sIIIIIIHHI", b".idata2\x00"[:8], vsize, new_va,
                         rawsize, new_rawptr, 0, 0, 0, 0, CNT_CODE_EXEC_READ)
    data[sec_table + num_sections * 40:
         sec_table + num_sections * 40 + 40] = header

    # Update NumberOfSections and SizeOfImage.
    struct.pack_into("<H", data, e_lfanew + 0x6, num_sections + 1)
    new_size_of_image = _align_up(new_va + vsize, sect_align)
    struct.pack_into("<I", data, e_lfanew + 0x50, new_size_of_image)
    # Invalidate the (now-stale) checksum; Windows doesn't verify it for EXEs.
    struct.pack_into("<I", data, e_lfanew + 0x58, 0)

    with open(pe_path, "wb") as f:
        f.write(data)
    LOG.info("Injected %d trampoline(s), re-pointed %d data cell(s)",
             len(resolved), patched)


def _bind_data_cells_as_imports(
        pe_path: str, image_base: int,
        bindings: List[Tuple[str, str, List[int]]], ptr_size: int) -> None:
    """
    Turn each stale DATA cell into a Windows-loader-bound import slot.

    A data cell (e.g. `_acmdln`, a locale `id`) is read as data, not called:
    CRT startup does `mov rax,[cell]; mov rbx,[rax]`, so the cell must hold
    `&symbol` at run time -- a code trampoline can't provide that, and the
    packer's frozen ASLR value is stale. The fix is to make the cell itself a
    named import's `FirstThunk`: the loader writes `&symbol` into it, exactly
    like the original (pre-pack) `__imp_` slot.

    One `IMAGE_IMPORT_DESCRIPTOR` per cell (its own `FirstThunk` = the cell RVA,
    since cells are scattered), plus a relocated descriptor array in a fresh
    section (the existing one has no slack). The dump has ASLR stripped, so
    everything is RVA-addressed -- no relocations needed. The loader only
    unprotects the region named by the IAT data-directory (Scylla's rebuilt
    IAT) while snapping, so any `.text` section holding a bound cell is marked
    MEM_WRITE here -- otherwise the loader's write to the (scattered, out-of-IAT)
    cell would fault at load. Themida dumps already ship W+X sections, so this
    doesn't change the artifact's posture.
    """
    with open(pe_path, "rb") as f:
        data = bytearray(f.read())

    is_64 = ptr_size == 8
    thunk_fmt = "<Q" if is_64 else "<I"
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    sect_align = struct.unpack_from("<I", data, e_lfanew + 0x38)[0]
    file_align = struct.unpack_from("<I", data, e_lfanew + 0x3C)[0]
    num_sections = struct.unpack_from("<H", data, e_lfanew + 0x6)[0]
    size_opt_hdr = struct.unpack_from("<H", data, e_lfanew + 0x14)[0]
    sec_table = e_lfanew + 0x18 + size_opt_hdr
    dd_offset = e_lfanew + 0x18 + (0x70 if is_64 else 0x60)
    import_dd = dd_offset + 1 * 8

    sections = _read_section_headers(bytes(data))
    first_section_rawptr = min(s["rawptr"] for s in sections if s["rawptr"])
    if sec_table + (num_sections + 1) * 40 > first_section_rawptr:
        LOG.error("No room for a new section header; skipping data-cell binds")
        return

    def rva_to_off(rva: int) -> Optional[int]:
        for s in sections:
            if s["va"] <= rva < s["va"] + max(s["vsize"], s["rawsize"]):
                return s["rawptr"] + (rva - s["va"])
        return None

    # Copy the existing descriptor array verbatim (its ILT/Name/FirstThunk RVAs
    # stay valid -- we only move the array itself), dropping the null terminator.
    import_rva = struct.unpack_from("<I", data, import_dd)[0]
    off = rva_to_off(import_rva)
    existing_descs = bytearray()
    while off is not None and data[off:off + 20] != b"\x00" * 20:
        existing_descs += data[off:off + 20]
        off += 20

    cell_count = sum(len(cells) for _, _, cells in bindings)
    new_va = _align_up(max(s["va"] + s["vsize"] for s in sections), sect_align)

    # Section layout: [descriptor array][dll strings][name blobs][ILTs]. Build
    # the trailing blobs first (need their RVAs), then back-fill the array.
    desc_array_size = (len(existing_descs) // 20 + cell_count + 1) * 20
    section = bytearray(existing_descs) + b"\x00" * ((cell_count + 1) * 20)

    def cur_rva() -> int:
        return new_va + len(section)

    dll_rva: Dict[str, int] = {}
    for dll in dict.fromkeys(b[0] for b in bindings):
        dll_rva[dll] = cur_rva()
        section += dll.encode("ascii") + b"\x00"

    syms = list(dict.fromkeys(b[1] for b in bindings))
    name_rva: Dict[str, int] = {}
    for sym in syms:
        if len(section) & 1:  # IMAGE_IMPORT_BY_NAME is WORD-aligned
            section += b"\x00"
        name_rva[sym] = cur_rva()
        section += b"\x00\x00" + sym.encode("ascii") + b"\x00"  # hint + name
    ilt_rva: Dict[str, int] = {}
    for sym in syms:
        while (new_va + len(section)) % ptr_size:
            section += b"\x00"
        ilt_rva[sym] = cur_rva()
        section += struct.pack(thunk_fmt, name_rva[sym])  # ILT[0] = &by_name
        section += struct.pack(thunk_fmt, 0)              # ILT[1] = terminator

    # Back-fill one descriptor per cell: FirstThunk = the (scattered) cell RVA.
    # Mark each cell's host section MEM_WRITE so the loader can snap into it.
    di = len(existing_descs)
    MEM_WRITE = 0x80000000
    for dll, sym, cells in bindings:
        for cell_va in cells:
            cell_rva = cell_va - image_base
            struct.pack_into("<IIIII", section, di,
                             ilt_rva[sym], 0, 0, dll_rva[dll], cell_rva)
            di += 20
            for s in sections:
                if s["va"] <= cell_rva < s["va"] + max(s["vsize"], s["rawsize"]):
                    ch = struct.unpack_from("<I", data, s["off"] + 0x24)[0]
                    struct.pack_into("<I", data, s["off"] + 0x24,
                                     ch | MEM_WRITE)
                    break

    vsize = len(section)
    rawsize = _align_up(vsize, file_align)
    new_rawptr = _align_up(len(data), file_align)
    data += b"\x00" * (new_rawptr - len(data))
    data += section + b"\x00" * (rawsize - vsize)

    CNT_INIT_READ = 0x40000040  # initialized data, read-only
    header = struct.pack("<8sIIIIIIHHI", b".idata3\x00"[:8], vsize, new_va,
                         rawsize, new_rawptr, 0, 0, 0, 0, CNT_INIT_READ)
    data[sec_table + num_sections * 40:
         sec_table + num_sections * 40 + 40] = header

    struct.pack_into("<H", data, e_lfanew + 0x6, num_sections + 1)
    struct.pack_into("<I", data, e_lfanew + 0x50,
                     _align_up(new_va + vsize, sect_align))
    # Re-point the import data directory at the relocated (now larger) array.
    struct.pack_into("<I", data, import_dd, new_va)
    struct.pack_into("<I", data, import_dd + 4, desc_array_size)
    struct.pack_into("<I", data, e_lfanew + 0x58, 0)  # invalidate checksum

    with open(pe_path, "wb") as f:
        f.write(data)
    LOG.info("Bound %d data cell(s) as loader imports across %d symbol(s)",
             cell_count, len(syms))


def pointer_size_to_fmt(pointer_size: int) -> str:
    if pointer_size == 4:
        return "<I"
    if pointer_size == 8:
        return "<Q"
    raise NotImplementedError("Platform not supported")


def interpreter_can_dump_pe(pe_file_path: str) -> bool:
    current_platform = platform.machine()
    binary = lief.parse(pe_file_path)
    pe_architecture = binary.header.machine

    # 64-bit OS on x86
    if current_platform == "AMD64":
        bitness = struct.calcsize("P") * 8
        if bitness == 64:
            # Only 64-bit PEs are supported
            return bool(pe_architecture == lief.PE.MACHINE_TYPES.AMD64)
        if bitness == 32:
            # Only 32-bit PEs are supported
            return bool(pe_architecture == lief.PE.MACHINE_TYPES.I386)
        return False

    # 32-bit OS on x86
    if current_platform == "x86":
        # Only 32-bit PEs are supported
        return bool(pe_architecture == lief.PE.MACHINE_TYPES.I386)

    return False
