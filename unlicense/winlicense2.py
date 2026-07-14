import logging
import struct
from typing import Dict, List, Tuple, Any, Optional

from capstone import (  # type: ignore
    Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64)

from .imports import (ImportToCallSiteDict, WrapperSet, DataCellDict,
                      DataCellWrapperSet, find_wrapped_imports,
                      find_stale_data_pointers, enumerate_executable_ranges)
from .dump_utils import dump_pe, pointer_size_to_fmt
from .emulation import resolve_wrapped_api
from .function_hashing import compute_function_hash, EMPTY_FUNCTION_HASH
from .process_control import (ProcessController, Architecture, MemoryRange,
                              ReadProcessMemoryError)

LOG = logging.getLogger(__name__)


def fix_and_dump_pe(process_controller: ProcessController, pe_file_path: str,
                    image_base: int, oep: int,
                    text_section_range: MemoryRange) -> None:
    """
    Main dumping routine for Themida/WinLicense 2.x.
    """
    # Convert RVA range to VA range
    section_virtual_addr = image_base + text_section_range.base
    text_section_range = MemoryRange(
        section_virtual_addr, text_section_range.size, "r-x",
        process_controller.read_process_memory(section_virtual_addr,
                                               text_section_range.size))
    assert text_section_range.data is not None
    LOG.debug(".text section: %s", str(text_section_range))

    arch = process_controller.architecture
    exports_dict = process_controller.enumerate_exported_functions()

    # Instanciate the disassembler
    if arch == Architecture.X86_32:
        cs_mode = CS_MODE_32
    elif arch == Architecture.X86_64:
        cs_mode = CS_MODE_64
    else:
        raise NotImplementedError(f"Unsupported architecture: {arch}")
    md = Cs(CS_ARCH_X86, cs_mode)
    md.detail = True

    LOG.info("Looking for wrapped imports ...")
    api_to_calls, wrapper_set = find_wrapped_imports(text_section_range,
                                                     exports_dict, md,
                                                     process_controller)

    LOG.info("Potential import wrappers found: %d", len(wrapper_set))
    export_hashes = None
    # Hash-matching strategy is only needed for 32-bit PEs
    if arch == Architecture.X86_32:
        LOG.info("Generating exports' hashes, this might take some time ...")
        export_hashes = _generate_export_hashes(md, exports_dict,
                                                process_controller)

    LOG.info("Resolving imports ...")
    _resolve_imports(api_to_calls, wrapper_set, export_hashes, md,
                     process_controller)
    LOG.info("Imports resolved: %d", len(api_to_calls))

    # Look for raw pointer-table cells (not call/jmp instructions) holding a
    # live-only, process-instance-specific export address -- e.g. a packer's
    # own resolved-wrapper cache walked as plain data by CRT startup code
    # (`_initterm`/`_initterm_e` iterating C++ static-initializer arrays).
    # These are invisible to `find_wrapped_imports` (it only looks for
    # call/jmp instruction bytes) and, left untouched, keep the ORIGINAL
    # run's ASLR-randomized absolute pointer baked into the dump -- which
    # crashes on every subsequent run once the exporting DLL gets a new base.
    LOG.info("Looking for stale data-cell pointers ...")
    executable_ranges = enumerate_executable_ranges(process_controller)
    data_cell_apis, data_cell_wrappers = find_stale_data_pointers(
        text_section_range, exports_dict, executable_ranges,
        process_controller.pointer_size)
    LOG.info("Potential stale data cells found: %d",
             sum(len(v) for v in data_cell_apis.values()) +
             len(data_cell_wrappers))
    _resolve_data_cell_wrappers(data_cell_apis, data_cell_wrappers,
                                process_controller)
    LOG.info("Data-cell APIs resolved: %d", len(data_cell_apis))

    # Ensure every data-cell API also gets a fake IAT slot, even if it has no
    # .text call/jmp site of its own -- so Scylla imports it by name and the
    # post-dump trampolines (below) have a real IAT slot to jump through.
    for api_addr in data_cell_apis:
        if api_addr not in api_to_calls:
            api_to_calls[api_addr] = []

    # Map each stale data cell to the API name(s) it should call. The
    # trampolines that re-point these cells can only be built AFTER the dump
    # (Scylla discards anything handed to it as IAT data that isn't a valid
    # export pointer, and it relocates the IAT to a new section), so we resolve
    # names now and hand them to dump_pe for a post-dump fix-up pass. Every
    # alias of the resolved address is kept, because Scylla may have imported
    # the function under a different alias than the one frida happened to pick.
    export_aliases = process_controller.enumerate_export_name_aliases()
    stale_cell_entries = _build_stale_cell_entries(data_cell_apis, exports_dict,
                                                   export_aliases)

    iat_addr, iat_size = _generate_new_iat_in_process(api_to_calls,
                                                      text_section_range.base,
                                                      process_controller)
    LOG.info("Generated the fake IAT at %s, size=%s", hex(iat_addr),
             hex(iat_size))

    # Ensure the range is writable
    process_controller.set_memory_protection(text_section_range.base,
                                             text_section_range.size, "rwx")
    # Fix up jmp-thunk tables misclassified as calls (see the function docstring)
    _promote_ilt_thunk_calls_to_jmps(api_to_calls)
    # Replace detected references to wrappers or imports
    LOG.info("Patching call and jmp sites ...")
    _fix_import_references_in_process(api_to_calls, iat_addr,
                                      process_controller)
    # Restore memory protection to RX
    process_controller.set_memory_protection(text_section_range.base,
                                             text_section_range.size, "r-x")

    LOG.info("Dumping PE with OEP=%s ...", hex(oep))
    dump_pe(process_controller, pe_file_path, image_base, oep, iat_addr,
            iat_size, True, stale_cell_entries)


def _generate_export_hashes(
        md: Cs, exports_dict: Dict[int, Dict[str, Any]],
        process_controller: ProcessController) -> Dict[int, int]:
    """
    Go through the given export dictionary and produce a hash for each function
    listed in it.
    """
    result = {}
    modules = process_controller.enumerate_modules()
    LOG.debug("Hashing exports for %s", str(modules))
    ranges = []
    for module_name in modules:
        if module_name != process_controller.main_module_name:
            ranges += process_controller.enumerate_module_ranges(
                module_name, include_data=True)
    ranges = list(
        filter(lambda mem_range: mem_range.protection[2] == 'x', ranges))

    def get_data(addr: int, size: int) -> bytes:
        for mem_range in ranges:
            if mem_range.data is None:
                continue
            if mem_range.contains(addr):
                offset = addr - mem_range.base
                return mem_range.data[offset:offset + size]
        return bytes()

    exports_count = len(exports_dict)
    for i, (export_addr, _) in enumerate(exports_dict.items()):
        export_hash = compute_function_hash(md, export_addr, get_data,
                                            process_controller)
        if export_hash != EMPTY_FUNCTION_HASH:
            result[export_hash] = export_addr
        else:
            LOG.debug("Empty hash for %s", hex(export_addr))
        LOG.debug("Exports hashed: %d/%d", i, exports_count)

    return result


def _resolve_imports(api_to_calls: ImportToCallSiteDict,
                     wrapper_set: WrapperSet,
                     export_hashes: Optional[Dict[int, int]], md: Cs,
                     process_controller: ProcessController) -> None:
    """
    Resolve potential import wrappers by hash-matching or emulation.
    """
    arch = process_controller.architecture
    page_size = process_controller.page_size

    def get_data(addr: int, size: int) -> bytes:
        try:
            return process_controller.read_process_memory(addr, size)
        except ReadProcessMemoryError:
            # In case we crossed a page boundary and tried to read an invalid
            # page, reduce size to stop at page boundary, and try again.
            size = page_size - (addr % page_size)
        return process_controller.read_process_memory(addr, size)

    # Iterate over the set of potential import wrappers and try to resolve them
    resolved_wrappers: Dict[int, int] = {}
    problematic_wrappers = set()
    for call_addr, call_size, instr_was_jmp, wrapper_addr, _ in wrapper_set:
        resolved_addr = resolved_wrappers.get(wrapper_addr)
        if resolved_addr is not None:
            LOG.debug("Already resolved wrapper: %s -> %s", hex(wrapper_addr),
                      hex(resolved_addr))
            api_to_calls[resolved_addr].append(
                (call_addr, call_size, instr_was_jmp))
            continue

        if wrapper_addr in problematic_wrappers:
            # Already failed to resolve this one, ignore
            LOG.debug("Skipping unresolved wrapper")
            continue

        # If 32-bit executable, try hash-matching
        if export_hashes is not None and arch == Architecture.X86_32:
            try:
                import_hash = compute_function_hash(md, wrapper_addr, get_data,
                                                    process_controller)
            except Exception as ex:
                LOG.debug("Failure for wrapper at %s: %s", hex(wrapper_addr),
                          str(ex))
                problematic_wrappers.add(wrapper_addr)
                continue
            if import_hash != EMPTY_FUNCTION_HASH:
                LOG.debug("Hash: %s", hex(import_hash))
                resolved_addr = export_hashes.get(import_hash)
                if resolved_addr is not None:
                    LOG.debug("Hash matched")
                    LOG.debug("Resolved API: %s -> %s", hex(wrapper_addr),
                              hex(resolved_addr))
                    resolved_wrappers[wrapper_addr] = resolved_addr
                    api_to_calls[resolved_addr].append(
                        (call_addr, call_size, instr_was_jmp))
                    continue

        # Try to resolve the destination address by emulating the wrapper
        resolved_addr = resolve_wrapped_api(call_addr, process_controller,
                                            call_addr + call_size)
        if resolved_addr is not None:
            LOG.debug("Resolved API: %s -> %s", hex(wrapper_addr),
                      hex(resolved_addr))
            resolved_wrappers[wrapper_addr] = resolved_addr
            api_to_calls[resolved_addr].append(
                (call_addr, call_size, instr_was_jmp))
        else:
            problematic_wrappers.add(wrapper_addr)


def _resolve_data_cell_wrappers(
        data_cell_apis: DataCellDict, data_cell_wrappers: DataCellWrapperSet,
        process_controller: ProcessController) -> None:
    """
    Resolve data cells whose value points to an unresolved wrapper stub
    (rather than directly to a named export) by emulating the stub, mirroring
    the wrapper-resolution branch of `_resolve_imports`. There's no call site
    to return to here (the value is read as plain data, not executed from a
    known instruction), so emulation runs with no expected return address.
    """
    resolved_wrappers: Dict[int, int] = {}
    for cell_addr, wrapper_addr in data_cell_wrappers:
        resolved_addr = resolved_wrappers.get(wrapper_addr)
        if resolved_addr is None:
            resolved_addr = resolve_wrapped_api(wrapper_addr,
                                                process_controller)
            if resolved_addr is None:
                continue
            resolved_wrappers[wrapper_addr] = resolved_addr
        data_cell_apis[resolved_addr].append(cell_addr)


def _build_stale_cell_entries(
        data_cell_apis: DataCellDict,
        exports_dict: Dict[int, Dict[str, Any]],
        export_aliases: Dict[int, List[str]]
) -> List[Tuple[List[str], List[int]]]:
    """
    Produce, per resolved data-cell API, the list of candidate import names
    (all export aliases of the address) paired with the data cells that
    reference it. The post-dump pass tries each candidate against the rebuilt
    import table -- Scylla may have imported the function under a different
    alias than the one frida reported (e.g. basic_string<wchar_t> vs
    <unsigned short>), so a single name isn't enough.
    """
    entries: List[Tuple[List[str], List[int]]] = []
    for api_addr, cell_addrs in data_cell_apis.items():
        if not cell_addrs:
            continue
        names = list(export_aliases.get(api_addr, []))
        export = exports_dict.get(api_addr)
        if export is not None and export.get("name") \
                and export["name"] not in names:
            names.append(export["name"])
        if not names:
            LOG.debug("No export name for data-cell API %s", hex(api_addr))
            continue
        entries.append((names, cell_addrs))
    return entries


def _generate_new_iat_in_process(
        imports_dict: ImportToCallSiteDict, near_to_ptr: int,
        process_controller: ProcessController) -> Tuple[int, int]:
    """
    Generate a new IAT from a list of imported function addresses and write
    it into a new buffer into the target process. `near_to_ptr` is used to
    allocate the new IAT near the unpacked module (which is needed for 64-bit
    processes).
    """
    ptr_size = process_controller.pointer_size
    ptr_format = pointer_size_to_fmt(ptr_size)
    iat_size = len(imports_dict) * ptr_size
    # Allocate a new buffer in the target process
    iat_addr = process_controller.allocate_process_memory(
        iat_size, near_to_ptr)

    # Generate the new IAT and write it into the buffer
    new_iat_data = bytearray()
    for import_addr in imports_dict:
        new_iat_data += struct.pack(ptr_format, import_addr)
    process_controller.write_process_memory(iat_addr, list(new_iat_data))

    return iat_addr, iat_size


def _fix_import_references_in_process(
        api_to_calls: ImportToCallSiteDict, iat_addr: int,
        process_controller: ProcessController) -> None:
    """
    Replace resolved wrapper call sites with call/jmp to the new IAT (that
    contains resolved imports).
    """
    arch = process_controller.architecture
    ptr_size = process_controller.pointer_size

    for i, call_addrs in enumerate(api_to_calls.values()):
        for call_addr, _, instr_was_jmp in call_addrs:
            if arch == Architecture.X86_32:
                # Absolute
                operand = iat_addr + i * ptr_size
                fmt = "<I"
            elif arch == Architecture.X86_64:
                # RIP-relative
                operand = iat_addr + i * ptr_size - (call_addr + 6)
                fmt = "<i"
            else:
                raise NotImplementedError(f"Unsupported architecture: {arch}")

            if instr_was_jmp:
                # jmp [iat_addr + i * ptr_size]
                new_instr = bytes([0xFF, 0x25]) + struct.pack(fmt, operand)
            else:
                # call [iat_addr + i * ptr_size]
                new_instr = bytes([0xFF, 0x15]) + struct.pack(fmt, operand)
            process_controller.write_process_memory(call_addr, list(new_instr))


def _promote_ilt_thunk_calls_to_jmps(
        api_to_calls: ImportToCallSiteDict) -> None:
    """
    MSVC emits import thunks (`jmp [__imp_X]`) packed into contiguous tables
    that the rest of the code reaches with a `call`. `find_wrapped_imports`
    only tags a thunk as a jmp when it is followed by int3/nop padding, so it
    marks the *last* entry of such a table correctly but misclassifies the
    interior entries as calls. A `call [IAT]` where a `jmp [IAT]` belongs makes
    control fall through into the next table entry once the API returns --
    calling unrelated APIs with garbage arguments and, because of the extra
    return address, skewing 16-byte stack alignment until a callee faults on an
    aligned SSE access (e.g. a crash deep inside iphlpapi/ntdll).

    Any maximal run of back-to-back thunks (contiguous, same size) whose final
    entry is already a jmp is such a table, so promote every call in the run to
    a jmp. Two adjacent bare `call [IAT]` with no instructions between them does
    not occur in real code, so this does not touch genuine inline calls.
    """
    # call_addr -> [api_addr, index_in_list, call_size, instr_was_jmp]
    sites: Dict[int, List[Any]] = {}
    for api_addr, call_list in api_to_calls.items():
        for idx, (call_addr, call_size, instr_was_jmp) in enumerate(call_list):
            sites[call_addr] = [api_addr, idx, call_size, instr_was_jmp]

    addrs = sorted(sites)
    i = 0
    while i < len(addrs):
        run = [addrs[i]]
        while i + 1 < len(addrs) and \
                addrs[i + 1] == addrs[i] + sites[addrs[i]][2]:
            run.append(addrs[i + 1])
            i += 1
        i += 1
        # A jmp-thunk table is a run of 2+ thunks anchored by a jmp terminal.
        if len(run) >= 2 and sites[run[-1]][3]:
            for addr in run:
                sites[addr][3] = True

    for call_addr, (api_addr, idx, call_size, was_jmp) in sites.items():
        old = api_to_calls[api_addr][idx]
        if old[2] != was_jmp:
            api_to_calls[api_addr][idx] = (old[0], old[1], was_jmp)
