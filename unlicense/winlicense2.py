import logging
import struct
from typing import Dict, Tuple, Any, Optional

from capstone import (  # type: ignore
    Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64)

from .imports import (ImportToCallSiteDict, WrapperSet, DataCellDict,
                      DataCellWrapperSet, find_wrapped_imports,
                      find_stale_data_pointers)
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
    data_cell_apis, data_cell_wrappers = find_stale_data_pointers(
        text_section_range, exports_dict, process_controller)
    LOG.info("Potential stale data cells found: %d",
             sum(len(v) for v in data_cell_apis.values()) +
             len(data_cell_wrappers))
    _resolve_data_cell_wrappers(data_cell_apis, data_cell_wrappers,
                                process_controller)
    LOG.info("Data-cell APIs resolved: %d", len(data_cell_apis))

    # Ensure every data-cell API also gets a fake IAT slot, even if it has no
    # .text call/jmp site of its own.
    for api_addr in data_cell_apis:
        if api_addr not in api_to_calls:
            api_to_calls[api_addr] = []

    iat_addr, iat_size = _generate_new_iat_and_trampolines_in_process(
        api_to_calls, data_cell_apis, text_section_range.base,
        process_controller)
    LOG.info("Generated the fake IAT (+trampolines) at %s, size=%s",
             hex(iat_addr), hex(iat_size))

    # Ensure the range is writable
    process_controller.set_memory_protection(text_section_range.base,
                                             text_section_range.size, "rwx")
    # Replace detected references to wrappers or imports
    LOG.info("Patching call and jmp sites ...")
    _fix_import_references_in_process(api_to_calls, iat_addr,
                                      process_controller)
    # Restore memory protection to RX
    process_controller.set_memory_protection(text_section_range.base,
                                             text_section_range.size, "r-x")

    LOG.info("Dumping PE with OEP=%s ...", hex(oep))
    dump_pe(process_controller, pe_file_path, image_base, oep, iat_addr,
            iat_size, True)


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


def _generate_new_iat_and_trampolines_in_process(
        imports_dict: ImportToCallSiteDict, data_cell_apis: DataCellDict,
        near_to_ptr: int,
        process_controller: ProcessController) -> Tuple[int, int]:
    """
    Generate a new IAT from a list of imported function addresses, plus one
    `jmp qword [iat_slot]` trampoline per API that's referenced from a raw
    data cell (see `find_stale_data_pointers`), and patch each such cell to
    point at its trampoline instead of the original live-only absolute
    address. `near_to_ptr` is used to allocate the buffer near the unpacked
    module (needed for 64-bit RIP-relative displacements).

    A data cell holds a raw pointer VALUE, not a call/jmp instruction with an
    operand -- it can't be rewritten in place the way `.text` call sites are
    (that's what `_fix_import_references_in_process` does). Instead, each
    such cell is redirected to a tiny synthesized thunk that re-reads the
    resolved address from the (freshly rebuilt, correctly relocated at
    runtime) fake IAT on every call, so it stays valid across ASLR-randomized
    runs instead of freezing one process instance's live address.
    """
    ptr_size = process_controller.pointer_size
    ptr_format = pointer_size_to_fmt(ptr_size)
    iat_size = len(imports_dict) * ptr_size
    # One 6-byte `FF25 disp32` thunk per API actually referenced by a data
    # cell (shared across every cell holding that same API's address).
    trampoline_targets = [addr for addr in data_cell_apis if data_cell_apis[addr]]
    trampoline_size = len(trampoline_targets) * 6
    total_size = iat_size + trampoline_size

    # Single allocation so the IAT and its trampolines land in one region
    # (guaranteed nearby for the RIP-relative math, and guaranteed to be
    # captured together by the dump/fix-IAT step via the returned size).
    iat_addr = process_controller.allocate_process_memory(
        total_size, near_to_ptr)

    # Generate the new IAT and write it into the buffer
    new_iat_data = bytearray()
    slot_index: Dict[int, int] = {}
    for i, import_addr in enumerate(imports_dict):
        slot_index[import_addr] = i
        new_iat_data += struct.pack(ptr_format, import_addr)
    process_controller.write_process_memory(iat_addr, list(new_iat_data))

    # Generate one trampoline per referenced API and repoint its data cells
    arch = process_controller.architecture
    trampoline_base = iat_addr + iat_size
    for j, api_addr in enumerate(trampoline_targets):
        trampoline_addr = trampoline_base + j * 6
        iat_slot_addr = iat_addr + slot_index[api_addr] * ptr_size
        if arch == Architecture.X86_32:
            # `FF25 disp32` on x86 addresses an absolute location, not
            # PC-relative -- no subtraction, unlike the x64 RIP-relative form.
            operand = iat_slot_addr
            fmt = "<I"
        elif arch == Architecture.X86_64:
            operand = iat_slot_addr - (trampoline_addr + 6)
            fmt = "<i"
        else:
            raise NotImplementedError(f"Unsupported architecture: {arch}")
        thunk = bytes([0xFF, 0x25]) + struct.pack(fmt, operand)
        process_controller.write_process_memory(trampoline_addr, list(thunk))

        cell_bytes = list(struct.pack(ptr_format, trampoline_addr))
        for cell_addr in data_cell_apis[api_addr]:
            process_controller.write_process_memory(cell_addr, cell_bytes)

    if trampoline_size > 0:
        # The IAT slots only need to be read; the trampolines need to be
        # executed. r-x covers both (data reads are permitted from
        # executable pages).
        process_controller.set_memory_protection(iat_addr, total_size, "r-x")

    return iat_addr, total_size


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
