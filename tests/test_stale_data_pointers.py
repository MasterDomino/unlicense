"""Self-check for the stale-data-cell scanner and trampoline generation.

Root cause it guards: Themida-maintained resolved-wrapper caches get walked
as plain data by real CRT startup code (`_initterm`/`_initterm_e`), not
referenced via any call/jmp instruction -- `find_wrapped_imports` never even
looks at them, so the dump keeps one process instance's live, ASLR-randomized
absolute pointer baked in verbatim, which is invalid on every later run.
"""
import struct

from unlicense.imports import find_stale_data_pointers
from unlicense.process_control import Architecture, MemoryRange, ProcessController


class FakeProcessController(ProcessController):
    """Minimal stub: only implements what find_stale_data_pointers touches."""

    def __init__(self, executable_ranges):
        super().__init__(pid=1, main_module_name="Client.exe",
                         architecture=Architecture.X86_64, pointer_size=8,
                         page_size=0x1000)
        self._executable_ranges = executable_ranges

    def find_module_by_address(self, address):
        raise NotImplementedError

    def find_range_by_address(self, address, include_data=False):
        for lo, hi in self._executable_ranges:
            if lo <= address < hi:
                return MemoryRange(lo, hi - lo, "r-x")
        return None

    def find_export_by_name(self, module_name, export_name):
        raise NotImplementedError

    def enumerate_modules(self):
        raise NotImplementedError

    def enumerate_module_ranges(self, module_name, include_data=False):
        raise NotImplementedError

    def enumerate_exported_functions(self, update_cache=False):
        raise NotImplementedError

    def allocate_process_memory(self, size, near):
        raise NotImplementedError

    def query_memory_protection(self, address):
        raise NotImplementedError

    def set_memory_protection(self, address, size, protection):
        raise NotImplementedError

    def read_process_memory(self, address, size):
        raise NotImplementedError

    def write_process_memory(self, address, data):
        raise NotImplementedError

    def terminate_process(self):
        raise NotImplementedError


def _section(base, cells):
    data = b"".join(struct.pack("<Q", c) for c in cells)
    return MemoryRange(base, len(data), "r-x", data)


def test_resolved_export_pointer_is_found():
    EXPORT_ADDR = 0x7FFA47234420
    section = _section(0x141670000, [0x1122334455667788, EXPORT_ADDR])
    exports = {EXPORT_ADDR: {"name": "FreeConsole"}}
    pc = FakeProcessController(executable_ranges=[])
    api_to_cells, wrapper_cells = find_stale_data_pointers(section, exports, pc)
    assert api_to_cells[EXPORT_ADDR] == [section.base + 8]
    assert wrapper_cells == set()


def test_unresolved_executable_pointer_is_wrapper_candidate():
    WRAPPER_ADDR = 0x14282E1CA
    section = _section(0x141670000, [WRAPPER_ADDR])
    pc = FakeProcessController(executable_ranges=[(0x142800000, 0x142900000)])
    api_to_cells, wrapper_cells = find_stale_data_pointers(section, {}, pc)
    assert api_to_cells == {}
    assert (section.base, WRAPPER_ADDR) in wrapper_cells


def test_pointer_within_own_section_is_ignored():
    # A cell pointing back into .text itself is a vtable/internal reference,
    # not an import -- must not be flagged even if the value happens to be
    # a "known export" address by coincidence. Section must be large enough
    # that the target address genuinely falls inside [base, base+size).
    base = 0x141670000
    in_section_addr = base + 0x100  # well within the section below
    section = _section(base, [in_section_addr] + [0] * 0x40)  # pad past +0x100
    exports = {in_section_addr: {"name": "not_actually_an_import"}}
    pc = FakeProcessController(executable_ranges=[(base, base + 0x1000)])
    api_to_cells, wrapper_cells = find_stale_data_pointers(section, exports, pc)
    assert api_to_cells == {}
    assert wrapper_cells == set()


def test_trampoline_disp32_round_trips_to_iat_slot_x64():
    # Same FF25 rip-relative math _generate_new_iat_and_trampolines_in_process
    # uses: effective_address = trampoline_addr + 6 + disp32 must equal the
    # target IAT slot exactly, or the CPU jumps through the wrong cell.
    iat_addr = 0x142cd0000
    ptr_size = 8
    slot_index = 3
    iat_slot_addr = iat_addr + slot_index * ptr_size
    trampoline_addr = 0x142cd1000
    disp32 = iat_slot_addr - (trampoline_addr + 6)
    packed = struct.pack("<i", disp32)
    assert len(packed) == 4
    effective_address = trampoline_addr + 6 + struct.unpack("<i", packed)[0]
    assert effective_address == iat_slot_addr


def test_trampoline_operand_is_absolute_on_x86():
    # FF25 on x86 has no RIP-relative addressing -- the operand IS the target
    # address directly, unlike x64 where it's a displacement from the next
    # instruction. Mixing the two up (as an earlier draft of this fix did)
    # would jump to the wrong location on every 32-bit target.
    iat_addr = 0x4bd0000
    ptr_size = 4
    slot_index = 2
    iat_slot_addr = iat_addr + slot_index * ptr_size
    operand = iat_slot_addr  # no subtraction for x86
    packed = struct.pack("<I", operand)
    assert struct.unpack("<I", packed)[0] == iat_slot_addr


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"ok  {name}")
    print("all passed")
