"""Round-trip self-check for the post-dump data-cell trampoline injection.

Builds a minimal but valid PE32+ with one named import and one "stale data
cell", runs _inject_data_cell_trampolines, and verifies the appended section,
the trampoline's FF25 displacement, and the re-pointed cell. This is the only
way to validate the raw PE surgery without a Windows/Scylla run.
"""
import os
import struct
import tempfile

from unlicense.dump_utils import (_inject_data_cell_trampolines,
                                  _parse_import_name_to_iat_slot,
                                  _read_section_headers, _align_up,
                                  _name_candidates)

IMAGE_BASE = 0x140000000
E_LFANEW = 0x80


def _build_pe():
    data = bytearray(0x800)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, E_LFANEW)
    data[E_LFANEW:E_LFANEW + 4] = b"PE\x00\x00"
    struct.pack_into("<H", data, E_LFANEW + 0x4, 0x8664)   # Machine x64
    struct.pack_into("<H", data, E_LFANEW + 0x6, 2)        # NumberOfSections
    struct.pack_into("<H", data, E_LFANEW + 0x14, 0xF0)    # SizeOfOptionalHeader
    struct.pack_into("<H", data, E_LFANEW + 0x16, 0x22)    # Characteristics
    opt = E_LFANEW + 0x18
    struct.pack_into("<H", data, opt + 0x00, 0x20B)        # Magic PE32+
    struct.pack_into("<I", data, opt + 0x20, 0x1000)       # SectionAlignment
    struct.pack_into("<I", data, opt + 0x24, 0x200)        # FileAlignment
    struct.pack_into("<I", data, opt + 0x38, 0x3000)       # SizeOfImage
    struct.pack_into("<I", data, opt + 0x3C, 0x400)        # SizeOfHeaders
    struct.pack_into("<I", data, opt + 0x6C, 16)           # NumberOfRvaAndSizes
    struct.pack_into("<II", data, opt + 0x70 + 8, 0x2000, 0x28)  # import dir

    sec_table = E_LFANEW + 0x108
    # .text
    struct.pack_into("<8sIIIIIIHHI", data, sec_table, b".text",
                     0x200, 0x1000, 0x200, 0x400, 0, 0, 0, 0, 0x60000020)
    # .idata
    struct.pack_into("<8sIIIIIIHHI", data, sec_table + 40, b".idata",
                     0x200, 0x2000, 0x200, 0x600, 0, 0, 0, 0, 0xC0000040)

    # .text raw @ 0x400: stale data cell at RVA 0x1100 (file off 0x500)
    struct.pack_into("<Q", data, 0x500, 0xDEADBEEF)

    # .idata raw @ 0x600 (VA 0x2000)
    b = 0x600
    # import descriptor[0]: OFT=0x2030, name=0x2050, FT(IAT)=0x2040
    struct.pack_into("<IIIII", data, b + 0x00, 0x2030, 0, 0, 0x2050, 0x2040)
    # descriptor[1] = null terminator (already zero)
    struct.pack_into("<Q", data, b + 0x30, 0x2060)   # ILT[0] -> IMPORT_BY_NAME
    struct.pack_into("<Q", data, b + 0x40, 0x2060)   # IAT[0] (slot RVA 0x2040)
    data[b + 0x50:b + 0x59] = b"TEST.dll\x00"
    struct.pack_into("<H", data, b + 0x60, 0)        # hint
    data[b + 0x62:b + 0x62 + 12] = b"FreeConsole\x00"
    return data


def test_import_parse_finds_named_slot():
    slots = _parse_import_name_to_iat_slot(bytes(_build_pe()))
    assert slots == {"FreeConsole": 0x2040}


def test_full_injection_round_trip():
    data = _build_pe()
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
        tf.write(data)
        path = tf.name
    try:
        cell_va = IMAGE_BASE + 0x1100
        _inject_data_cell_trampolines(
            path, IMAGE_BASE, [(["FreeConsole"], [cell_va])], ptr_size=8)
        with open(path, "rb") as f:
            out = bytearray(f.read())
    finally:
        os.unlink(path)

    # NumberOfSections bumped 2 -> 3
    assert struct.unpack_from("<H", out, E_LFANEW + 0x6)[0] == 3
    # New section landed at VA 0x3000 (aligned end of image)
    new_va = 0x3000
    tramp_va = IMAGE_BASE + new_va
    # Cell re-pointed to the trampoline
    assert struct.unpack_from("<Q", out, 0x500)[0] == tramp_va
    # SizeOfImage grew to cover the new section
    assert struct.unpack_from("<I", out, E_LFANEW + 0x50)[0] == \
        _align_up(new_va + 6, 0x1000)

    # Locate the appended section's raw data and check the trampoline
    secs = _read_section_headers(bytes(out))
    new_sec = next(s for s in secs if s["va"] == new_va)
    off = new_sec["rawptr"]
    assert out[off:off + 2] == b"\xff\x25"          # jmp qword [rip+disp]
    disp = struct.unpack_from("<i", out, off + 2)[0]
    # Effective target must be the FreeConsole IAT slot (RVA 0x2040)
    assert tramp_va + 6 + disp == IMAGE_BASE + 0x2040


def test_forwarder_alias_resolution():
    # ntdll Rtl* name resolves to the kernel32 forwarder name via prefix strip,
    # and the known heap map covers the non-prefix cases.
    assert list(_name_candidates("RtlEnterCriticalSection"))[-1] == \
        "EnterCriticalSection"
    assert "HeapReAlloc" in _name_candidates("RtlReAllocateHeap")
    assert list(_name_candidates("memcpy")) == ["memcpy"]


def test_stale_cell_patched_via_forwarder_alias():
    # Build a PE whose import table has EnterCriticalSection (kernel32 name),
    # but the stale cell's frida-resolved name is RtlEnterCriticalSection.
    # The alias strip must still find and patch it.
    data = _build_pe()
    # rename the imported function to EnterCriticalSection
    b = 0x600
    data[b + 0x62:b + 0x62 + 20] = b"EnterCriticalSection\x00"[:20]
    data[b + 0x62 + 20] = 0
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
        tf.write(data)
        path = tf.name
    try:
        cell_va = IMAGE_BASE + 0x1100
        _inject_data_cell_trampolines(
            path, IMAGE_BASE, [(["RtlEnterCriticalSection"], [cell_va])],
            ptr_size=8)
        with open(path, "rb") as f:
            out = f.read()
    finally:
        os.unlink(path)
    # section added and cell re-pointed => alias matched
    assert struct.unpack_from("<H", out, E_LFANEW + 0x6)[0] == 3
    assert struct.unpack_from("<Q", out, 0x500)[0] == IMAGE_BASE + 0x3000


def test_second_alias_matches_when_first_misses():
    # Import table has FreeConsole; the cell's primary frida name is a wchar
    # alias that isn't imported, but the second candidate (FreeConsole) is.
    data = _build_pe()
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
        tf.write(data)
        path = tf.name
    try:
        cell_va = IMAGE_BASE + 0x1100
        _inject_data_cell_trampolines(
            path, IMAGE_BASE,
            [(["SomeWcharAliasNotImported", "FreeConsole"], [cell_va])],
            ptr_size=8)
        with open(path, "rb") as f:
            out = f.read()
    finally:
        os.unlink(path)
    assert struct.unpack_from("<H", out, E_LFANEW + 0x6)[0] == 3
    assert struct.unpack_from("<Q", out, 0x500)[0] == IMAGE_BASE + 0x3000


def test_unresolvable_name_is_skipped_gracefully():
    # A cell whose import isn't in the table must not crash and must leave
    # the file's section count unchanged (nothing to trampoline).
    data = _build_pe()
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
        tf.write(data)
        path = tf.name
    try:
        _inject_data_cell_trampolines(
            path, IMAGE_BASE, [(["NotARealImport"], [IMAGE_BASE + 0x1100])],
            ptr_size=8)
        with open(path, "rb") as f:
            out = f.read()
    finally:
        os.unlink(path)
    assert struct.unpack_from("<H", out, E_LFANEW + 0x6)[0] == 2  # unchanged


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"ok  {name}")
    print("all passed")
