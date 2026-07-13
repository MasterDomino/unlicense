"""Self-check for the scan-advance fix in find_wrapped_imports.

Root cause it guards: `i += call_size + 1` skipped the wrapped call that
immediately follows a bare 6-byte FF15/FF25 (no nop padding to skip).
"""
from unlicense.imports import _advance_past_wrapped_call, _is_indirect_jmp


def test_bare_ff15_does_not_over_advance():
    # FF15 disp32 (6 bytes) followed immediately by a wrapped E8 call.
    # The advance must land ON the E8 (offset 6), not skip it (offset 7).
    data = bytes([0xFF, 0x15, 0, 0, 0, 0,      # bare indirect call, no nop
                  0xE8, 0, 0, 0, 0, 0x90])
    assert _advance_past_wrapped_call(data, 0, 6) == 6


def test_trailing_nop_form_skips_nop():
    # E8 rel32 (5) + trailing 0x90 -> advance past the nop (offset 6).
    data = bytes([0xE8, 0, 0, 0, 0, 0x90, 0x4C])
    assert _advance_past_wrapped_call(data, 0, 5) == 6


def test_trailing_int3_tailcall_skips_cc():
    data = bytes([0xE8, 0, 0, 0, 0, 0xCC, 0x00])
    assert _advance_past_wrapped_call(data, 0, 5) == 6


def test_leading_nop_form_skips_nop():
    # 90 E8 rel32 -> offset points at the nop; consume nop + 5-byte call = 6.
    data = bytes([0x90, 0xE8, 0, 0, 0, 0, 0x4C])
    assert _advance_past_wrapped_call(data, 0, 5) == 6


def test_bare_ff25_thunk_is_detected():
    # jmp qword [rip+disp] -- a one-instruction import thunk, no trailing
    # 0x8B/0xC0, so _is_wrapped_thunk_jmp's narrow "Turbo Delphi" case misses
    # it; _is_indirect_jmp must catch it directly.
    data = bytes([0xFF, 0x25, 0x11, 0x22, 0x33, 0x00, 0x90])
    assert _is_indirect_jmp(data, 0) is True


def test_sib_based_jump_table_not_flagged():
    # jmp [rax*8+table] uses FF 24 (SIB), not FF 25 -- must not match, so
    # genuine compiler jump-table dispatches aren't swept in.
    data = bytes([0xFF, 0x24, 0xC5, 0x11, 0x22, 0x33, 0x00])
    assert _is_indirect_jmp(data, 0) is False


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"ok  {name}")
    print("all passed")
