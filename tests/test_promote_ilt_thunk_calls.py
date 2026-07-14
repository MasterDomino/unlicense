"""Self-check for the jmp-thunk-table fix in winlicense2.

Root cause it guards: `find_wrapped_imports` only tags an import thunk as a jmp
when it is followed by int3/nop padding, so interior entries of a contiguous
MSVC ILT jmp-thunk table (`jmp [__imp_X]`) get written as `call [IAT]`. That
makes control fall through into the next table entry after the API returns and
eventually crashes on stack-alignment-sensitive code (e.g. inside iphlpapi).
`_promote_ilt_thunk_calls_to_jmps` promotes every call in such a run to a jmp.
"""
from unlicense.winlicense2 import _promote_ilt_thunk_calls_to_jmps


def _flatten(api_to_calls):
    return {addr: was_jmp
            for calls in api_to_calls.values()
            for (addr, _size, was_jmp) in calls}


def test_interior_call_thunks_promoted_to_jmp():
    # A 6-byte-stride table at 0x1000: six calls + a jmp terminal (the anchor
    # find_wrapped_imports saw followed by int3). Mirrors the iphlpapi table.
    base = 0x1000
    api_to_calls = {
        0xA: [(base + 0, 6, False)],
        0xB: [(base + 6, 6, False)],
        0xC: [(base + 12, 6, False)],
        0xD: [(base + 18, 6, True)],   # terminal jmp
    }
    _promote_ilt_thunk_calls_to_jmps(api_to_calls)
    flat = _flatten(api_to_calls)
    assert all(flat[a] for a in (base, base + 6, base + 12, base + 18))


def test_lone_inline_call_left_alone():
    # A single isolated call [IAT] is real inline code, not a thunk table.
    api_to_calls = {0xA: [(0x2000, 6, False)]}
    _promote_ilt_thunk_calls_to_jmps(api_to_calls)
    assert _flatten(api_to_calls)[0x2000] is False


def test_run_without_jmp_terminal_left_alone():
    # Two contiguous calls with no jmp anchor -> not a proven thunk table.
    api_to_calls = {0xA: [(0x3000, 6, False)], 0xB: [(0x3006, 6, False)]}
    _promote_ilt_thunk_calls_to_jmps(api_to_calls)
    flat = _flatten(api_to_calls)
    assert flat[0x3000] is False and flat[0x3006] is False


def test_noncontiguous_calls_not_merged():
    # Gap between the call and the jmp -> different tables, no promotion.
    api_to_calls = {0xA: [(0x4000, 6, False)], 0xB: [(0x4100, 6, True)]}
    _promote_ilt_thunk_calls_to_jmps(api_to_calls)
    assert _flatten(api_to_calls)[0x4000] is False


if __name__ == "__main__":
    test_interior_call_thunks_promoted_to_jmp()
    test_lone_inline_call_left_alone()
    test_run_without_jmp_terminal_left_alone()
    test_noncontiguous_calls_not_merged()
    print("ok")
