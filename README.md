# vmxlib

Header-only C++ for Intel VT-x, plus `vmxctl` — a decoder for the values you end
up staring at in WinDbg after a failed `vmlaunch`. Also a pure-logic SLAT hook
model, `slathook.h`, for working through EPT/NPT code-hook bookkeeping without a
driver, a VM, or a reboot.

status: tables, formulas and the SLAT model are verified against a 103-case
selftest that runs on every build. the intrinsics wrappers compile in ring 3 but
are only *callable* in ring 0 — they are there so a kernel driver can include
the header directly. the selftest covers negative cases: unmapped GPAs, rejected hook
inputs, allocation exhaustion, invalid EPTP encodings and SMX-scoped VMXON.

[sdm]: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
[uapi]: https://github.com/torvalds/linux/blob/master/arch/x86/include/uapi/asm/vmx.h
[asmvmx]: https://github.com/torvalds/linux/blob/master/arch/x86/include/asm/vmx.h
[hyperrev]: https://github.com/noahware/hyper-reV

---

## Table of contents

1. [How the encoding works](#how-the-encoding-works)
2. [Repository layout](#repository-layout)
3. [Build from source](#build-from-source)
4. [vmxctl command reference](#vmxctl-command-reference)
5. [The VMCS field encoding](#the-vmcs-field-encoding)
6. [Capability MSRs and control adjustment](#capability-msrs-and-control-adjustment)
7. [EPT and EPTP](#ept-and-eptp)
8. [SLAT code hooks](#slat-code-hooks)
   - [Split and merge](#split-and-merge)
   - [Two views and the shadow page](#two-views-and-the-shadow-page)
   - [Intel and AMD policies](#intel-and-amd-policies)
   - [Invalidation](#invalidation)
9. [Verification](#verification)
10. [Sources](#sources)
11. [License](#license)

---

## How the encoding works

A VMCS field encoding is a 16-bit number with four packed pieces:

```
bits 14:13   width      0 = 16-bit, 1 = 64-bit, 2 = 32-bit, 3 = natural-width
bits 11:10   area       0 = control, 1 = vm-exit information,
                        2 = guest state, 3 = host state
bits  9:1    index      field number within that (width, area) group
bit      0   access     0 = full field, 1 = high half of a 64-bit field
```

So `field_encode(Width::Natural, Area::Guest, 15)` is
`(3 << 13) | (2 << 10) | (15 << 1) | 0` = `0x681E` = `GUEST_RIP`. A `_HIGH`
field is the same encoding with bit 0 set: `EPT_POINTER` is `0x201A`,
`EPT_POINTER_HIGH` is `0x201B`. Nothing else about the field changes.

Startup and query sequence for the CLI:

```
main()
  ↳ parse argv
  ↳ basic / fc / ctl / cr      MSR and control decodes
  ↳ epte / eptp / qual         EPT paging structures
  ↳ exit / err                 exit reason and instruction error tables
  ↳ field / enc / fields       VMCS encoding lookup
  ↳ slat / slathook            SLAT simulation
  ↳ selftest                   run all 103 assertions, exit non-zero on failure
```

There is no runtime state. `vmxctl` is a pure function of its arguments;
`slathook.h` keeps its state inside a `Slat` object the caller owns.

---

## Repository layout

```
vmxlib/
├── vmx.h                     VT-x constants, MSR indices, VMCS field table,
│                             EPT/EPTP helpers, exit reasons, intrinsics wrappers
├── slathook.h                SLAT paging model: split/merge, shadow pages,
│                             hook entries, per-core invalidation bitmap
├── src/
│   └── vmxctl.cpp            CLI + selftest (the only translation unit)
├── build.bat                 cl → vmxctl.exe → selftest
├── example/                  captured CLI output
├── notes.txt                 where the SDM and the kernel disagree
├── LICENSE                   MIT
└── README.md
```

**How the pieces fit.** `vmx.h` is self-contained and includes nothing but
`<cstdint>` and `<cstddef>` (plus `<intrin.h>` on MSVC x64). `slathook.h` is
likewise standalone — it does not include `vmx.h`. `vmxctl.cpp` is the only
file that pulls both in, which keeps the headers usable from a kernel driver,
a user-mode tool, or a test harness without dragging in the CRT.

**Layer discipline.** Nothing in `slathook.h` calls a VMX instruction. It models
page tables as arrays of 512 `uint64_t` entries, with a tag bit (`kPtrTag`,
bit 62) marking a pointer to the next level. That bit is outside the physical
address mask, so an entry is either a leaf or a table pointer with no ambiguity.
The model is deliberately not executable — it is a bookkeeping sandbox, not a
hypervisor.

**Sizing.** `vmx.h` is 583 lines, `slathook.h` 462, `vmxctl.cpp` 528. The
`Slat` arena is 16 page-sized tables by default (64 KiB), which is enough for
the split/merge and hook tests; change `kMaxPages` if you want to model a
larger guest.

---

## Build from source

Requires **MSVC 2022 x64** (`cl`). No CMake, no WDK, no external libraries. Run
from any prompt — `build.bat` finds `vcvars64.bat` itself if `cl` is not on
`PATH`.

```
git clone https://github.com/vmgexit/vmxlib.git
cd vmxlib
build.bat
```

Output: `build\vmxctl.exe`. The build then runs `vmxctl selftest`; a failing
assertion fails the build.

```
[*] selftest
vmxlib selftest
  ok    GUEST_RIP encoding
  ...
slathook selftest
  ok    hook entry is 16 bytes
  ...
  PASS
[*] smoke
[+] build\vmxctl.exe
```

`/std:c++17 /EHsc /O2 /W3 /MT`. `/MT` links the user-mode CRT statically so
`vmxctl.exe` has no runtime DLL dependency. It does not make that CRT
kernel-compatible: `/MT` is a setting of this executable, not a property of
the headers. `vmx.h` and `slathook.h` include only `<cstdint>`, `<cstddef>` and
(on MSVC x64) `<intrin.h>` and make no CRT calls, which is why they can be
included from a driver built with its own kernel-mode settings.

---

## vmxctl command reference

| command | what it decodes |
| --- | --- |
| `basic <msr>` | `IA32_VMX_BASIC`: revision, region size, memory type, true controls |
| `fc <msr>` | `IA32_FEATURE_CONTROL`: lock, VMXON in/out of SMX, `vmxon_legal` |
| `ctl <msr> <desired>` | allowed-1 control adjustment, must-be-1 bits, impossible bits |
| `cr <cr> <fixed0> <fixed1>` | CR0/CR4 fixed-bit result and conflicts |
| `epte <entry>` | EPT paging-structure entry: RWX, memory type, large, A/D, PFN |
| `eptp <eptp>` | EPTP: PML4, memory type, walk length, accessed/dirty enable |
| `qual <qual>` | EPT violation exit qualification (SDM table 27-7) |
| `exit <n>` | VM-exit reason, plus failed-VM-entry and SGX-enclave flags |
| `err <n>` | VM-instruction error number |
| `field <enc\|name>` | VMCS field encoding, or lookup by name |
| `enc <w> <a> <idx> [hi]` | build an encoding from width/area/index |
| `fields` / `exits` / `errors` | dump the tables |
| `slat <gpa>` | simulate a 1G → 2M → 4K split/merge cycle |
| `slathook <gpa>` | simulate an execute-only code hook and its removal |
| `selftest` | run every assertion |

Numbers accept `0x` hex or decimal. Examples:

```
vmxctl basic 0x00D810000000001A
vmxctl ctl 0x0000007F00000001 0x40
vmxctl qual 0x1189
vmxctl exit 48
vmxctl slat 0x400000
vmxctl slathook 0x201000
```

```
IA32_VMX_BASIC  0x00D810000000001A
  vmcs revision      0x0000001A
  vmxon/vmcs size    4096 bytes (0x1000)
  memory type        6 (WB)
  ins/outs info      yes
  true controls      yes
  -> region_init(rev 0x1A, 4096 bytes)
```

```
SLAT split/merge cycle at 0x400000
  start     2 table pages, leaf 0x40000000 bytes
  split 1G  3 table pages, leaf 0x200000 bytes
  split 2M  4 table pages, leaf 0x1000 bytes
  +4K       hpa 0x401000  stop none
  merge     3 table pages, leaf 0x200000 bytes
  merge     2 table pages, leaf 0x40000000 bytes
```

More output in `example/`.

---

## The VMCS field encoding

`field_encode` / `field_decode` and a table of 155 named encodings live in
`vmx.h`. The table is a flat `constexpr FieldName[]`, so `field_name` and
`field_by_name` are linear scans over 155 entries — fast enough for a debugger
tool and small enough to eyeball.

| encoding | name | width | area | index |
| --- | --- | --- | --- | --- |
| `0x0000` | `VIRTUAL_PROCESSOR_ID` | 16-bit | control | 0 |
| `0x201A` | `EPT_POINTER` | 64-bit | control | 13 |
| `0x4002` | `CPU_BASED_VM_EXEC_CONTROL` | 32-bit | control | 1 |
| `0x4402` | `VM_EXIT_REASON` | 32-bit | exit info | 1 |
| `0x6400` | `EXIT_QUALIFICATION` | natural | exit info | 0 |
| `0x681E` | `GUEST_RIP` | natural | guest | 15 |
| `0x6C16` | `HOST_RIP` | natural | host | 11 |

The table was checked against [Linux `arch/x86/include/asm/vmx.h`][asmvmx]. The
control-field encodings are the ones that shift by two if you build the index by
hand; `notes.txt` has the bit layout.

Intrinsics wrappers (`vmxon`, `vmclear`, `vmptrld`, `vmread`, `vmwrite`,
`vmlaunch`, `vmresume`, `vmxoff`, `rdmsr`, `cr0..cr4`) are behind
`VMXLIB_HAS_INTRINSICS` and only exist on MSVC x64. `__vmx_on` takes a
*pointer* to a physical address, not the address itself — the wrappers take a
`uint64_t` and handle the pointer locally. `Region` is 4096-byte aligned and
`region_init` writes the VMCS revision into dword 0.

---

## Capability MSRs and control adjustment

`msr::` holds the `0x480`–`0x491` indices. Two helpers matter:

```cpp
uint32_t adjust_controls(uint32_t desired, uint64_t cap) {
    return (desired | (uint32_t)cap) & (uint32_t)(cap >> 32);
}
uint64_t fix_cr(uint64_t cr, uint64_t fixed0, uint64_t fixed1) {
    return (cr | fixed0) & fixed1;
}
```

`IA32_VMX_TRUE_*_CTLS` (0x48D–0x490) should be used instead of the legacy
0x481–0x484 when `IA32_VMX_BASIC` bit 55 is set. `basic_decode` reports that
bit. `impossible_control_bits` tells you which bits of a desired control value
cannot be set at all, which is usually the reason a `vmlaunch` fails with
VM-instruction error 7.

---

## EPT and EPTP

`ept_entry_encode/decode` and `eptp_encode/decode` cover the parts that are easy
to get wrong:

- EPT entry bits 2:0 are R/W/X, bits 5:3 are memory type, bit 7 is large page,
  bits 8/9 are accessed/dirty, bit 10 is user-mode execute, bit 63 is
  suppress-VE, bits 51:12 are the physical address.
- EPTP bits 2:0 are memory type, bits 5:3 are the page-walk length minus one
  (`0x18` for 4-level), bit 6 enables accessed/dirty. A normal WB 4-level EPTP
  has low byte `0x1E` — forgetting the walk-length bits produces `0x06`, which
  is reserved.
- `ept_qual_decode` follows SDM table 27-7: bits 0/1/2 are the access,
  3/4/5 are the EPT entry permissions, 7 is guest-linear-address valid, 8 is
  the translated-GPA flag, 12 is NMI unblocking due to IRET. Bits 6, 9, 10, 11
  are the advanced-information bits; newer SDM revisions and Linux define them
  where older ones say reserved. `notes.txt` has the discrepancy.

`exit_reason_name` preserves the reserved holes (5, 11, 17, 35, 38, 42) rather
than building a dense array, and `do_exit` masks the basic reason out of the
upper flags (`FAILED_VMENTRY` bit 31, `SGX_ENCLAVE_MODE` bit 27).

### Checked versus unchecked helpers

`ept_entry_encode()` is a raw bit-packing helper: it masks the physical address
and accepts whatever the caller supplies. `eptp_encode()` is stricter — it goes
through `eptp_encode_checked()` and returns 0 for a bad walk level, memory type
or alignment. Use `ept_entry_encode_checked()` and `eptp_encode_checked()` when
inputs are not already known good: they reject misaligned addresses, addresses
outside the 52-bit mask, unsupported memory types, large pages that are not
2 MiB aligned, unsupported page-walk levels, and entries with no R/W/X bits.

`eptp_decode()` reports `valid = false` and `walk_levels = 0` for a reserved
page-walk-length encoding. It does not normalise an invalid hardware value into
"4-level". `vmxon_allowed(f, in_smx)` takes the execution environment into
account; `vmxon_legal(f)` only reports that the lock bit is set and at least
one of the two permission bits is set.

---

## SLAT code hooks

`slathook.h` models the bookkeeping described in [hyper-reV §4.5][hyperrev]:
splitting a large page to reach a 4 KiB target, keeping a shadow page with
hidden contents, and merging the page tables back when the last hook in a range
is removed. No code from that project is used; this is an independent model of
the state machine, MIT licensed, and entirely offline.

A `Slat` starts with either 1 GiB or 2 MiB identity-mapped large pages.
`MapMode::k1G` populates all 512 PDPT entries and therefore covers 512 GiB;
`MapMode::k2M` populates one PDPT entry and covers 1 GiB. `map_size_` follows
the mode, so `add_hook()` accepts addresses across the whole mapped range.

`Translation` has a `mapped` flag and a `Stop::kUnmapped` value. A zeroed
page-table entry is an absent mapping, not a valid translation with blocked
permissions. `add_hook()` is transactional: it builds both views on a copy,
verifies that the original view traps execution and the hook view maps the
shadow page, and only then commits. On any failure — an unmapped GPA, arena
exhaustion, a failed clone — the caller's state is unchanged.

`HookEntry` stays 16 bytes intentionally, so 256 hooks fit in one 4 KiB page.
That means `shadow_pfn` is 32 bits and shadow HPAs are limited to 44 bits;
`add_hook()` rejects anything above `kMaxShadowHpa` rather than truncating it.
Widening the PFN would double the entry size and lose the density property the
model is demonstrating.

```cpp
Slat s(MapMode::k1G, 8);   // PML4 + PDPT, 8 logical processors
s.split(0x400000);         // 1G PDPTE -> PD of 2M PDEs
s.split(0x400000);         // 2M PDE   -> PT of 4K PTEs
s.merge(0x400000);         // PT  -> 2M PDE, frees one table
s.merge(0x400000);         // PD  -> 1G PDPTE, frees one table
```

`split` and `merge` each do exactly one level per call. `translate(gpa, access,
hook_view)` returns the host physical address, the leaf size, which access was
denied, and whether the page is hooked.

### Split and merge

To hook a 4 KiB page inside a 2 MiB large page, the PDE is split into a 512-entry
PT whose PTEs inherit the large page's permissions and contiguous PFNs. On
removal, `can_collapse` checks all 512 children: no table pointers, identical
permissions, contiguous addresses, and no remaining hook anywhere in the merge
range. Only then is the parent collapsed back and the table freed. This is why
`HookEntry` is 16 bytes — 256 of them fit in one 4 KiB page, which is asserted
at compile time.

### Two views and the shadow page

The first hook creates a second view (`view1`) by deep-copying the whole
hierarchy. Then:

- `view0` clears execute on the target PTE. Execution traps.
- `view1` makes the target executable and repoints its PFN at a shadow page.
- the 4 KiB pages immediately before and after the target stay executable in
  `view1`, so an instruction straddling the page boundary does not fault.

Removing the last hook restores `view0` and tears `view1` down. `find_hook`,
`hook_count`, `view1_exists` and `table_pages` let you inspect the state.

### Intel and AMD policies

`Policy::kIntel` is execute-only: only the hooked page loses X in `view0`.
`Policy::kAmd` inverts it — NPT entries have no read bit, so execute-only pages
are impossible. In `view1` every non-hooked page is made non-executable and a
nested page fault occurs on each execution of a hooked page. The inversion is
AMD-only here; `build_view1()` gates it on `policy_ == Policy::kAmd`, and on
Intel only the hooked page changes.

### Invalidation

SLAT caches are per-core, so a hook change needs an invalidation IPI.
`mark_all_dirty` sets a bitmap of pending processors; `needs_flush(cpu)` and
`flush(cpu)` are the per-core side. A real implementation pairs this with NMI
broadcasts — and because Hyper-V uses NMIs for its own inter-processor traffic,
the flush is gated on the bitmap rather than performed on every NMI.

---

## Verification

`vmxctl selftest` runs 103 assertions. The first 40 cover `vmx.h`: field
encoding round trips, MSR decodes, `adjust_controls`, `fix_cr`, EPT/EPTP
formats, exit reasons, VM-instruction errors, SMX-scoped VMXON, invalid EPTP
page-walk encodings and checked-encoder rejections. The remaining 63 cover
`slathook.h`:

- 16-byte hook entries, 256 per page
- 1G → 2M → 4K splits and the corresponding merges, with table pages freed
- PTE strides, untouched adjacent large pages, and the full 512 GiB range in
  `MapMode::k1G` including a hook above 1 GiB
- zeroed PML4 entries reported as **unmapped**, not as permission-denied
  translations
- hook add/remove, shadow-page translation in `view1`, boundary pages
- per-core invalidation bitmap, partial flush
- view teardown and execute restoration after the last hook is removed
- AMD non-hooked-page execute faults with reads unaffected
- hook-table capacity at 256, clean drain, and free-slot reuse
- rejection of shadow addresses above the 44-bit PFN limit, misaligned GPAs
  and misaligned shadow HPAs, with no partial state left behind
- page-table arena exhaustion, failed clone rollback, and verification that
  every accepted hook is installed in both views

Sample output:

```
slathook selftest
  ok    hook entry is 16 bytes
  ok    256 hooks fit in one 4K page
  ok    1G identity map is PML4 + PDPT
  ok    split 1G leaf
  ...
  PASS
```

No driver, no VM, no reboot. `slathook.h` is a model, so its results are
properties of the bookkeeping, not claims about hardware behaviour.

---

## Sources

- [Intel SDM][sdm] vol 3C appendix C (basic exit reasons), table 27-7 (EPT
  violation qualification), vol 3D appendix B (VMCS field encodings)
- [Linux `include/uapi/asm/vmx.h`][uapi] and
  [`arch/x86/include/asm/vmx.h`][asmvmx] for exit reasons and field encodings
- [hyper-reV §4.5][hyperrev] for the SLAT hook state machine that `slathook.h`
  models. read for the architecture, not copied
- `notes.txt` records where the SDM revision I read and the Linux headers
  disagree

---

## License

MIT — see `LICENSE`. Use it as a header, a decoder, or a starting point for your
own hypervisor work; keep the copyright notice if you redistribute it.
