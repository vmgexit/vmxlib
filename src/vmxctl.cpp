#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include "vmx.h"
#include "slathook.h"

using namespace vmx;

static uint64_t num(const char* s) {
    return strtoull(s, nullptr, 0);
}

static const char* on(bool b) { return b ? "yes" : "no"; }

static int usage() {
    printf("vmxctl 0.5  |  decode values pasted out of windbg\n\n");
    printf("  basic <msr>              IA32_VMX_BASIC\n");
    printf("  fc <msr>                 IA32_FEATURE_CONTROL\n");
    printf("  ctl <msr> <desired>      allowed-1 control adjustment\n");
    printf("  cr <cr> <fixed0> <fixed1>   CR0/CR4 fixed bit check\n");
    printf("  epte <entry>             EPT paging-structure entry\n");
    printf("  eptp <eptp>              extended page table pointer\n");
    printf("  qual <qual>              EPT violation exit qualification\n");
    printf("  exit <n>                 VM-exit reason\n");
    printf("  err <n>                  VM-instruction error\n");
    printf("  field <enc|name>         VMCS field encoding\n");
    printf("  enc <w> <a> <idx> [hi]   build a field encoding (w 0..3, a 0..3)\n");
    printf("  slat <gpa>              simulate a SLAT split/merge cycle\n");
    printf("  slathook <gpa>          simulate an execute-only code hook\n");
    printf("  fields | exits | errors  list tables\n");
    printf("  selftest                 verify every table and formula\n");
    return 2;
}

static int do_basic(const char* a) {
    uint64_t v = num(a);
    VmxBasic b = basic_decode(v);
    printf("IA32_VMX_BASIC  0x%016llX\n", (unsigned long long)v);
    printf("  vmcs revision      0x%08X\n", b.revision);
    printf("  vmxon/vmcs size    %u bytes (0x%X)\n", b.region_size, b.region_size);
    printf("  memory type        %u (%s)\n", b.memory_type,
           b.memory_type == 0 ? "UC" : b.memory_type == 6 ? "WB" : "other");
    printf("  32-bit phys only   %s\n", on(b.physaddr_32_only));
    printf("  dual monitor smi   %s\n", on(b.dual_monitor));
    printf("  ins/outs info      %s\n", on(b.ins_outs_info));
    printf("  true controls      %s\n", on(b.true_controls));
    printf("  no hw error code   %s\n", on(b.no_hw_error_code));
    printf("  -> region_init(rev 0x%X, %u bytes)\n", b.revision, b.region_size);
    return 0;
}

static int do_fc(const char* a) {
    uint64_t v = num(a);
    FeatureControl f = feature_control_decode(v);
    printf("IA32_FEATURE_CONTROL  0x%016llX\n", (unsigned long long)v);
    printf("  lock                  %s\n", on(f.lock));
    printf("  vmxon in smx          %s\n", on(f.vmxon_in_smx));
    printf("  vmxon outside smx     %s\n", on(f.vmxon_outside_smx));
    printf("  senter local enables  0x%X\n", f.senter_local);
    printf("  senter global         %s\n", on(f.senter_global));
    printf("  -> vmxon legal: %s\n", on(vmxon_legal(f)));
    return 0;
}

static int do_ctl(const char* a, const char* b) {
    uint64_t cap = num(a);
    uint32_t desired = (uint32_t)num(b);
    uint32_t adjusted = adjust_controls(desired, cap);
    uint32_t impossible = impossible_control_bits(desired, cap);
    printf("capability msr   0x%016llX\n", (unsigned long long)cap);
    printf("  must-be-1      0x%08X\n", (uint32_t)cap);
    printf("  allowed-to-be-1 0x%08X\n", (uint32_t)(cap >> 32));
    printf("  desired         0x%08X\n", desired);
    printf("  adjusted        0x%08X\n", adjusted);
    printf("  impossible      0x%08X\n", impossible);
    return 0;
}

static int do_cr(const char* a, const char* b, const char* c) {
    uint64_t cr = num(a), f0 = num(b), f1 = num(c);
    printf("cr       0x%016llX\n", (unsigned long long)cr);
    printf("  fixed0 0x%016llX  (must be 1)\n", (unsigned long long)f0);
    printf("  fixed1 0x%016llX  (allowed to be 1)\n", (unsigned long long)f1);
    printf("  fixed  0x%016llX\n", (unsigned long long)fix_cr(cr, f0, f1));
    printf("  conflict 0x%016llX\n", (unsigned long long)cr_conflicts(cr, f0, f1));
    return 0;
}

static int do_epte(const char* a) {
    uint64_t v = num(a);
    EptEntry e = ept_entry_decode(v);
    printf("EPT entry  1x%016llX\n", (unsigned long long)v);
    printf("  %c%c%c  mem type %u  ipat %s  large %s  A %s  D %s  X_U %s  suppress_ve %s\n",
           e.read ? 'r' : '-', e.write ? 'w' : '-', e.execute ? 'x' : '-',
           e.memory_type, on(e.ignore_pat), on(e.large), on(e.accessed),
           on(e.dirty), on(e.user_execute), on(e.suppress_ve));
    printf("  hpa 0x%llX\n", (unsigned long long)e.phys);
    return 0;
}

static int do_eptp(const char* a) {
    uint64_t v = num(a);
    Eptp e = eptp_decode(v);
    printf("EPTP  0x%016llX\n", (unsigned long long)v);
    printf("  pml4        0x%llX\n", (unsigned long long)e.pml4);
    printf("  mem type    %u (%s)\n", e.memory_type,
           e.memory_type == 0 ? "UC" : e.memory_type == 6 ? "WB" : "other");
    printf("  walk levels %u  (pwl bits 5:3 = 0x%llX)\n", e.walk_levels,
           (unsigned long long)(v & 0x38));
    printf("  A/D enabled %s\n", on(e.accessed_dirty));
    printf("  encoding    %s\n", e.valid ? "valid" : "INVALID");
    return 0;
}

static int do_qual(const char* a) {
    uint64_t v = num(a);
    EptQual q = ept_qual_decode(v);
    printf("EPT violation qualification  0x%016llX\n", (unsigned long long)v);
    printf("  access     read %s  write %s  fetch %s\n",
           on(q.data_read), on(q.data_write), on(q.instruction_fetch));
    printf("  ept perms  R %s  W %s  X %s  X_U %s\n",
           on(q.ept_readable), on(q.ept_writeable), on(q.ept_executable),
           on(q.user_execute_allowed));
    printf("  gla valid  %s  translated %s\n", on(q.gla_valid), on(q.gla_translated));
    printf("  gla flags  user %s  writable %s  nx %s\n",
           on(q.gla_user), on(q.gla_writable), on(q.gla_nx));
    printf("  nmi unblocking due to IRET  %s\n", on(q.nmi_unblocking_iret));
    printf("  sdm table 27-7; bits 6/9/10/11 are the advanced-info bits\n");
    return 0;
}

static int do_exit(const char* a) {
    uint32_t v = (uint32_t)num(a);
    uint16_t basic = (uint16_t)(v & 0xFFFF);
    const char* n = exit_reason_name(basic);
    printf("VM_EXIT_REASON  0x%08X\n", v);
    printf("  basic    %u  %s\n", basic, n ? n : "?");
    printf("  flags    ");
    if (v & kExitFailedVmentry) printf("FAILED_VMENTRY ");
    if (v & kExitSgxEnclave) printf("SGX_ENCLAVE_MODE ");
    if (!(v & (kExitFailedVmentry | kExitSgxEnclave))) printf("none");
    printf("\n");
    return 0;
}

static int do_err(const char* a) {
    uint32_t v = (uint32_t)num(a);
    const char* s = vm_instruction_error(v);
    printf("VM_INSTRUCTION_ERROR %u  %s\n", v, s ? s : "unknown");
    return 0;
}

static int do_field(const char* a) {
    /* revisit */
    uint32_t enc;
    if (a[0] == '0' && (a[1] == 'x' || a[1] == 'X')) enc = (uint32_t)num(a);
    else enc = field_by_name(a);
    if (enc == 0xFFFFFFFFu) {
        printf("no such field: %s\n", a);
        return 1;
    }
    Field f = field_decode(enc);
    const char* n = field_name(enc);
    printf("VMCS field  0x%08X  %s\n", enc, n ? n : "-");
    printf("  width  %s  area  %s  index %u  high %s\n",
           width_name(f.width), area_name(f.area), f.index, on(f.high));
    printf("  encode (%u, %u, %u%s) = 0x%08X\n",
           (uint32_t)f.width, (uint32_t)f.area, f.index,
           f.high ? ", high" : "", field_encode(f.width, f.area, f.index, f.high));
    return 0;
}

static int do_enc(const char* w, const char* ar, const char* idx, bool hi) {
    uint32_t e = field_encode((Width)num(w), (Area)num(ar), (uint32_t)num(idx), hi);
    printf("0x%08X  %s\n", e, field_name(e) ? field_name(e) : "-");
    return 0;
}

static int do_fields() {
    for (size_t i = 0; i < kFieldCount; i++)
        printf("  0x%08X  %s\n", kFields[i].enc, kFields[i].name);
    printf("  %zu fields\n", kFieldCount);
    return 0;
}

static int do_exits() {
    for (size_t i = 0; i < kExitReasonCount; i++)
        printf("  %3u  %s\n", kExitReasons[i].id, kExitReasons[i].name);
    printf("  holes 5, 11, 17, 35, 38, 42 are undefined/reserved\n");
    return 0;
}

static int do_errors() {
    size_t n = 0;
    const char* const* t = vm_instruction_errors(&n);
    for (size_t i = 0; i < n; i++) printf("  %2zu  %s\n", i, t[i]);
    return 0;
}

static const char* stop_name(vmx::slat::Stop s) {
    using namespace vmx::slat;
    return s == Stop::kUnmapped ? "unmapped" : s == Stop::kRead ? "read" :
           s == Stop::kWrite ? "write" : s == Stop::kExecute ? "execute" : "none";
}

static int do_slat(const char* a) {
    using namespace vmx::slat;
    Slat s(MapMode::k1G, 8);
    uint64_t gpa = num(a) & ~(k4K - 1);
    printf("SLAT split/merge cycle at 0x%llX\n", (unsigned long long)gpa);
    printf("  start     %u table pages, leaf 0x%llX bytes\n",
           s.table_pages(0), (unsigned long long)s.translate(gpa, kR, false).size);
    s.split(gpa);
    printf("  split 1G  %u table pages, leaf 0x%llX bytes\n",
           s.table_pages(0), (unsigned long long)s.translate(gpa, kR, false).size);
    s.split(gpa);
    printf("  split 2M  %u table pages, leaf 0x%llX bytes\n",
           s.table_pages(0), (unsigned long long)s.translate(gpa, kR, false).size);
    Translation t = s.translate(gpa + k4K, kR, false);
    printf("  +4K       hpa 0x%llX  stop %s\n",
           (unsigned long long)t.hpa, stop_name(t.stop));
    s.merge(gpa);
    printf("  merge     %u table pages, leaf 0x%llX bytes\n",
           s.table_pages(0), (unsigned long long)s.translate(gpa, kR, false).size);
    s.merge(gpa);
    printf("  merge     %u table pages, leaf 0x%llX bytes\n",
           s.table_pages(0), (unsigned long long)s.translate(gpa, kR, false).size);
    return 0;
}

static int do_slathook(const char* a) {
    using namespace vmx::slat;
    Slat s(MapMode::k2M, 8);
    uint64_t gpa = num(a) & ~(k4K - 1);
    uint64_t shadow = 0x900000 | (gpa & 0x7FFF);
    printf("SLAT code hook at 0x%llX  shadow 0x%llX\n",
           (unsigned long long)gpa, (unsigned long long)shadow);
    s.add_hook(gpa, shadow);
    printf("  hooks     %u  view0 tables %u  view1 tables %u  pending 0x%llX\n",
           s.hook_count(), s.table_pages(0), s.table_pages(1),
           (unsigned long long)s.pending_mask());
    Translation o = s.translate(gpa, kX, false);
    Translation h = s.translate(gpa, kX, true);
    printf("  orig      stop %s  hpa 0x%llX\n",
           stop_name(o.stop), (unsigned long long)o.hpa);
    printf("  hook      stop %s  hpa 0x%llX  hooked %s\n",
           stop_name(h.stop), (unsigned long long)h.hpa, on(h.hooked));
    s.remove_hook(gpa);
    printf("  removed   hooks %u  view0 tables %u  view1 exists %s\n",
           s.hook_count(), s.table_pages(0), on(s.view1_exists()));
    return 0;
}

static int selftest_slat() {
    using namespace vmx::slat;
    int bad = 0;
    auto ck = [&](bool c, const char* what) {
        printf("  %s  %s\n", c ? "ok  " : "BAD ", what);
        if (!c) bad++;
    };
    printf("\nslathook selftest\n");

    ck(sizeof(HookEntry) == 16, "hook entry is 16 bytes");
    ck(sizeof(HookEntry) * 256 == 4096, "256 hooks fit in one 4K page");

    Slat s(MapMode::k1G, 8);
    ck(s.table_pages(0) == 2, "1G identity map is PML4 + PDPT");
    ck(s.translate(0x400000, kR, false).size == k1G, "1G leaf translates as large");
    ck(s.split(0x400000), "split 1G leaf");
    ck(s.table_pages(0) == 3, "1G split adds a PD");
    ck(s.translate(0x400000, kR, false).size == k2M, "2M leaf after first split");
    ck(s.split(0x400000), "split 2M leaf");
    ck(s.table_pages(0) == 4, "2M split adds a PT");
    ck(s.translate(0x400000, kR, false).size == k4K, "4K leaf after full split");
    ck(s.translate(0x401000, kR, false).hpa == 0x401000, "PTE strides are 4K");
    ck(s.translate(0x600000, kR, false).hpa == 0x600000, "adjacent 2M page unaffected");
    ck(s.merge(0x400000), "merge back to 2M");
    ck(s.table_pages(0) == 3, "PT freed on merge");
    ck(s.merge(0x400000), "merge back to 1G");
    ck(s.table_pages(0) == 2, "PD freed on merge");

    Slat h(MapMode::k2M, 8);
    ck(h.hook_count() == 0, "no hooks initially");
    ck(h.add_hook(0x201000, 0x900000), "add hook at 0x201000");
    ck(h.hook_count() == 1, "hook count 1");
    ck(h.view1_exists(), "hook view created on first hook");
    ck(h.find_hook(0x201000) != nullptr, "find_hook by GPA");
    ck(h.translate(0x201000, kX, false).stop == Stop::kExecute,
       "orig view traps execute on hooked page");
    ck(h.translate(0x201000, kR, false).stop == Stop::kNone,
       "orig view still reads hooked page");
    Translation t = h.translate(0x201000, kR, true);
    ck(t.stop == Stop::kNone && t.hpa == 0x900000, "hook view maps the shadow page");
    ck(t.hooked, "translation reports the page is hooked");
    ck(h.translate(0x201000, kX, true).stop == Stop::kNone,
       "hook view executes the shadow page");
    ck(h.translate(0x200000, kX, true).stop == Stop::kNone,
       "page before hooked page stays executable");
    ck(h.translate(0x202000, kX, true).stop == Stop::kNone,
       "page after hooked page stays executable");
    ck(h.add_hook(0x202000, 0x910000), "second hook in same 2M range");
    ck(h.hook_count() == 2, "hook count 2");
    ck(h.pending_mask() == 0xFF, "all 8 processors marked for invalidation");
    h.flush(3);
    ck(!h.needs_flush(3) && h.needs_flush(2), "flush clears only one processor");
    ck(h.remove_hook(0x202000), "remove one hook");
    ck(h.hook_count() == 1, "hook count back to 1");
    ck(h.translate(0x201000, kX, false).stop == Stop::kExecute,
    /* revisit */
       "remaining hook still traps execute");
    ck(h.remove_hook(0x201000), "remove last hook");
    ck(h.hook_count() == 0, "hook count 0");
    ck(!h.view1_exists(), "hook view torn down with last hook");
    ck(h.table_pages(0) == 3, "view0 merged back to 2M pages");
    ck(h.translate(0x201000, kX, false).stop == Stop::kNone,
       "orig execute restored after merge");
    ck(!h.remove_hook(0x201000), "removing a missing hook fails");

    Slat a(MapMode::k2M, 4);
    a.set_policy(Policy::kAmd);
    ck(a.add_hook(0x201000, 0x900000), "AMD: add hook");
    ck(a.translate(0x201000, kX, true).stop == Stop::kNone,
       "AMD: hooked page executable in hook view");
    ck(a.translate(0x205000, kX, true).stop == Stop::kExecute,
       "AMD: non-hooked 4K page faults on execute");
    ck(a.translate(0x200000, kX, true).stop == Stop::kNone,
       "AMD: page before hooked page still executable");
    ck(a.translate(0x205000, kR, true).stop == Stop::kNone,
       "AMD: reads are unaffected");

    Slat f(MapMode::k2M, 2);
    bool all_ok = true;
    for (uint32_t i = 0; i < 300; i++) {
        if (!f.add_hook(0x100000 + i * k4K, 0x800000 + i * k4K)) { all_ok = false; break; }
    }
    ck(!all_ok && f.hook_count() == f.kMaxHooks, "hook table caps at 256 entries");
    for (uint32_t i = 0; i < f.kMaxHooks; i++)
        if (!f.remove_hook(0x100000 + i * k4K)) { all_ok = false; break; }
    ck(f.hook_count() == 0, "hook table drains cleanly");
    ck(f.add_hook(0x100000, 0x800000), "freed slots are reusable");

    Slat b(MapMode::k1G, 8);
    Translation hi = b.translate(100ULL * k1G, kR, false);
    ck(hi.mapped && hi.hpa == 100ULL * k1G && hi.size == k1G,
       "k1G map covers its full 512GiB range");
    Translation past = b.translate(k512G + k4K, kR, false);
    ck(!past.mapped && past.stop == Stop::kUnmapped && past.hpa == 0,
       "absent PML4 entry is unmapped, not a blocked translation");
    Translation zero = b.translate(k512G * 3, kR, false);
    ck(!zero.mapped, "zeroed entry never produces an hpa");
    ck(b.add_hook(100ULL * k1G + k4K, 0x900000),
       "hook above 1GiB accepted in k1G mode");
    ck(b.find_hook(100ULL * k1G + k4K) != nullptr,
       "high hook is present in the hook table");

    Slat align_test(MapMode::k2M, 8);
    ck(!align_test.add_hook(0x100000, 1ULL << 45),
       "shadow hpa above the 44-bit PFN limit is rejected");
    ck(align_test.hook_count() == 0 && !align_test.view1_exists(),
       "rejected hook leaves no metadata and no hook view");
    ck(align_test.add_hook(0x100001, 0x900000) &&
       align_test.find_hook(0x100000) != nullptr,
       "gpa is aligned to 4K before insertion");
    ck(!align_test.add_hook(0x200000, 0x900001),
       "misaligned shadow hpa is rejected");

    Slat x(MapMode::k2M, 8);
    bool exhausted = false;
    uint64_t accepted[32];
    uint32_t n_accepted = 0;
    for (uint32_t i = 0; i < 32; i++) {
        uint64_t gpa = (uint64_t)i * k2M + k4K;
        if (!x.add_hook(gpa, 0x900000 + i * k4K)) {
            exhausted = true;
            break;
        }
        accepted[n_accepted++] = gpa;
    }
    ck(exhausted, "page-table arena exhaustion is detected");
    ck(x.total_pages() <= x.kMaxPages, "no page leak after a failed clone");

    bool all_installed = true;
    for (uint32_t i = 0; i < n_accepted; i++) {
        const HookEntry* he = x.find_hook(accepted[i]);
        if (!he) { all_installed = false; break; }
        Translation o = x.translate(he->gpa, kX, false);
        Translation h = x.translate(he->gpa, kX, true);
        if (!o.mapped || o.stop != Stop::kExecute ||
            !h.mapped || h.hpa != ((uint64_t)he->shadow_pfn << 12)) {
            all_installed = false;
            break;
        }
    }
    ck(all_installed, "every accepted hook is installed in both views");
    uint32_t pages_before = x.total_pages();
    ck(!x.add_hook(0x900000000ULL, 0xA00000),
       "hook in an unmapped region fails");
    ck(x.total_pages() == pages_before && x.hook_count() == n_accepted,
       "failed hook rolls back allocations and metadata");

    printf("  %s\n", bad ? "FAILED" : "PASS");
    return bad;
}

static int selftest() {
    int bad = 0;
    auto ck = [&](bool c, const char* what) {
        printf("  %s  %s\n", c ? "ok  " : "BAD ", what);
        if (!c) bad++;
    };
    printf("vmxlib selftest\n");

    ck(field_encode(Width::Natural, Area::Guest, 15) == 0x681E, "GUEST_RIP encoding");
    ck(field_encode(Width::Natural, Area::Host, 11) == 0x6C16, "HOST_RIP encoding");
    ck(field_encode(Width::W32, Area::ExitInfo, 1) == 0x4402, "VM_EXIT_REASON encoding");
    ck(field_encode(Width::W64, Area::Control, 13) == 0x201A, "EPT_POINTER encoding");
    ck(field_encode(Width::W64, Area::Control, 13, true) == 0x201B, "EPT_POINTER_HIGH encoding");
    ck(field_encode(Width::W64, Area::Guest, 0) == 0x2800, "VMCS_LINK_POINTER encoding");

    Field f = field_decode(0x201B);
    ck(f.width == Width::W64 && f.area == Area::Control && f.index == 13 && f.high,
       "field_decode round trip with high bit");
    ck(strcmp(field_name(0x681E), "GUEST_RIP") == 0, "field_name lookup");
    ck(field_by_name("HOST_RIP") == 0x6C16, "field_by_name lookup");
    ck(field_by_name("NOPE") == 0xFFFFFFFFu, "unknown field name");

    uint64_t bv = basic_encode(0x1A, 0x1000, 6) | (1ULL << 55) | (1ULL << 49);
    VmxBasic b = basic_decode(bv);
    ck(b.revision == 0x1A && b.region_size == 0x1000 && b.memory_type == 6 &&
       b.true_controls && b.dual_monitor, "IA32_VMX_BASIC encode/decode");

    FeatureControl fc = feature_control_decode(0x5);
    ck(fc.lock && fc.vmxon_outside_smx && !fc.vmxon_in_smx && vmxon_legal(fc),
       "IA32_FEATURE_CONTROL vmxon legal");
    ck(!vmxon_legal(feature_control_decode(0x4)), "unlocked feature control is not legal");

    uint64_t cap = (0x7FULL << 32) | 0x1;
    ck(adjust_controls(0x40, cap) == 0x41, "adjust_controls forces must-be-1 bits");
    ck(impossible_control_bits(0x100, cap) == 0x100, "impossible bits outside allowed-1");

    ck(fix_cr(0, 0x20, ~0ULL) == 0x20, "fix_cr applies fixed0");
    ck(cr_conflicts(0, 0x20, ~0ULL) == 0x20, "cr_conflicts reports missing fixed0");
    ck(fix_cr(0x800, 0, ~0x800ULL) == 0, "fix_cr masks off fixed1-forbidden bits");

    uint64_t ee = ept_entry_encode(0x1000, true, true, false, 6, false);
    EptEntry e = ept_entry_decode(ee);
    ck(e.read && e.write && !e.execute && e.memory_type == 6 && e.phys == 0x1000,
       "EPT entry encode/decode");

    uint64_t ep = eptp_encode(0x1000, 6, 4, false);
    ck(ep == 0x101E, "EPTP default is WB + 4-level (0x1E low bits)");
    Eptp pd = eptp_decode(ep);
    ck(pd.pml4 == 0x1000 && pd.memory_type == 6 && pd.walk_levels == 4 &&
       !pd.accessed_dirty, "EPTP decode");
    ck(eptp_decode(eptp_encode(0x2000, 6, 5, true)).walk_levels == 5,
       "5-level EPTP walk");

    EptQual q = ept_qual_decode((1 << 0) | (1 << 3) | (1 << 7) | (1 << 8) | (1 << 12));
    ck(q.data_read && q.ept_readable && q.gla_valid && q.gla_translated &&
       q.nmi_unblocking_iret && !q.data_write, "EPT violation qualification bits");

    ck(strcmp(exit_reason_name(48), "EPT_VIOLATION") == 0, "exit reason 48 is EPT_VIOLATION");
    ck(strcmp(exit_reason_name(10), "CPUID") == 0, "exit reason 10 is CPUID");
