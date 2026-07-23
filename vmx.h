#pragma once

#include <cstdint>
#include <cstddef>

#if defined(_MSC_VER) && defined(_M_X64)
#include <intrin.h>
#define VMXLIB_HAS_INTRINSICS 1
#endif

namespace vmx {

constexpr uint64_t kPhysAddrMask = 0x000FFFFFFFFFF000ULL;

namespace msr {
enum : uint32_t {
    IA32_FEATURE_CONTROL        = 0x03A,
    IA32_VMX_BASIC              = 0x480,
    IA32_VMX_PINBASED_CTLS      = 0x481,
    IA32_VMX_PROCBASED_CTLS     = 0x482,
    IA32_VMX_EXIT_CTLS          = 0x483,
    IA32_VMX_ENTRY_CTLS         = 0x484,
    IA32_VMX_MISC               = 0x485,
    IA32_VMX_CR0_FIXED0         = 0x486,
    IA32_VMX_CR0_FIXED1         = 0x487,
    IA32_VMX_CR4_FIXED0         = 0x488,
    IA32_VMX_CR4_FIXED1         = 0x489,
    IA32_VMX_VMCS_ENUM          = 0x48A,
    IA32_VMX_PROCBASED_CTLS2    = 0x48B,
    IA32_VMX_EPT_VPID_CAP       = 0x48C,
    IA32_VMX_TRUE_PINBASED_CTLS = 0x48D,
    IA32_VMX_TRUE_PROCBASED_CTLS= 0x48E,
    IA32_VMX_TRUE_EXIT_CTLS     = 0x48F,
    IA32_VMX_TRUE_ENTRY_CTLS    = 0x490,
    IA32_VMX_VMFUNC             = 0x491,
};
}

enum class Width : uint32_t { W16 = 0, W64 = 1, W32 = 2, Natural = 3 };
enum class Area : uint32_t { Control = 0, ExitInfo = 1, Guest = 2, Host = 3 };

struct Field {
    Width width;
    Area area;
    uint32_t index;
    bool high;
};

constexpr uint32_t field_encode(Width w, Area a, uint32_t index, bool high = false) {
    return ((uint32_t)w << 13) | ((uint32_t)a << 10) | (index << 1) | (high ? 1u : 0u);
}

constexpr Field field_decode(uint32_t e) {
    return Field{
        (Width)((e >> 13) & 3),
        (Area)((e >> 10) & 3),
        (e >> 1) & 0x1ff,
        (e & 1) != 0
    };
}

constexpr const char* width_name(Width w) {
    return w == Width::W16 ? "16-bit" :
           w == Width::W64 ? "64-bit" :
           w == Width::W32 ? "32-bit" : "natural-width";
}

constexpr const char* area_name(Area a) {
    return a == Area::Control ? "control" :
           a == Area::ExitInfo ? "vm-exit information" :
           a == Area::Guest ? "guest state" : "host state";
}

struct FieldName { uint32_t enc; const char* name; };

constexpr FieldName kFields[] = {
    { 0x0000, "VIRTUAL_PROCESSOR_ID" },
    { 0x0002, "POSTED_INTR_NV" },
    { 0x0008, "LAST_PID_POINTER_INDEX" },
    { 0x0800, "GUEST_ES_SELECTOR" },
    { 0x0802, "GUEST_CS_SELECTOR" },
    { 0x0804, "GUEST_SS_SELECTOR" },
    { 0x0806, "GUEST_DS_SELECTOR" },
    { 0x0808, "GUEST_FS_SELECTOR" },
    { 0x080A, "GUEST_GS_SELECTOR" },
    { 0x080C, "GUEST_LDTR_SELECTOR" },
    { 0x080E, "GUEST_TR_SELECTOR" },
    { 0x0810, "GUEST_INTR_STATUS" },
    { 0x0812, "GUEST_PML_INDEX" },
    { 0x0C00, "HOST_ES_SELECTOR" },
    { 0x0C02, "HOST_CS_SELECTOR" },
    { 0x0C04, "HOST_SS_SELECTOR" },
    { 0x0C06, "HOST_DS_SELECTOR" },
    { 0x0C08, "HOST_FS_SELECTOR" },
    { 0x0C0A, "HOST_GS_SELECTOR" },
    { 0x0C0C, "HOST_TR_SELECTOR" },
    { 0x2000, "IO_BITMAP_A" },
    { 0x2001, "IO_BITMAP_A_HIGH" },
    { 0x2002, "IO_BITMAP_B" },
    { 0x2003, "IO_BITMAP_B_HIGH" },
    { 0x2004, "MSR_BITMAP" },
    { 0x2005, "MSR_BITMAP_HIGH" },
    { 0x2006, "VM_EXIT_MSR_STORE_ADDR" },
    { 0x2007, "VM_EXIT_MSR_STORE_ADDR_HIGH" },
    { 0x2008, "VM_EXIT_MSR_LOAD_ADDR" },
    { 0x2009, "VM_EXIT_MSR_LOAD_ADDR_HIGH" },
    { 0x200A, "VM_ENTRY_MSR_LOAD_ADDR" },
    { 0x200B, "VM_ENTRY_MSR_LOAD_ADDR_HIGH" },
    { 0x200E, "PML_ADDRESS" },
    { 0x200F, "PML_ADDRESS_HIGH" },
    { 0x2010, "TSC_OFFSET" },
    { 0x2011, "TSC_OFFSET_HIGH" },
    { 0x2012, "VIRTUAL_APIC_PAGE_ADDR" },
    { 0x2013, "VIRTUAL_APIC_PAGE_ADDR_HIGH" },
    { 0x2014, "APIC_ACCESS_ADDR" },
    { 0x2015, "APIC_ACCESS_ADDR_HIGH" },
    { 0x2016, "POSTED_INTR_DESC_ADDR" },
    { 0x2017, "POSTED_INTR_DESC_ADDR_HIGH" },
    { 0x2018, "VM_FUNCTION_CONTROL" },
    { 0x2019, "VM_FUNCTION_CONTROL_HIGH" },
    { 0x201A, "EPT_POINTER" },
    { 0x201B, "EPT_POINTER_HIGH" },
    { 0x201C, "EOI_EXIT_BITMAP0" },
    { 0x201D, "EOI_EXIT_BITMAP0_HIGH" },
    { 0x201E, "EOI_EXIT_BITMAP1" },
    { 0x2020, "EOI_EXIT_BITMAP2" },
    { 0x2022, "EOI_EXIT_BITMAP3" },
    { 0x2024, "EPTP_LIST_ADDRESS" },
    { 0x2026, "VMREAD_BITMAP" },
    { 0x2028, "VMWRITE_BITMAP" },
    { 0x202A, "VE_INFORMATION_ADDRESS" },
    { 0x202C, "XSS_EXIT_BITMAP" },
    { 0x202E, "ENCLS_EXITING_BITMAP" },
    { 0x2032, "TSC_MULTIPLIER" },
    { 0x2034, "TERTIARY_VM_EXEC_CONTROL" },
    { 0x2400, "GUEST_PHYSICAL_ADDRESS" },
    { 0x2401, "GUEST_PHYSICAL_ADDRESS_HIGH" },
    { 0x2800, "VMCS_LINK_POINTER" },
    { 0x2801, "VMCS_LINK_POINTER_HIGH" },
    { 0x2802, "GUEST_IA32_DEBUGCTL" },
    { 0x2804, "GUEST_IA32_PAT" },
    { 0x2806, "GUEST_IA32_EFER" },
    { 0x2808, "GUEST_IA32_PERF_GLOBAL_CTRL" },
    { 0x280A, "GUEST_PDPTR0" },
    { 0x280C, "GUEST_PDPTR1" },
    { 0x280E, "GUEST_PDPTR2" },
    { 0x2810, "GUEST_PDPTR3" },
    { 0x2812, "GUEST_BNDCFGS" },
    { 0x2814, "GUEST_IA32_RTIT_CTL" },
    { 0x2C00, "HOST_IA32_PAT" },
    { 0x2C02, "HOST_IA32_EFER" },
    { 0x2C04, "HOST_IA32_PERF_GLOBAL_CTRL" },
    { 0x4000, "PIN_BASED_VM_EXEC_CONTROL" },
    { 0x4002, "CPU_BASED_VM_EXEC_CONTROL" },
    { 0x4004, "EXCEPTION_BITMAP" },
    { 0x4006, "PAGE_FAULT_ERROR_CODE_MASK" },
    { 0x4008, "PAGE_FAULT_ERROR_CODE_MATCH" },
    { 0x400A, "CR3_TARGET_COUNT" },
    { 0x400C, "VM_EXIT_CONTROLS" },
    { 0x400E, "VM_EXIT_MSR_STORE_COUNT" },
    { 0x4010, "VM_EXIT_MSR_LOAD_COUNT" },
    { 0x4012, "VM_ENTRY_CONTROLS" },
    { 0x4014, "VM_ENTRY_MSR_LOAD_COUNT" },
    { 0x4016, "VM_ENTRY_INTR_INFO" },
    { 0x4018, "VM_ENTRY_EXCEPTION_ERROR_CODE" },
    { 0x401A, "VM_ENTRY_INSTRUCTION_LEN" },
    { 0x401C, "TPR_THRESHOLD" },
    { 0x401E, "SECONDARY_VM_EXEC_CONTROL" },
    { 0x4020, "PLE_GAP" },
    { 0x4022, "PLE_WINDOW" },
    { 0x4024, "NOTIFY_WINDOW" },
    { 0x4400, "VM_INSTRUCTION_ERROR" },
    { 0x4402, "VM_EXIT_REASON" },
    { 0x4404, "VM_EXIT_INTR_INFO" },
    { 0x4406, "VM_EXIT_INTR_ERROR_CODE" },
    { 0x4408, "IDT_VECTORING_INFO" },
    { 0x440A, "IDT_VECTORING_ERROR_CODE" },
    { 0x440C, "VM_EXIT_INSTRUCTION_LEN" },
    { 0x440E, "VMX_INSTRUCTION_INFO" },
    { 0x4800, "GUEST_ES_LIMIT" },
    { 0x4802, "GUEST_CS_LIMIT" },
    { 0x4814, "GUEST_ES_AR_BYTES" },
    { 0x4816, "GUEST_CS_AR_BYTES" },
    { 0x4818, "GUEST_SS_AR_BYTES" },
    { 0x4824, "GUEST_INTERRUPTIBILITY_INFO" },
    { 0x4826, "GUEST_ACTIVITY_STATE" },
    { 0x482A, "GUEST_SYSENTER_CS" },
    { 0x482E, "VMX_PREEMPTION_TIMER_VALUE" },
    { 0x4C00, "HOST_IA32_SYSENTER_CS" },
    { 0x6000, "CR0_GUEST_HOST_MASK" },
    { 0x6002, "CR4_GUEST_HOST_MASK" },
    { 0x6004, "CR0_READ_SHADOW" },
    { 0x6006, "CR4_READ_SHADOW" },
    { 0x6008, "CR3_TARGET_VALUE0" },
    { 0x600A, "CR3_TARGET_VALUE1" },
    { 0x600C, "CR3_TARGET_VALUE2" },
    { 0x600E, "CR3_TARGET_VALUE3" },
    { 0x6400, "EXIT_QUALIFICATION" },
    { 0x640A, "GUEST_LINEAR_ADDRESS" },
    { 0x6800, "GUEST_CR0" },
    { 0x6802, "GUEST_CR3" },
    { 0x6804, "GUEST_CR4" },
    { 0x6806, "GUEST_ES_BASE" },
    { 0x6808, "GUEST_CS_BASE" },
    { 0x680A, "GUEST_SS_BASE" },
    { 0x680C, "GUEST_DS_BASE" },
    { 0x680E, "GUEST_FS_BASE" },
    { 0x6810, "GUEST_GS_BASE" },
    { 0x6812, "GUEST_LDTR_BASE" },
    { 0x6814, "GUEST_TR_BASE" },
    { 0x6816, "GUEST_GDTR_BASE" },
    { 0x6818, "GUEST_IDTR_BASE" },
    { 0x681A, "GUEST_DR7" },
    { 0x681C, "GUEST_RSP" },
    { 0x681E, "GUEST_RIP" },
    { 0x6820, "GUEST_RFLAGS" },
    { 0x6822, "GUEST_PENDING_DBG_EXCEPTIONS" },
    { 0x6824, "GUEST_SYSENTER_ESP" },
    { 0x6826, "GUEST_SYSENTER_EIP" },
    { 0x6C00, "HOST_CR0" },
    { 0x6C02, "HOST_CR3" },
    { 0x6C04, "HOST_CR4" },
    { 0x6C06, "HOST_FS_BASE" },
    { 0x6C08, "HOST_GS_BASE" },
    { 0x6C0A, "HOST_TR_BASE" },
    { 0x6C0C, "HOST_GDTR_BASE" },
    { 0x6C0E, "HOST_IDTR_BASE" },
    { 0x6C10, "HOST_IA32_SYSENTER_ESP" },
    { 0x6C12, "HOST_IA32_SYSENTER_EIP" },
    { 0x6C14, "HOST_RSP" },
    { 0x6C16, "HOST_RIP" },
};

constexpr size_t kFieldCount = sizeof(kFields) / sizeof(kFields[0]);

inline const char* field_name(uint32_t enc) {
    for (size_t i = 0; i < kFieldCount; i++)
        if (kFields[i].enc == enc) return kFields[i].name;
    return nullptr;
}

inline uint32_t field_by_name(const char* name) {
    for (size_t i = 0; i < kFieldCount; i++) {
        const char* a = kFields[i].name;
        const char* b = name;
        while (*a && *b && *a == *b) { a++; b++; }
        if (!*a && !*b) return kFields[i].enc;
    }
    return 0xFFFFFFFFu;
}

struct VmxBasic {
    uint32_t revision;
    uint32_t region_size;
    uint8_t memory_type;
    bool physaddr_32_only;
    bool dual_monitor;
    bool ins_outs_info;
    bool true_controls;
    bool no_hw_error_code;
    uint64_t raw;
};

inline VmxBasic basic_decode(uint64_t raw) {
    VmxBasic b{};
    b.raw = raw;
    b.revision = (uint32_t)(raw & 0x7FFFFFFF);
    b.region_size = (uint32_t)((raw >> 32) & 0x1FFF);
    b.physaddr_32_only = (raw >> 48) & 1;
    b.dual_monitor = (raw >> 49) & 1;
    b.memory_type = (uint8_t)((raw >> 50) & 0xF);
    b.ins_outs_info = (raw >> 54) & 1;
    b.true_controls = (raw >> 55) & 1;
    b.no_hw_error_code = (raw >> 56) & 1;
    return b;
}

inline uint64_t basic_encode(uint32_t revision, uint16_t size, uint8_t memtype) {
    return (uint64_t)revision | ((uint64_t)size << 32) | ((uint64_t)memtype << 50);
}

struct FeatureControl {
    bool lock;
    bool vmxon_in_smx;
    bool vmxon_outside_smx;
    uint8_t senter_local;
    bool senter_global;
    uint64_t raw;
};

inline FeatureControl feature_control_decode(uint64_t raw) {
    FeatureControl f{};
    f.raw = raw;
    f.lock = raw & 1;
    f.vmxon_in_smx = (raw >> 1) & 1;
    f.vmxon_outside_smx = (raw >> 2) & 1;
    f.senter_local = (uint8_t)((raw >> 3) & 0x1F);
    f.senter_global = (raw >> 8) & 1;
    return f;
}

inline bool vmxon_allowed(const FeatureControl& f, bool in_smx) {
    if (!f.lock) return false;
    return in_smx ? f.vmxon_in_smx : f.vmxon_outside_smx;
}

inline bool vmxon_legal(const FeatureControl& f) {
    return vmxon_allowed(f, false) || vmxon_allowed(f, true);
}

inline uint32_t adjust_controls(uint32_t desired, uint64_t cap) {
    return (desired | (uint32_t)cap) & (uint32_t)(cap >> 32);
}

inline uint32_t impossible_control_bits(uint32_t desired, uint64_t cap) {
    return desired & ~((uint32_t)(cap >> 32) | (uint32_t)cap);
}

inline uint64_t fix_cr(uint64_t cr, uint64_t fixed0, uint64_t fixed1) {
    return (cr | fixed0) & fixed1;
}

inline uint64_t cr_conflicts(uint64_t cr, uint64_t fixed0, uint64_t fixed1) {
    return ((~cr) & fixed0) | (cr & ~fixed1);
}

struct EptEntry {
    bool read, write, execute;
    uint8_t memory_type;
    bool ignore_pat, large, accessed, dirty, user_execute, suppress_ve;
    uint64_t phys;
    uint64_t raw;
};

inline uint64_t ept_entry_encode(uint64_t hpa, bool r, bool w, bool x,
                                 uint8_t mem_type = 6, bool large = false) {
    return (hpa & 0x000FFFFFFFFFF000ULL) |
           (r ? 1ULL : 0) | (w ? 2ULL : 0) | (x ? 4ULL : 0) |
           ((uint64_t)(mem_type & 7) << 3) |
           (large ? (1ULL << 7) : 0);
}

inline bool ept_entry_encode_checked(uint64_t hpa, bool r, bool w, bool x,
                                     uint8_t mem_type, bool large,
                                     uint64_t* out) {
    if (!out) return false;
    if (hpa & ~kPhysAddrMask) return false;
    if (hpa & 0xFFFULL) return false;
    if (large && (hpa & 0x1FFFFFULL)) return false;
    if (mem_type > 7) return false;
    if (!r && !w && !x) return false;
    *out = ept_entry_encode(hpa, r, w, x, mem_type, large);
    return true;
}

inline EptEntry ept_entry_decode(uint64_t raw) {
    EptEntry e{};
    e.raw = raw;
    e.read = raw & 1;
    e.write = (raw >> 1) & 1;
    e.execute = (raw >> 2) & 1;
    e.memory_type = (uint8_t)((raw >> 3) & 7);
    e.ignore_pat = (raw >> 6) & 1;
    e.large = (raw >> 7) & 1;
    e.accessed = (raw >> 8) & 1;
    e.dirty = (raw >> 9) & 1;
    e.user_execute = (raw >> 10) & 1;
    e.suppress_ve = (raw >> 63) & 1;
    e.phys = raw & 0x000FFFFFFFFFF000ULL;
    return e;
}

constexpr uint64_t kEptpPwl4 = 0x18ULL;
constexpr uint64_t kEptpPwl5 = 0x20ULL;

inline bool eptp_encode_checked(uint64_t pml4_pa, uint8_t mem_type,
                                uint8_t walk_levels, bool ad, uint64_t* out) {
    if (!out) return false;
    if (walk_levels != 4 && walk_levels != 5) return false;
    if (mem_type > 7) return false;
    if (pml4_pa & ~kPhysAddrMask) return false;
    if (pml4_pa & 0xFFFULL) return false;
    uint64_t pwl = walk_levels == 5 ? kEptpPwl5 : kEptpPwl4;
    *out = (pml4_pa & kPhysAddrMask) | (mem_type & 7) | pwl |
           (ad ? (1ULL << 6) : 0);
    return true;
}

inline uint64_t eptp_encode(uint64_t pml4_pa, uint8_t mem_type = 6,
                            uint8_t walk_levels = 4, bool ad = false) {
    uint64_t out = 0;
    return eptp_encode_checked(pml4_pa, mem_type, walk_levels, ad, &out) ? out : 0;
}

struct Eptp {
    uint64_t pml4;
    uint8_t memory_type;
    uint8_t walk_levels;
    bool accessed_dirty;
    bool valid;
    uint64_t raw;
};

inline Eptp eptp_decode(uint64_t raw) {
    Eptp e{};
    e.raw = raw;
    e.pml4 = raw & kPhysAddrMask;
    e.memory_type = (uint8_t)(raw & 7);
    uint64_t pwl = raw & 0x38;
    e.walk_levels = pwl == kEptpPwl4 ? 4 : pwl == kEptpPwl5 ? 5 : 0;
    e.accessed_dirty = (raw >> 6) & 1;
    e.valid = e.walk_levels != 0 && (raw & 7) <= 6;
    if (!e.valid) e.walk_levels = 0;
    return e;
}

struct EptQual {
    bool data_read, data_write, instruction_fetch;
    bool ept_readable, ept_writeable, ept_executable;
    bool user_execute_allowed;
    bool gla_valid;
    bool gla_translated;
    bool gla_user, gla_writable, gla_nx;
    bool nmi_unblocking_iret;
    uint64_t raw;
};

inline EptQual ept_qual_decode(uint64_t raw) {
    EptQual q{};
    q.raw = raw;
    q.data_read = raw & 1;
    q.data_write = (raw >> 1) & 1;
    q.instruction_fetch = (raw >> 2) & 1;
    q.ept_readable = (raw >> 3) & 1;
    q.ept_writeable = (raw >> 4) & 1;
    q.ept_executable = (raw >> 5) & 1;
    q.user_execute_allowed = (raw >> 6) & 1;
    q.gla_valid = (raw >> 7) & 1;
    q.gla_translated = (raw >> 8) & 1;
    q.gla_user = (raw >> 9) & 1;
    q.gla_writable = (raw >> 10) & 1;
    q.gla_nx = (raw >> 11) & 1;
    q.nmi_unblocking_iret = (raw >> 12) & 1;
    return q;
}

struct ExitReason { uint16_t id; const char* name; };

constexpr ExitReason kExitReasons[] = {
    { 0, "EXCEPTION_NMI" }, { 1, "EXTERNAL_INTERRUPT" }, { 2, "TRIPLE_FAULT" },
    { 3, "INIT_SIGNAL" }, { 4, "SIPI_SIGNAL" }, { 6, "OTHER_SMI" },
    { 7, "INTERRUPT_WINDOW" }, { 8, "NMI_WINDOW" }, { 9, "TASK_SWITCH" },
    { 10, "CPUID" }, { 12, "HLT" }, { 13, "INVD" }, { 14, "INVLPG" },
    { 15, "RDPMC" }, { 16, "RDTSC" }, { 18, "VMCALL" }, { 19, "VMCLEAR" },
    { 20, "VMLAUNCH" }, { 21, "VMPTRLD" }, { 22, "VMPTRST" }, { 23, "VMREAD" },
    { 24, "VMRESUME" }, { 25, "VMWRITE" }, { 26, "VMOFF" }, { 27, "VMON" },
    { 28, "CR_ACCESS" }, { 29, "DR_ACCESS" }, { 30, "IO_INSTRUCTION" },
    { 31, "MSR_READ" }, { 32, "MSR_WRITE" }, { 33, "INVALID_STATE" },
    { 34, "MSR_LOAD_FAIL" }, { 36, "MWAIT_INSTRUCTION" },
    { 37, "MONITOR_TRAP_FLAG" }, { 39, "MONITOR_INSTRUCTION" },
    { 40, "PAUSE_INSTRUCTION" }, { 41, "MCE_DURING_VMENTRY" },
    { 43, "TPR_BELOW_THRESHOLD" }, { 44, "APIC_ACCESS" },
    { 45, "EOI_INDUCED" }, { 46, "GDTR_IDTR" }, { 47, "LDTR_TR" },
    { 48, "EPT_VIOLATION" }, { 49, "EPT_MISCONFIG" }, { 50, "INVEPT" },
    { 51, "RDTSCP" }, { 52, "PREEMPTION_TIMER" }, { 53, "INVVPID" },
    { 54, "WBINVD" }, { 55, "XSETBV" }, { 56, "APIC_WRITE" },
    { 57, "RDRAND" }, { 58, "INVPCID" }, { 59, "VMFUNC" }, { 60, "ENCLS" },
    { 61, "RDSEED" }, { 62, "PML_FULL" }, { 63, "XSAVES" }, { 64, "XRSTORS" },
    { 67, "UMWAIT" }, { 68, "TPAUSE" }, { 74, "BUS_LOCK" }, { 75, "NOTIFY" },
    { 76, "SEAMCALL" }, { 77, "TDCALL" }, { 84, "MSR_READ_IMM" },
    { 85, "MSR_WRITE_IMM" },
};

constexpr size_t kExitReasonCount = sizeof(kExitReasons) / sizeof(kExitReasons[0]);
constexpr uint32_t kExitFailedVmentry = 0x80000000u;
constexpr uint32_t kExitSgxEnclave = 0x08000000u;

inline const char* exit_reason_name(uint16_t id) {
    for (size_t i = 0; i < kExitReasonCount; i++)
        if (kExitReasons[i].id == id) return kExitReasons[i].name;
    return nullptr;
}

inline const char* const* vm_instruction_errors(size_t* count) {
    static const char* t[] = {
        "no error",
        "VMCALL executed in VMX root operation",
        "VMCLEAR with invalid physical address",
        "VMCLEAR with VMXON pointer",
        "VMLAUNCH with non-clear VMCS",
        "VMRESUME with non-launched VMCS",
        "VMRESUME after VMXOFF",
        "VM-entry with invalid control field(s)",
        "VM-entry with invalid host-state field(s)",
        "VMPTRLD with invalid physical address",
        "VMPTRLD with VMXON pointer",
        "VMPTRLD with wrong VMCS revision identifier",
        "VMREAD/VMWRITE from/to unsupported VMCS component",
        "VMWRITE to read-only VMCS component",
        "reserved",
        "VMXON executed in VMX root operation",
        "VM-entry with invalid executive-VMCS pointer",
        "VM-entry with non-launched executive VMCS",
        "VM-entry with executive-VMCS pointer not VMXON pointer",
        "VMCALL with non-clear VMCS",
        "VMCALL with invalid VM-exit control field(s)",
        "reserved",
        "VMCALL with incorrect MSEG revision identifier",
        "VMXOFF under dual-monitor treatment of SMIs and SMM",
        "VMCALL with invalid SMM-monitor features",
        "VM-entry with invalid VM-execution control fields in executive VMCS",
        "VM-entry with events blocked by MOV SS",
        "reserved",
        "invalid operand to INVEPT/INVVPID"
    };
    *count = sizeof(t) / sizeof(t[0]);
    return t;
}

inline const char* vm_instruction_error(uint32_t n) {
    size_t c = 0;
    const char* const* t = vm_instruction_errors(&c);
    return n < c ? t[n] : nullptr;
}

#ifdef VMXLIB_HAS_INTRINSICS

struct alignas(4096) Region {
    unsigned char bytes[4096];
};

inline void region_init(Region& r, uint32_t revision) {
    for (size_t i = 0; i < sizeof r.bytes; i++) r.bytes[i] = 0;
    r.bytes[0] = (unsigned char)(revision & 0xff);
    r.bytes[1] = (unsigned char)((revision >> 8) & 0xff);
    r.bytes[2] = (unsigned char)((revision >> 16) & 0xff);
    r.bytes[3] = (unsigned char)((revision >> 24) & 0xff);
}

inline unsigned char vmxon(uint64_t pa) {
    uint64_t p = pa;
    return __vmx_on(&p);
}

inline unsigned char vmclear(uint64_t pa) {
    uint64_t p = pa;
    return __vmx_vmclear(&p);
}

inline unsigned char vmptrld(uint64_t pa) {
    uint64_t p = pa;
    return __vmx_vmptrld(&p);
}

inline uint64_t vmptrst() {
    uint64_t p = 0;
    __vmx_vmptrst(&p);
    return p;
}

inline unsigned char vmread(uint32_t field, uint64_t* value) {
    size_t v = 0;
    unsigned char r = __vmx_vmread((size_t)field, &v);
    *value = (uint64_t)v;
    return r;
}

inline unsigned char vmwrite(uint32_t field, uint64_t value) {
    return __vmx_vmwrite((size_t)field, (size_t)value);
}

inline unsigned char vmlaunch() { return __vmx_vmlaunch(); }
inline unsigned char vmresume() { return __vmx_vmresume(); }
inline void vmxoff() { __vmx_off(); }
inline uint64_t rdmsr(uint32_t m) { return (uint64_t)__readmsr((unsigned long)m); }
inline uint64_t cr0() { return (uint64_t)__readcr0(); }
inline uint64_t cr3() { return (uint64_t)__readcr3(); }
inline uint64_t cr4() { return (uint64_t)__readcr4(); }
inline void write_cr4(uint64_t v) { __writecr4(v); }

#endif

}
