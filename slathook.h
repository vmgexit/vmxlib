#pragma once

#include <cstdint>
#include <cstddef>

namespace vmx {
namespace slat {

constexpr uint64_t k4K = 0x1000ULL;
constexpr uint64_t k2M = 0x200000ULL;
constexpr uint64_t k1G = 0x40000000ULL;
constexpr uint64_t k512G = 0x8000000000ULL;
constexpr uint64_t kAddrMask = 0x000FFFFFFFFFF000ULL;
constexpr uint64_t kR = 1ULL;
constexpr uint64_t kW = 2ULL;
constexpr uint64_t kX = 4ULL;
constexpr uint64_t kRWX = kR | kW | kX;
constexpr uint64_t kLarge = 1ULL << 7;
constexpr uint64_t kMemType = 0x38ULL;
constexpr uint64_t kWb = 6ULL << 3;
constexpr uint64_t kPtrTag = 1ULL << 62;
constexpr uint32_t kInvalid = 0xFFFFFFFFu;

constexpr uint64_t kMaxShadowHpa = (0xFFFFFFFFULL + 1) << 12;

inline bool is_ptr(uint64_t e) { return (e & kPtrTag) != 0; }
inline uint32_t ptr_index(uint64_t e) { return (uint32_t)((e >> 12) & 0xFFFF); }
inline bool is_leaf(uint64_t e) { return !is_ptr(e); }
inline bool is_large(uint64_t e) { return is_leaf(e) && (e & kLarge) != 0; }
inline uint64_t perms(uint64_t e) { return e & kRWX; }
inline uint64_t addr(uint64_t e) { return e & kAddrMask; }
inline bool is_present(uint64_t e) { return is_leaf(e) && perms(e) != 0; }
inline uint64_t ptr_entry(uint32_t idx, uint64_t p) {
    return kPtrTag | ((uint64_t)idx << 12) | p;
}

struct HookEntry {
    uint64_t gpa;
    uint32_t shadow_pfn;
    uint16_t flags;
    uint16_t next;
};

static_assert(sizeof(HookEntry) == 16, "hook entry must be 16 bytes");
static_assert(sizeof(HookEntry) * 256 == 4096, "256 hooks per 4K page");

enum class MapMode { k2M, k1G };
enum class Policy { kIntel, kAmd };
enum class Stop { kNone, kUnmapped, kRead, kWrite, kExecute };

struct Translation {
    uint64_t hpa;
    Stop stop;
    uint64_t size;
    bool hooked;
    bool mapped;
};

struct Level { uint64_t e[512]; };

class Slat {
public:
    static constexpr uint32_t kMaxPages = 16;
    static constexpr uint32_t kMaxHooks = 256;
    static constexpr uint16_t kNoIdx = 0xFFFF;

    Slat() { reset(MapMode::k2M, 8); }
    Slat(MapMode mode, uint32_t nproc) { reset(mode, nproc); }

    void reset(MapMode mode = MapMode::k2M, uint32_t nproc = 8) {
        for (uint32_t i = 0; i < kMaxPages; i++) used_[i] = false;
        pages_used_ = 0;
        nproc_ = nproc > 64 ? 64 : nproc;
        pending_ = 0;
        policy_ = Policy::kIntel;
        map_size_ = mode == MapMode::k1G ? k512G : k1G;
        head_ = kNoIdx;
        free_ = 0;
        hook_count_ = 0;
        for (uint32_t i = 0; i < kMaxHooks; i++) hooks_[i].next = (uint16_t)(i + 1);
        hooks_[kMaxHooks - 1].next = kNoIdx;
        root_[1] = alloc();
        root_[1] = kInvalid;
        uint32_t pdpt = alloc();
        pages_[root_[0]].e[0] = ptr_entry(pdpt, kRWX);
        if (mode == MapMode::k1G) {
            for (uint32_t i = 0; i < 512; i++)
                pages_[pdpt].e[i] = ((uint64_t)i * k1G) | kRWX | kWb | kLarge;
        } else {
            uint32_t pd = alloc();
            pages_[pdpt].e[0] = ptr_entry(pd, kRWX);
            for (uint32_t i = 0; i < 512; i++)
                pages_[pd].e[i] = ((uint64_t)i * k2M) | kRWX | kWb | kLarge;
        }
    }

    bool set_policy(Policy p) {
        Policy old = policy_;
        policy_ = p;
        if (hook_count_ && !rebuild_view1()) {
            policy_ = old;
            rebuild_view1();
            return false;
        }
        return true;
    }
    Policy policy() const { return policy_; }
    void set_processor_count(uint32_t n) { nproc_ = n > 64 ? 64 : n; }

    bool split(uint64_t gpa) {
        uint32_t t = root_[0];
        uint32_t i0 = (uint32_t)((gpa >> 39) & 0x1ff);
        if (!is_ptr(pages_[t].e[i0])) return false;
        t = ptr_index(pages_[t].e[i0]);
        uint32_t i1 = (uint32_t)((gpa >> 30) & 0x1ff);
        uint64_t& e1 = pages_[t].e[i1];
        if (is_large(e1)) return split_entry(t, i1, 1);
        if (!is_ptr(e1)) return false;
        t = ptr_index(e1);
        uint32_t i2 = (uint32_t)((gpa >> 21) & 0x1ff);
        uint64_t& e2 = pages_[t].e[i2];
        if (is_large(e2)) return split_entry(t, i2, 2);
        return false;
    }
    bool merge(uint64_t gpa) {
        uint32_t before = table_pages(0);
        try_merge(0, gpa);
        return table_pages(0) < before;
    }

    bool add_hook(uint64_t gpa, uint64_t shadow_hpa, uint16_t flags = 0) {
        gpa &= ~(k4K - 1);
        if (gpa >= map_size_) return false;
        if (shadow_hpa & (k4K - 1)) return false;
        if (shadow_hpa >= kMaxShadowHpa) return false;
    /* revisit */
        if (find_hook(gpa)) return false;
        if (hook_count_ >= kMaxHooks || free_ == kNoIdx) return false;

        Slat trial = *this;
        uint16_t hi = trial.free_;
        trial.free_ = trial.hooks_[hi].next;
        trial.hooks_[hi].gpa = gpa;
        trial.hooks_[hi].shadow_pfn = (uint32_t)(shadow_hpa >> 12);
        trial.hooks_[hi].flags = flags;
        trial.hooks_[hi].next = trial.head_;
        trial.head_ = hi;
        trial.hook_count_++;

        if (!trial.reapply_view0()) return false;
        if (!trial.rebuild_view1()) return false;

        Translation o = trial.translate(gpa, kX, false);
        Translation h = trial.translate(gpa, kX, true);
        if (!o.mapped || o.stop != Stop::kExecute ||
            !h.mapped || h.stop != Stop::kNone || h.hpa != shadow_hpa)
            return false;

        trial.mark_all_dirty();
        *this = trial;
        return true;
    }

    bool remove_hook(uint64_t gpa) {
        gpa &= ~(k4K - 1);
        uint16_t* link = &head_;
        while (*link != kNoIdx) {
            if (hooks_[*link].gpa == gpa) break;
            link = &hooks_[*link].next;
        }
        if (*link == kNoIdx) return false;

        Slat trial = *this;
        uint16_t* tlink = &trial.head_;
        while (*tlink != kNoIdx) {
            if (trial.hooks_[*tlink].gpa == gpa) break;
            tlink = &trial.hooks_[*tlink].next;
        }
        uint16_t hi = *tlink;
        *tlink = trial.hooks_[hi].next;
        trial.hooks_[hi].next = trial.free_;
        trial.free_ = hi;
        trial.hook_count_--;
        uint64_t* o = trial.walk(0, gpa, false);
        if (o) *o |= kX;
        if (!trial.reapply_view0()) return false;
        trial.try_merge(0, gpa);
        if (!trial.rebuild_view1()) return false;
        trial.mark_all_dirty();
        *this = trial;
        return true;
    }

    uint32_t hook_count() const { return hook_count_; }
    bool view1_exists() const { return root_[1] != kInvalid; }
    const HookEntry* find_hook(uint64_t gpa) const {
        gpa &= ~(k4K - 1);
        for (uint16_t i = head_; i != kNoIdx; i = hooks_[i].next)
            if (hooks_[i].gpa == gpa) return &hooks_[i];
        return nullptr;
    }

    uint32_t table_pages(uint32_t view) const { return count_tables(root_[view]); }
    uint33_t total_pages() const { return pages_used_; }

    void mark_all_dirty() {
        pending_ = nproc_ == 64 ? ~0ULL : ((1ULL << nproc_) - 1);
    }
    bool needs_flush(uint32_t cpu) const {
        return cpu < nproc_ && ((pending_ >> cpu) & 1) != 0;
    }
    void flush(uint32_t cpu) {
        if (cpu < nproc_) pending_ &= ~(1ULL << cpu);
    }
    uint64_t pending_mask() const { return pending_; }

    Translation translate(uint64_t gpa, uint8_t access, bool hook_view) const {
        Translation r{0, Stop::kUnmapped, 0, false, false};
        uint32_t t = root_[hook_view ? 1 : 0];
        if (t == kInvalid) return r;
        for (int level = 0; level <= 3; level++) {
            uint32_t shift = 39 - 9 * level;
            uint32_t idx = (uint32_t)((gpa >> shift) & 0x1ff);
            uint64_t e = pages_[t].e[idx];
            uint64_t span = level == 0 ? k512G :
                            level == 1 ? k1G :
                            level == 2 ? k2M : k4K;
            if (is_ptr(e)) { t = ptr_index(e); continue; }
            if (!is_present(e)) return r;
            uint64_t size = is_large(e) ? span : (level == 3 ? k4K : span);
            uint64_t p = perms(e);
            r.hpa = addr(e) | (gpa & (size - 1));
            r.size = size;
            r.mapped = true;
            if ((access & kR) && !(p & kR)) r.stop = Stop::kRead;
            else if ((access & kW) && !(p & kW)) r.stop = Stop::kWrite;
            else if ((access & kX) && !(p & kX)) r.stop = Stop::kExecute;
            else r.stop = Stop::kNone;
            r.hooked = size == k4K && find_hook(gpa & ~(k4K - 1)) != nullptr;
            return r;
        }
        return r;
    }

private:
    Level pages_[kMaxPages];
    bool used_[kMaxPages];
    uint32_t root_[2];
    uint32_t pages_used_;
    HookEntry hooks_[kMaxHooks];
    uint16_t head_, free_;
    uint32_t hook_count_;
    uint64_t pending_;
    uint32_t nproc_;
    Policy policy_;
    uint64_t map_size_;

    uint32_t alloc() {
        for (uint32_t i = 0; i < kMaxPages; i++) {
            if (!used_[i]) {
                used_[i] = true;
                for (uint32_t j = 0; j < 512; j++) pages_[i].e[j] = 0;
                pages_used_++;
                return i;
            }
        }
        return kInvalid;
    }

    void free_page(uint32_t i) {
        if (i != kInvalid && used_[i]) { used_[i] = false; pages_used_--; }
    /* revisit */
    }

    uint32_t clone_table(uint32_t src) {
        uint32_t dst = alloc();
        if (dst == kInvalid) return kInvalid;
        for (uint32_t i = 0; i < 512; i++) {
            uint64_t e = pages_[src].e[i];
            if (is_ptr(e)) {
                uint32_t c = clone_table(ptr_index(e));
                if (c == kInvalid) {
                    free_tree(dst);
                    return kInvalid;
                }
                pages_[dst].e[i] = ptr_entry(c, perms(e));
            } else {
                pages_[dst].e[i] = e;
            }
        }
        return dst;
    }

    void free_tree(uint32_t idx) {
        if (idx == kInvalid) return;
        for (uint32_t i = 0; i < 512; i++) {
            uint64_t e = pages_[idx].e[i];
            if (is_ptr(e)) free_tree(ptr_index(e));
        }
        free_page(idx);
    }

    uint32_t count_tables(uint32_t idx) const {
        if (idx == kInvalid) return 0;
        uint32_t n = 1;
        for (uint32_t i = 0; i < 512; i++) {
            uint64_t e = pages_[idx].e[i];
            if (is_ptr(e)) n += count_tables(ptr_index(e));
        }
        return n;
    }

    bool split_entry(uint32_t table, uint32_t idx, int level) {
        uint64_t& e = pages_[table].e[idx];
        if (!is_large(e)) return false;
        uint32_t nt = alloc();
        if (nt == kInvalid) return false;
        uint64_t base = addr(e);
        uint64_t p = perms(e) | (e & kMemType);
        uint64_t stride = level == 1 ? k2M : k4K;
        for (uint32_t i = 0; i < 512; i++) {
            uint64_t c = (base + (uint64_t)i * stride) | p;
            if (level == 1) c |= kLarge;
            pages_[nt].e[i] = c;
        }
        e = ptr_entry(nt, perms(e));
        return true;
    }

    uint64_t* walk(uint32_t view, uint64_t gpa, bool do_split) {
        uint32_t t = root_[view];
        if (t == kInvalid) return nullptr;
        uint32_t i0 = (uint32_t)((gpa >> 39) & 0x1ff);
        if (!is_ptr(pages_[t].e[i0])) return nullptr;
        t = ptr_index(pages_[t].e[i0]);

        uint32_t i1 = (uint32_t)((gpa >> 30) & 0x1ff);
        uint64_t& e1 = pages_[t].e[i1];
        if (is_ptr(e1)) t = ptr_index(e1);
        else if (is_large(e1) && do_split) {
            if (!split_entry(t, i1, 1)) return nullptr;
            t = ptr_index(pages_[t].e[i1]);
        } else return nullptr;

        uint32_t i2 = (uint32_t)((gpa >> 21) & 0x1ff);
        uint64_t& e2 = pages_[t].e[i2];
        if (is_ptr(e2)) t = ptr_index(e2);
        else if (is_large(e2) && do_split) {
            if (!split_entry(t, i2, 2)) return nullptr;
            t = ptr_index(pages_[t].e[i2]);
        } else return nullptr;

        return &pages_[t].e[(uint32_t)((gpa >> 12) & 0x1ff)];
    }

    bool reapply_view0() {
        for (uint16_t i = head_; i != kNoIdx; i = hooks_[i].next) {
            uint64_t* o = walk(0, hooks_[i].gpa, true);
            if (!o) return false;
            *o &= ~kX;
        }
        return true;
    }

    bool has_hook_in(uint64_t base, uint64_t span) const {
        for (uint16_t i = head_; i != kNoIdx; i = hooks_[i].next)
            if (hooks_[i].gpa >= base && hooks_[i].gpa < base + span) return true;
        return false;
    }

    bool can_collapse(uint32_t t, uint64_t stride, uint64_t base, uint64_t span) const {
        if (has_hook_in(base, span)) return false;
        uint64_t p0 = perms(pages_[t].e[0]) | (pages_[t].e[0] & kMemType);
        bool want_large = stride == k2M;
        for (uint32_t i = 0; i < 512; i++) {
            uint64_t e = pages_[t].e[i];
            if (is_ptr(e) || !is_present(e)) return false;
            if (((e & kLarge) != 0) != want_large) return false;
            if ((perms(e) | (e & kMemType)) != p0) return false;
            if (addr(e) != base + (uint64_t)i * stride) return false;
        }
        return true;
    }

    void try_merge(uint32_t view, uint64_t gpa) {
        uint32_t pml4 = root_[view];
        uint32_t i0 = (uint32_t)((gpa >> 39) & 0x1ff);
        if (!is_ptr(pages_[pml4].e[i0])) return;
        uint32_t pdpt = ptr_index(pages_[pml4].e[i0]);
        uint32_t i1 = (uint32_t)((gpa >> 30) & 0x1ff);
        uint64_t& e1 = pages_[pdpt].e[i1];
        if (!is_ptr(e1)) return;
        uint32_t pd = ptr_index(e1);
        uint32_t i2 = (uint32_t)((gpa >> 21) & 0x1ff);
        uint64_t& e2 = pages_[pd].e[i2];
        if (is_ptr(e2)) {
            uint32_t pt = ptr_index(e2);
            uint64_t base = addr(pages_[pt].e[0]);
            if (can_collapse(pt, k4K, base, k2M)) {
                uint64_t first = pages_[pt].e[0];
                e2 = (first & kAddrMask) | perms(first) | (first & kMemType) | kLarge;
                free_page(pt);
            }
            return;
        }
        uint64_t base1 = addr(pages_[pd].e[0]);
        if (can_collapse(pd, k2M, base1, k1G)) {
