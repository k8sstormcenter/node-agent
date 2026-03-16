// Kernel types definitions
#include <vmlinux.h>

// eBPF helpers signatures
// Check https://man7.org/linux/man-pages/man7/bpf-helpers.7.html to learn
// more about different available helpers
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// Inspektor Gadget buffer
#include <gadget/buffer.h>
// Helpers to handle common data
#include <gadget/common.h>
// Inspektor Gadget macros
#include <gadget/macros.h>
// Inspektor Gadget filtering
#include <gadget/filter.h>
// Inspektor Gadget types
#include <gadget/types.h>
// Inspektor Gadget mntns
#include <gadget/mntns.h>

#include "program.h"
#include "upper_layer.h"
#include "exe_path.h"

#if defined(__TARGET_ARCH_x86)

#define TARGET_RANDOMX_EVENTS_COUNT 5
// 5 seconds in nanoseconds
#define MAX_NS_BETWEEN_EVENTS 5000000000ULL

// RandomX MXCSR fingerprint detection.
// RandomX (used by XMR miners) configures SSE via MXCSR with:
//   - Flush-to-zero (FZ, bit 15)
//   - Denormals-are-zero (DAZ, bit 6)
//   - All exception masks set (bits 7-12)
//   - Rounding mode varies (bits 13-14): may be round-to-nearest (00)
//     or round-to-zero (11) depending on RandomX execution step.
//
// Observed xmrig MXCSR values: 0x9fe0 (FZ+DAZ+masks, RC=00)
//                               0xffe0 (FZ+DAZ+masks, RC=11)
// Normal process defaults:      0x1f80 (masks only)
//                               0x1fa0 (masks + DAZ, set by some runtimes)
//
// Detection: FZ bit (0x8000) is almost never set by normal applications.
// When FZ is set together with DAZ (0x0040), this is a strong signal of
// RandomX-style numeric processing. We require both bits.
#define MXCSR_FZ   0x8000  // Flush-to-zero (bit 15)
#define MXCSR_DAZ  0x0040  // Denormals-are-zero (bit 6)
#define RANDOMX_MXCSR_MASK  (MXCSR_FZ | MXCSR_DAZ)

// This struct will hold the state for each mount namespace
struct mntns_cache {
    u64 timestamp;
    u64 events_count;
    bool alerted;
};

// A map to store the cache per mntns_id.
// key: mntns_id (u64), value: struct mntns_cache
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, struct mntns_cache);
} mntns_event_count SEC(".maps");

// events is the name of the buffer map and 1024 * 256 (256KB) is its size.
GADGET_TRACER_MAP(events, 1024 * 256);

// Define a tracer
GADGET_TRACER(randomx, events, event);

// Utilize the kernel version provided by libbpf. (kconfig must be present).
extern int LINUX_KERNEL_VERSION __kconfig;

#if LINUX_KERNEL_VERSION <= KERNEL_VERSION(5, 15, 0)
struct old_fpu {
    unsigned int last_cpu;
    unsigned char initialized;
    long: 24;
    long: 64;
    long: 64;
    long: 64;
    long: 64;
    long: 64;
    long: 64;
    long: 64;
    union fpregs_state state;
};
#endif

// Read MXCSR from the FPU struct, handling different kernel layouts.
static __always_inline int read_mxcsr(void *fpu, u32 *out)
{
    if (LINUX_KERNEL_VERSION <= KERNEL_VERSION(5, 15, 0)) {
        return bpf_probe_read_kernel(out, sizeof(*out),
            &((struct old_fpu *)fpu)->state.xsave.i387.mxcsr);
    }
    *out = BPF_CORE_READ((struct fpu *)fpu, fpstate, regs.xsave.i387.mxcsr);
    return 0;
}

// Check if the MXCSR value matches the RandomX fingerprint.
// Returns true when both FZ and DAZ bits are set — the hallmark of
// RandomX-style SSE configuration that normal workloads don't use.
static __always_inline bool is_randomx_mxcsr(u32 mxcsr)
{
    return (mxcsr & RANDOMX_MXCSR_MASK) == RANDOMX_MXCSR_MASK;
}

SEC("tracepoint/x86_fpu/x86_fpu_regs_deactivated")
int tracepoint__x86_fpu_regs_deactivated(struct trace_event_raw_x86_fpu *ctx)
{
    if (gadget_should_discard_data_current()) {
        return 0;
    }

    // --- Read MXCSR early and bail out for normal processes ---
    void *fpu = BPF_CORE_READ(ctx, fpu);
    if (fpu == NULL) {
        return 0;
    }

    u32 mxcsr;
    if (read_mxcsr(fpu, &mxcsr) < 0) {
        return 0;
    }

    if (!is_randomx_mxcsr(mxcsr)) {
        return 0;
    }

    // --- MXCSR looks like RandomX. Count events per mount namespace ---
    u64 mntns_id = gadget_get_current_mntns_id();
    struct mntns_cache *cache;
    cache = bpf_map_lookup_elem(&mntns_event_count, &mntns_id);

    u64 now = bpf_ktime_get_ns();

    if (!cache) {
        struct mntns_cache new_cache = {};
        new_cache.timestamp = now;
        new_cache.events_count = 1;
        new_cache.alerted = false;
        bpf_map_update_elem(&mntns_event_count, &mntns_id, &new_cache, BPF_ANY);
        return 0;
    }

    if (cache->alerted) {
        return 0;
    }

    if (now - cache->timestamp > MAX_NS_BETWEEN_EVENTS) {
        cache->timestamp = now;
        cache->events_count = 1;
        bpf_map_update_elem(&mntns_event_count, &mntns_id, cache, BPF_ANY);
        return 0;
    }

    cache->events_count++;
    cache->timestamp = now;

    if (cache->events_count <= TARGET_RANDOMX_EVENTS_COUNT) {
        bpf_map_update_elem(&mntns_event_count, &mntns_id, cache, BPF_ANY);
        return 0;
    }

    // --- Threshold reached — emit alert once per mntns ---
    cache->alerted = true;
    bpf_map_update_elem(&mntns_event_count, &mntns_id, cache, BPF_ANY);

    struct event *event;
    event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event) {
        return 0;
    }

    gadget_process_populate(&event->proc);
    event->upper_layer = has_upper_layer();
    read_exe_path(event->exepath, sizeof(event->exepath));
    event->timestamp_raw = bpf_ktime_get_boot_ns();

    gadget_submit_buf(ctx, &events, event, sizeof(*event));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";