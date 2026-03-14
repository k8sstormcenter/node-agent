// Kernel types definitions
#include <vmlinux.h>

// eBPF helpers signatures
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// Inspektor Gadget headers
#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/macros.h>
#include <gadget/filter.h>
#include <gadget/types.h>
#include <gadget/mntns.h>

#include "program.h"
#include "upper_layer.h"
#include "exe_path.h"

#if defined(__TARGET_ARCH_x86)

// ============================================================================
// Crypto miner detection via kernel-version-adaptive signals:
//
// The detection strategy depends on the kernel version because FPU scheduling
// behavior changed significantly across versions:
//
// Kernel < 6.2 (e.g. 6.1, 5.15):
//   FPU lazy restore is active — x86_fpu_regs_deactivated fires selectively.
//   Signal 3 (x87 xfeatures) is the primary detector: RandomX uses x87 FPU
//   (xfeatures=3, x87+SSE) while normal workloads use SSE only (xfeatures=2).
//   Signal 1 (preemptions) as backup — may be low on few-core systems.
//
// Kernel >= 6.2 (e.g. 6.5, 6.8):
//   Eager-FPU optimization — x86_fpu_regs_deactivated fires for ALL processes
//   or not at all for CPU-bound ones. x87 xfeatures is unreliable here.
//   Signal 1 (preemptions) is the primary detector.
//   Signal 2 (raw FPU count, very high threshold) as backup.
//
// Any enabled signal crossing its threshold fires the alert (one per container).
// ============================================================================

// Kernel version detection via kconfig (available at BPF load time).
extern int LINUX_KERNEL_VERSION __kconfig;

#define PREEMPT_THRESHOLD  10000
#define FPU_THRESHOLD     500000
// x87 threshold — only used on kernels < 6.2 where FPU tracing is selective.
#define X87_FPU_THRESHOLD  5
// 30 seconds in nanoseconds
#define WINDOW_NS          30000000000ULL

struct mntns_cache {
    u64 window_start;
    u64 fpu_count;
    u64 preempt_count;
    u64 x87_fpu_count;
    bool alerted;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, struct mntns_cache);
} mntns_event_count SEC(".maps");

// Ring buffer for events — 256KB.
GADGET_TRACER_MAP(events, 1024 * 256);

// Define the tracer (links the "randomx" datasource to the event struct).
GADGET_TRACER(randomx, events, event);

// ---------------------------------------------------------------------------
// Helper: reset the sliding window if it expired.
// Returns true if the window was reset (caller should return 0 early).
// ---------------------------------------------------------------------------
static __always_inline bool maybe_reset_window(
    struct mntns_cache *cache, u64 now, u64 mntns_id)
{
    if (now - cache->window_start > WINDOW_NS) {
        cache->window_start = now;
        cache->fpu_count = 0;
        cache->preempt_count = 0;
        cache->x87_fpu_count = 0;
        bpf_map_update_elem(&mntns_event_count, &mntns_id, cache, BPF_ANY);
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Helper: check if either threshold is met and emit the alert event.
// Returns true if alert was emitted.
// ---------------------------------------------------------------------------
static __always_inline bool maybe_alert(
    struct mntns_cache *cache, u64 mntns_id, void *ctx)
{
    bool preempt_hit = cache->preempt_count >= PREEMPT_THRESHOLD;
    bool x87_hit = cache->x87_fpu_count >= X87_FPU_THRESHOLD;
    bool detected = false;

    if (LINUX_KERNEL_VERSION < KERNEL_VERSION(6, 2, 0)) {
        // Kernel < 6.2: FPU lazy restore is active.
        // x87 xfeatures is the strongest signal (xmrig=3, normal=2).
        // Preemptions as backup (may be low on few-core systems).
        detected = x87_hit || preempt_hit;
    } else {
        // Kernel >= 6.2: Eager-FPU. The FPU tracepoint may fire for all
        // processes (noisy) OR not fire at all for CPU-bound ones.
        // x87 check still works IF the tracepoint fires — if it doesn't
        // fire for xmrig, x87_count stays 0 (no false positive).
        // Preemptions work if there's CPU contention.
        // Use all three signals: preemption, x87, raw FPU count.
        bool fpu_hit = cache->fpu_count >= FPU_THRESHOLD;
        detected = preempt_hit || x87_hit || fpu_hit;
    }

    if (!detected)
        return false;

    // Mark alerted so no further events are emitted for this container.
    cache->alerted = true;
    bpf_map_update_elem(&mntns_event_count, &mntns_id, cache, BPF_ANY);

    struct event *event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event)
        return true; // alerted flag is set, nothing more to do

    gadget_process_populate(&event->proc);
    event->upper_layer = has_upper_layer();
    read_exe_path(event->exepath, sizeof(event->exepath));
    event->timestamp_raw = bpf_ktime_get_boot_ns();

    bpf_printk("randomx: ALERT mntns=%llu fpu=%llu preempt=%llu x87=%llu",
               mntns_id, cache->fpu_count, cache->preempt_count,
               cache->x87_fpu_count);

    gadget_submit_buf(ctx, &events, event, sizeof(*event));
    return true;
}

// ===========================================================================
// Signal 1: sched_switch — count involuntary preemptions per container.
//
// prev_state == 0 (TASK_RUNNING) means the task wanted to keep running but
// was preempted by the scheduler.  Crypto miners are almost always in this
// state because they never voluntarily sleep.
// ===========================================================================
SEC("tracepoint/sched/sched_switch")
int tracepoint__sched_switch(struct trace_event_raw_sched_switch *ctx)
{
    // Fast path: ignore voluntary context switches (task yielded / slept).
    // This filters out ~60-80% of events before any map lookup.
    long prev_state = BPF_CORE_READ(ctx, prev_state);
    if (prev_state != 0)
        return 0;

    if (gadget_should_discard_data_current())
        return 0;

    u64 mntns_id = gadget_get_current_mntns_id();
    u64 now = bpf_ktime_get_ns();

    struct mntns_cache *cache = bpf_map_lookup_elem(&mntns_event_count, &mntns_id);
    if (!cache) {
        struct mntns_cache new_cache = {};
        new_cache.window_start = now;
        new_cache.preempt_count = 1;
        bpf_map_update_elem(&mntns_event_count, &mntns_id, &new_cache, BPF_ANY);
        return 0;
    }

    if (cache->alerted)
        return 0;

    if (maybe_reset_window(cache, now, mntns_id))
        return 0;

    cache->preempt_count++;
    bpf_map_update_elem(&mntns_event_count, &mntns_id, cache, BPF_ANY);
    maybe_alert(cache, mntns_id, ctx);

    return 0;
}

// ===========================================================================
// Signal 2 + 3: x86_fpu_regs_deactivated — count FPU events per container.
//
// Signal 2: Raw FPU event count (high threshold, backup for older kernels).
// Signal 3: x87 FPU usage — xfeatures bit 0 indicates x87 FPU state is live.
//   RandomX uses x87 for double-precision floats → xfeatures=3 (x87+SSE).
//   Normal workloads use SSE only → xfeatures=2. Almost nothing in containers
//   uses x87 in 2025, so this is a very strong discriminator on kernel 6.1
//   where the tracepoint fires but preemption counts are low.
// ===========================================================================
SEC("tracepoint/x86_fpu/x86_fpu_regs_deactivated")
int tracepoint__x86_fpu_regs_deactivated(struct trace_event_raw_x86_fpu *ctx)
{
    if (gadget_should_discard_data_current())
        return 0;

    u64 mntns_id = gadget_get_current_mntns_id();
    u64 now = bpf_ktime_get_ns();

    // Read xfeatures: bit 0 = x87 FPU state is live.
    u64 xfeatures = BPF_CORE_READ(ctx, xfeatures);
    bool has_x87 = (xfeatures & 0x1);

    struct mntns_cache *cache = bpf_map_lookup_elem(&mntns_event_count, &mntns_id);
    if (!cache) {
        struct mntns_cache new_cache = {};
        new_cache.window_start = now;
        new_cache.fpu_count = 1;
        new_cache.x87_fpu_count = has_x87 ? 1 : 0;
        bpf_map_update_elem(&mntns_event_count, &mntns_id, &new_cache, BPF_ANY);
        return 0;
    }

    if (cache->alerted)
        return 0;

    if (maybe_reset_window(cache, now, mntns_id))
        return 0;

    cache->fpu_count++;
    if (has_x87)
        cache->x87_fpu_count++;
    bpf_map_update_elem(&mntns_event_count, &mntns_id, cache, BPF_ANY);
    maybe_alert(cache, mntns_id, ctx);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";

#endif // defined(__TARGET_ARCH_x86)
