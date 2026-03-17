// Kernel types definitions
#include <vmlinux.h>

// eBPF helpers signatures
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// Inspektor Gadget
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

// events is the name of the buffer map and 1024 * 256 (256KB) is its size.
GADGET_TRACER_MAP(events, 1024 * 256);

// Define a tracer
GADGET_TRACER(randomx, events, event);

// --- FPU struct for direct bpf_probe_read_kernel access ---
// On kernels <= 5.15 the layout is:
//   struct fpu { ...; union fpregs_state state; }
// On kernels > 5.15 the layout changed to use a fpstate pointer,
// but BPF_CORE_READ through that pointer fails on some 6.x kernels.
//
// The bpftrace approach (fpu->state.xsave.i387.mxcsr) works because
// bpftrace resolves offsets from the running kernel's BTF at load time.
// We replicate that here: define a struct matching the old layout and
// use bpf_probe_read_kernel — this bypasses CO-RE relocation entirely.
//
// If the kernel has the new layout, the read will land at the wrong
// offset and we'll get a garbage mxcsr (which we emit as mxcsr_raw
// so we can diagnose). If it works, fpcr != 0 means detection fires.
struct fpu_old_layout {
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

SEC("tracepoint/x86_fpu/x86_fpu_regs_deactivated")
int tracepoint__x86_fpu_regs_deactivated(struct trace_event_raw_x86_fpu *ctx)
{
    if (gadget_should_discard_data_current()) {
        return 0;
    }

    void *fpu = BPF_CORE_READ(ctx, fpu);
    if (fpu == NULL) {
        return 0;
    }

    // Read MXCSR the old way: fpu->state.xsave.i387.mxcsr
    // This is the bpftrace approach that works on kernel 6.1.
    u32 mxcsr = 0;
    bpf_probe_read_kernel(&mxcsr, sizeof(mxcsr),
        &((struct fpu_old_layout *)fpu)->state.xsave.i387.mxcsr);

    int fpcr = (mxcsr & 0x6000) >> 13;
    if (fpcr == 0) {
        return 0;
    }

    // Detection triggered — emit event
    struct event *event;
    event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event) {
        return 0;
    }

    gadget_process_populate(&event->proc);
    event->upper_layer = has_upper_layer();
    event->mxcsr_raw = mxcsr;
    read_exe_path(event->exepath, sizeof(event->exepath));
    event->timestamp_raw = bpf_ktime_get_boot_ns();

    gadget_submit_buf(ctx, &events, event, sizeof(*event));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";

#endif // defined(__TARGET_ARCH_x86)
