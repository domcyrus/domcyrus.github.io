---
layout: post
title: "macOS PKTAP vs Linux eBPF"
date: 2025-01-18 12:00:00 +0000
categories: [systems-programming, networking, ebpf, macos, linux]
tags: [ebpf, pktap, kernel, networking, rustnet, systems-programming]
---

While working on adding process identification to the network monitoring tool [`RustNet`](https://github.com/domcyrus/rustnet), I discovered fascinating differences in how macOS and Linux tackle a common challenge: mapping network packets to processes—especially those short-lived processes that traditional polling approaches often miss.

## The Challenge

Traditional approaches like polling `/proc/net/*` on Linux or running `lsof` in a loop on macOS work well for long-lived connections, but they struggle with short-lived processes. By the time you poll, the process might already be gone, leaving you with orphaned connections whose origins remain a mystery.

## macOS: The PKTAP Approach

macOS (and possibly some BSDs) provides PKTAP (Packet Tap), where the kernel automatically includes process information in packet headers. This makes implementation remarkably straightforward:

```c
// From Apple's darwin-xnu (bsd/net/pktap.h)
struct pktap_header {
    // ... other fields
    pid_t pth_pid;               // Process ID
    char pth_comm[17];           // Process name (MAXCOMLEN + 1)
    pid_t pth_epid;              // Effective process ID
    char pth_ecomm[17];          // Effective command name
    // ... more fields
};
```

You simply read packets and the process info is *right there* in the header. The kernel handles all the heavy lifting of mapping packets to processes. Want to know which process sent a packet? Just parse the header:

```rust
pub fn get_process_info(&self) -> (Option<String>, Option<u32>) {
    let process_name = extract_process_name_from_bytes(&self.pth_comm);
    let pid = if self.pth_epid != 0 { 
        Some(self.pth_epid as u32) 
    } else { 
        None 
    };
    (process_name, pid)
}
```

That's it. Clean, simple, and it works for most packets. Interestingly, some packet types (like ICMP and ARP) don't always include process information—likely because they're handled differently by the kernel or lack a clear originating process context.

## Linux: The Powerful but Complex eBPF Route

Linux doesn't have an equivalent to PKTAP, so one solution involves using eBPF programs that hook into kernel networking functions:

```c
SEC("kprobe/tcp_connect")
int trace_tcp_connect(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1_CORE(ctx);

    // Extract network info from socket
    key.saddr[0] = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    key.daddr[0] = BPF_CORE_READ(sk, __sk_common.skc_daddr);

    // Get process info
    info.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&info.comm, sizeof(info.comm));

    // Store in map for userspace retrieval
    bpf_map_update_elem(&socket_map, &key, &info, BPF_ANY);
    return 0;
}
```

But here's where it gets interesting (and complicated):

1. **You need separate kprobes** for `tcp_connect`, `inet_csk_accept`, `udp_sendmsg`, `tcp_v6_connect`, etc.
2. **The comm field is limited to 16 characters**—so "Firefox" becomes "Socket Thread"
3. **You must understand kernel internals**—socket structures, CO-RE relocations, BTF
4. **Build complexity**: Requires libelf, clang, LLVM, and kernel headers

## The Trade-offs

**macOS PKTAP Pros:**
- Dead simple API
- Works out of the box
- Full process names (when available)
- Zero kernel programming required
- Automatic process-packet association for most traffic

**macOS PKTAP Cons:**
- macOS only (possibly other BSDs)
- Requires special interface setup
- Limited to what Apple exposes
- Some packet types (ICMP, ARP) may lack process info

**Linux eBPF Pros:**
- Incredibly powerful and flexible
- Can hook into virtually any kernel function
- Lower overhead than polling
- Works on most modern kernels

**Linux eBPF Cons:**
- Steep learning curve
- Complex build requirements
- 16-char process name limit (`comm` field)
- Must handle kernel version differences
- More moving parts

## Implementation Notes

For `RustNet`, I ended up using libbpf instead of Rust's aya framework specifically to avoid the nightly compiler dependency. While aya offers more idiomatic Rust, libbpf's stability and broader compatibility made it the better choice for this project.

The contrast really highlights different OS design philosophies: macOS provides high-level, purpose-built APIs versus Linux offering low-level primitives that can be composed into powerful solutions—albeit with significantly more complexity. Whether this pattern extends beyond networking APIs is an interesting question.

Both approaches solve the same problem effectively, but the developer experience couldn't be more different. I wonder if Linux could benefit from higher-level networking APIs like PKTAP, though perhaps that's antithetical to the Unix philosophy of composable tools.

Has anyone else worked with similar kernel-level networking APIs? I'd be curious to hear about other platforms' approaches to this problem.

**Note on the `comm` field:** The 16-character limitation is a kernel constraint where thread names get truncated. Firefox appears as "Socket Thread", Chrome as "ThreadPoolForeg", etc. You can work around it by combining eBPF with selective procfs lookups, but that defeats some of the performance benefits.

The eBPF implementation is available in [RustNet v0.9.0](https://github.com/domcyrus/rustnet/releases/tag/v0.9.0) as an experimental feature. You can try it with `--features=ebpf` on Linux systems with appropriate permissions.
