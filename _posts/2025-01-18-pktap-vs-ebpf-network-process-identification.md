---
layout: post
title: "The Tale of Two Approaches: macOS PKTAP vs Linux eBPF for Network Process Identification"
date: 2025-01-18 12:00:00 +0000
categories: [systems-programming, networking, ebpf, macos, linux]
tags: [ebpf, pktap, kernel, networking, rustnet, systems-programming]
---

While working on adding process identification to a network monitoring tool, I discovered fascinating differences in how macOS and Linux handle the challenge of mapping network packets to processes—especially those short-lived processes that traditional polling approaches often miss.

## The Challenge

Traditional approaches like polling `/proc/net/*` on Linux or running `lsof` in a loop on macOS work for long-lived connections, but they struggle with short-lived processes. By the time you poll, the process might already be gone, leaving you with orphaned connections.

## macOS: The Elegant PKTAP Approach

macOS provides PKTAP (Packet Tap), where the kernel automatically includes process information in packet headers. It's almost trivially simple:

```c
struct PktapHeader {
    // ... other fields
    u32 pth_epid;        // Effective process ID
    u8 pth_comm[20];     // Command name
    u32 pth_pid;         // Process ID
    u8 pth_e_comm[20];   // Effective command name
};
```

You just read packets and the process info is *right there* in the header. The kernel does all the heavy lifting of mapping packets to processes. Want to know which process sent a packet? Just parse the header.

```rust
pub fn get_process_info(&self) -> (Option<String>, Option<u32>) {
    let process_name = extract_process_name_from_bytes(&self.pth_comm);
    let pid = if self.pth_epid != 0 { Some(self.pth_epid) } else { None };
    (process_name, pid)
}
```

That's it. Clean, simple, and it works for most packets. Though interestingly, some packet types (like ICMP and ARP) don't always include process information—likely because they're handled differently by the kernel or don't have a clear originating process context.

## Linux: The Powerful but Complex eBPF Route

Linux doesn't have an equivalent to PKTAP, so you need eBPF programs that hook into kernel networking functions:

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
2. **The comm field is limited to 16 characters** - so "Firefox" becomes "Socket Thread"
3. **You need to understand kernel internals** - socket structures, CO-RE relocations, BTF
4. **Build complexity**: Need libelf, clang, LLVM, and kernel headers

## The Trade-offs

**macOS PKTAP Pros:**
- Dead simple API
- Works out of the box
- Full process names (when available)
- Zero kernel programming required
- Automatic process-packet association for most traffic

**macOS PKTAP Cons:**
- macOS only
- Requires special interface setup
- Limited to what Apple exposes
- Some packet types (ICMP, ARP) may not include process info

**Linux eBPF Pros:**
- Incredibly powerful and flexible
- Can hook into any kernel function
- Lower overhead than polling
- Works on most modern kernels

**Linux eBPF Cons:**
- Steep learning curve
- Complex build requirements
- 16-char process name limit (`comm` field)
- Need to handle kernel version differences
- More moving parts

## Implementation Notes

We ended up using libbpf instead of Rust's aya framework specifically to avoid the nightly compiler dependency. While aya is more idiomatic Rust, libbpf's stability and broader compatibility won out.

The contrast really highlights different OS design philosophies: macOS providing high-level, purpose-built APIs vs Linux offering low-level primitives that can be composed into powerful solutions—but with significantly more complexity.

Both approaches solve the same problem, but the developer experience couldn't be more different. Sometimes I wonder if Linux could benefit from higher-level networking APIs like PKTAP, though I suppose that's antithetical to the Unix philosophy.

Has anyone else worked with similar kernel-level networking APIs? I'd be curious to hear about other platforms' approaches to this problem.

---

**Edit:** For those asking about the `comm` field limitation - it's a kernel limitation where thread names are truncated. Firefox shows up as "Socket Thread", Chrome as "ThreadPoolForeg", etc. You can work around it by combining eBPF with selective procfs lookups, but that defeats some of the performance benefits.

**Edit 2:** This eBPF implementation is now available in [RustNet v0.9.0](https://github.com/domcyrus/rustnet/releases/tag/v0.9.0) as an experimental feature. You can try it with `--features=ebpf` on Linux systems with appropriate permissions.