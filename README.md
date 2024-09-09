# BPF64: platform-independent hardware-friendly backwards-compatible eBPF alternative

This is an extension to classic BPF, Berkeley Packet Filter, in a way which is alternative to Linux' eBPF. The project is currently in a designing stage.

See `bpf64spec.md` for draft of Specification, and motivation (explanation of eBPF problems).

The `nuc_ts_prog_kern.c` (and it's include `nuc_ts_common_kern_user.h`) is XDP/eBPF program (for Linux 6.5) for parsing TCP packet and incrementing it's Timestamp option, if any, recording statisitics intop eBPF map.

The `nuc_ts_incr.baw` (and it's include `nuc_ts_incr.bah`) is the equivalent program doing the same thing, but in a new BPF64 Assembler Wrapper language, not yet written and subject to change. Note this is a lower-level language than C, viewed as intermediate solution until BPF64 becomes stable, after which more higher-level language (higher than C) should be written, at least as expressible as `tcpdump` (`libpcap`) one.

The `fbpf_rus.txt` was recording of thinking/designing process at it first 2 months while living as GitHub gist, it's raw, in mix of languages and not for the faint of heart (alas, Git is not good for recording of thinking, not code).

The code is assumed to be written later when specification becames somewhat settled after discussion in BSD mail lists.
