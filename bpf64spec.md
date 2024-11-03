(this is currently a "draft of draft" under construction selecting variants from `fbpf_rus.txt` - see there if something is missing)


    * * * DRAFT * * *

# BPF64: platform-independent hardware-friendly backwards-compatible eBPF alternative

## Intro

### Motivation

I've recently had some experience with Linux's ePBF in it's XDP, and this left
quite negative impression. I was following via https://github.com/xdp-project/xdp-tutorial
and after 3rd lesson was trying to create a simple program for searching TCP
timestamp option and incrementing it by one. As you know, eBPF tool stack
consists of at least clang and eBPF verifier in the kernel, and after two dozen
tries eBPF verifier still didn't accept my code. I was digging into verifier
sources, and the abysses opened in front of me! Carefully and boringly going
via disassembler and verifier output, I've found that clang optimizer ignores
just checked register - patching one byte in assembler sources (and target .o)
did help. I've filed https://github.com/iovisor/bcc/issues/5062 with details
if one curious.

So, looking at eBPF ecosystem, I must say it's a Frankenstein. Sewn from good,
sometimes brilliant parts, it's a monster in outcome. Verifier is in it's own
right, compiler/optimizer is in it's own right... But at the end you even
don't have a high-level programming language! You must write in C, relatively
low-level C, and restricted subset of C. This requires very skilled
professionals - it's far from something not even user-friendly, but at least
sysadmin-friendly, like `ipfw` or `iptables` firewall rules.

Thus I looked at the foundation of eBPF architecture, with which presuppositions
in mind it was created with. In fact, it tries to be just usual programming
after checks - that is, with all that pointers. It's too x86-centric and
Linux-centric - number of registers was added just ten. So if you look at the
GitHub ticket above, when I tried to add debug to program - you know, just
specific `printf()`s - it failed verifier checks again because compiler now
had to move some variables between registers and memory, as there is limit on
just 5 arguments to call due to limit of 5 registers! And verifier, despite
being more than 20,000 lines of code, still was not smart enough to track info
between registers and stack.

So, if we'd started from beginning, what should we do? Remember classic BPF:
it has very simple validator due to it's Virtual Machine design - only forward
jumps, checks for packet boundaries at runtime, etc. You'd say eBPF tries for
performance if verifier's checks were passed? But in practice you have to toss
in as much packet boundary checks as near to actual access as possible, or
verifier may "forget" it, because of compiler optimizer. So this is not of
much difference for checking if access is after packet in classic BPF - the
same CMP/JUMP in JIT if buffer is linear, and if your OS has put packet in
several buffers, like `*BSD` or DPDK `mbuf`'s, the runtime check overhead is
negligible in comparison.

Ensuring kernel stability? Just don't allow arbitrary pointers, like original BPF.
Guaranteed termination time? It's possible if you place some restrictions. For
example, don't allow backward jumps but allow function calls - in case of
stack overflow, terminate program. Really need backward jumps? Let's analyze
for what purpose. You'll find these are needed for loops on packet contents.
Solve it but supporting loops in "hardware"-controlled loops, which can's be
infinite.

Finally, platforms. It's beginning of sunset of x86 era now - RISC is coming.
ARM is now not only on mobiles, but on desktops and servers. Moreover, it's
era of specialized hardware accelerators - e.g. GPU, neural processors. Even
general purpose ARM64 has 31 register, and specialized hardware can
implement much more. Then, don't tie to Linux kernel - BPF helpers are very
rigid interface, from ancient era, like syscalls.

So, let's continue *Berkeley* Packet Filter with Berkeley RISC design - having
register window idea, updated by SPARC and then by Itanium (to not waste
registers). Take NetBSD's coprocessor functions which set is passed with
a context, instead of hardcoded enums of functions - for example, BPF maps is
not something universal, both NetBSD and FreeBSD have their own tables in
firewall.

Add more features actually needed for *network* processor - e.g. 128-bit
registers for IPv6 (eBPF axed out even BPF_MSH!). And do all of this in fully
backwards-compatible way - new language should allow to run older programs
from e.g. `tcpdump` to run without any modifications, binary-compatible
(again, eBPF does not do this - it's incompatible with classiv BPF and uses
a translator from it).

Next, eBPF took "we are masquerading usual x86 programming" way not only just
in assembly language. They have very complex ELF infrastructure around it which
may be not suitable for every network card - having pc-addressed literals, as
in RISC processors allows for much simpler format: just BLOB of instructions.
BPF64 adds BPF_LITERAL "instruction" of varying length (it's interpreted by
just skipping over contents as if it was jump), which, if have special
signatures and format, allow for this BLOB of instructions to contain some
metadata about itself for loading, much simpler than ELF (esp. with DWARF).

Then, ecosystem. eBPF defines functions callable from user code like:

> enum bpf_func_id___x { BPF_FUNC_snprintf___x = 42 /* avoid zero */ };

That is, ancient syscall-like way of global constant, instead of context. A
"context" here is the structure passed with code to execution which contains
function pointers of what is available to this user code, in spirit of
NetBSD's `bpf_ctx_t` for their BPF_COP/BPF_COPX extensions. This is not only
provides better way than "set in stone" syscall-like number, but BPF64 goes
further and defines an "packages" in running kernel with namespaces to allow
e.g. Foo::Bar::baz() function to call Foo::quux() from another BPF program,
populating ("linking") it's context with needed function without relocations.
These "packages" expected to be available to admin in e.g. sysctl tree, with
descriptions, versioning and other attributes.

Some other quotes about how restricted eBPF is:

> First, a BPF program using bpf_trace_printk() has to have a GPL-compatible license.
> Another hard limitation is that bpf_trace_printk() can accept only up to 3 input arguments (in addition to fmt and fmt_size). This is quite often pretty limiting and you might need to use multiple bpf_trace_printk() invocations to log all the data. This limitation stems from the BPF helpers ability to accept only up to 5 input arguments in total.
> Previously, bpf_trace_printk() allowed the use of only one string (%s) argument, which was quite limiting. Linux 5.13 release lifts this restriction and allows multiple string arguments, as long as total formatted output doesn't exceed 512 bytes. Another annoying restriction was the lack of support for width specifiers, like %10d or %-20s. This restriction is gone now as well

> Helper function bpf_snprintf
> Outputs a string into the str buffer of size str_size based on a format string stored in a read-only map pointed by fmt.
>
> Each format specifier in fmt corresponds to one u64 element in the data array. For strings and pointers where pointees are accessed, only the pointer values are stored in the data array. The data_len is the size of data in bytes - must be a multiple of 8.
>
> Formats %s and %p{i,I}{4,6} require to read kernel memory. Reading kernel memory may fail due to either invalid address or valid address but requiring a major memory fault. If reading kernel memory fails, the string for %s will be an empty string, and the ip address for %p{i,I}{4,6} will be 0. Not returning error to bpf program is consistent with what bpf_trace_printk() does for now.
>
> Returns
>
> The strictly positive length of the formatted string, including the trailing zero character. If the return value is greater than str_size, str contains a truncated string, guaranteed to be zero-terminated except when str_size is 0.
>
> Or -EBUSY if the per-CPU memory copy buffer is busy.
>
> static long (* const bpf_snprintf)(char *str, __u32 str_size, const char *fmt, __u64 *data, __u32 data_len) = (void *) 165;

So, let's start with description of changes.

### Classic BPF

First of all, familiriaty with classic BPF is required. If you are not, go to https://man.freebsd.org/cgi/man.cgi?bpf#FILTER_MACHINE and read it, there is only 3 screens of text. It's really simple.

Having knowledge about eBPF or NetBSD's extensions (e.g. https://nxr.netbsd.org/xref/src/sys/net/bpf_filter.c#bpf_filter_ext) is not required, but good to have.

### Notation

> usual RFC 2119 blabla

Due to fact that, although it's unversal and can be used e.g. in syscall arguments filtering, still the primary target for BPF is networking, the traditional RFC style diagrams are used in a modified way. As we are byte-order dependent, bits are numbered in "mathematic" way from ritht to left, that is, from LSB to MSB, usually 16 bits wide - to allow more letters. If diagram is about C structure, fields may be named left to diagram. Some fields may be called in uppercase by corresponding C macros names. If field width is not enough for full name, then common prefix is stripped, e.g. `BPF_SIZE` may become `_SIZE`. Some fields may have numbers with in, either by bits set or as value, possibly with e.g. `constant = 3` record so reader don't need to go to corresponding C header for constant's value.

Example:

```
    MSB 15  14  13  12  11  10  9   8   7   6   5   4   3   2   1   0 LSB
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 code |   Field name  |               |     BPF_OP    | SOMECONST = 3 |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |               jt              |               jf              |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                                                               |
k/imm +                                                               +
      |                                                               |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
```

On diagrams where `jt` and `jf` reused for other fields, they are depicted as above, as if it was big-endian machine - however, note that this is just picture convention and fields in `jt` and `jf` are in distinct bytes which would be in opposite order if casted to halfword on little-endian machine.

As C macro names in code are typically ORed together forming too long line (ususal coding convention is 80 chars max per line), they are continued to be called as short as possible, even if it is wrong grammar etc.

TODO systematic where `BPF_` and where `BFP64_` prefixes

### Packages

Aforementioned `Foo::Bar::baz()` may look like following if implemented via `sysctl`:

```
bpf64.namespace.foo.bar
bpf64.namespace.foo.bar.baz
bpf64.namespace.foo.bar.baz.$: "abcd efgh segment value"
bpf64.namespace.foo.bar.baz.&: { code_struct=members version=0x123 }
bpf64.namespace.foo.bar.baz.*attributes
bpf64.namespace.foo.bar.baz.*attributes.input: "nh_pos,l4_off"
bpf64.namespace.foo.bar.baz.*attributes.version: 1668969726
```

TODO

### Constrained implementations (IoT)

In Internet-of-Things world devices are typically severely constrained in comparison to general-purpose computers due to power saving requirements (e.g. ability to work for years without battery replacement). Such implementations, provided they:

1. support no more than 32 bits width, and
2. do not need interoperation outside of their limited ecosystem

allowed to relax some of the `MUST`'s of this specification, mainly to save memory. They are allowed to:

* have 32-bit registers only, 32-bit `M[]` entries and reduced count of registers and `M[]`
* not implement packages system
* *very* constrained implementation may even live without loops, stack and register window

In fact, all that constrained device may need from BPF64 is just classic BPF with some writing ability. Thus limits such implementations must support are deduced from classic BPF - number of 32-bit entitities accessible by program fits into 32-bit bitmask, that is, at least 16 words of memory `M[]` (32 bit each) and sum of addressable registers, including `X`, up to 32 - for example, 6 global registers `A`..`F`, `X` and `R0`..`R8` for arguments (no selector registers etc. - just hardcoded segment numbers). Given that programs on such device probably will be shorter than 65336 instructions, backstack frame could be reduced to 8 bytes (2 byte return address and no package pointer), reducing total memory for BPF64 to just 256 bytes (e.g. for machines with just 8 bit for index immediates).
- TODO 10.10.24 ~01:49 with remapped global and loop `LC0..LC7` registers give example where A.., Rn.., and I, J, K for loops

Very constrained implementations may choose to eliminate even stack and loop/call mechanism (treating `R#` registers like any other), reducing this memory to just 128 bytes (32 32-bit words). However, it is questionable if reducing stack may compensate for higher memory requirements for BPF program itself (repeating chunks due to no subprograms), so it's up to implementors to decide in every case.

As there is no interoperability in such systems with other BPF64 implementations, instead `BPF_LITERAL` with section headers etc. a custom (used mainly for fool-proof error-checking) alternative may be used, probably in just 1-2 `bpf_insn`'s - byteorder mark, magic number of poarticular system and some system specific feature flags.

### TBD

08.10.24 evaluate MPK - https://fengweiz.github.io/paper/moat-usenixsecurity24.pdf :
```
Given the increasing security threats in BPF and the chal-
lenge of enforcing safe BPF programs with merely static
verification, we seek to employ hardware extensions to sand-
box untrusted BPF programs. In particular, we leverage Intel
Memory Protection Keys (MPK ) [11 ], an emerging hardware
extension that partitions memory into distinct permission
groups by assigning up to 16 keys to their Page Table En-
tries ( PTE s). With the aid of MPK , we present MOAT, which
isolates untrusted BPF programs in a low-cost and principled
manner. For instance, two MPK protection keys K and E can
be assigned to the kernel and the BPF programs, respectively.
When the kernel transfers control to a BPF program, it can
set K as access-disabled to prevent the potentially malicious
BPF program from tampering with kernel memory.
Despite its promising potential, using MPK to enforce BPF
isolation is not straightforward. In designing MOAT, we faced
and overcame two major technical hurdles. First, MPK pro-
vides a maximum of 16 keys. Thus, supporting numerous
BPF programs with this limited number of keys is challeng-
ing. Existing workarounds like key virtualization [ 62 ] heavily
rely on scheduling and notification mechanisms that are only
available to user space; our

[11] Intel 64 and IA-32 Architectures Software
Developer Manuals, 2022. URL https:
//www.intel.com/content/www/us/en/developer/
articles/technical/intel-sdm.html.

[62] Soyeon Park, Sangho Lee, Wen Xu, HyunGon Moon,
and Taesoo Kim. libmpk: Software abstraction for intel
memory protection keys (Intel MPK). In 2019 USENIX
Annual Technical Conference (USENIX ATC 19), pages
241–254, Renton, WA, July 2019. USENIX Association.
```

09.10.24 https://lwn.net/Articles/877062/ :
> For ultimate performance one can do what JS JITs do. Start a timer when JS is started. Then, when the timer expires, patch the generated code to turn NOP sequences placed before backward jumps into exit jumps. 

WebAssembly `call_indirect` is by index to table, so if we making several tables, is it better than CV in AV ?

## Changes to classic BPF

There are no directly available backward jumps in BPF64 - they are possible only via calling to new stack frames. Thus the `bpf_insn` structure is reused as is, with exception that `k` field may be sometimes be used as signed, in which case it is called `imm`.

Memory addressing extended beyond the `P[]` packet to a number of *segments*, up to 2^32 bytes in size, each having it's type, permissions etc.

### Registers

The general-purpose registers encoding is so that when older program is
encounters, it corresponds to A register, so compatibility is preserved.

```
   Num | Name | Bits | Type            | Visible | Comments
   ====+======+======+=================+=========+=========================
    0  |   A  |  32  | General-purpose | Global  | Accumulator
    1  |   B  |  32  | General-purpose | Global  | 
    2  |   C  |  32  | General-purpose | Global  | 
    3  |   D  |  32  | General-purpose | Global  | 
    4  |   E  |  32  | General-purpose | Global  | 
    5  |   F  |  32  | General-purpose | Global  | 
    6  |   G  |  32  | General-purpose | Global  | 
    7  |   H  |  32  | General-purpose | Global  | 
    8  |   W0 |  32  | Rotated/renamed | Local   | usually 1st arg to func
    9  |   W1 |  32  | Rotated/renamed | Local   | 2nd arg to func
    10 |   W2 |  32  | Rotated/renamed | Local   | and so on
    11 |   W3 |  32  | Rotated/renamed | Local   | 
    12 |   W4 |  32  | Rotated/renamed | Local   | some of them is first
    13 |   W5 |  32  | Rotated/renamed | Local   | local variable
    14 |   W6 |  32  | Rotated/renamed | Local   | 
    15 |   W7 |  32  | Rotated/renamed | Local   | some for input/output
    16 |   W8 |  32  | Rotated/renamed | Local   | with next callee
    17 |   W9 |  32  | Rotated/renamed | Local   | 
    18 |  W10 |  32  | Rotated/renamed | Local   | 
    19 |  W11 |  32  | Rotated/renamed | Local   | 
    20 |  W12 |  32  | Rotated/renamed | Local   | 
    21 |  W13 |  32  | Rotated/renamed | Local   | 
    22 |  W14 |  32  | Rotated/renamed | Local   | 
    23 |  W15 |  32  | Rotated/renamed | Local   | 
    24 |  W16 |  32  | Rotated/renamed | Local   | 
    25 |  W17 |  32  | Rotated/renamed | Local   | 
    26 |   X  |  32  | Special: index  | Global  | 
    27 |   Y  |  32  | Special: index  | Global  | 
    28 |  LC0 |  32  | Special: loop 0 | Local   | read-only, most inner loop
    29 |  LC1 |  32  | Special: loop 1 | Local   | read-only 
    30 |  LC2 |  32  | Special: loop 2 | Local   | read-only 
    31 |  LC3 |  32  | Special: loop 3 | Local   | read-only, most outer loop 
   ----+------+------+-----------------+---------+---------------------------
    32 |  AA  |  64  | General-purpose | Global  | A is low 32 bits of AA
    33 |  BB  |  64  | General-purpose | Global  | B is low 32 bits of BA
    34 |  CC  |  64  | General-purpose | Global  | and so on
    35 |  DD  |  64  | General-purpose | Global  | 
    36 |  EE  |  64  | General-purpose | Global  | 
    37 |  FF  |  64  | General-purpose | Global  | 
    38 |  GG  |  64  | General-purpose | Global  | 
    39 |  HH  |  64  | General-purpose | Global  | 
    40 |  R0  |  64  | Rotated/renamed | Local   | usually 1st arg to func
    41 |  R1  |  64  | Rotated/renamed | Local   | 2nd arg to func
    42 |  R2  |  64  | Rotated/renamed | Local   | and so on
    43 |  R3  |  64  | Rotated/renamed | Local   | 
    44 |  R4  |  64  | Rotated/renamed | Local   | some of them is first
    45 |  R5  |  64  | Rotated/renamed | Local   | local variable
    46 |  R6  |  64  | Rotated/renamed | Local   | 
    47 |  R7  |  64  | Rotated/renamed | Local   | some for input/output
    48 |  R8  |  64  | Rotated/renamed | Local   | with next callee
    49 |  R9  |  64  | Rotated/renamed | Local   | 
    50 |  R10 |  64  | Rotated/renamed | Local   | 
    51 |  R11 |  64  | Rotated/renamed | Local   | 
    52 |  R12 |  64  | Rotated/renamed | Local   | 
    53 |  R13 |  64  | Rotated/renamed | Local   | 
    54 |  R14 |  64  | Rotated/renamed | Local   | 
    55 |  R15 |  64  | Rotated/renamed | Local   | 
    56 |  R16 |  64  | Rotated/renamed | Local   | 
    57 |  R17 |  64  | Rotated/renamed | Local   | 
    58 | Reserved for future use e.g. as flags & trap jump condition
    59 | Reserved for future use
    60 |   V0 | 128+ | Special: b/vect | Global  | IPv6/strings: no ALU
    61 |   V1 | 128+ | Special: b/vect | Global  | except AND, OR, and LSH
    62 |   V2 | 128+ | Special: b/vect | Global  | or RSH in multiple of 8
    63 |   V3 | 128+ | Special: b/vect | Global  | (e.g. memmove() or like)
```

FIXME seems that JIT on RISC-V (and MIPS different names but same count) must use x0-x8 for it's own needs, which leave us only 23 available registers... including X and Y ?.. //mainly yes but smth wrong
- 13.09.24 RISC-V leaves 26 registers to JIT including it's own temporaries, MIPS even one less if in userspace, x86 need 1 temporary for "memory-memory", and there too many architectures, e.g. Intel APX raises number of registers. So what will be in ten years? Someone will do 64 registers? So let's move to maximum registers possible by encoding and put JIT authors do deal with that - e.g. AMD64 ABI already uses "some in registers, some in memory" to speed up at least something
- 14.09.24 this requires for JIT implementation to know which registers is input/local/output, so it's either return to fixed register windows (as in SPARC) or somewhat like annotating each instruction which register is which
   - probably for first version for simplicity is enough "let JIT use R0..as much as it can" without dividing to classes, but supplement `BPF_PROLOG` with a version which will be `NOP` for bytecode interpreter (and to capable JIT) but hint to limited JIT of which registers may be unused UPD see notes of 29.09 about remapping global registers
     - 10.10.24 02:14 and remapping loop (`LC0`) registers also

In addition to registers above, there are also special registers like segment selectors described under `BPF_TAX`/`BPF_TXA`, and pseudoregisters, which abstracts typical RISC's zero register to strings of zeroes ond ones - that is, the main application is for CIDR masks.

If register encoding takes one byte, than it is normal register if high bit is 0, otherwise it's "zero-ones 64-bit pseudo-register" described as follows:

```
      MSB      6       5       4       3       2       1       0
    +-------+-------+-------+-------+-------+-------+-------+-------+
    |Pseudo?|Starts |        Count of 'Starts' bit minus one        |
    +-------+-------+-------+-------+-------+-------+-------+-------+
```

This encoding allows of up to 64 zeroes or ones filled from MSB to LSB. For example, value 0xd0 means "start from 1, 0x10+1 times, then inversion of start bit" - that is,
0xffff800000000000.

Another example, if we want to have a hostmask for /24 IPv4 network, that is, 0x000000ff, then after extending this to 64 bits we get 56 zeroes from MSB, so 0x80 + 0x37 gives us 0xb7.

In the BPF64 Assembler Wrapper and also in spec, this has the following generic notation: letters OZ or ZO for "ones, then zeroes" and vice versa, then width, slash `/` and allocated bits for starting from MSB  in definite length,or `+` or `-` signs for "to infinity from left or right". Thus, CIDR netmask is written as `OZm/a` for `m` width and `a` one bits, e.g. `OZ128/48` for IPv6 /48 subnet mask.

TODO generic notation encoding for longer than 64 bits

TBD `BPF_JUMP_BITSET` may be done by ZOZ encoding and just `BPF_JSET` with literal?

TODO ensure single-switch decoding of all insns as in original BPF paper (XFk everywhere?)

### In BPF_LD and BPF_LDX classes

```
    MSB 15  14  13  12  11  10  9   8   7   6   5   4   3   2   1   0 LSB
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 code | Register number N |S??|    BPF_EXTMODE    | _SIZE | BPF_CLASS |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      | jt = Type: atomic op/reg/etc. |        jf = from segment      |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                                                               |
k/imm +                                                               +
      |                                                               |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
```

The register number field is 5 bits and is treated if it was 6 bits with high bit set, for register table above - as actual operation size is determined by `BPF_SIZE`, there is no need to encode both versions.

`BPF_EXTMODE` is a superset of classic `BPF_MODE`:

```c
#define	BPF_IMM 	0x000	// 0 0 0 0 0 regs[N] <- k
#define	BPF_ABS		0x020	// 0 0 0 0 1 regs[N[ <- P[k:BPF_SIZE]
#define	BPF_IND		0x040	// 0 0 0 1 0 regs[N] <- P[X+k:BPF_SIZE]
#define	BPF_MEM		0x060	// 0 0 0 1 1 regs[N] <- M[k]
#define	BPF_LEN		0x080	// 0 0 1 0 0 regs[N] <- pkt.len
#define	BPF_MSH		0x0a0	// 0 0 1 0 1 X <- 4*(P[k:1]&0xf)
#define	BPF_IND_Y	0x0c0	// 0 0 1 1 0 regs[N] <- P[Y+k:BPF_SIZE]
// BPF_IND+BPF_MSH	0x0e0	// 0 0 1 1 1 X <- 4*(P[X+k:1]&0xf) # when DLT unknown

#define BPF_SIGN	0x400

#define BPF_L		0x100
#define BPF_SEG		0x200

#define	BPF_RODATA (BPF_L|BPF_IMM) // 0 1 0 0 0 regs[N] <- C[8*pc+imm:BPF_SIZE]
```

The `BPF_L` in LD means "little-endian" if load is from packet. For
example, on little-endian platform loading `BPF_H` requires `ntohs()` but
`from_leH()` is no-op, on big-endian platform ordinary load do not require
conversion (it's already network byte order), but `*_PKT_LE` modes will require.
These modes defined only for packet access because other memory segment are
expected to be in native machine byte order. For rare cases when this is not
true, there is `BPF_ENDIAN` instruction in `BPF_ALU` class.

`BPF_RODATA` is another use of `BPF_L` (meaning "literal" here) for generic literal, addressing mode around `pc` in code segment, see `BPF_LITERAL` instruction.

If `BPF_SEG` is set, then access is not to packet `P[]` but to externally-supplied memory segment. Segments are treated like packets in a sense of checks: e.g. access past end of segment is not allowed, length of segment can be obtained by `BPF_SEG|BPF_LEN`, etc.

Segments, in addition to functions, are the main way for BPF program to interact with the rest of system. Segment numbers, which may live in segment selector registers, are part of BPF program environment - like File Descriptors for Unix processes.

Note that only one another index register, Y, is added - the encoding don't allow more.

The `jt` field, depenging on register, segment and mode, allows additional operation types ("t" im mnemonic) - in a way defined by platform. For example, access to per-CPU data or atomic operations (always on segments, not packet) can be here, subject to check by implementation (e.g. that atomic operation do not go to per-CPU segment, etc.).

### in BPF_LDX

TBD 23.09.24 ~23:26 use extended b/vector registers as a (str) key to (hash)map
- 24.09.24 and such key can also be a path in e.g. parsed JSON like
       $root->{media}->{photo}->{sizes}->[3]->{sizes}->[4]
  with strings being offsets in literal, of course, and path be like Version String of VarUInt32's
  - generic references inside segments?..
    - 26.09.24 a way to reference BPF function for callbacks? e.g. for:
      > `[json lmap varlist1 json_val1 ?varlist2 json_val2 ...? script]` - As for [json foreach], except that it is collecting - the result from each evaluation of script is added to a list and returned as the result of the [json lmap] command. If the script results in a `TCL_CONTINUE` code, that iteration is skipped and no element is added to the result list.
      - 27.09 ~04-05 may be, but related moment: as our target userland runner is Perl, likely from XS program - then segments memory model should be suitable for when BPF64 segments are backed by Perl scalars, e.g. from JSON::XS; so need to look how SV are accessed from XS side
        - 28.09 02:30 so also access to meta-fields, e.g. SvCUR or mbuf's
        - do it via `BPF_LEN` addressing mode, like new indexes for `X`?
  - 29.09 for passing callbacks it may be simple - just export them and import and use `k`, but what to do on receiving procedure which did not import it? `k` starting from 0xc0000000 may be to call, but how to add there? also, for remapping global registers: so indexes are now 0-23 globals/Rn and 24-31 for extended 
    - may be reduce to R40 and have, like LC0, in backstack frame also an offset:size in `M[]` to be "heap" or like C's `alloca()` for "public" data (`:our()` in BAW?) where addressing be e.g. `M[HEAP0+k]` ? or be it separate from `M[]` ? and where iterator will keep it's data in parent's heap between invocations?..
      - 10.10.24 ~02:14 as `LC0` be also remappable, should think better...
    - send cb: call to create a CV in SV table, call cb: ...huh, 0xc0000000 is static
- 25.09.24 16:22 what if make these registers remappable? then b/vector could really be just segment, and in future floating-point registers may be added - as they are already available in `BPF_ALU` encoding TBD where remap, `BPF_TAX` ?

TODO 24.10.24 more variants to `BPF_MSH` due to new IPnh field lengths

### In BPF_ST and BPF_STX classes

Here existing implementations check just `BPF_ST` or `BPF_STX`, that is, `BPF_IMM`
is treated like `BPF_MEM`. However, new code need not be defined, because there
is no point to store in 'k' of instruction - self-modifying code can't be
verified.

TBD 07.09 what if bit/byte vector strings instead? then IPv6 (128) is just
    fixed width particular case and any strings can be used (e.g. for text
    protocols) by special SVs, but how to load then? cur++ ? and Z() be
    rethought to even more generic... OZm/a (e.g. OZ128/48), ZO-35 ?
  - 07.09 SIGN/MSX bit do not match it's place with `BPF_ALU/BPF_JMP`, but we
    don't need 6 bits here as `BPF_SIZE` tells it already, what to do? in any
    case put a note (rationale) to spec
    - eBPF has `is_sdiv_smod() insn->off == 1`, `is_movsx() off == 8/16/32`
      and `BPF_MEMSX` as bit in `BPF_MODE`
TBD

TODO

### In BPF_ALU class

```
    MSB 15  14  13  12  11  10  9   8   7   6   5   4   3   2   1   0 LSB
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 code |   Register number N   |S??|XFk|     BPF_OP    |SRC| BPF_ALU=4 |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |jt - TBD type or third register|     jf - "from" register      |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                                                               |
k/imm +                                                               +
      |                                                               |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
```

Register number is of full 6 bit space, classic programs will have it zero meaning `A` register. `XFk` bit enables eXtended Format, as we can not be sure that every classic BPF code generator leaves `jt` and `jf` zeroed outside of `BPF_JMP` - existing interpeter implementations simply ignore them, so this probably may be possible.
- TODO 28.09.24 we can free one bit here (and in other classes) by the following trick: first, run program against classic `bpf_validate()` - if it passes, then we forcefully change to zero all `jt` and `jf` outside of `BPF_JMP` class (TBD may be put under sysctl knob to speed up a little if admin knows classic generators on this system (e.g. tcpdump/pcap only) are safe?)
e.g. tcpdump/pcap only

```c
#define	BPF_ADD		0x00
#define	BPF_SUB		0x10
#define	BPF_MUL		0x20
#define	BPF_DIV		0x30
#define	BPF_OR		0x40
#define	BPF_AND		0x50
#define	BPF_LSH		0x60
#define	BPF_RSH		0x70
#define	BPF_NEG		0x80
#define	BPF_MOD		0x90
#define	BPF_XOR		0xa0
/*			0xb0	reserved */
#define	BPF_ARSH	0xc0	/* sign extending arithmetic shift right */
#define	BPF_ENDIAN	0xd0	/* byteswap/endianness change */
#define	BPF_SDIV	0xe0	/* signed division */
#define	BPF_SMOD	0xf0	/* signed %= */
```

TBD two new opcodes sdiv/smod or MSX bit? `BPF_NOT` is missing, and if put it to
0xb0 then no reserved left if sdiv/smod used

TBD decide if XFk refers to `k` for third register under `BPF_X` in `BPF_SRC`, or to `jt`

Note that for extended registers (e.g. 128 bit IPv6), implementation MUST support only `BPF_AND`, `BPF_OR` and `BPF_LSH`/`BPF_RSH` in multiple of 8 (e.g. `memmove()` could be used byte-wise). However implementation MAY support long arithmetics on them if wish so.

TODO 25.09.24 0xf0 for Floating-Point and Vector extensions in `jt`; sign into `jf` (and bit 6 in `jf` as reserved as we know operation width from bit 14)
- 26.09 classic BPF paper was on better decoding by single switch/case, so probably move register out of `code` as possible, and for other classes, too (except `BPF_JMP` where it is unavoidable)
- 10.10.24 ~01:49 sign/MSX is actual when load is to low half - what if abstract it to offset for *any* general-purpose register? then for standard registers it is fixed e.g. to either low or `loadhi` variant, and for extended vector register offset can be anywhere up to what encoding allows; e.g. it may be relative to `CUR` of register, which is always constant for GPRs

TODO

### In BPF_JMP class

```
    MSB 15  14  13  12  11  10  9   8   7   6   5   4   3   2   1   0 LSB
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 code |   Register number N   |S??|XFk|     BPF_OP    |SRC| BPF_JMP=5 |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |               jt              |               jf              |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                                                               |
k/imm +                                                               +
      |                                                               |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
```

This class, as in classic BPF, retains forward jumps only, and, given that `jt` and `jf` fields are present, for possibility for future opcode extensions only "greater" opcodes are used, in contrast to eBPF (eBPF changed `jt` and `jf` to single 16 bit `off` field so need to have inverted tests, but we don't need to - `BPF_JA` still available). However, signed versions of those are added as 0x60 and 0x70 (same as in eBPF). 

```c
				// SRC = BPF_K or BPF_X
#define	BPF_JA		0x00	// pc += k
#define	BPF_JEQ		0x10	// pc += (A == SRC) ? jt : jf
#define	BPF_JGT		0x20	// pc += (A > SRC) ? jt : jf
#define	BPF_JGE		0x30	// pc += (A >= SRC) ? jt : jf
#define	BPF_JSET	0x40	// pc += (A & SRC) ? jt : jf
#define BPF_JTBL	0x50	/* in literal, like TBB in ARM */
#define BPF_JSGT	0x60	/* SGT is signed '>', GT in x86 */
#define BPF_JSGE	0x70	/* SGE is signed '>=', GE in x86 */
/*			0x80	reserved */
/*			0x90	reserved */
/*			0xa0	reserved */
/*			0xb0	reserved */
/*			0xc0	reserved */
/*			0xd0	reserved */
#define BPF_JEXT	0xe0	/* extended operation in BPF_JMPMODE */
/*			0xf0	reserved */
```

If `XFk` bit is set, then (see ALU) instead of `BPF_X` the second register is encoded in `k`

TBD what is more priority, e.g. `BPF_K` and `XFk` ?

TBD encoding for `k` for strings longer 64 bits

### `BPF_JTBL` (0x50)

This is instruction multiple branch targets. In one of it's forms it's just like `TBB` instruction on ARM or `XLAT` on x86. It may be useful for common tasks where branching could be made O(1) with lookup by index, e.g. for separate processing of each TLV chunk by type (in protocols with such structure) or compact constant filtering rules, like 1 bit per entity.

All forms have a `BPF_LITERAL` which MUST immediately follow `BPF_JMP`-class instruction, and all jump offsets are calculated from end of literal (as if there were some NOPs with no literal and `BPF_JMP` was at the place of last 8 bytes of literal).

As this is new instruction, and immediates are in literal, no `XFk` is needed, and only registers are used as source - `BPF_SRC` either selects `BPF_X` or a register from usual field, if it's `BPF_K`.

Table jumps have subtype variants, encoded in `jt` field - for example, literal may contain not just index, but bits or something other. Exact variant may require that literal be strictly in short or long form.

`jt` has two bits of `BPF_MODE` inside - defining which part of register is masked to obtain value to lookup in table. Only some of `BPF_B`, `BPF_H` and `BPF_W` are allowed, depending on subtype. And variant - that is, table type - could be obtained by usual `BPF_CLASS` mask on `jt`.

```
    MSB 15  14  13  12  11  10  9   8   7   6   5   4   3   2   1   0 LSB
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 code |Reservd|   Register number N   | BPF_OP = 0x50 |SRC| BPF_JMP=5 |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |     jt    | _SIZE |Table type |               jf              |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                                                               |
  k   +                                                               +
      |                                                               |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 code |          Low 8 bits           | 0   0 |Hi bits| 1 | BPF_MISC  |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      /                                                               /
      \      Literal data, example given for short literal form       \
      /                                                               /
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

#### `BPF_JUMP_BITSET` (0):

Most simple form - value of register masked by `BPF_SIZE` produces bit position in literal, if that bit is 1, "if matched" branch is taken, and if it is zero, then execution continues at first instruction after literal (as if was no jump, just `BPF_LITERAL`).

```
    MSB 15  14  13  12  11  10  9   8   7   6   5   4   3   2   1   0 LSB
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 code |Reservd|   Register number N   | BPF_OP = 0x50 |SRC| BPF_JMP=5 |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |     jt    | _SIZE | 0   0   0 |               jf              |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                    Jump offset if matched                     |
   k  +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |           Base value of A above which to count bits           |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 code |          Low 8 bits           | 0   0 |Hi bits| 1 | BPF_MISC  |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      /                                                               /
      \            Bit string, literal may be short or long           \
      /                                                               /
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Implementation must take care of proper offset to start of bitstring, taking into account if `BPF_LITERAL` is in short or long form. A straightforward implementation's fragment may look like:

```c
	    if (A < above)
		    break;
	    A -= above; /* subtract base */
	    match = (A < (cmdlen-1)*64) &&
		( d[ 1 + (A>>5)] & (1<<(A & 0x1f)) );
```

so unused (padding) bits at end are just set to 0.

#### `BPF_JUMP_INDEX` (1)

Low `BPF_SIZE` of register (unsigned) is used as index into table, in which jump offset is found. As `BPF_W` sizes can potentially take more space than literals allow, and usefulness of so many jumps is questionable, implementations MAY choose to disallow `BPF_W` sizes.

Can exist in two forms, of short and long literal, which differ by jump offset width - 16 or 32 bits, for proper alignment. `BPF_B` size MUST be used only with short literal form, and `BPF_W` size (if supported) MUST be used only with long form. For `BPF_H` size there is choice between compactness and jump offsets longer than 16 bits.

Short form:

```
    MSB 15  14  13  12  11  10  9   8   7   6   5   4   3   2   1   0 LSB
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 code |Reservd|   Register number N   | BPF_OP = 0x50 |SRC| BPF_JMP=5 |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      | jt - type | _SIZE | 0   0   1 |               jf              |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                                                               |
  k   +    Jump offset if NOT matched (e.g. 'default' in 'switch')    +
      |                                                               |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 code |          Low 8 bits           | 0   0 |Hi bits| 1 | BPF_MISC  |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                    Jump offset at index 1                     |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                    Jump offset at index 2                     |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      /                                                               /
      \                                                               \
      /                                                               /
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                    Jump offset at index N                     |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
```

Long form:

```
    MSB 15  14  13  12  11  10  9   8   7   6   5   4   3   2   1   0 LSB
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 code |Reservd|   Register number N   | BPF_OP = 0x50 |SRC| BPF_JMP=5 |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      | jt - type | _SIZE | 0   0   1 |               jf              |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                                                               |
  k   +    Jump offset if NOT matched (e.g. 'default' in 'switch')    +
      |                                                               |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 code |     Usual                     | 1   1   1 |       | BPF_MISC  |
      +           long BPF_LITERAL    +---+---+---+       +---+---+---+
      |                            encoding                           |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                                                               |
      +                    Jump offset at index 1                     +
      |                                                               |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                                                               |
      +                    Jump offset at index 2                     +
      |                                                               |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      /                                                               /
      \                                                               \
      /                                                               /
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      +                    Jump offset at index N                     +
      |                                                               |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
```

For value 0, jump is not stored in table - it is implicitly first instruction after jump table.

### `BPF_JUMP_RANGES` (2)

There are cases where two previous variants can occupy too much space, for example, often occuring task - check if a number belongs to one or more ranges in short (16 bit) fields, e.g. ports or Ethernet protocol numbers. In first of encodings below 26 port ranges, together with `BPF_JMP` itself, will take 64 bytes, a typical cache line - but equivalent sequence of `BPF_JGT`'s etc. will take at least 256 bytes, and direct index variant or even bitset could take much longer if values are high enough. However, as this variant requires O(N) scanning of table which can be effective only on relatively small number of cache lines, only `BPF_H` version is provided (others MUST be rejected by validator).

There are two flavours, for short and long literal forms - with separate jump offset for each range (like `BPF_JUMP_INDEX`) and just match/non-match for entire rangeset (like `BPF_JUMP_BITSET`).

* Form with long literal is like `BPF_JUMP_BITSET` and if there is no match, then execution continues at first instruction after literal (as if was no jump, just `BPF_LITERAL`):

```
    MSB 15  14  13  12  11  10  9   8   7   6   5   4   3   2   1   0 LSB
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 code |Reservd|   Register number N   | BPF_OP = 0x50 |SRC| BPF_JMP=5 |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      | jt - type | 0   1 | 0   1   0 |               jf              |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                                                               |
  k   +                    Jump offset if matched                     +
      |                                                               |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 code |     Usual                     | 1   1   1 |       | BPF_MISC  |
      +           long BPF_LITERAL    +---+---+---+       +---+---+---+
      |                            encoding                           |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                 Range 0 low bound, inclusive                  |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                 Range 0 high bound, inclusive                 |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                 Range 1 low bound, inclusive                  |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                 Range 1 high bound, inclusive                 |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      /                                                               /
      \                                                               \
      /                                                               /
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                 Range N low bound, inclusive                  |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                 Range N high bound, inclusive                 |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
```

Ranges are inclusive, as both ipfw2 and tcpdump/libpcap 'portrange' do it
inclusive - it allows to use single numbers, e.g. '0-1023,6000,8000-8080'
is equivalent to '0-1023,6000-6000,8000-8080' and the latter is encoded.
Whenever padding is needed, the last range could be simply repeated.

A straightforward implementation fragment may look like:

```
	for (i = cmdlen*2 - 1; !match && i>0; i--, p += 2)
		match = (x>=p[0] && x<=p[1]);
```

  Underlying hardware or JIT compiler may utilize whatever optimizations
  available, of course.

* Form with short literal is like `BPF_JUMP_INDEX`:

```
    MSB 15  14  13  12  11  10  9   8   7   6   5   4   3   2   1   0 LSB
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 code |Reservd|   Register number N   | BPF_OP = 0x50 |SRC| BPF_JMP=5 |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      | jt - type | 0   1 | 0   1   0 |               jf              |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                                                               |
  k   + Jump offset if NO range matched (e.g. 'default' in 'switch')  +
      |                                                               |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 code |          Low 8 bits           | 0   0 |Hi bits| 1 | BPF_MISC  |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                 Range 0 low bound, inclusive                  |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                 Range 0 high bound, inclusive                 |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                Jump offset if range 0 matched                 |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                 Range 1 low bound, inclusive                  |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                 Range 1 high bound, inclusive                 |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                Jump offset if range 1 matched                 |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      /                                                               /
      \                                                               \
      /                                                               /
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                 Range N low bound, inclusive                  |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                 Range N high bound, inclusive                 |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                Jump offset if range N matched                 |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      .                                                               .
      .                 Possible padding, 0/2/4 bytes                 .
      .                                                               .
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
```

### TODO , JEXT etc. with literals, see in BPF_PACKED

### In BPF_RET class

Opcodes in this class are altering control flow graph program in a
possibly non-forward way - e.g. `BPF_JMP` allows only forward jumps, but `BPF_RET`
allows to jump backwards or even terminate current program.

#### BPF_EXIT (0)

The first is `BPF_EXIT`, the only instruction in this class in classic BPF.
It returns from current function or entire program, yielding return value in
register `A` for caller, if it was a procedure. Here for `BPF_RVAL` allowed values
are `BPF_A`, `BPF_K` and `BPF_X`. If more parameters were needed by calling
procedure, they are passed in input section of rotated registers.

```
    MSB 15  14  13  12  11  10  9   8   7   6   5   4   3   2   1   0 LSB
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 code |      Return code (class)      |BPF_EXIT=0 | _RVAL | BPF_RET=6 |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      | jt: return to this level      |               jf              |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                                                               |
k/imm +                  Return value, if BPF_K                       +
      |                                                               |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
```

If a return was to previous function in the stack, register window is
automatically restored as it was in previous function.

The most important new thing here is return code (class), used for exception handling ad altering control flow in caller. By default it's zero, `BPF_OK`, meaning just normal return - caller gets return value in `A` register. The following codes are processed by system, and others are also possible.

```c
#define BPF_OK      0
#define BPF_NEXT    1   /* 'continue'*/
#define BPF_LAST    2   /* 'break' */
#define BPF_RETURN  3   /* 'return' */
#define BPF_ERROR   4   /* 'die' */
```

These can be described, for caller, behaviour, as if in caller's code, instead of our procedure call, were written another statement: `continue`, `break`, `return` or exception was thrown. The primary use is for loop and exception handling, but cooperating BPF programs may implement their own control structures with this - which may be useful for higher-level languages (e.g. firewall description rules) which are compiled to BPF64.

See example later in how `BPF_LOOP` can be optimized, and how return code is used.

#### BPF_CALL (1)

Call a function. Backward address is allowed. Return address is placed in
shadow (back) stack. From the register window point of view, call is two-part
process - first, calling procedure advances window, hiding it's own input and
local registers from callee. Then, simple callee may choose to not do anything
at all, but if callee plans to call another functions, the rest of window must
be set up with `BPF_PROLOG` instruction.

```
    MSB 15  14  13  12  11  10  9   8   7   6   5   4   3   2   1   0 LSB
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 code |  RegWindow shift  |0/BPF_L/SEG|BPF_CALL=1 | _RVAL | BPF_RET=6 |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |               jt              |               jf              |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                                                               |
  imm +       Address of called function relative to pc, signed       +
      |                                                               |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
```

If there are too many frames - that is, (back)stack overflow - fatal exception is thrown and execution of this BPF machine is stopped. This is one of mechanisms of protecting instead of complex eBPF verifier - endless calling backwards will overflow stack.

TODO different calling conventions - to function by pc+imm if 0, to BPF
machine if `BPF_L` and external kernel functiond when SV/segment-wrapped,
also think about simple `k` resolving like in NetBSD `bpf_ctx_t` and with
run-time (may be each call) resolving by ASCII name; SV/segment-wrapped
means arguments are *not* in registers so they must be prepared before
call in some temporary space - Dtrace's `pushtr`/`pushtv`? Perl's `ST(n)` ?

TODO jt != 0 & jf != 0 - it's `catch` (pairs like 'error => labelname' in awc)

TBD or not in `call`? where to capture other [trappable] exceptions?

TBD about `BPF_TAILCALL` flag:

`#define BPF_TAILCALL 0x400`

  Like `execve()` - replaces current running BPF program with another one. The
  stack is rewinded - current output registers become input registers at
  offset 0, all loops are reset. All other registers are reset, except A.
  The retained resources consist only of A and input (former output)
  registers as "argv", current packet and memory segments and first
  `jt` (default `BPF_MEMWORDS`) of scratch memory as "environment".
  Everything other is cleared, just like if new program was loaded fresh.

  The platform-dependent identificator of new program is in `k` or `X`. The
  instruction does not return if load was successful, otherwise execution is
  continued from next instruction with A set to error number (so that program
  could e.g. deny or accept packet).

TBD 21.09.24 no, no separate `execve()`, and `BPF_TAILCALL` for every functions - so it's possible to `BPF_EXIT` with big `-level` and then replace program from `main()`; better to move some flags to `jt` or `jf` and remaining type bits use for OOP - e.g. `k` pointing to string for method call on "blessed" segment TBD where to pass `$self` ? in `BS` for "blessed"? TBD 28-29.09 also due to locking problem, isn't OOP on segments an overkill? and how to friend with when we already in such OOP-lang such as Perl (do thunks for their method calls)? instead, mb another resurrection of coroutines via nested functions, see other notes at 29.09 ? (also mb separate field "global regs" in addition to window 13.10 if globals mapped from some are which is unused if callee declares less globals, then this probably not needed)
- 10.10.24 ~01:49 probably a bit should be reserved for "a linear stack register window call" as it is now - for possible future extensions e.g. coroutines in non-linear/memory locals stack; and so `LC0..LC7` registers may be also abstracted to something more generic

TBD

#### BPF_PROLOG (2)

  Usually the first instruction of called function. Advances register window,
  declaring how many input, local and output registers will be used.

```
    MSB 15  14  13  12  11  10  9   8   7   6   5   4   3   2   1   0 LSB
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 code | Reserved  | # of private regs | BPF_ROLOG = 2 |SRC| BPF_RET=6 |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      | Reserved  | jt: # of out regs | Reserved  |jf: # of input regs|
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                                                               |
k/imm +                            Reserved                           +
      |                                                               |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
```

Caller reserves it's output registers number to maximum of any called function can accept. Thus every called function must declare how many it has input registers actually - and reserves rest of space for both local and it's own output registers. Then, when it's time to do it's own call, it knows how many local registers it has and advances window by this number in `BPF_CALL`.

Limiting output registers is two-purpose: to not overdo zero initialization of those registers on call (and most importantly, in JIT with limited registers to leave them in backing memory) and to check for errors - an exception will be thrown on access to register after declared.

TBD
- 10.10.24 ~01:49 remap also `LC0..LC7` registers here

TBD

#### BPF_LOOP (3)

Language with no backward jumps, such as classic BPF, is severely restricted for practical purposes. Adding them provides pain with program verification. But if we try to classify for what backward jumps are needed, we'll find, in addition to function calls, that such need is looping. So `BPF_LOOP` provides exactly this - looping controlled by execution environment. All loops start from some value and repeating until loop counter variable reaches zero, decrementing it on each pass for 1 (or more) - this way loop is guaranteed to terminate.

```
    MSB 15  14  13  12  11  10  9   8   7   6   5   4   3   2   1   0 LSB
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 code |  RegWindow shift  |   Flags   |BPF_LOOP=3 | _RVAL | BPF_RET=6 |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |               jt              |               jf              |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                                                               |
  k   +             Initial loop counter value, unsigned              +
      |                                                               |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
```

Actually, `BPF_LOOP` is a call: loop body is executed in it's own stack frame. Current - where the `BPF_LOOP` opcode is - stack frame contains flag and value of loop counter variable. Loop body's stack frame accessed counter as `LC0` in parent frame, as `LC` in parent of parent frame, and so on up to `LC3`, giving up to four nested loops. Typical loop control constructs like `break` or `continue` are all handled with `BPF_EXIT` with corresponding return code (class) - allowing loop body even to adjust loop counter for more than 1, which is read only by normal means.

`jt` is interpreted like in `BPF_JMP` class: it is offset to loop body. Loop counter variable is initialized according to `BPF_RVAL`: from `BPF_A`, `BPF_X` or `k` if `BPF_K`. While format allows full 32 bits for counter, implementations will likely want to restrict maximum number of loop iterations to much lower values, e.g. 16 bits or even MTU of the link (typically 1500). Implementations MAY also choose a global limit for loop iterations, if malicious code tries e.g. to circumvent "10 iterations per frame" limit by creating nested loops.

TBD doWhile in Flags? or make `jt` signed so first body before loop is always executed?
- 19.09.24 coroutine-like for-init with `jf`

TBD 13.10.24 in contrast to eBPF's `bpf_for_each_map_elem()` , `foreach` probably should be made here, in additional `BPF_LOOP` mode for iterators, instead of custom C functions which call BPF callback? so `k` here will be as in `BPF_CALL` and loop count limiting mechanism is common in opcode instead of in each C implementation (however, `BPF_NEXT` etc. is still generic for other types of callbacks); so again need to think on callback addresses, (OOP) state keeping for iterators, and coroutines

While calling each iteration may seem as too much overhead, it is possible to optimize stack manipulation. The following sketch of C code (not a full production code) should give an idea how loop processing should work (see data structures in a later section):

```c
#define RETURN(x) if (caller_arg!=NULL) *caller_arg=retcode; return (x);
#define DIE ... //similar
	while (1) {
		++pc;
		switch (pc->code & 0x00ff) {
		case BPF_RET|BPF_K:
			A = ((u_int)pc->k);
		case BPF_RET|BPF_A:
			retcode = pc->code >> 8;
			if (bsp == 0)
				RETURN ((u_int)A);
			pc = backstack[bsp]->ret;
			bsp--;
			if (pc->code == BPF_LOOP &&
			    backstack[bsp]->flags == BPF_BSFLAG_LOOP_DESC) {
				/*
				 * Optimization for loop body - reuse frame.
				 */
				if (retcode >= BPF_RETURN) {
					/* As if it was on this level */
					pc = backstack[bsp]->ret;
					bsp--;
					/* TODO '-level' and error handling /
				 }
				 else {
					/* Loop continuation. */
					int decr = retcode == BPF_NEXT ? A : 1;
					if (decr == 0 && retcode == BPF_NEXT)
						DIE(INFINITE_LOOP);
					/* Handle both do/while and next too big */
					if (decr >= backstack[bsp]->loop_counter)
						backstack[bsp]->loop_counter = 0;
					else
						backstack[bsp]->loop_counter -= decr;
					if (retcode == BPF_LAST ||
					    backstack[bsp]->loop_counter == 0) {
						backstack[bsp]->flags |= BPF_BSFLAG_LOOP_DONE;
						/* Leave bsp/counter as is */
					} else {
						/* Return to loop body. */
						pc += pc->jt; // XXX signed?
						bsp++;
					}
				 }
			}
			continue;
        ...
		case BPF_JMP|BPF_JA:
			pc += pc->k;
			continue;
		case BPF_JMP|BPF_JGT|BPF_K:
			pc += (A > pc->k) ? pc->jt : pc->jf;
			continue;
	...
		case BPF_RET|BPF_CALL:
			if (bsp >= BPF_MAX_BACKSTACK)
				DIE(BACKSTACK_OVERFLOW);
			int shft = (pc->code >> 12) + backstack[bsp]->reg_shift;
			if (shft > 255)
				DIE(REGSTACK_OVERFLOW);
			bsp++;
			backstack[bsp]->ret = pc;
			backstack[bsp]->ctx = whatever_callee_ctx(pc);
			backstack[bsp]->reg_shift = shft;
			backstack[bsp]->reg_input = 0; /* XXX if no prolog? */
			backstack[bsp]->reg_local = 0;
			backstack[bsp]->flags = 0;
			backstack[bsp]->loop_counter = 0;
			... //adjust & other checks by cmd flags etc.
			pc += (int)pc->k; // actuall get by flags
			continue;
	...
		case BPF_LOOP:
			if (bsp >= BPF_MAX_BACKSTACK)
				DIE(BACKSTACK_OVERFLOW);
			if (backstack[bsp]->flags == BPF_BSFLAG_LOOP_DESC)
				DIE(LOOP_ALREADY_ACTIVE);
			backstack[bsp]->flags = BPF_BSFLAG_LOOP_DONE;
			backstack[bsp]->loop_counter = get_reg_or_k(pc);
			if (backstack[bsp]->loop_counter == 0)
				continue; // XXX do/while flag
			backstack[bsp]->flags = BPF_BSFLAG_LOOP_DESC;
			bsp++;
			backstack[bsp]->ret = pc;
			backstack[bsp]->ctx = backstack[bsp-1]->ctx;
			// TODO prolog
			backstack[bsp]->reg_shift = backstack[bsp-1]->reg_shift;
			backstack[bsp]->reg_input = get_prolog_input(pc);
			backstack[bsp]->reg_local = get_prolog_local(pc);
			backstack[bsp]->flags = BPF_BSFLAG_PROLOGSEEN;
			backstack[bsp]->loop_counter = 0;
			... //adjust & other checks by cmd flags etc.
			pc += (int)pc->jt; // XXX
			continue;
```

TBD ok, it's single instruction now, then why 3 states? they are now impossible?

TBD 07.09 what if we'll have more registers, and even if not, it's better for
JITs to know which registers are local, so need decoupling local+out thus:
1) space for it in backstack frame (at least 5 bits for each possible in 16)
2) in `BPF_LOOP/BPF_RET` optimization above, probably decouple `BPF_PROLOG` from
   `BPF_LOOP` (too little space in upper `code` + `jf`) - e.g. check by seen
   flag in body? or check `jt` points to `BPF_PROLOG` ?

### In BPF_MISC class

Here as it was in classic BPF:

```c
#define	BPF_TAX		0x00
/*			0x08	reserved */
/*			0x10	reserved */
/*			0x18	reserved */
#define	BPF_COP		0x20	/* NetBSD "coprocessor" extensions */
/*			0x28	reserved */
/*			0x30	reserved */
/*			0x38	reserved */
#define	BPF_COPX	0x40/* 	NetBSD "coprocessor" extensions */
/*				also used on BSD/OS */
/*			0x48	reserved */
/*			0x50	reserved */
/*			0x58	reserved */
/*			0x60	reserved */
/*			0x68	reserved */
/*			0x70	reserved */
/*			0x78	reserved */
#define	BPF_TXA		0x80
/*			0x88	reserved */
/*			0x90	reserved */
/*			0x98	reserved */
/*			0xa0	reserved */
/*			0xa8	reserved */
/*			0xb0	reserved */
/*			0xb8	reserved */
/*			0xc0	reserved; used on BSD/OS */
/*			0xc8	reserved */
/*			0xd0	reserved */
/*			0xd8	reserved */
/*			0xe0	reserved */
/*			0xe8	reserved */
/*			0xf0	reserved */
/*			0xf8	reserved */
```

We modify here two classic instructions and add `BPF_LITERAL` occupying several instruction codes.

#### BPF_TAX and BPF_TXA

```
    MSB 15  14  13  12  11  10  9   8   7   6   5   4   3   2   1   0 LSB
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 code | Register number N |X numspace | BPF_TAX / BPF_TXA | BPF_MISC=7|
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |               jt              |               jf              |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                                                               |
k/imm +                                                               +
      |                                                               |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
```

If both general-purpose register and special register are zero, then this a classic BPF opcode - with `X` and `A` registers. Otherwise, it is either non-`A` 32-bit register or non-`X` register. Encoding for X numspace is:

* 0 - X register
* 1 - Y register
* 2 - AS segment selector
* 3 - BS segment selector
* 4 - CS segment selector
* 5 - DS segment selector
* 6 - ES segment selector
* 7 - Reserved fo future use

Segment selectors have no predefined meaning, just whatever abbreviation makes sense then such a letter may be used in functions, e.g. A for "arguments", C for "current", D for "data", etc.

#### BPF_LITERAL data

This is not an instruction but data definition, addressable relative to `pc` instruction pointer, like in RISC processor designs (e.g. ARM). If this opcode encountered by code, it is simply skipped by it's length, as if it was `BPF_JA` unconditional jump. Validators MUST ensure that another jumps are not landing inside of `BPF_LITERAL`.

It has two forms: short and long. Both form count length in `bpf_insn`'s minus one, that is, a value of 1 means there is 1 more `bpf_insn` after this head which have `BPF_MISC` and other code.

Short form is contained entirely in `code` field:

```
    MSB 15  14  13  12  11  10  9   8   7   6   5   4   3   2   1   0 LSB
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 code |          Low 8 bits           | 0   0 |Hi bits| 1 | BPF_MISC  |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                                                               |
      .                                                               .
      .               Literal data, up to 8*N + 6 bytes               .
      .                                                               .
      |                                                               |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
```

That is, `code` for short form always end in 0x0f, and 0x08, 0x18, 0x28 and 0x38 form two higher bits of literl's length, low bits are in higher byte of `code`, giving 10 bits for `bpf_insn`'s total, or 8 Kbyte.

Long form contain 16 more bits, using codes from 0xe0 to 0xf8:

```
    MSB 15  14  13  12  11  10  9   8   7   6   5   4   3   2   1   0 LSB
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 code |          Low 8 bits           | 1   1   1 |Hi bits| BPF_MISC  |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 code |                         Middle 16 bits                        |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                                                               |
      .                                                               .
      .               Literal data, up to 8*N + 4 bytes               .
      .                                                               .
      |                                                               |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
```

This gives 26 bits of `bpf_insn`'s, or 2^29 bytes. This is 512 Mb, such a bitmap can cover entire IPv4 space.

### To Be Determined if needed: BPF_PACKED

This is in spirit of ARM Thumb, MIPS16e/microMIPS or RV16E etc. compressed instruction sets. This section is provided in this spec temporarily - jump literals should be moved in their class, and for IPv6 it is unclear if it provides any benefits. If used, it will use 7 lengths from 0x88 to 0xd8 (not as in copypaste below). In any case, a copy text here as it was in early stages:

```
<<Because (like Thumb-1 and MIPS16) the compressed instructions are simply
alternate encodings (aliases) for a selected subset of larger instructions,
the compression can be implemented in the assembler, and it is not essential
for the compiler to even know about it. >>

* BPF_LD128IMM:

  Opcode reminds BPF_LD (0) and specifies how many to load at once, 1-3:

    MSB 15  14  13  12  11  10  9   8   7   6   5   4   3   2   1   0 LSB
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 code | 0   0   0   0 |Count-1|   Remaining length    |X=1| BPF_MISC=7|
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      /                                                               /
      \         Array of halfwords, describing pieces to load         \
      /                                                               /
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  First there are 1-3 halfwords each describing how to load pieces of
  immediate(s) from halfwords, hereafter in which command called hextets,
  which form final value in register(s). Each description halfword looks like:

    MSB 15  14  13  12  11  10  9   8   7   6   5   4   3   2   1   0 LSB
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 code | Hextets Seq 1 | Hextets Seq 2 | Hextets Seq 3 |PadSkip|Registr|
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
	              '               '
        .___________./                \_______________________,
       /                                                       \
       +-------------+-------------+-------------+-------------+
       |Increment hextet offset in |  Load this number of      |
       |register by this number    |  hextets from stream      |
       +-------------+-------------+-------------+-------------+

  Offset is also incremented after putting hextets from stream, by their number.
  So, in other words, first two bits in each sequence mean "load this number
  of zero hextets".

  Four examples of instructions where only one address is loaded into register 2.

  Example 1. An address with 3 zero hextets is loaded by length 2 instruction
  (16 bytes total).

  Hextet offset       0    4    5    6    7
  IPv6 address 1   fe80::1ff:fe23:4567:890a

    MSB 15  14  13  12  11  10  9   8   7   6   5   4   3   2   1   0 LSB
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 code | 0   0   0   0 | 0   0 | 0   0   0   0   0   1 |X=1| BPF_MISC=7|
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 desc |   0   |   2   |    2  |   3   |   0   |   1   |   0   | 1   0 |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                0xfe80 - hextet to load by seq 1               |
    6 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                0x0000 - hextet to load by seq 1               |
    8 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                0x01ff - hextet to load by seq 2               |
   10 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                0xfe23 - hextet to load by seq 2               |
   12 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                0x4567 - hextet to load by seq 2               |
   14 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                0x890a - hextet to load by seq 3               |
   16 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+

   1) offset is not incremented (0) as there is nothing to skip, then
      two hextets copied (2), and offset incremented by 2
   2) offset is incremented by 2 and now becomes 4, then 3 hextets (3+1)
      are copied, then offset is incremented by their amount
   3) offset is 7, one last hextet is load from stream to least significant
      hextet of register.


  Example 2. An address with 4 zero hextets is loaded by instruction of
  length 2 (16 bytes total).

  Hextet offset     0    1    6       7
  IPv6 address 2   64:ff9b::1.1.255.255

    MSB 15  14  13  12  11  10  9   8   7   6   5   4   3   2   1   0 LSB
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 code | 0   0   0   0 | 0   0 | 0   0   0   0   0   1 |X=1| BPF_MISC=7|
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 desc |   0   |   2   |   3   |   2   |   0   |   0   |   0   | 1   0 |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                0x0064 - hextet to load by seq 1               |
    6 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                0xff9b - hextet to load by seq 1               |
    8 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                0x0000 - hextet to load by seq 2               |
   10 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                0x0101 - hextet to load by seq 2               |
   12 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                0xffff - hextet to load by seq 2               |
   14 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                        0x0000 - padding                       |
   16 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+

   1) offset is not incremented (0) as there is nothing to skip, then
      two hextets copied (2), so then offset incremented by 2
   2) offset was 2 and is incremented by 3, becoming 5, but this is not
      enough to skip entire zero "::" gap, so an 0x0000 hextet is present
      in the stream, and 3 hextets are copied from stream into register,
      after which offset is incremented by 3 (their amount)
   3) as offset is now 8, nothing left to do, hextet sequence 3 is ignored,
      leftover 0x0000 hextet in the stream is padding to instruction boundary
      and also ignored.


  Example 3. An address with all bytes being non-zero hextets is loaded by
  instruction of length 3, padded, 24 bytes total.

  Hextet offset       0   1    2   3    4    5   6    7
  IPv6 address 3   2001:db8:85a3:8d3:1319:8a2e:370:7348

    MSB 15  14  13  12  11  10  9   8   7   6   5   4   3   2   1   0 LSB
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 code | 0   0   0   0 | 0   0 | 0   0   0   0   0   1 |X=1| BPF_MISC=7|
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 desc |   0   |   3   |   0   |   3   |   0   |   2   | 1   0 | 1   0 |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                        0x0000 - padding                       |
    6 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                        0x0000 - padding                       |
    8 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                0x2001 - hextet to load by seq 1               |
   10 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                0x0db8 - hextet to load by seq 1               |
   12 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                0x85a3 - hextet to load by seq 1               |
   14 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                0x08d3 - hextet to load by seq 2               |
   16 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                0x1319 - hextet to load by seq 2               |
   18 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                0x8a2e - hextet to load by seq 2               |
   20 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                0x0370 - hextet to load by seq 3               |
   22 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                0x7348 - hextet to load by seq 3               |
   24 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+

   1) first PadSkip is processed, giving two words of padding to skip in
      stream.
   2) offset is not incremented (0) as there is nothing to skip, then
      three (3) hextets are copied from stream, so then offset is
      incremented by 3, becoming 3
   3) offset was 3 and not incremented (0), 3 hextets are copied from stream
      into register, offset is incremented by 3, becoming 6
   4) finally, two (2) hextets are loaded from stream at offset 6.
 

  Example 4. An IPv4-compatible address (on network with old clients).
 
  Hextet offset    0   6   7
  IPv6 address 2   ::8.8.8.8

    MSB 15  14  13  12  11  10  9   8   7   6   5   4   3   2   1   0 LSB
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 code | 0   0   0   0 | 0   0 | 0   0   0   0   0   1 |X=1| BPF_MISC=7|
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 desc |   3   |   0   |   3   |   0   |   0   |   2   | 1   0 | 1   0 |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                0x0808 - hextet to load by seq 3               |
    6 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                0x0808 - hextet to load by seq 3               |
    8 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+

   1) offset is incremented by 3 but nothing loaded from stream (0)
   2) same, offset is incremented by 3 becoming 6, but nothing is taken
      from stream
   3) last (3rd) sequence add nothing (0) to offset and loads final 2
      hextets from stream.


Extended jumps, with multiple checks at once - opcodes remind BPF_JMP (5).


```

## Possible C structures & infrastructure

### Machine memory

Here is how possible implementation of a BPF64 "process memory" could look like. It is sized to one page, and 

TODO more description

TBD 31.08.24 if verifier is simple, but having killed by timeout is too ugly for solution, may be statistical approach: if program consumed too much time on a first few launches, mark it as bad?

```c
#define BPF_BSFLAG_LOOP_MASK	0x03	/* loop state bits */
#define BPF_BSFLAG_LOOP_NONE	0	/* not started, throw on LC access */
#define BPF_BSFLAG_LOOP_ASC	1	/* counter incrementing \ die on   */
#define BPF_BSFLAG_LOOP_DESC	2	/* counter decrementing / new loop */
#define BPF_BSFLAG_LOOP_DONE	3	/* finished, l.counter accessible */
#define BPF_BSFLAG_PROLOGSEEN	0x04	/* BPF_PROLOG was issued */
#define BPF_BSFLAG_CATCHING	0x08	/* return will be to BPF_CATCH */

struct bpf_backstack_frame {
	struct bpf_insn *ret; // XXX what for C functions?
	bpf_ctx_t	*ctx;		/* where we live in? */
	uint8_t		reg_shift;	/* base for input registers */
	uint8_t		reg_input;	/* locals after reg_shift+this */
	uint8_t		reg_local;	/* local+out: reg_shift+input */
	uint8_t		flags;		/* is loop active & other */
	uint16_t	start_tick;	/* profiling/kill: time entered */
	uint16_t	loop_counter;	/* value for loop counter */
};

#define BPF_MAX_MEMWORDS	128
#define BPF_MAX_BACKSTACK	32
#define BPF_MAX_REGWINDOW	264

/* Entire "process" and "CPU" memory - fit on 4 Kb page */
struct bpf_process_mem {
	STAILQ_ENTRY ...		/* XXX other housekeeping */
	uint64_t	start_tick;	/* do we run too much? base for bsp */
	uint16_t	as, bs, cs, ds, es; /* segment selector registers */
	uint32_t	X, Y;		/* index registers */
	uint8_t		bsp;		/* backstack pointer */
	uint8_t		flags;		/* TBD */
	uint8_t		__align[26];	/* to 64 bytes from beginning */
	uint64_t	g_regs[8];	/* A..H (64 bytes) */
	struct in6_addr V[4];		/* 128-bit registers (64 bytes) */
	struct bpf_backstack_frame backstack[BPF_MAX_BACKSTACK]; /* 768 bytes */
	uint64_t	reg_file[BPF_MAX_REGWINDOW];	/* 2112 bytes */
	uint64_t	mem[BPF_MAX_MEMWORDS];	/* 1024 bytes * */
};
```

TODO `bpf_argv`, `*input_argv`, `scalar_table[]`, space for exception handlers

TODO 18.09.24 save user credentials in ctx/package so that insecure functions (like timer access leading to Spectre vulnerability) can throw trap signal

TBD 19.09.24 some limited form of coroutines? at least split `bpf_filter()` to dispatcher calling bytecode runner or JITted function: both are saving registers, setuping backstack etc. until in same package / need to transfer control between bytecode and compiled or vice versa - to always return to same place in defense against ROP (need to think more about this)
- 20.09 probably limited form is enough - for iterators, e.g. loop body (itself a coro due to no space for prolog in 1 insn) calls an iterator coroutine for next value, thus making `foreach` but additionally subject to usual max loop limit count; in stack frame need flag, 1 byte offset which `yield` to resume and somehow check that child frame is same coro as in call insn
  - or just special call insn to resume child? then still need to keep address of it, where? 8 bytes too much
    - possible if saving `k` of parent's `BPF_CALL`, will require rethinking `BPF_TAILCALL`/EXECVE; and `BPF_LOOP` as it has no such `k` (or move it to parent where looping flag present?)
- 29.09 ~23:30 reading about `ENTER` second (nesting) operand on x86 gave idea of R0..R47 being *remappable* registers also in a sense that:
  1) first part of them being global - so support different numbers of hardware registers is possible, e.g. first 26 to be global on ARM
  2) other part being mapped not only from register file, but allow access to more stack memory than fits in 64 registers number - meaning a new addressing mode for stack and such registers be just convenient part of it

## Loading: binary file header, packages

A BPF64 program is just a BLOB, with length multiple of 8 bytes. So kernel, or network card, or whatever capable of executing, just passes it to validator and then may just execute (if test passed). But it is possible for this BLOB to begin from `BPF_LITERAL` of specified format, and then it will be somewhat like executable file header.

```
    MSB 15  14  13  12  11  10  9   8   7   6   5   4   3   2   1   0 LSB
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 code | 0   0 | 0..3  | 1   1   1   1 | 1   1 | 0..3  | 1 | BPF_MISC=7|
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  off |              'B'              |              'P'              |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |              'F'              |              '6'              |
   k  +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |              '4'              | Version/Format/2nd flag byte  |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 code |                  Endianness marker = 0x1234                   |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      /                                                               /
      \   The rest is described by format, e.g. sequence for binary   \
      /                                                               /
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Actually this will be cast to C struct once matched. But before that, as it must be possible to detect wrong endianness on which program is tried to load, first two bytes of header (and `BPF_LITERAL` short form) is done so that it will be read as `BPF_LITERAL` (and file header) on both, and then detected by endianness marker.

As `BPF_LITERAL` short version has 0x08 bit set in `BPF_MISC` class allows 2 bits,
requirement for file header to be read as literal on BOTH endianness, this
essentially means `code & 0xcfcf == 0x0f0f` test for first two bytes of the
file - giving a few instructions, so wrong endainnes will be found by reading
(always available) second `bpf_insn` after first which matched magic number.
This - after masking out `BPF_MISC|0x08` (0x0f) - gives the following
possibilities for file header sizes:

```
0xf     128	code == 0x0f0f
0x1f    256	code == 0x1f0f
0x2f    384	code == 0x2f0f
0x3f    512	code == 0x3f0f
0x10f   2176	code == 0x0f1f
0x11f   2304	code == 0x1f1f
0x12f   2432	code == 0x2f1f
0x13f   2560	code == 0x3f1f
0x20f   4224	and so on
0x21f   4352
0x22f   4480
0x23f   4608
0x30f   6272
0x31f   6400
0x32f   6528
0x33f   6656	code == 03f3f
```

This file header is always present in all BPF64 files - whether they contain
code, or debug info, or both. It contains UUID which allows to link files
together if they are split, and describes all sections which would be present
in file if contained everything from the program - however, not every section
may be present in particular file. Sections themselves are just BPF_LITERAL
which contains CRC32 of entire literal in it's `k` field (with first 4 bytes
of section header substituted to `k` while calculating - this allows producer,
in case of collision, to change section name offset to get CRC32 value which
remains unique), so section contents always starts at offset 8 from literal
start, and have no additional description (it is in the file header, which
must always present).

```
struct bpf_file_header_v0 {	/* header is multiple of 128 bytes (16 insns) */
    uint16_t	len_insn_code;	/* & 0xcfcf == 0x0f0f */
    char	magic[5];	/* "BPF64" */
    uint8_t	verformat;	/* e.g. 0, low bit  */
    uint16_t	endianness;	/* 0x4321 */
    uint8_t	numsections;	/* how many sections are in secthdr[] */
    uint8_t	flags;
    uint32_t	platformver;	/* min ver req, depends on platform */
    char	platform[8];	/* e.g. "portable" or "NetBSD\0\0" */
    uint32_t	sections_size;	/* sum of all present, so = offset to code */
    uint32_t	entrypoint;	/* counted from code offset */
    uint8_t	uuid[16];	/* same in all files, like BuildID */
    uint64_t	__reserved[2];	/* to 64 bytes */
    bpf_insn	secthdr[0];	/* 7 max in tinyest header size */
    /* char strings[0]; after */
};
```

TBD 29.09.24 add platform flavor, char[] name "x86-64" or just global registers number in it's JIT? (see other notes this day) and/or take them from end of register file everywhere?

Space in header after `numsections` section headers array is formatted just
like any other strings section contents (starts and ends with NUL byte), but
it is used only inside file header - it contains section names.

Section headers do not spawn another `struct` type and use `bpf_insn`'s which
are interpreted as follows:

* `code` - upper 3 bits padding, lower 13 bits - offset to section name
* `jt` - section type
* `jf` - section flags
* `k` - ident (CRC32) of section

```
#define BPF64_SHFLAG_ZIP	0x01	/* Section contents is compressed */
#define BPF64_SHFLAG_NEEDC	0x80	/* Section needed by code / loading */
#define BPF64_SHFLAG_NEEDD1	0x40	/* Section needed by D1 */
#define BPF64_SHFLAG_NEEDD2	0x20	/* Section needed by D2 */
```

Immediately after header follow `BPF_LITERAL`'s with those sections which are
present in this file, always in order of `secthdr[]` - so missing section can be
detected by CRC32 of some later section in real literal.

TODO

### The String Section(s)

Other sections may refer to strings by offset, which are here. This section(s)
encodes all of the strings that appear throughout the other sections.  It
is laid out as a series of characters followed by a null terminator.
Generally, all names are written out in ASCII, as most C compilers do not
allow any characters to appear in identifiers outside of a subset of
ASCII.  However, any extended characters sets should be written out as a
series of UTF-8 bytes.

The first entry in the section, at offset zero, is a single null
terminator to reference the empty string.  Following that, each C string
should be written out, including the null terminator.  Offsets that refer
to something in this section should refer to the first byte which begins
a string.  Beyond the first byte in the section being the null
terminator, the order of strings is unimportant (however size requirement in
offsets may require specific sorting). In other words, section MUST start and end with ASCII NULL byte.

### The "impex" Section

Imports and exports. This is just array of `uint64_t` with "instructions" for a simple `switch/case` - what to do and with what. Command `{` is like `cd namespace` and `}` is like `cd ..` which achieves cheap compression of repeated (in "Foo::Bar...", "Foo::Baz...") substrings (and more performance-friendly for implementations like `sysctl`).

First there is export section. Starts with empty namespace, so on corresponding `}` it is known that exports are ended and now imports start. The order is such because import may refer to something we just exported - e.g. absolute `k` function number instead of relative-to-`pc`.

    MSB                                                               LSB
       63   56 55                      29 28                         0
      +-------+-------+-------+-------+-------+-------+-------+-------+
      |  '{'  |                          |       Namespace name       |
      +-------+-------+-------+-------+-------+-------+-------+-------+

    MSB                                                               LSB
       63   56 55                   32 31                            0
      +-------+-------+-------+-------+-------+-------+-------+-------+
      |  '&'  |    Function name      |        Entry point / k        |
      +-------+-------+-------+-------+-------+-------+-------+-------+

    MSB                                                               LSB
       63   56 55                   32 31                    8 7     0
      +-------+-------+-------+-------+-------+-------+-------+-------+
      |  '$'  |   Segment (SV) name   |    Type (fmt) name    |N/Ctltp|
      +-------+-------+-------+-------+-------+-------+-------+-------+

    MSB                                                               LSB
       63   56 55                      29 28                         0
      +-------+-------+-------+-------+-------+-------+-------+-------+
      |  'd'  |Platform: label / API ver |       Description          |
      +-------+-------+-------+-------+-------+-------+-------+-------+

    MSB                                                               LSB
       63   56 55                                                    0
      +-------+-------+-------+-------+-------+-------+-------+-------+
      |  'v'  |                    Version                            |
      +-------+-------+-------+-------+-------+-------+-------+-------+
    MSB                                                               LSB

       63   56 55 53 52                29 28                         0
      +-------+-------+-------+-------+-------+-------+-------+-------+
      |  'a'  |4Type|   Attribute name   |     Attribute value        |
      +-------+-------+-------+-------+-------+-------+-------+-------+
- TBD 03.09 no, not "for type", but just first symbol in name? e.g. "$name" for
  attribute on scalar and "&name" for attribute on code? 28-29 bits to 32 by string section number?

TODO Version Strings

TODO copy needed more from .txt

TBD this format for exported scalars, but for imported SVs we also need their `k`, just as number for a function - even if it will not fit in 1 byte of `jf`, program still may want to know what to put into segment selector for them
- 24.09.24 problem is that `k` is static per each compiled code package, but segment selectors are runtime thing - and we are against relocations, but they are not the answer as dynamic assigning must be also possible, the `open("/path/to/file")` is more appropriate metaphor here... look at capability systems which constrain allowed files, e.g. Capsicum?..

### The "on_fatal" Section

Contents of this section is a bunch of `bpf_insn`'s in classic BPF called when the main program receives untrappable exception, like stack overflow. These classic BPF instructions are extended in the `BPF_EXIT` instruction to give ability to return additional code with flags, for example, to record a stack backtrace, but otherwise are more restricted than even classic BPF - every instruction which potentially can cause exception is disallowed, e.g. load from packet or arithmetic division.

The purpose of this "signal handler" is to provide meaningful return value to caller in case of exception. By default, if this section is not present, trap handling is as in classic BPF - every such error causes 0 to be returned.

This classic BPF program receives error number in `X` register and possible argument to error in `A` register (e.g. number of stack frames) and allowed to access only 16 words of `M[]` (it's size in classic), so main program before probably fatal actions can setup some defaults in these low addresses.

TBD do we need access to `P[]` as packet or main program's memory? probably not, that's duplication of main packet parsing and potential double faults (or allow latter to reuse classic filter function as is?)

TODO signal/trap error numbers, in somewhat systematic manner

### The Debug Section(s)

TODO

### The Plain Old Documentation Section

## The BPF64 Assembler Wrapper language

TBD be it here or separate document?
