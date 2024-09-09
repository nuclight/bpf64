(this is currently a "draft of draft" under construction selecting variants from `fbpf_rus.txt` - see there if something is missing)


    * * * DRAFT * * *

# BPF64: platform-independent hardware-friendly eBPF alternative

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
      |                                                               |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                                                               |
k/imm +                                                               +
      |                                                               |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
```

As C macro names in code are typically ORed together forming too long line (ususal coding convention is 80 chars max per line), they are continued to be called as short as possible, even if it is wrong grammar etc.

## Changes to classic BPF

There are no directly available backward jumps in BPF64 - they are possible only via calling to new stack frames. Thus the `bpf_insn` structure is reused as is, with exception that `k` field may be sometimes be used as signed, in which case it is called `imm`.

Memory addressing extended beyond the `P[]` packet to a number of *segments*, up to 2^32 bytes in size, each having it's type, permissions etc.

## Registers

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

```
				// SRC = BPF_K or BPF_X
#define	BPF_JA		0x00	// pc += k
#define	BPF_JEQ		0x10	// pc += (A == SRC) ? jt : jf
#define	BPF_JGT		0x20	// pc += (A > SRC) ? jt : jf
#define	BPF_JGE		0x30	// pc += (A >= SRC) ? jt : jf
#define	BPF_JSET	0x40	// pc += (A & SRC) ? jt : jf
#define BPF_JTABLE	0x50	/* in literal, like TBB in ARM */
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

```
#define BPF_OK      0
#define BPF_NEXT    1   /* 'continue'*/
#define BPF_LAST    2   /* 'break' */
#define BPF_RETURN  3   /* 'return' */
#define BPF_ERROR   4   /* 'die' */
```

These can be described, for caller, behaviour, as if in caller's code, instead of our procedure call, were written another statement: `continue`, `break`, `return` or exception was thrown. The primary use is for loop and exception handling, but cooperating BPF programs may implement their own control structures with this - which may be useful for higher-level languages (e.g. firewall description rules) which are compiled to BPF64.

See example later in how `BPF_LOOP` can be optimized.

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
 code |RegWindow shift| 0/BPF_L/BPF_S |BPF_CALL=1 | _RVAL | BPF_RET=6 |
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

#### BPF_LOOP (3)






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

