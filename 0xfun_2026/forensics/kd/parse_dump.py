#!/usr/bin/env python3
"""
parse_dump.py — Full analysis of the crypter.dmp minidump
Challenge: kd (Forensics) — Pragyan CTF 2026

Parses the minidump and extracts:
  1. Threads and their contexts (registers)
  2. Loaded modules
  3. Memory regions
  4. Exception(s)
  5. Search for interesting strings in memory
  6. Search for the first 16 bytes of config.dat
  7. Search for possible AES-256 keys (32 bytes with high entropy)
"""

import struct
import math
import sys
from minidump.minidumpfile import MinidumpFile

DUMP_PATH = "/home/ubuntu/0xfun/ctf/challenges/forensics/kd/kd/crypter.dmp"

# First 16 bytes of config.dat in bytes format
CONFIG_DAT_HEADER = bytes.fromhex("8ab3d76759b0d72538decb3ee4226431")

# Strings to search for in the dump memory
SEARCH_STRINGS = [
    b"SHARD", b"shard", b"Shard",
    b"SALT", b"salt", b"Salt",
    b"AES", b"aes",
    b"IV", b"iv",
    b"key", b"KEY", b"Key",
    b"config", b"CONFIG", b"Config",
    b"encrypt", b"decrypt",
    b"password", b"PASSWORD",
    b"secret", b"SECRET",
    b"flag", b"FLAG", b"pragyan",
    b"shard_", b"SHARD_",
]


def banner(title):
    line = "=" * 80
    print(f"\n{line}")
    print(f"  {title}")
    print(f"{line}\n")


def entropy(data):
    """Calculate the Shannon entropy for a block of bytes."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    ent = 0.0
    for f in freq:
        if f > 0:
            p = f / length
            ent -= p * math.log2(p)
    return ent


def parse_threads(mdmp):
    banner("THREADS AND CONTEXTS (REGISTERS)")

    if mdmp.threads is None or not mdmp.threads.threads:
        print("  [!] No threads found.")
        return

    regs_64 = [
        "Rax", "Rbx", "Rcx", "Rdx", "Rsi", "Rdi", "Rbp", "Rsp", "Rip",
        "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
        "EFlags", "SegCs", "SegDs", "SegEs", "SegFs", "SegGs", "SegSs",
    ]

    for i, thread in enumerate(mdmp.threads.threads):
        print(f"  --- Thread #{i} ---")
        print(f"    ThreadId       : {thread.ThreadId} (0x{thread.ThreadId:x})")
        print(f"    SuspendCount   : {thread.SuspendCount}")
        print(f"    Priority       : {thread.Priority}")
        print(f"    PriorityClass  : {thread.PriorityClass}")
        print(f"    Teb            : 0x{thread.Teb:016x}")

        ctx = thread.ContextObject
        if ctx is None:
            print("    [!] No context available.")
            print()
            continue

        print(f"    ContextFlags   : 0x{ctx.ContextFlags:08x}")
        for reg in regs_64:
            if hasattr(ctx, reg):
                val = getattr(ctx, reg)
                print(f"    {reg:15s}: 0x{val:016x}")
        print()


def parse_modules(mdmp):
    banner("LOADED MODULES")

    if mdmp.modules is None or not mdmp.modules.modules:
        print("  [!] No modules found.")
        return

    print(f"  {'#':>3s}  {'Base Address':>18s}  {'End Address':>18s}  {'Size':>12s}  {'Name'}")
    print(f"  {'---':>3s}  {'------------------':>18s}  {'------------------':>18s}  {'------------':>12s}  {'----'}")

    for i, mod in enumerate(mdmp.modules.modules):
        base = mod.baseaddress
        size = mod.size
        end = mod.endaddress
        name = mod.name if mod.name else "<unknown>"
        print(f"  {i:3d}  0x{base:016x}  0x{end:016x}  {size:12,d}  {name}")

    print(f"\n  Total: {len(mdmp.modules.modules)} modules")


def parse_memory_regions(mdmp):
    banner("MEMORY REGIONS")

    segments = []

    if mdmp.memory_segments_64 is not None:
        segments = mdmp.memory_segments_64.memory_segments
        source = "Memory64ListStream"
    elif mdmp.memory_segments is not None:
        segments = mdmp.memory_segments.memory_segments
        source = "MemoryListStream"
    else:
        print("  [!] No memory regions found.")
        return []

    print(f"  Source: {source}")
    print(f"  Total regions: {len(segments)}")
    print()

    total_size = 0
    print(f"  {'#':>4s}  {'Virtual Address':>18s}  {'Size':>14s}  {'Size (hex)':>14s}")
    print(f"  {'----':>4s}  {'------------------':>18s}  {'--------------':>14s}  {'--------------':>14s}")

    for i, seg in enumerate(segments):
        va = seg.start_virtual_address
        sz = seg.size
        total_size += sz
        if len(segments) > 100:
            if i < 50 or i >= len(segments) - 10:
                print(f"  {i:4d}  0x{va:016x}  {sz:14,d}  0x{sz:012x}")
            elif i == 50:
                print(f"  {'...':>4s}  {'... (' + str(len(segments) - 60) + ' regions omitted) ...':>18s}")
        else:
            print(f"  {i:4d}  0x{va:016x}  {sz:14,d}  0x{sz:012x}")

    print(f"\n  Total memory size: {total_size:,d} bytes ({total_size / (1024*1024):.2f} MB)")

    return segments


def parse_exception(mdmp):
    banner("EXCEPTIONS")

    if mdmp.exception is None or not mdmp.exception.exception_records:
        print("  [!] No exceptions found.")
        return

    EXCEPTION_CODES = {
        0x80000003: "EXCEPTION_BREAKPOINT",
        0x80000004: "EXCEPTION_SINGLE_STEP",
        0xC0000005: "EXCEPTION_ACCESS_VIOLATION",
        0xC0000017: "STATUS_NO_MEMORY",
        0xC000001D: "EXCEPTION_ILLEGAL_INSTRUCTION",
        0xC0000094: "EXCEPTION_INT_DIVIDE_BY_ZERO",
        0xC0000096: "EXCEPTION_PRIVILEGED_INSTRUCTION",
        0xC00000FD: "EXCEPTION_STACK_OVERFLOW",
        0x40010006: "DBG_PRINTEXCEPTION_C",
        0x406D1388: "MS_VC_EXCEPTION (SetThreadName)",
        0xE06D7363: "C++ Exception (Microsoft)",
    }

    for i, exc in enumerate(mdmp.exception.exception_records):
        print(f"  --- Exception #{i} ---")
        print(f"    ThreadId         : {exc.ThreadId} (0x{exc.ThreadId:x})")

        rec = exc.ExceptionRecord
        code_raw = rec.ExceptionCode_raw if hasattr(rec, 'ExceptionCode_raw') else 0
        code_name = EXCEPTION_CODES.get(code_raw & 0xFFFFFFFF, str(rec.ExceptionCode) if hasattr(rec, 'ExceptionCode') else "UNKNOWN")
        print(f"    ExceptionCode    : 0x{code_raw:08x} ({code_name})")
        print(f"    ExceptionFlags   : 0x{rec.ExceptionFlags:08x}")
        print(f"    ExceptionAddress : 0x{rec.ExceptionAddress:016x}")
        print(f"    NumberParameters : {rec.NumberParameters}")

        if rec.NumberParameters > 0 and rec.ExceptionInformation:
            for j, info in enumerate(rec.ExceptionInformation[:rec.NumberParameters]):
                print(f"    ExceptionInfo[{j}] : 0x{info:016x}")

        # Context of the thread that caused the exception
        if mdmp.threads:
            for t in mdmp.threads.threads:
                if t.ThreadId == exc.ThreadId:
                    c = t.ContextObject
                    if c:
                        print(f"    --- Exception thread context ---")
                        print(f"    Rip = 0x{c.Rip:016x}")
                        print(f"    Rsp = 0x{c.Rsp:016x}")
                        print(f"    Rbp = 0x{c.Rbp:016x}")
                        print(f"    Rax = 0x{c.Rax:016x}")
                        print(f"    Rcx = 0x{c.Rcx:016x}")
                        print(f"    Rdx = 0x{c.Rdx:016x}")
                    break
        print()


def read_segment_data(mdmp, seg):
    """Read the data of a memory segment from the file."""
    fh = mdmp.file_handle
    fh.seek(seg.start_file_address)
    return fh.read(seg.size)


def search_strings_in_memory(mdmp, segments):
    banner("STRING SEARCH IN MEMORY")

    results = {s: [] for s in SEARCH_STRINGS}

    for idx, seg in enumerate(segments):
        if seg.size == 0:
            continue

        try:
            data = read_segment_data(mdmp, seg)
        except Exception as e:
            continue

        va_base = seg.start_virtual_address

        for search_str in SEARCH_STRINGS:
            offset = 0
            while True:
                pos = data.find(search_str, offset)
                if pos == -1:
                    break

                ctx_start = max(0, pos - 16)
                ctx_end = min(len(data), pos + len(search_str) + 64)
                context_bytes = data[ctx_start:ctx_end]

                va = va_base + pos
                results[search_str].append({
                    "va": va,
                    "seg_idx": idx,
                    "context": context_bytes,
                    "offset_in_context": pos - ctx_start,
                })

                offset = pos + 1
                if len(results[search_str]) > 50:
                    break

        if (idx + 1) % 100 == 0:
            print(f"  [*] Processed {idx + 1}/{len(segments)} segments...", file=sys.stderr)

    print(f"  Search results:")
    print()
    for search_str, hits in results.items():
        if hits:
            print(f"  String: {search_str!r} — {len(hits)} match(es)")
            for h in hits[:20]:
                try:
                    ctx_text = ""
                    for b in h["context"]:
                        if 32 <= b < 127:
                            ctx_text += chr(b)
                        else:
                            ctx_text += "."
                except:
                    ctx_text = h["context"].hex()

                print(f"    VA: 0x{h['va']:016x}  Context: {ctx_text}")
            if len(hits) > 20:
                print(f"    ... and {len(hits) - 20} more")
            print()


def search_config_dat_header(mdmp, segments):
    banner("SEARCH FOR config.dat HEADER IN MEMORY")

    print(f"  Searching for bytes: {CONFIG_DAT_HEADER.hex()}")
    print()

    found = False
    for idx, seg in enumerate(segments):
        if seg.size == 0:
            continue

        try:
            data = read_segment_data(mdmp, seg)
        except Exception:
            continue

        va_base = seg.start_virtual_address
        offset = 0
        while True:
            pos = data.find(CONFIG_DAT_HEADER, offset)
            if pos == -1:
                break
            found = True

            va = va_base + pos
            ctx_end = min(len(data), pos + 256)
            context_bytes = data[pos:ctx_end]

            print(f"  [+] FOUND at VA: 0x{va:016x} (segment #{idx})")
            print(f"      Hex dump (up to 256 bytes):")
            for line_off in range(0, len(context_bytes), 16):
                hex_part = " ".join(f"{b:02x}" for b in context_bytes[line_off:line_off+16])
                ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in context_bytes[line_off:line_off+16])
                print(f"        0x{va + line_off:016x}: {hex_part:<48s}  {ascii_part}")
            print()

            offset = pos + 1

    if not found:
        print("  [!] config.dat header bytes were NOT found in memory.")


def search_aes_keys(mdmp, segments):
    banner("SEARCH FOR POSSIBLE AES-256 KEYS (HIGH ENTROPY)")

    print("  Searching for 32-byte blocks with entropy >= 4.5 and interesting patterns...")
    print("  (This may take a while with a 400 MB dump)")
    print()

    candidates = []
    KEY_LEN = 32
    MIN_ENTROPY = 4.5

    for idx, seg in enumerate(segments):
        if seg.size < KEY_LEN:
            continue

        try:
            data = read_segment_data(mdmp, seg)
        except Exception:
            continue

        va_base = seg.start_virtual_address

        step = 16
        for off in range(0, len(data) - KEY_LEN, step):
            block = data[off:off + KEY_LEN]

            unique_bytes = len(set(block))
            if unique_bytes < 16:
                continue

            printable_count = sum(1 for b in block if 32 <= b < 127)
            if printable_count == KEY_LEN:
                continue

            ent = entropy(block)
            if ent >= MIN_ENTROPY:
                candidates.append({
                    "va": va_base + off,
                    "entropy": ent,
                    "data": block,
                    "seg_idx": idx,
                    "unique_bytes": unique_bytes,
                })

        if (idx + 1) % 100 == 0:
            print(f"  [*] Processed {idx + 1}/{len(segments)} segments, {len(candidates)} candidates so far...",
                  file=sys.stderr)

    candidates.sort(key=lambda c: c["entropy"], reverse=True)

    print(f"\n  Total candidates found: {len(candidates)}")
    print()

    shown = min(50, len(candidates))
    print(f"  Showing top {shown} by entropy:")
    print()
    for i, c in enumerate(candidates[:shown]):
        hex_str = c["data"].hex()
        print(f"  [{i:3d}] VA: 0x{c['va']:016x}  Entropy: {c['entropy']:.3f}  Unique: {c['unique_bytes']:3d}")
        print(f"        Hex: {hex_str}")
        print()


def main():
    print(f"[*] Parsing minidump: {DUMP_PATH}")
    mdmp = MinidumpFile.parse(DUMP_PATH)
    print(f"[+] Minidump parsed successfully.")

    # System information
    if mdmp.sysinfo:
        si = mdmp.sysinfo
        banner("SYSTEM INFORMATION")
        for attr in ['ProcessorArchitecture', 'ProcessorLevel', 'ProcessorRevision',
                      'NumberOfProcessors', 'MajorVersion', 'MinorVersion',
                      'BuildNumber', 'PlatformId', 'OperatingSystem']:
            if hasattr(si, attr):
                print(f"  {attr}: {getattr(si, attr)}")

    # 1. Threads and contexts
    parse_threads(mdmp)

    # 2. Loaded modules
    parse_modules(mdmp)

    # 3. Memory regions
    segments = parse_memory_regions(mdmp)

    # 4. Exception
    parse_exception(mdmp)

    # 5. String search
    search_strings_in_memory(mdmp, segments)

    # 6. Search for config.dat header
    search_config_dat_header(mdmp, segments)

    # 7. Search for possible AES-256 keys
    search_aes_keys(mdmp, segments)

    print("\n" + "=" * 80)
    print("  ANALYSIS COMPLETED")
    print("=" * 80)


if __name__ == "__main__":
    main()
