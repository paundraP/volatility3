# Mach-O Core Triage for Volatility 3

## Submission summary

Mach-O Core Triage adds native analysis of modern macOS process-memory core
files to Volatility 3, including Apple Silicon (`arm64`/`AArch64`).  It provides
a validated sparse virtual-memory layer, automatic format detection, process
metadata and thread-register extraction, memory-map enumeration, embedded
Mach-O discovery, and AArch64 support in Volatility's generic regex and YARA
scanners.

The entry was developed and demonstrated on an Apple M1 MacBook Air running
macOS 26.6.2 (Darwin 25.6.0) with Volatility 3 Framework 2.28.2.

## Motivation

Volatility 3 currently labels macOS analysis as unmaintained, and its existing
macOS kernel stacker is specifically implemented for Intel page tables.  That
leaves investigators with few practical Volatility workflows for present-day
Apple Silicon systems.  Full physical-memory acquisition is also constrained
by Apple's platform security and requires kernel-level acquisition software.

LLDB, however, can produce a native `MH_CORE` Mach-O snapshot of an authorized
process on current macOS.  These files preserve sparse virtual mappings,
protections, thread state, dyld image information, and actual captured bytes.
They are useful for incident response, malware detonation, application-secret
exposure investigations, crash triage, and analyzing suspicious injected code.
Before this entry, Volatility treated such a file only as flat bytes and could
not address its captured virtual memory correctly.

## Contribution

The entry adds:

1. `MachOCoreLayer`, which validates the 64-bit Mach-O header, load-command
   bounds, segment file bounds, and virtual overlap before mapping each
   `LC_SEGMENT_64` region at its original virtual address.
2. `MachOCoreStacker`, which automatically detects `MH_CORE` files supplied
   with `-f` and constructs the new layer without symbols or manual offsets.
3. `mac.core.CoreInfo`, reporting architecture and core-level counts.
4. `mac.core.CoreMaps`, reporting virtual ranges, file offsets, sizes, and
   current/maximum memory protections.
5. `mac.core.CoreNotes`, decoding LLDB process metadata and exposing other
   `LC_NOTE` records for further research.
6. `mac.core.CoreThreads`, extracting AArch64 PC, SP, FP, LR, CPSR, and state
   flavors from `LC_THREAD` records.
7. `mac.core.MachOImages`, finding captured arm64 executables, dylibs, bundles,
   filesets, and dyld images and reporting their UUIDs.
8. AArch64 compatibility for the generic `regexscan.RegExScan` and
   `yarascan.YaraScan` plugins.
9. A consent-safe capture helper and a deterministic demonstration program
   containing two known, explicitly fake forensic markers.

## Security and correctness properties

Untrusted memory images are parsed defensively.  Command counts and command
sizes are bounded; segment data must remain inside the underlying file;
`filesize` may not exceed `vmsize`; overlapping virtual segments are rejected;
and malformed thread records cannot read beyond their command.  Sparse holes
remain unmapped, so scans cannot silently reinterpret unrelated file bytes as
process memory.

The sample program is ad-hoc signed with only the `get-task-allow` entitlement
and is launched as LLDB's own child.  The workflow does not disable System
Integrity Protection, change boot security, install a kernel extension, or
attach to an unrelated process.  Real core files can contain credentials and
must be treated as sensitive evidence.

## Demonstration

Build and capture:

```sh
cc -g -O0 tools/macos_core_demo.c -o /tmp/vol3_macos_core_demo
codesign --force --sign - --entitlements tools/debug-entitlements.plist \
  /tmp/vol3_macos_core_demo
./tools/capture_macos_core.sh macos-arm64-submission.core \
  /tmp/vol3_macos_core_demo
```

Analyze:

```sh
python vol.py -f macos-arm64-submission.core mac.core.CoreInfo
python vol.py -f macos-arm64-submission.core mac.core.CoreMaps
python vol.py -f macos-arm64-submission.core mac.core.CoreNotes
python vol.py -f macos-arm64-submission.core mac.core.CoreThreads
python vol.py -f macos-arm64-submission.core mac.core.MachOImages
python vol.py -f macos-arm64-submission.core regexscan.RegExScan \
  --pattern 'VOL3_MACOS_CONTEST_MARKER_2026|DEMO_TOKEN_7f3b2a18_NOT_A_REAL_CREDENTIAL'
```

The included demonstration core has SHA-256
`a0392f464731d8d5248b9c31887b9646fa341a179cbdd2e8915bf13cac446e1e`.
It is a 64-bit arm64 Mach-O core with seven mapped regions, three notes, one
thread, the test executable, and dyld.  Both known markers are recovered at
their original virtual addresses.

## Testing

The unit test constructs an arm64 Mach-O core in memory and verifies virtual
translation, segment metadata, note parsing, and AArch64 PC/SP extraction.  The
complete repository test suite passes (`7 passed, 24 skipped` where skips are
image-dependent tests).  Ruff passes for every changed Python file.  The five
new plugins plus generic regex scanning were also run successfully against the
real core produced on the M1 host.

## Limitations and future work

This entry analyzes process-memory cores, not full physical RAM.  It does not
claim Apple Silicon kernel-memory or page-table support.  LLDB's `all image
infos` note is retained and surfaced, but a future version could decode every
version of that evolving binary record directly.  Future work also includes
stack unwinding from the extracted registers, richer dyld shared-cache
enumeration, per-region dumping, and acquisition integrations for endpoint
response tools.

## Why this entry should win

The extension opens a practical Volatility workflow on current Apple Silicon
hardware without weakening platform security.  It contributes reusable
framework infrastructure rather than a single artifact signature, composes
with existing scanners, validates hostile input carefully, ships with capture
and demonstration tooling, and is backed by both synthetic tests and a real
macOS 26 arm64 sample.  It directly addresses a visible platform gap while
leaving a clear path for further macOS memory-forensics research.
