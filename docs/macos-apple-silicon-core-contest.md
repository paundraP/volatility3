# Apple Silicon Mach-O core analysis

This entry adds first-class Volatility 3 support for the native `MH_CORE`
Mach-O files produced by LLDB on modern macOS.  It targets the gap in the
existing macOS support: the shipped kernel stacker is Intel-only, while Apple
Silicon is now the common Mac architecture.

## Capture a demonstration sample

Developer Mode is required by LLDB.  Enable it once, then allow the terminal
application in **System Settings → Privacy & Security → Developer Tools**.

```sh
sudo DevToolsSecurity -enable
spctl developer-mode enable-terminal
lldb --batch \
  -o 'target create /path/to/a-test-program' \
  -o 'process launch --stop-at-entry --' \
  -o 'process save-core -s full macos-arm64.core' \
  -o 'process kill'
```

Use a disposable test program or a program whose owner has consented to the
capture.  A core contains process memory and may contain credentials, tokens,
or private documents; treat it as sensitive evidence and do not commit it to a
public repository.

The repository includes a small demonstration process containing two known,
non-secret markers.  Build and ad-hoc sign it before capture:

```sh
cc -g -O0 tools/macos_core_demo.c -o artifacts/macos_core_demo
codesign --force --sign - --entitlements tools/debug-entitlements.plist \
  artifacts/macos_core_demo
./tools/capture_macos_core.sh artifacts/macos-arm64.core \
  artifacts/macos_core_demo
```

## Analyze it

From the repository root:

```sh
python vol.py -f macos-arm64.core mac.core.CoreInfo
python vol.py -f macos-arm64.core mac.core.CoreMaps
python vol.py -f macos-arm64.core mac.core.CoreNotes
python vol.py -f macos-arm64.core mac.core.CoreThreads
python vol.py -f macos-arm64.core mac.core.MachOImages
python vol.py -f macos-arm64.core regexscan.RegExScan --pattern 'SECRET|TOKEN'
```

Select an address reported by `MachOImages` and reconstruct that executable or
library into an output directory:

```sh
mkdir -p extracted
python vol.py -o extracted -f macos-arm64.core mac.core.MachODump \
  --address 0x100000000
```

Extraction is deliberately address-based so a large core containing thousands
of shared-cache images cannot accidentally fill the output disk.  Reconstructed
files preserve the original Mach-O file layout where all file-backed segments
remain captured; runtime modifications may invalidate their code signatures.

`MachOCoreStacker` validates the 64-bit Mach-O header and every load-command
boundary before constructing a sparse virtual address layer.  The layer keeps
VM holes unmapped, records protections and notes, and supports normal
Volatility scanners.  `mac.machoimages` then identifies arm64 images embedded
in the captured mappings and reports UUIDs, which is useful for matching an
image to a symbol or a known-good binary.

## Contest submission checklist

The 2026 contest rules require source code, a memory sample demonstrating the
capability, usage instructions, a motivation/write-up, and a signed Individual
Contributor License Agreement.  The deadline shown by the Foundation is
December 31, 2026.  Request the ICLA from `contest@volatilityfoundation.org`
before submitting.  This project does not include a live memory sample because
the sample can contain the user's private data; capture one locally with the
commands above and include its SHA-256 in the submission package.
