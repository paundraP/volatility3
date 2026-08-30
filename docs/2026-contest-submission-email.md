# Draft submission email

To: `contest@volatilityfoundation.org`

Subject: 2026 Volatility Plugin Contest — Mach-O Core Triage for Apple Silicon

Hello Volatility Foundation team,

Please accept my entry, **Mach-O Core Triage for Volatility 3**, for the 2026
Volatility Plugin Contest.

The entry adds automatic and symbol-free analysis of native macOS `MH_CORE`
process-memory files, including Apple Silicon.  It includes a sparse virtual
memory layer and stacker, plugins for core metadata, maps, LLDB notes, AArch64
thread registers and embedded Mach-O images, plus AArch64 support for generic
regex/YARA scanning.  It was tested against a real core captured on an M1 Mac
running macOS 26.6.2 and Volatility 3 Framework 2.28.2.

Attached are:

- `mach-o-core-triage-source.zip` — source, tests, capture helper and write-up
- `macos-arm64-submission.core` — demonstration memory sample
- `macos-arm64-submission.core.sha256` — sample integrity hash
- the signed Individual Contributor License Agreement

The sample contains only a purpose-built test process and two explicitly fake
markers.  Its expected SHA-256 is
`a0392f464731d8d5248b9c31887b9646fa341a179cbdd2e8915bf13cac446e1e`.

Source branch:
`https://github.com/paundraP/volatility3/tree/feature/macos-core-analysis`

Thank you for reviewing the entry.  Please let me know if you need another
sample format or any additional documentation.

Best regards,

`<YOUR NAME OR ALIAS>`
