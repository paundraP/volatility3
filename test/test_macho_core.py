# Copyright 2026 paundraP. Licensed under the Volatility Software License 1.0.

import struct

from volatility3.framework import contexts
from volatility3.framework.layers import macho, physical


def test_macho_core_layer_maps_arm64_segments():
    thread_state = struct.pack("<29Q4QII", *([0] * 29), 0x11, 0x12, 0x13, 0x14, 0x15, 0)
    thread = struct.pack("<IIII", 0x4, 288, 6, 68) + thread_state
    note = struct.pack("<II16sQQ", 0x31, 40, b"test metadata", 0x208, 4)
    commands = b"".join(
        [
            struct.pack(
                "<II16sQQQQiiII",
                0x19,
                72,
                b"__DATA",
                0x100000,
                0x1000,
                0x200,
                14,
                3,
                3,
                0,
                0,
            ),
            note,
            thread,
        ]
    )
    header = struct.pack(
        "<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 4, 3, len(commands), 0, 0
    )
    image = (
        header
        + commands
        + bytes(0x200 - len(header) - len(commands))
        + b"CORETESTMETA"
        + bytes(2)
    )
    ctx = contexts.Context()
    ctx.config["base.location"] = image
    base = physical.BufferDataLayer(ctx, "base", "base", image)
    ctx.add_layer(base)
    ctx.config["core.base_layer"] = "base"
    layer = macho.MachOCoreLayer(ctx, "core", "core")
    ctx.add_layer(layer)
    assert layer.metadata["architecture"] == "AArch64"
    assert layer.read(0x100000, 8) == b"CORETEST"
    assert layer.segments_info[0]["name"] == "__DATA"
    assert layer.notes[0]["owner"] == "test metadata"
    assert layer.threads[0]["sp"] == 0x13
    assert layer.threads[0]["pc"] == 0x14
