# Copyright 2026 paundraP. Licensed under the Volatility Software License 1.0.

import struct

from volatility3.framework import contexts
from volatility3.framework.layers import macho, physical
from volatility3.plugins.mac.core import MachOImages


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


def test_parse_embedded_arm64_macho_image():
    image_uuid = bytes.fromhex("00112233445566778899aabbccddeeff")
    image_commands = b"".join(
        [
            struct.pack(
                "<II16sQQQQiiII",
                0x19,
                72,
                b"__TEXT",
                0x100000,
                0x1000,
                0,
                0x100,
                5,
                5,
                0,
                0,
            ),
            struct.pack("<II16s", 0x1B, 24, image_uuid),
        ]
    )
    embedded = (
        struct.pack(
            "<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 2, len(image_commands), 0, 0
        )
        + image_commands
    )
    embedded += bytes(0x100 - len(embedded))
    core_segment = struct.pack(
        "<II16sQQQQiiII",
        0x19,
        72,
        b"__DATA",
        0x100000,
        0x1000,
        0x200,
        len(embedded),
        5,
        5,
        0,
        0,
    )
    core_header = struct.pack(
        "<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 4, 1, len(core_segment), 0, 0
    )
    core = core_header + core_segment
    core += bytes(0x200 - len(core)) + embedded
    ctx = contexts.Context()
    ctx.config["base.location"] = core
    ctx.add_layer(physical.BufferDataLayer(ctx, "base", "base", core))
    ctx.config["core.base_layer"] = "base"
    layer = macho.MachOCoreLayer(ctx, "core", "core")
    ctx.add_layer(layer)
    image = MachOImages.parse_image(layer, 0x100000)
    assert image["type"] == "EXECUTE"
    assert image["uuid"] == image_uuid.hex()
    assert image["segments"][0]["name"] == "__TEXT"
