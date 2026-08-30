# Copyright 2026 paundraP. Licensed under the Volatility Software License 1.0.
"""Analysis plugins for modern Apple Silicon Mach-O process cores."""

import json
import struct
from typing import List

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners
from volatility3.framework.layers.macho import MachOCoreLayer
from volatility3.framework.renderers import format_hints


class CoreInfo(interfaces.plugins.PluginInterface):
    """Reports the architecture and loader metadata of an Apple Mach-O core."""

    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name="primary", description="Mach-O core address space"
            )
        ]

    def _generator(self):
        layer = self.context.layers[self.config["primary"]]
        if not isinstance(layer, MachOCoreLayer):
            raise ValueError("mac.coreinfo requires an MH_CORE Mach-O input")
        yield 0, ("architecture", str(layer.metadata.get("architecture", "Unknown")))
        yield 0, ("cpu_type", str(layer.metadata.get("cpu_type", "Unknown")))
        yield 0, ("cpu_subtype", str(layer.metadata.get("cpu_subtype", "Unknown")))
        yield 0, ("load_commands", str(layer.metadata.get("ncmds", "Unknown")))
        yield 0, ("mapped_regions", str(len(layer.segments_info)))
        yield 0, ("notes", str(len(layer.notes)))
        yield 0, ("threads", str(len(layer.threads)))

    def run(self):
        return renderers.TreeGrid(
            [("Property", str), ("Value", str)], self._generator()
        )


class CoreMaps(interfaces.plugins.PluginInterface):
    """Lists every virtual region captured by LLDB's Mach-O core writer."""

    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name="primary", description="Mach-O core address space"
            )
        ]

    def _generator(self):
        layer = self.context.layers[self.config["primary"]]
        if not isinstance(layer, MachOCoreLayer):
            raise ValueError("mac.coremaps requires an MH_CORE Mach-O input")
        for region in layer.segments_info:
            protection = (
                "".join(
                    letter
                    for bit, letter in ((1, "r"), (2, "w"), (4, "x"))
                    if region["initprot"] & bit
                )
                or "-"
            )
            maximum = (
                "".join(
                    letter
                    for bit, letter in ((1, "r"), (2, "w"), (4, "x"))
                    if region["maxprot"] & bit
                )
                or "-"
            )
            yield (
                0,
                (
                    format_hints.Hex(region["vmaddr"]),
                    format_hints.Hex(region["vmaddr"] + region["vmsize"]),
                    format_hints.Hex(region["fileoff"]),
                    region["filesize"],
                    protection,
                    maximum,
                    region["name"],
                ),
            )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Start", format_hints.Hex),
                ("End", format_hints.Hex),
                ("FileOffset", format_hints.Hex),
                ("FileSize", int),
                ("Protection", str),
                ("MaxProtection", str),
                ("Segment", str),
            ],
            self._generator(),
        )


class CoreNotes(interfaces.plugins.PluginInterface):
    """Displays LLDB metadata notes embedded in a Mach-O core."""

    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name="primary", description="Mach-O core address space"
            )
        ]

    def _generator(self):
        layer = self.context.layers[self.config["primary"]]
        if not isinstance(layer, MachOCoreLayer):
            raise ValueError("mac.corenotes requires an MH_CORE Mach-O input")
        base = self.context.layers[layer.dependencies[0]]
        for note in layer.notes:
            data = base.read(note["offset"], note["size"])
            display = data[:64].hex()
            if note["owner"] == "process metadata":
                try:
                    display = json.dumps(json.loads(data.rstrip(b"\0")), sort_keys=True)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass
            yield (
                0,
                (
                    note["owner"],
                    format_hints.Hex(note["offset"]),
                    note["size"],
                    display,
                ),
            )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Owner", str),
                ("FileOffset", format_hints.Hex),
                ("Size", int),
                ("Data", str),
            ],
            self._generator(),
        )


class CoreThreads(interfaces.plugins.PluginInterface):
    """Reports Apple Silicon thread program counters and stack registers."""

    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name="primary", description="Mach-O core address space"
            )
        ]

    def _generator(self):
        layer = self.context.layers[self.config["primary"]]
        if not isinstance(layer, MachOCoreLayer):
            raise ValueError("mac.corethreads requires an MH_CORE Mach-O input")
        for thread in layer.threads:
            yield (
                0,
                (
                    thread["index"],
                    format_hints.Hex(thread.get("pc", 0)),
                    format_hints.Hex(thread.get("sp", 0)),
                    format_hints.Hex(thread.get("fp", 0)),
                    format_hints.Hex(thread.get("lr", 0)),
                    format_hints.Hex(thread.get("cpsr", 0)),
                    ",".join(str(flavor) for flavor in thread["flavors"]),
                ),
            )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Index", int),
                ("PC", format_hints.Hex),
                ("SP", format_hints.Hex),
                ("FP", format_hints.Hex),
                ("LR", format_hints.Hex),
                ("CPSR", format_hints.Hex),
                ("Flavors", str),
            ],
            self._generator(),
        )


class MachOImages(interfaces.plugins.PluginInterface):
    """Finds embedded arm64 Mach-O images and reports their UUIDs.

    This is deliberately independent of kernel symbols: dyld shared-cache images
    and injected libraries remain discoverable in a process core.
    """

    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)
    _HEADER = struct.Struct("<IiiIIIII")
    _LOAD = struct.Struct("<II")
    _UUID = 0x1B
    _ID_DYLIB = 0xD
    _ID_DYLINKER = 0xF
    _TYPES = {2: "EXECUTE", 6: "DYLIB", 7: "DYLINKER", 8: "BUNDLE", 12: "FILESET"}

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name="primary", description="Mach-O core address space"
            ),
            requirements.VersionRequirement(
                name="bytes_scanner",
                component=scanners.BytesScanner,
                version=(1, 0, 0),
            ),
        ]

    def _generator(self):
        layer = self.context.layers[self.config["primary"]]
        if not isinstance(layer, MachOCoreLayer):
            raise ValueError("mac.machoimages requires an MH_CORE Mach-O input")
        for offset in layer.scan(
            context=self.context,
            scanner=scanners.BytesScanner(b"\xcf\xfa\xed\xfe"),
        ):
            try:
                header = layer.read(offset, self._HEADER.size)
                (
                    magic,
                    cputype,
                    subtype,
                    filetype,
                    ncmds,
                    sizeofcmds,
                    flags,
                    reserved,
                ) = self._HEADER.unpack(header)
                if (
                    magic != 0xFEEDFACF
                    or cputype != 0x0100000C
                    or filetype not in self._TYPES
                    or not 0 < ncmds <= 512
                    or sizeofcmds > 0x100000
                ):
                    continue
                commands = layer.read(offset + self._HEADER.size, sizeofcmds)
                uuid = ""
                identifier = ""
                cursor = 0
                for _ in range(ncmds):
                    cmd, cmdsize = self._LOAD.unpack_from(commands, cursor)
                    if cmdsize < 8 or cursor + cmdsize > len(commands):
                        raise ValueError
                    if cmd == self._UUID and cmdsize >= 24:
                        uuid = commands[cursor + 8 : cursor + 24].hex()
                    elif cmd in (self._ID_DYLIB, self._ID_DYLINKER) and cmdsize >= 12:
                        name_offset = struct.unpack_from("<I", commands, cursor + 8)[0]
                        if 0 < name_offset < cmdsize:
                            identifier = (
                                commands[cursor + name_offset : cursor + cmdsize]
                                .split(b"\0", 1)[0]
                                .decode("utf-8", "replace")
                            )
                    cursor += cmdsize
                yield (
                    0,
                    (
                        format_hints.Hex(offset),
                        self._TYPES[filetype],
                        uuid,
                        identifier,
                    ),
                )
            except (exceptions.InvalidAddressException, struct.error, ValueError):
                continue

    def run(self):
        return renderers.TreeGrid(
            [
                ("Address", format_hints.Hex),
                ("Type", str),
                ("UUID", str),
                ("Identifier", str),
            ],
            self._generator(),
        )
