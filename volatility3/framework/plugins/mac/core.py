# Copyright 2026 paundraP. Licensed under the Volatility Software License 1.0.
"""Analysis plugins for modern Apple Silicon Mach-O process cores."""

import json
import os
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
    _SEGMENT_64 = 0x19
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
                image = self.parse_image(layer, offset)
                yield (
                    0,
                    (
                        format_hints.Hex(offset),
                        image["type"],
                        image["uuid"],
                        image["identifier"],
                    ),
                )
            except (exceptions.InvalidAddressException, struct.error, ValueError):
                continue

    @classmethod
    def parse_image(cls, layer: MachOCoreLayer, offset: int):
        """Parses one in-memory Mach-O image and its file-backed segments."""
        header = layer.read(offset, cls._HEADER.size)
        (
            magic,
            cputype,
            _subtype,
            filetype,
            ncmds,
            sizeofcmds,
            _flags,
            _reserved,
        ) = cls._HEADER.unpack(header)
        if (
            magic != 0xFEEDFACF
            or cputype != 0x0100000C
            or filetype not in cls._TYPES
            or not 0 < ncmds <= 512
            or sizeofcmds > 0x100000
        ):
            raise ValueError("invalid arm64 Mach-O header")
        commands = layer.read(offset + cls._HEADER.size, sizeofcmds)
        image = {
            "address": offset,
            "type": cls._TYPES[filetype],
            "uuid": "",
            "identifier": "",
            "segments": [],
        }
        cursor = 0
        for _ in range(ncmds):
            cmd, cmdsize = cls._LOAD.unpack_from(commands, cursor)
            if cmdsize < 8 or cursor + cmdsize > len(commands):
                raise ValueError("invalid Mach-O load command")
            if cmd == cls._UUID and cmdsize >= 24:
                image["uuid"] = commands[cursor + 8 : cursor + 24].hex()
            elif cmd in (cls._ID_DYLIB, cls._ID_DYLINKER) and cmdsize >= 12:
                name_offset = struct.unpack_from("<I", commands, cursor + 8)[0]
                if 0 < name_offset < cmdsize:
                    image["identifier"] = (
                        commands[cursor + name_offset : cursor + cmdsize]
                        .split(b"\0", 1)[0]
                        .decode("utf-8", "replace")
                    )
            elif cmd == cls._SEGMENT_64 and cmdsize >= MachOCoreLayer.SEGMENT.size:
                (
                    _,
                    _,
                    raw_name,
                    vmaddr,
                    vmsize,
                    fileoff,
                    filesize,
                    maxprot,
                    initprot,
                    nsects,
                    segflags,
                ) = MachOCoreLayer.SEGMENT.unpack_from(commands, cursor)
                if filesize > vmsize:
                    raise ValueError("Mach-O segment filesize exceeds vmsize")
                image["segments"].append(
                    {
                        "name": raw_name.rstrip(b"\0").decode("ascii", "replace"),
                        "vmaddr": vmaddr,
                        "vmsize": vmsize,
                        "fileoff": fileoff,
                        "filesize": filesize,
                        "maxprot": maxprot,
                        "initprot": initprot,
                        "nsects": nsects,
                        "flags": segflags,
                    }
                )
            cursor += cmdsize
        if not image["segments"]:
            raise ValueError("Mach-O has no segments")
        return image

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


class MachODump(interfaces.plugins.PluginInterface):
    """Reconstructs one selected Mach-O image from captured virtual memory."""

    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)
    DEFAULT_MAX_SIZE = 0x40000000
    CHUNK_SIZE = 0x1000000

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name="primary", description="Mach-O core address space"
            ),
            requirements.IntRequirement(
                name="address",
                description="Virtual address reported by mac.core.MachOImages",
            ),
            requirements.IntRequirement(
                name="max_size",
                description="Maximum reconstructed file size",
                default=cls.DEFAULT_MAX_SIZE,
                optional=True,
            ),
        ]

    def _generator(self):
        layer = self.context.layers[self.config["primary"]]
        if not isinstance(layer, MachOCoreLayer):
            raise ValueError("mac.machodump requires an MH_CORE Mach-O input")
        address = self.config["address"]
        image = MachOImages.parse_image(layer, address)
        header_segment = next(
            (
                segment
                for segment in image["segments"]
                if segment["fileoff"] == 0 and segment["filesize"]
            ),
            None,
        )
        if header_segment is None:
            raise ValueError("Mach-O has no file-backed header segment")
        slide = address - header_segment["vmaddr"]
        output_size = max(
            segment["fileoff"] + segment["filesize"] for segment in image["segments"]
        )
        if output_size <= 0 or output_size > self.config["max_size"]:
            raise ValueError(
                f"Reconstructed Mach-O size {output_size:#x} exceeds max_size"
            )
        basename = os.path.basename(image["identifier"]) or image["type"].lower()
        output_name = f"macho.{address:#x}.{basename}.dmp"
        written_segments = 0
        file_handle = self.open(output_name)
        try:
            for segment in sorted(image["segments"], key=lambda item: item["fileoff"]):
                remaining = segment["filesize"]
                if not remaining:
                    continue
                source = segment["vmaddr"] + slide
                file_handle.seek(segment["fileoff"])
                copied = 0
                while copied < remaining:
                    length = min(self.CHUNK_SIZE, remaining - copied)
                    data = layer.read(source + copied, length)
                    file_handle.write(data)
                    copied += length
                written_segments += 1
            file_handle.truncate(output_size)
            file_handle.close()
        except Exception:
            file_handle.close()
            raise
        yield (
            0,
            (
                format_hints.Hex(address),
                file_handle.preferred_filename,
                output_size,
                written_segments,
                "Reconstructed from memory; code signatures may not validate",
            ),
        )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Address", format_hints.Hex),
                ("File", str),
                ("Size", int),
                ("Segments", int),
                ("Status", str),
            ],
            self._generator(),
        )
