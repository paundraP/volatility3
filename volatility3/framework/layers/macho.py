# Copyright 2026 paundraP. Licensed under the Volatility Software License 1.0.
"""Address-space support for 64-bit Mach-O core files.

Apple Silicon Macs expose useful, self-consistent process snapshots as MH_CORE
Mach-O files.  This layer maps each LC_SEGMENT_64 command back to its virtual
address, preserving holes between VM regions instead of treating the file as a
flat address space.
"""

import struct
from typing import Any, Dict, List

from volatility3.framework import exceptions, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import physical, segmented


class MachOCoreFormatException(exceptions.LayerException):
    """The input is not a safe, supported Mach-O core file."""


class MachOCoreLayer(segmented.SegmentedLayer):
    """Maps 64-bit ``MH_CORE`` ``LC_SEGMENT_64`` regions into virtual memory."""

    _direct_metadata = {"os": "mac", "architecture": "AArch64"}
    HEADER = struct.Struct("<IiiIIIII")
    COMMAND = struct.Struct("<II")
    SEGMENT = struct.Struct("<II16sQQQQiiII")
    NOTE = struct.Struct("<II16sQQ")
    MAGIC = 0xFEEDFACF
    MH_CORE = 4
    LC_SEGMENT_64 = 0x19
    LC_THREAD = 0x4
    LC_NOTE = 0x31
    ARM_THREAD_STATE64 = 6
    MAX_COMMANDS = 4096

    def __init__(self, context, config_path: str, name: str, metadata=None) -> None:
        self._segments_info: List[Dict[str, Any]] = []
        self._notes: List[Dict[str, Any]] = []
        self._threads: List[Dict[str, Any]] = []
        self._base_layer = context.config.branch(config_path).get("base_layer")
        super().__init__(context, config_path, name, metadata)

    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name="base_layer")]

    def _load_segments(self) -> None:
        base = self.context.layers[self._base_layer]
        header = base.read(0, self.HEADER.size)
        magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = (
            self.HEADER.unpack(header)
        )
        if magic != self.MAGIC or filetype != self.MH_CORE:
            raise MachOCoreFormatException(
                self.name, "not a 64-bit MH_CORE Mach-O file"
            )
        if (
            not 0 < ncmds <= self.MAX_COMMANDS
            or sizeofcmds > base.maximum_address + 1 - self.HEADER.size
        ):
            raise MachOCoreFormatException(
                self.name, "invalid Mach-O load-command bounds"
            )
        self._metadata.update(
            {
                "architecture": "AArch64"
                if cputype == 0x0100000C
                else "Intel64"
                if cputype == 0x01000007
                else "Unknown",
                "cpu_type": cputype,
                "cpu_subtype": cpusubtype,
                "filetype": filetype,
                "ncmds": ncmds,
            }
        )
        commands = base.read(self.HEADER.size, sizeofcmds)
        cursor = 0
        for _ in range(ncmds):
            if cursor + self.COMMAND.size > len(commands):
                raise MachOCoreFormatException(self.name, "truncated load command")
            cmd, cmdsize = self.COMMAND.unpack_from(commands, cursor)
            if cmdsize < self.COMMAND.size or cursor + cmdsize > len(commands):
                raise MachOCoreFormatException(self.name, "invalid load command size")
            data = commands[cursor : cursor + cmdsize]
            if cmd == self.LC_SEGMENT_64 and cmdsize >= self.SEGMENT.size:
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
                ) = self.SEGMENT.unpack_from(data)
                if filesize > vmsize or fileoff + filesize > base.maximum_address + 1:
                    raise MachOCoreFormatException(
                        self.name, "segment lies outside core file"
                    )
                if filesize:
                    self._segments.append((vmaddr, fileoff, filesize, filesize))
                self._segments_info.append(
                    {
                        "vmaddr": vmaddr,
                        "vmsize": vmsize,
                        "fileoff": fileoff,
                        "filesize": filesize,
                        "maxprot": maxprot,
                        "initprot": initprot,
                        "name": raw_name.rstrip(b"\0").decode("ascii", "replace"),
                        "nsects": nsects,
                        "flags": segflags,
                    }
                )
            elif cmd == self.LC_NOTE and cmdsize >= self.NOTE.size:
                _, _, owner, offset, size = self.NOTE.unpack_from(data)
                if offset + size <= base.maximum_address + 1:
                    self._notes.append(
                        {
                            "owner": owner.rstrip(b"\0").decode("ascii", "replace"),
                            "offset": offset,
                            "size": size,
                        }
                    )
            elif cmd == self.LC_THREAD:
                self._parse_thread_command(data)
            cursor += cmdsize
        self._segments.sort()
        for previous, current in zip(self._segments, self._segments[1:]):
            if previous[0] + previous[2] > current[0]:
                raise MachOCoreFormatException(
                    self.name, "overlapping virtual segments"
                )

    @property
    def segments_info(self):
        return tuple(self._segments_info)

    @property
    def notes(self):
        return tuple(self._notes)

    @property
    def threads(self):
        return tuple(self._threads)

    def _parse_thread_command(self, data: bytes) -> None:
        """Extracts arm64 general registers from an ``LC_THREAD`` command."""
        cursor = self.COMMAND.size
        thread: Dict[str, Any] = {"index": len(self._threads), "flavors": []}
        while cursor + 8 <= len(data):
            flavor, count = struct.unpack_from("<II", data, cursor)
            cursor += 8
            state_size = count * 4
            if state_size > len(data) - cursor:
                raise MachOCoreFormatException(self.name, "truncated thread state")
            thread["flavors"].append(flavor)
            if flavor == self.ARM_THREAD_STATE64 and state_size >= 272:
                values = struct.unpack_from("<29Q4QII", data, cursor)
                for register, value in enumerate(values[:29]):
                    thread[f"x{register}"] = value
                thread.update(
                    {
                        "fp": values[29],
                        "lr": values[30],
                        "sp": values[31],
                        "pc": values[32],
                        "cpsr": values[33],
                    }
                )
            cursor += state_size
        self._threads.append(thread)


class MachOCoreStacker(interfaces.automagic.StackerLayerInterface):
    """Detects an MH_CORE Mach-O image before OS-specific stackers run."""

    stack_order = 15

    @classmethod
    def stack(cls, context, layer_name, progress_callback=None):
        layer = context.layers[layer_name]
        if (
            not isinstance(layer, physical.FileLayer)
            or layer.maximum_address < MachOCoreLayer.HEADER.size
        ):
            return None
        try:
            header = layer.read(0, MachOCoreLayer.HEADER.size)
            magic, _, _, filetype, _, _, _, _ = MachOCoreLayer.HEADER.unpack(header)
            if magic != MachOCoreLayer.MAGIC or filetype != MachOCoreLayer.MH_CORE:
                return None
            name = context.layers.free_layer_name("MachOCoreLayer")
            config_path = interfaces.configuration.path_join(
                "automagic", "layer_stacker", "stack", name
            )
            context.config[
                interfaces.configuration.path_join(config_path, "base_layer")
            ] = layer_name
            return MachOCoreLayer(context, config_path, name)
        except (OSError, ValueError, struct.error):
            return None
