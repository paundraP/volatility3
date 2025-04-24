# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import struct
from typing import List, Set

from volatility3.framework import exceptions, constants
from volatility3.framework.renderers import TreeGrid, NotAvailableValue, format_hints
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.symbols import linux
from volatility3.framework import symbols
from volatility3.plugins.linux import lsof, pslist, sockstat
from volatility3.framework.layers import scanners
from volatility3.framework.symbols.linux import network

vollog = logging.getLogger(__name__)


class Sockscan(plugins.PluginInterface):
    """Scans for network connections found in memory layer."""

    _required_framework_version = (2, 6, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="SockHandlers", component=sockstat.SockHandlers, version=(4, 0, 0)
            ),
            requirements.VersionRequirement(
                name="lsof", component=lsof.Lsof, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(4, 0, 0)
            ),
            requirements.VersionRequirement(
                name="linuxutils", component=linux.LinuxUtilities, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="linux_net", component=network.NetSymbols, version=(1, 0, 0)
            ),
        ]

    def _canonicalize_symbol_addrs(
        self, symbol_table_name: str, symbol_names: List[str]
    ) -> Set[bytes]:
        """Takes a list of symbol names and converts the address of each to the bytes
        as they would appear in memory so that they can be scanned for.

        Symbols that cannot be found are ignored and not included in the results.

        Args:
            symbol_table_name: The name of the kernel module on which to operate
            symbol_names: A list of symbol names to be looked up

        Returns:
            A set of bytes which are the packed addresses.
        """
        # get vmlinux module from context in order to build objects and read symbols
        vmlinux = self.context.modules[symbol_table_name]

        # get kernel layer from context so that it's dependencies can be found, and therefore scanned.
        # kernel layer will be virtual and built ontop of a physical layer.
        kernel_layer = self.context.layers[vmlinux.layer_name]

        # detmine if kernel is 64bit or not. The plugin scans for pointers and these need to formated
        # to the correct size so that they can be accurately located in the physical layer.
        if symbols.symbol_table_is_64bit(self.context, vmlinux.symbol_table_name):
            pack_format = "Q"  # 64 bit
        else:
            pack_format = "I"  # 32 bit

        packed_needles = set()
        for symbol_name in symbol_names:
            try:
                needle_addr = vmlinux.object_from_symbol(symbol_name).vol.offset
            except exceptions.SymbolError:
                vollog.log(
                    constants.LOGLEVEL_VVVV,
                    f"Unable to find symbol {symbol_name} this will not be scanned for.",
                )
                continue
            # use canonicalize to set the appropriate sign extension for the addr
            addr = kernel_layer.canonicalize(needle_addr)
            packed_addr = struct.pack(pack_format, addr)
            packed_needles.add(packed_addr)
            vollog.log(
                constants.LOGLEVEL_VVVV,
                f"Will scan for {symbol_name} using the bytes: {packed_addr.hex()}",
            )

        # make a warning if no symbols at all could be resolved.
        if not packed_needles:
            vollog.warning(
                "_canonicalize_symbol_addrs was unable to resolve any symbols, use -vvvv for more information."
            )

        return packed_needles

    def _find_memory_layer_name(self, symbol_table_name: str):
        """Find the memory layer below the kernel. Only returns a single layer,
        and will warn the user if multiple layers are found.

        Args:
            symbol_table_name: The name of the kernel module on which to operate.

        Returns:
            memory_layer_name: The name of the layer below the kernel to be scanned.
        """

        # get vmlinux module from context in order to build objects and read symbols
        vmlinux = self.context.modules[symbol_table_name]

        # get kernel layer from context so that it's dependencies can be found, and therefore scanned.
        # kernel layer will be virtual and built ontop of a physical layer.
        kernel_layer = self.context.layers[vmlinux.layer_name]

        # TODO: Update plugin to support multiple dependencies. e.g. a memory layer and swap file.
        # This is a shared problem with psscan and having a generic solution would be useful.

        # Find the memory layer to scan, and provide warnings if more than one is located.
        if len(kernel_layer.dependencies) > 1:
            vollog.warning(
                f"Kernel layer depends on multiple layers however only {kernel_layer.dependencies[0]} will be scanned by this plugin."
            )
        elif len(kernel_layer.dependencies) == 0:
            vollog.error(
                "Kernel layer has no dependencies, meaning there is no memory layer for this plugin to scan."
            )
            raise exceptions.LayerException(
                vmlinux.layer_name, f"Layer {vmlinux.layer_name} has no dependencies"
            )

        memory_layer_name = kernel_layer.dependencies[0]

        return memory_layer_name

    def _find_file_ops_needles(self, symbol_table_name: str):
        # get vmlinux module from context in order to read symbols
        vmlinux = self.context.modules[symbol_table_name]

        file_ops_symbol_names = [
            "socket_file_ops",
            "sockfs_dentry_operations",
        ]
        file_ops_needles = self._canonicalize_symbol_addrs(
            symbol_table_name, file_ops_symbol_names
        )
        # get file struct to find the offset to the f_op pointer
        # this is so that the file object can be created at the correct offset,
        # the results of the scanner will be for the f_op member within the file
        f_op_offset = vmlinux.get_type("file").relative_child_offset("f_op")

        return (file_ops_needles, f_op_offset)

    def _find_sk_destruct_needles(self, symbol_table_name: str):
        # get vmlinux module from context in order to read symbols
        vmlinux = self.context.modules[symbol_table_name]

        socket_destructor_symbol_names = [
            "sock_def_destruct",
            "packet_sock_destruct",
            "unix_sock_destructor",
            "netlink_sock_destruct",
            "inet_sock_destruct",
        ]
        socket_destructor_needles = self._canonicalize_symbol_addrs(
            symbol_table_name, socket_destructor_symbol_names
        )
        # get sock struct to find the offset to the sk_destruct pointer
        # this is so that the sock object can be created at the correct offset,
        # the results of the scanner will be for the sk_destruct member within the scock
        sk_destruct_offset = vmlinux.get_type("sock").relative_child_offset(
            "sk_destruct"
        )
        return (socket_destructor_needles, sk_destruct_offset)

    def _walk_file_ops_needles(
        self, symbol_table_name, memory_layer_name, needle_addr, f_op_offset
    ):
        vmlinux = self.context.modules[symbol_table_name]
        try:
            # create file in the memory_layer, the native layer matches the
            # kernel so that pointers can be followed
            sock_physical_addr = needle_addr - f_op_offset
            pfile = self.context.object(
                vmlinux.symbol_table_name + constants.BANG + "file",
                offset=sock_physical_addr,
                layer_name=memory_layer_name,
                native_layer_name=vmlinux.layer_name,
            )
            dentry = pfile.get_dentry()
            if not dentry:
                vollog.log(
                    constants.LOGLEVEL_VVVV,
                    f"Skipping file at {hex(needle_addr)} as unable to locate dentry",
                )
                return None

            d_inode = dentry.d_inode
            if not d_inode:
                vollog.log(
                    constants.LOGLEVEL_VVVV,
                    f"Skipping file at {hex(needle_addr)} as unable to locate inode for dentry",
                )
                return None

            socket_alloc = linux.LinuxUtilities.container_of(
                d_inode, "socket_alloc", "vfs_inode", vmlinux
            )
            socket = socket_alloc.socket
            if not (socket and socket.sk):
                vollog.log(
                    constants.LOGLEVEL_VVVV,
                    f"Skipping file at {hex(needle_addr)} as socket created by LinuxUtilities.container_of is invalid",
                )
                return None

            # sucessfully trversed from file to sock, this will exist in the
            # kernel layer, and need to be translated to the memory layer.
            psock = socket.sk.dereference()
            return psock

        except exceptions.InvalidAddressException as error:
            vollog.log(
                constants.LOGLEVEL_VVVV,
                f"Unable to follow file at {hex(needle_addr)} to socket due to invalid address: {error}",
            )
        return None

    def _extract_sock_fields(self, psock, sock_handler):
        try:
            sock_physical_addr = psock.vol.offset
            sock_type = psock.get_type()

            family = psock.get_family()
            # remove results with no family
            if family is None:
                vollog.log(
                    constants.LOGLEVEL_VVVV,
                    f"Skipping socket at {hex(sock_physical_addr)} as unable to determin family.",
                )
                return None

            # TODO: invesitgate options for more invalid address handling in proccess_sock
            # and the later formatting of it's results.
            sock_fields = sock_handler.process_sock(psock)
            # if no sock_fields we're able to be extracted then skip this result.
            if not sock_fields:
                vollog.log(
                    constants.LOGLEVEL_VVVV,
                    f"Skipping socket at {hex(sock_physical_addr)} as unable to process with SockHandlers.",
                )
                return None

            sock, sock_stat, extended = sock_fields
            src, src_port, dst, dst_port, state = sock_stat
            protocol = sock.get_protocol()

            # format results
            src = NotAvailableValue() if src is None else str(src)
            src_port = NotAvailableValue() if src_port is None else str(src_port)
            dst = NotAvailableValue() if dst is None else str(dst)
            dst_port = NotAvailableValue() if dst_port is None else str(dst_port)
            state = NotAvailableValue() if state is None else str(state)
            protocol = NotAvailableValue() if protocol is None else str(protocol)
            # extended attributes is a dict, so this is formated to string show each
            # key and value pair, seperated with a comma.
            socket_filter_str = (
                ",".join(f"{k}={v}" for k, v in extended.items())
                if extended
                else NotAvailableValue()
            )

            # remove empty results
            if (src == "0.0.0.0" or isinstance(src, NotAvailableValue)) and (
                dst == "0.0.0.0" or isinstance(src, NotAvailableValue)
            ):
                if state == "UNCONNECTED":
                    return None
                elif src_port == "0" and dst_port == "0":
                    return None
            return (
                format_hints.Hex(sock_physical_addr),
                family,
                sock_type,
                protocol,
                src,
                src_port,
                dst,
                dst_port,
                state,
                socket_filter_str,
            )

        except exceptions.InvalidAddressException as error:
            vollog.log(
                constants.LOGLEVEL_VVVV,
                f"Unable create results for socket at {hex(sock_physical_addr)} due to invalid address: {error}",
            )
        return None

    def _build_sock_handler(self, symbol_table_name: str):
        vmlinux = self.context.modules[symbol_table_name]
        init_task = vmlinux.object_from_symbol(symbol_name="init_task")
        return sockstat.SockHandlers(self.context, symbol_table_name, init_task)

    def _scan_for_sockets(
        self, memory_layer, file_ops_needles, socket_destructor_needles
    ):
        return memory_layer.scan(
            self.context,
            scanners.MultiStringScanner(socket_destructor_needles | file_ops_needles),
            self._progress_callback,
        )

    def _parse_scanner_result(
        self,
        match,
        needle_addr,
        file_ops_needles,
        socket_destructor_needles,
        symbol_table_name,
        memory_layer_name,
        f_op_offset,
        sk_destruct_offset,
    ):

        if match in socket_destructor_needles:
            sock_physical_addr = needle_addr - sk_destruct_offset
            psock = self._get_socket_from_sk_destruct(
                sock_physical_addr, symbol_table_name, memory_layer_name
            )
        elif match in file_ops_needles:
            psock = self._walk_file_ops_needles(
                symbol_table_name, memory_layer_name, needle_addr, f_op_offset
            )
            sock_physical_addr = psock.vol.offset if psock else None
        else:
            psock = sock_physical_addr = None

        return psock, sock_physical_addr

    def _get_socket_from_sk_destruct(
        self, sock_physical_addr, symbol_table_name, memory_layer_name
    ):
        vmlinux = self.context.modules[symbol_table_name]
        return self.context.object(
            vmlinux.symbol_table_name + constants.BANG + "sock",
            offset=sock_physical_addr,
            layer_name=memory_layer_name,
            native_layer_name=vmlinux.layer_name,
        )

    def _generator(self, symbol_table_name: str):
        memory_layer_name = self._find_memory_layer_name(symbol_table_name)
        memory_layer = self.context.layers[memory_layer_name]
        sock_handler = self._build_sock_handler(symbol_table_name)

        file_ops_needles, f_op_offset = self._find_file_ops_needles(symbol_table_name)
        socket_destructor_needles, sk_destruct_offset = self._find_sk_destruct_needles(
            symbol_table_name
        )

        seen_sock_physical_addr = set()

        for needle_addr, match in self._scan_for_sockets(
            memory_layer, file_ops_needles, socket_destructor_needles
        ):
            psock, sock_physical_addr = self._parse_scanner_result(
                match,
                needle_addr,
                file_ops_needles,
                socket_destructor_needles,
                symbol_table_name,
                memory_layer_name,
                f_op_offset,
                sk_destruct_offset,
            )

            if psock and sock_physical_addr not in seen_sock_physical_addr:
                seen_sock_physical_addr.add(sock_physical_addr)
                fields = self._extract_sock_fields(psock, sock_handler)
                if fields:
                    yield (0, fields)

    def run(self):

        tree_grid_args = [
            ("Sock Offset", format_hints.Hex),
            ("Family", str),
            ("Type", str),
            ("Proto", str),
            ("Source Addr", str),
            ("Source Port", str),
            ("Destination Addr", str),
            ("Destination Port", str),
            ("State", str),
            ("Filter", str),
        ]

        return TreeGrid(
            tree_grid_args,
            self._generator(self.config["kernel"]),
        )
