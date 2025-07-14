# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import datetime
import logging
import sys
from typing import (
    Any,
    Dict,
    List,
    Tuple,
    TextIO,
)
from volatility3.framework import interfaces, renderers
from volatility3.framework.renderers import format_hints
from volatility3.cli.text_renderer import (
    CLIRenderer,
    display_disassembly,
    LayerDataRenderer,
)

vollog = logging.getLogger(__name__)

try:
    ARROW_PRESENT = True
    import pyarrow as pa
    import pyarrow.parquet as pq
except ImportError:
    ARROW_PRESENT = False
    vollog.debug("Arrow/Parquet libraries not found")


class ArrowRenderer(CLIRenderer):
    def __init__(
        self, options: List[interfaces.renderers.RenderOption] | None = None
    ) -> None:
        super().__init__(options)

        if not ARROW_PRESENT:
            raise RuntimeError("Arrow output format requires the pyarrow package")

        self._to_arrow_type = {
            renderers.Disassembly: pa.utf8,
            bool: pa.bool_,
            int: pa.int64,
            float: pa.float64,
            str: pa.utf8,
            datetime.datetime: lambda: pa.timestamp("ms"),
            format_hints.Bin: pa.int64,
            format_hints.Hex: pa.int64,
            format_hints.MultiTypeData: pa.utf8,
            format_hints.HexBytes: pa.binary,
            renderers.LayerData: pa.binary,
            bytes: pa.binary,
        }

    name = "arrow"
    structured_output = True

    def get_render_options(self) -> List[interfaces.renderers.RenderOption]:
        return []

    def to_arrow_schema(self, grid: interfaces.renderers.TreeGrid) -> "pa.Schema":
        fields = []
        for column in grid.columns:
            arrow_type = self._to_arrow_type[column.type]
            fields.append(pa.field(column.name, arrow_type()))
        return pa.schema(fields)

    def output_result(self, schema: "pa.Schema", outfd: TextIO, result):
        """Outputs the JSON data to a file in a particular format"""

        t = pa.Table.from_pylist(result, schema=schema)
        self.write_data(t, outfd)

    def write_data(self, t: "pa.Table", outfd: TextIO) -> None:
        buf = pa.BufferOutputStream()

        writer = pa.ipc.new_stream(buf, t.schema)
        writer.write_table(t)
        writer.close()

        # Get the buffer bytes and write to output
        buf_bytes = buf.getvalue().to_pybytes()
        outfd.buffer.write(buf_bytes)

    def render(self, grid: interfaces.renderers.TreeGrid):
        outfd = sys.stdout
        final_output: Tuple[
            Dict[str, List[interfaces.renderers.TreeNode]],
            List[interfaces.renderers.TreeNode],
        ] = ({}, [])

        ignore_columns = self.ignored_columns(grid)

        def visitor(
            node: interfaces.renderers.TreeNode,
            accumulator: Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]],
        ) -> Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
            # Nodes always have a path value, giving them a path_depth of at least 1, we use max just in case
            acc_map, final_tree = accumulator
            node_dict: Dict[str, Any] = {"__children": []}
            line = []
            for column_index, column in enumerate(grid.columns):
                if column in ignore_columns:
                    continue

                data = list(node.values)[column_index]

                if isinstance(data, interfaces.renderers.BaseAbsentValue):
                    data = None

                if isinstance(data, renderers.Disassembly):
                    data = display_disassembly(data)

                if isinstance(data, renderers.LayerData):
                    data = LayerDataRenderer().render_bytes(data)[0]

                node_dict[column.name] = data
                line.append(data)

            if self.filter and self.filter.filter(line):
                return accumulator

            if node.parent:
                acc_map[node.parent.path]["__children"].append(node_dict)
            else:
                final_tree.append(node_dict)
            acc_map[node.path] = node_dict

            return (acc_map, final_tree)

        if not grid.populated:
            grid.populate(visitor, final_output)
        else:
            grid.visit(node=None, function=visitor, initial_accumulator=final_output)

        schema = self.to_arrow_schema(grid)
        self.output_result(schema, outfd, final_output[1])


class ParquetRenderer(ArrowRenderer):
    name = "parquet"
    structured_output = True

    def get_render_options(self) -> List[interfaces.renderers.RenderOption]:
        return []

    def write_table(self, table: "pa.Table", outfd: TextIO) -> None:
        """
        Writes a table to stdout using the Parquet format.

        Args:
            t: The Arrow table to write
            outfd: The output file descriptor

        Returns:
            Nothing
        """
        # Write DataFrame to a temporary file-like object
        buf = pa.BufferOutputStream()
        pq.write_table(table, buf, compression="snappy")

        # Get the buffer as a bytes object
        buf_bytes = buf.getvalue().to_pybytes()
        outfd.buffer.write(buf_bytes)
