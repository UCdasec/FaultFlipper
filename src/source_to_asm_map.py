from cyclopts import App
from pathlib import Path
from rich.table import Table
from rich.console import Console
from typing_extensions import Annotated

import subprocess

import pandas as pd


console = Console()
app = App()


from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64


def parse_dwarf_info(binary_path):
    """
    Parse DWARF debugging information to map source lines to addresses.
    """
    source_to_address = {}

    with open(binary_path, "rb") as f:
        elffile = ELFFile(f)

        if not elffile.has_dwarf_info():
            raise ValueError(
                "DWARF debugging information not found in the binary."
            )

        dwarf_info = elffile.get_dwarf_info()

        for cu in dwarf_info.iter_CUs():
            line_program = dwarf_info.line_program_for_CU(cu)

            if not line_program:
                continue

            for entry in line_program.get_entries():
                state = entry.state
                if state and not state.end_sequence:
                    file_name = line_program["file_entry"][
                        state.file - 1
                    ].name.decode("utf-8")
                    if file_name not in source_to_address:
                        source_to_address[file_name] = {}
                    source_to_address[file_name][state.line] = state.address

    return source_to_address


def disassemble_text_section(binary_path, source_to_address):
    """
    Disassemble the .text section and map source lines to assembly instructions.
    """
    with open(binary_path, "rb") as f:
        elffile = ELFFile(f)
        text_section = elffile.get_section_by_name(".text")
        if not text_section:
            raise ValueError(".text section not found in the binary.")

        # Prepare Capstone disassembler
        code = text_section.data()
        address = text_section["sh_addr"]
        cs = Cs(CS_ARCH_X86, CS_MODE_64)  # Adjust architecture/mode as needed

        disassembly_mapping = []

        for insn in cs.disasm(code, address):
            matched = False
            for file_name, lines in source_to_address.items():
                for source_line, addresses in lines.items():
                    if not isinstance(addresses, list):
                        addresses = [addresses]
                    # Check if the instruction address falls within the range for this source line
                    if any(addr <= insn.address for addr in addresses):
                        disassembly_mapping.append(
                            {
                                "source_file": file_name,
                                "source_line": source_line,
                                "assembly_address": insn.address,
                                "mnemonic": insn.mnemonic,
                                "op_str": insn.op_str,
                            }
                        )
                        matched = True
                        break
                if matched:
                    break

        return disassembly_mapping


# def disassemble_text_section(binary_path, source_to_address):
#    """
#    Disassemble the .text section and map source lines to assembly instructions.
#    """
#    with open(binary_path, 'rb') as f:
#        elffile = ELFFile(f)
#        text_section = elffile.get_section_by_name(".text")
#        if not text_section:
#            raise ValueError(".text section not found in the binary.")
#
#        # Prepare Capstone disassembler
#        code = text_section.data()
#        address = text_section['sh_addr']
#        cs = Cs(CS_ARCH_X86, CS_MODE_64)  # Adjust architecture/mode as needed
#
#        disassembly_mapping = []
#
#        for insn in cs.disasm(code, address):
#            # Match instruction addresses to source lines
#            for file_name, lines in source_to_address.items():
#                for source_line, source_address in lines.items():
#                    if source_address <= insn.address:
#                        disassembly_mapping.append({
#                            "source_file": file_name,
#                            "source_line": source_line,
#                            "assembly_address": insn.address,
#                            "mnemonic": insn.mnemonic,
#                            "op_str": insn.op_str
#                        })
#                        break  # Break after the first match
#
#        return disassembly_mapping


@app.command()
def main(binary_path: Path):
    try:
        source_to_address = parse_dwarf_info(binary_path)
        disassembly_mapping = disassemble_text_section(
            binary_path, source_to_address
        )

        for entry in disassembly_mapping:
            print(
                f"Source: {entry['source_file']}:{entry['source_line']}, "
                f"Address: {entry['assembly_address']:#x}, "
                f"Instruction: {entry['mnemonic']} {entry['op_str']}"
            )
    except ValueError as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    app()
