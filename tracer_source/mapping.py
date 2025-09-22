import lief
import capstone

from capstone import Cs
from pathlib import Path

from cyclopts import App
from rich.table import Table
from rich.console import Console
from typing_extensions import Annotated


console = Console()
app = App()


def disassemble_text_section(binary_path):
    """
    Disassemble the .text section of the binary and output instructions.
    """
    # Parse the binary
    binary = lief.parse(binary_path)

    # Find the .text section
    text_section = binary.get_section(".text")
    if not text_section:
        raise ValueError(".text section not found in the binary.")

    # Prepare Capstone disassembler
    # arch, mode = (capstone.CS_ARCH_X86, capstone.CS_MODE_64) if binary.header.machine_type == lief.ELF.ARCH.x86_64 else (capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    # cs = capstone.Cs(arch, mode)

    # Disassemble the .text section
    # code = bytes(text_section.content)
    # address = text_section.virtual_address
    # disassembly = []

    md = Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    text_section = binary.get_section(".text")
    return list(md.disasm(text_section.content, binary.entrypoint))

    # for insn in cs.disasm(code, address):
    #    disassembly.append({
    #        "address": insn.address,
    #        "mnemonic": insn.mnemonic,
    #        "op_str": insn.op_str
    #    })

    # return disassembly


@app.command()
def disasm(binary: Path, start_addr: str, end_addr: str):
    disassembly = disassemble_text_section(binary)

    start_addr = int(start_addr, 16)
    end_addr = int(end_addr, 16)

    max_len = max(
        len(" ".join([f"{b:02x}" for b in x.bytes])) for x in disassembly
    )

    # for instr in disassembly:
    for thing in [
        x
        for x in disassembly
        if x.address >= start_addr and x.address <= end_addr
    ]:
        byte_ar = thing.bytes
        byte_string = " ".join([f"{b:02x}" for b in byte_ar])
        res_str = f"0x{thing.address:x} {byte_string:<{max_len}} {thing.mnemonic} {thing.op_str}"
        print(res_str)

        # if instr.address < start_addr:
        #    continue

        # print(f"Address: {instr['address']:#x}, Instruction: {instr['mnemonic']} {instr['op_str']}")

        # if instr.address > end_addr:
        #    return


if __name__ == "__main__":
    app()
