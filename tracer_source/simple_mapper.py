#!/usr/bin/env python3

import argparse
import os
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_ARCH_ARM, CS_MODE_ARM, CS_ARCH_ARM64, CS_MODE_ARM, CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_32
from elftools.elf.elffile import ELFFile

def parse_args():
    parser = argparse.ArgumentParser(description="Map all ASM addresses to C source lines for x86_64, ARM32, ARM64 binaries using pyelftools.")
    parser.add_argument("--binary", required=True, help="Path to the ELF binary (must be compiled with -g for DWARF).")
    parser.add_argument("--source", required=True, help="Path to the C source file.")
    parser.add_argument("--arch", default="x86_64", choices=["x86_64", "arm32", "arm64", "x86"], help="Architecture of the binary.")
    return parser.parse_args()

def find_addresses_with_pyelftools(arch, binary_path, source_path):
    addresses = {}

    # Open the ELF binary
    with open(binary_path, "rb") as bf:
        elffile = ELFFile(bf)

        if not elffile.has_dwarf_info():
            raise RuntimeError("No DWARF debug info found in the binary. Recompile with -g.")

        dwarfinfo = elffile.get_dwarf_info()
        text_section = elffile.get_section_by_name('.text')
        if text_section is None:
            raise RuntimeError("No .text section found in the ELF.")
        
        text_data = text_section.data()
        text_vaddr = text_section['sh_addr']  # The load address of .text

        # Architecture and mode mappings for Capstone
        arch_mode_map = {
            "x86_64": (CS_ARCH_X86, CS_MODE_64),
            "x86": (CS_ARCH_X86, CS_MODE_32),
            "arm32": (CS_ARCH_ARM, CS_MODE_ARM),
            "arm64": (CS_ARCH_ARM64, CS_MODE_ARM)
        }

        cs_arch, cs_mode = arch_mode_map[arch]
        md = Cs(cs_arch, cs_mode)

        addr_to_line = {}  # maps instruction address -> line number
        for cu in dwarfinfo.iter_CUs():
            line_program = dwarfinfo.line_program_for_CU(cu)

            if not line_program:
                continue

            for entry in line_program.get_entries():
                state = entry.state
                if state is None or state.file == 0 or state.line == 0:
                    continue

                file_entry = line_program['file_entry'][state.file - 1]
                file_name = file_entry.name.decode("utf-8", errors="ignore")

                if os.path.basename(file_name) == os.path.basename(source_path):
                    addr_to_line[state.address] = state.line

        for k, v in addr_to_line.items():
            print(f"{hex(k)} -> {v}")

        # Disassemble the .text section
        for insn in md.disasm(text_data, text_vaddr):
            candidate_lines = []
            if insn.address in addr_to_line:
                candidate_lines.append(addr_to_line[insn.address])

            # Find the largest address in addr_to_line that is <= insn.address
            best_line = None
            best_addr = None
            for addr, ln in addr_to_line.items():
                if addr <= insn.address:
                    if best_addr is None or addr > best_addr:
                        best_addr = addr
                        best_line = ln
            if best_line is not None:
                candidate_lines.append(best_line)

            if candidate_lines:
                addresses[insn.address] = candidate_lines

    if addresses == {}:
        raise Exception("No map")

    return addresses

def main():
    args = parse_args()

    # Get the map of ASM addresses to C source lines
    address_to_lines = find_addresses_with_pyelftools(args.arch, args.binary, args.source)

    # Output the map
    print("ASM Address -> C Source Line Mapping:")
    for asm_addr, source_lines in address_to_lines.items():
        source_line_str = ', '.join(str(line) for line in source_lines)
        print(f"0x{asm_addr:x} -> {source_line_str}")

if __name__ == "__main__":
    main()

