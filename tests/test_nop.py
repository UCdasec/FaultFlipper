import random
from pathlib import Path
from faultflipper.binary_tools import (
    generate_nops_mutated_bin,
    disassemble_text_section,
    detect_target,
    gen_nop_patch,
    get_target_nop,
)

import pytest

@pytest.fixture
def compiled_file():
    file = Path(__file__).parent.joinpath("inputs/password_check_arm32.o")
    if not file.exists():
        raise FileNotFoundError(f"Compiled file {file} not found.")
    return file


@pytest.fixture
def output_dir():
    dir_path = Path(__file__).parent.joinpath("tmp_artifacts")
    dir_path.mkdir(exist_ok=True)
    return dir_path


def test_single_nop_patch(compiled_file, output_dir):
    out_file = output_dir.joinpath("mut.o")

    disasm = disassemble_text_section(compiled_file)
    target_inst = random.choice(disasm)
    target = detect_target(compiled_file)

    generate_nops_mutated_bin(compiled_file, target, [target_inst], out_file)

    patch = gen_nop_patch(target_inst, target)
    nop = get_target_nop(target)

    nop_count = (
        1
        if nop.value == patch
        else sum(1 for i in range(0, len(patch), len(nop.value)) if patch[i : i + len(nop.value)] == nop.value)
    )

    mut_disasm = disassemble_text_section(out_file)

    while disasm and mut_disasm:
        inst, mut_inst = disasm.pop(0), mut_disasm.pop(0)

        if inst == target_inst:
            break

        assert inst.bytes == mut_inst.bytes, "Non-matching inst"

    for _ in range(nop_count):
        mut_disasm.pop(0)

    disasm.pop(0)

    assert len(disasm) == len(mut_disasm), "Non-matching remaining len"

    for inst, mut_inst in zip(disasm, mut_disasm):
        assert inst.bytes == mut_inst.bytes, "Non-matching inst"


def test_double_nop_patch(compiled_file, output_dir):
    out_file = output_dir.joinpath("mut.0")

    disasm = disassemble_text_section(compiled_file)
    target_idx = random.choice(range(len(disasm) - 1))
    target_inst = [disasm[target_idx], disasm[target_idx + 1]]
    target = detect_target(compiled_file)

    generate_nops_mutated_bin(compiled_file, target, target_inst, out_file)

    patch = gen_nop_patch(target_inst[0], target) + gen_nop_patch(target_inst[1], target)
    nop = get_target_nop(target)

    nop_count = (
        1
        if nop.value == patch
        else sum(1 for i in range(0, len(patch), len(nop.value)) if patch[i : i + len(nop.value)] == nop.value)
    )

    mut_disasm = disassemble_text_section(out_file)

    while disasm and mut_disasm:
        inst, mut_inst = disasm.pop(0), mut_disasm.pop(0)

        if inst == target_inst[0]:
            break

        assert inst.bytes == mut_inst.bytes, "Non-matching inst"

    for _ in range(nop_count):
        mut_disasm.pop(0)

    disasm.pop(0)
    disasm.pop(0)

    assert len(disasm) == len(mut_disasm), "Non-matching remaining len"

    for inst, mut_inst in zip(disasm, mut_disasm):
        assert inst.bytes == mut_inst.bytes, "Non-matching inst"

#TODO: generalized nop test

#TODO: test edge cases of .text - do a tst for every instructon in a bin
