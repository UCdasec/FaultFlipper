import hashlib
import random
from pathlib import Path

import pytest

import lief
from faultflipper.binary_tools import (
    OptimizationLevel,
    Target,
    compile_program,
    detect_target,
    detect_target_from_binary,
    disassemble_text_section,
    gen_nop_patch,
    generate_nops_mutated_bin,
    get_target_nop,
)


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

    for inst, mut_inst in zip(disasm, mut_disasm, strict=False):
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

    for inst, mut_inst in zip(disasm, mut_disasm, strict=False):
        assert inst.bytes == mut_inst.bytes, "Non-matching inst"

#TODO: generalized nop test

#TODO: test edge cases of .text - do a tst for every instructon in a bin


def test_nop_mutation_hashes_match_arm32(tmp_path: Path):
    repo_root = Path(__file__).resolve().parents[1]
    src = repo_root / "test_files" / "password_check.c"
    out_file = tmp_path / "password_check_arm32.o"

    try:
        compile_program(src, out_file, Target.ARM_32, OptimizationLevel.O0, None)
    except Exception as exc:
        pytest.skip(f"ARM32 toolchain not available: {exc}")

    binary = lief.parse(out_file)
    text_section = binary.get_section(".text")
    if not text_section:
        pytest.fail("Missing .text section in compiled binary")

    target = detect_target_from_binary(binary)
    disasm = list(disassemble_text_section(out_file, binary=binary, target=target))
    base_bytes = out_file.read_bytes()
    text_section_offset = text_section.offset
    text_section_vaddr = text_section.virtual_address

    def sha256(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    for inst in disasm:
        old_out = tmp_path / f"old_{inst.address:x}.o"
        new_out = tmp_path / f"new_{inst.address:x}.o"

        generate_nops_mutated_bin(out_file, target, [inst], old_out)
        generate_nops_mutated_bin(
            out_file,
            target,
            [inst],
            new_out,
            base_bytes=base_bytes,
            text_section_offset=text_section_offset,
            text_section_vaddr=text_section_vaddr,
        )

        assert sha256(old_out) == sha256(
            new_out
        ), f"Hash mismatch for nop mutation at {hex(inst.address)}"

        old_out.unlink()
        new_out.unlink()
