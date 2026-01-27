import random
from pathlib import Path

from faultflipper.binary_tools import (
    detect_target,
    disassemble_text_section,
    gen_nop_patch,
    generate_nops_mutated_bin,
    get_target_nop,
)


def test2():
    """
    Generate a nop patch 
    """

    compiled_file = Path(__file__).parent.joinpath("inputs/password_check_arm32.o")
    out_file = Path(__file__).parent.joinpath("tmp_artifacts/mut.0")

    if not compiled_file.exists():
        raise FileNotFoundError()
    
    disasm = disassemble_text_section(compiled_file)

    # Select an instrcution 
    target_idx= random.choice(list(range(len(disasm))))
    target_inst = [disasm[target_idx], disasm[target_idx+1]]

    target = detect_target(compiled_file)

    # Generate a patched binary 
    out_file = generate_nops_mutated_bin(compiled_file, target, target_inst, out_file)


    # genreate the patch so we know how lon it is 
    patch = gen_nop_patch(target_inst[0], target)
    patch.extend(gen_nop_patch(target_inst[1], target))

    # the valie is a list of bytes
    nop = get_target_nop(target)

    # See how many nop inst's are in the patch
    if nop.value == patch:
        nop_count = 1
    else:
        # Run a slidding window over the patch
        nop_count = 0
        for i in range(0, len(patch), len(nop.value)):
            window = patch[i:i+len(nop.value)]
            if window == nop.value:
                nop_count +=1 

    # Compare the out_file and orig
    mut_disasm = disassemble_text_section(out_file)

    for _ in range(len(mut_disasm)):
        inst = disasm[0]
        mut_inst = mut_disasm[0]

        # This include the location in the file, not just bytes 
        if target_inst[0] == inst:
            break

        assert inst.bytes == mut_inst.bytes, "Non-matching inst"

        # knock these off our todo list 
        disasm.pop(0)
        mut_disasm.pop(0)


    # Now at the mutated instruction, make sure 
    # Now script over len(patch) instcrutions in the mutated 
    # and over the target inst, and keep comparing 
    for _ in range(nop_count):
        # Make sure its a nop 
        mut_disasm.pop(0)


    # Pop the two nopped 
    disasm.pop(0)
    disasm.pop(0)


    assert len(disasm) == len(mut_disasm), "Non-matching remaining len"

    # From here out they should be the same
    zipped =  zip(disasm, mut_disasm, strict=False)
    for _, (inst, mut_inst) in enumerate(zipped):
        if inst.bytes != mut_inst.bytes:
            print(f"{inst.bytes}  {mut_inst.byt}")
        assert inst.bytes == mut_inst.bytes, "Non-matching inst"

    print("Passed")
    return True



def test1():
    """
    Generate a nop patch 
    """

    compiled_file = Path(__file__).parent.joinpath("inputs/password_check_arm32.o")
    out_file = Path(__file__).parent.joinpath("tmp_artifacts/mut.o")

    if not compiled_file.exists():
        raise FileNotFoundError()
    
    disasm = disassemble_text_section(compiled_file)

    # Select an instrcution 
    target_inst = random.choice(disasm)
    target = detect_target(compiled_file)

    # Generate a patched binary 
    out_file = generate_nops_mutated_bin(compiled_file, target, [target_inst], out_file)

    # genreate the patch so we know how lon it is 
    patch = gen_nop_patch(target_inst, target)

    # the valie is a list of bytes
    nop = get_target_nop(target)

    # See how many nop inst's are in the patch
    if nop.value == patch:
        nop_count = 1
    else:
        nop_count = 0
        for i in range(0, len(patch)-len(nop.value), len(nop.value)):
            if patch[i:i+len(nop.value)] == nop.value:
                nop_count +=1 

    # Compare the out_file and orig
    mut_disasm = disassemble_text_section(out_file)

    for _ in range(len(mut_disasm)):
        inst = disasm[0]
        mut_inst = mut_disasm[0]

        # This include the location in the file, not just bytes 
        if target_inst == inst:
            break

        assert inst.bytes == mut_inst.bytes, "Non-matching inst"

        # knock these off our todo list 
        disasm.pop(0)
        mut_disasm.pop(0)


    # Now at the mutated instruction, make sure 
    # Now script over len(patch) instcrutions in the mutated 
    # and over the target inst, and keep comparing 
    for _ in range(nop_count):
        # Make sure its a nop 
         mut_disasm.pop(0)

    disasm.pop(0)

    # From here out they should be the same
    zipped =  zip(disasm, mut_disasm, strict=False)
    for _, (inst, mut_inst) in enumerate(zipped):
        if inst.bytes != mut_inst.bytes:
            print(f"{inst.bytes}  {mut_inst.bytes}")
        assert inst.bytes == mut_inst.bytes, "Non-matching inst"

    print("Passed")

if __name__ == "__main__":
    test1()
    test2()
