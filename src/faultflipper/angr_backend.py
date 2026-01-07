from __future__ import annotations

import os
from collections import Counter
from pathlib import Path

import angr
import psutil
from angr.exploration_techniques import Timeout


class MemLimiter(angr.exploration_techniques.ExplorationTechnique):
    """Limiter for angr to cap total memory usage."""

    def __init__(self, max_gb: int, stash: str = "out_of_memory"):
        super().__init__()
        self.proc = psutil.Process(os.getpid())
        self.limit = max_gb * (1 << 30)
        self.cap = max_gb
        self.triggered = False
        self.stash = stash

    def _over(self) -> bool:
        return self.proc.memory_info().rss > self.limit

    def step(self, simgr, stash: str = "active", **kwargs):
        if self._over():
            self.triggered = True
            simgr.move(from_stash=stash, to_stash=self.stash)
            return simgr
        return simgr.step(stash=stash, **kwargs)


def run_angr_insn_trace(
    binary_path: str | Path,
    stdin_data: str | None = None,
) -> tuple[dict[int, int], int]:
    """
    Concretely execute a binary in angr and count executed instruction addresses.
    """

    binary_path = str(Path(binary_path).expanduser().absolute())
    proj = angr.Project(binary_path, auto_load_libs=False)
    base_addr = proj.loader.main_object.min_addr

    if stdin_data is not None:
        sim_stdin = angr.SimFileStream(name="stdin", content=stdin_data + "\n")
        state = proj.factory.full_init_state(stdin=sim_stdin)
    else:
        state = proj.factory.full_init_state()

    hit_counter: Counter[int] = Counter()

    def insn_cb(st: angr.SimState) -> None:
        hit_counter[st.addr] += 1

    state.inspect.b("instruction", when=angr.BP_BEFORE, action=insn_cb)

    simgr = proj.factory.simulation_manager(state)
    simgr.run()

    return dict(hit_counter), base_addr


def fast_sim_binary_w_input(bin: Path, inp: str, func_names: str):
    """
    Execute target functions directly via angr/unicorn with automatic prototypes.
    """

    proj = angr.Project(bin, load_options={"auto_load_libs": False})
    extra_options = angr.options.unicorn | {angr.options.LAZY_SOLVES}

    cfg = proj.analyses.CFGFast()
    proj.analyses.CompleteCallingConventions(recover_variables=True)

    assert [x in [y.name for _, y in cfg.functions.items()] for x in func_names]

    stdin_sf = angr.SimFile("stdin", content=inp.encode())
    state = proj.factory.full_init_state(stdin=stdin_sf, options=extra_options)

    captured = {}

    for func in func_names:
        cur_func = cfg.functions.function(name=func)

        if cur_func is None:
            captured[func] = []
            continue
        captured[func] = []

        ret = proj.factory.callable(
            cur_func.addr, prototype=proto.c_prototype(), concrete_only=True  # type: ignore[name-defined]
        )

        regs = {
            name: st.solver.eval(getattr(ret.regs, name), cast_to=int)
            for name in ret.arch.registers
        }

        captured[func] = [regs]

    simgr = proj.factory.simulation_manager(state).run()

    dead = simgr.deadended[0]
    stdout = dead.posix.dumps(1).decode()
    ret = get_program_rc(dead)

    return ret, stdout, captured


def sim_binary_w_calltime_input(
    bin: Path, inp: str, func_names: list[str], timeout, max_gb: int = 24
):
    """
    Simulate a binary with angr where the input is provided as a CLI argument.
    """

    proj = angr.Project(bin, load_options={"auto_load_libs": False})
    cfg = proj.analyses.CFGFast()

    assert [x in [y.name for _, y in cfg.functions.items()] for x in func_names], (
        "Function names missing!"
    )

    state = proj.factory.full_init_state(args=["ignored", inp])

    captured = {}

    def ret_hook(fn_name):
        def _after_ret(s):
            cur_regs = {}
            for name in s.arch.registers.keys():
                bv = getattr(s.regs, name)
                cur_regs[name] = s.solver.eval(bv, cast_to=int)

            if fn_name not in captured:
                captured[fn_name] = []
            captured[fn_name].append(cur_regs)

        return _after_ret

    for func in func_names:
        cur_func = cfg.functions.function(name=func)

        if cur_func is None:
            captured[func] = []
            continue

        state.inspect.b(
            "return",
            when=angr.BP_BEFORE,
            function_address=cur_func.addr,
            action=ret_hook(func),
        )

    simgr = proj.factory.simulation_manager(state)

    time_limiter = Timeout(timeout)
    simgr.use_technique(time_limiter)
    mem_limiter = MemLimiter(max_gb=max_gb)
    simgr.use_technique(mem_limiter)

    simgr.run()

    if len(simgr.deadended) != 0:
        dead = simgr.deadended[0]
        stdout = dead.posix.dumps(1).decode()
        ret = get_program_rc(dead)
    else:
        stdout = ""
        ret = "error"

    if mem_limiter.triggered:
        ret = "mem_limit"
    elif simgr.stashes.get("timeout"):
        ret = "timeout"

    return ret, stdout, captured


def sim_binary_w_input(
    bin: Path, inp: str, func_names: list[str], timeout, max_gb: int = 24
):
    """
    Simulate the binary with angr using stdin-based input.
    """

    proj = angr.Project(bin, load_options={"auto_load_libs": False})
    cfg = proj.analyses.CFGFast()

    assert [x in [y.name for _, y in cfg.functions.items()] for x in func_names], (
        "Function names missing!"
    )

    stdin_sf = angr.SimFile("stdin", content=inp.encode())
    state = proj.factory.full_init_state(stdin=stdin_sf)

    captured = {}

    def ret_hook(fn_name):
        def _after_ret(s):
            cur_regs = {}
            for name in s.arch.registers.keys():
                bv = getattr(s.regs, name)
                cur_regs[name] = s.solver.eval(bv, cast_to=int)

            if fn_name not in captured:
                captured[fn_name] = []
            captured[fn_name].append(cur_regs)

        return _after_ret

    for func in func_names:
        cur_func = cfg.functions.function(name=func)

        if cur_func is None:
            captured[func] = []
            continue

        state.inspect.b(
            "return",
            when=angr.BP_BEFORE,
            function_address=cur_func.addr,
            action=ret_hook(func),
        )

    simgr = proj.factory.simulation_manager(state)

    time_limiter = Timeout(timeout)
    simgr.use_technique(time_limiter)
    mem_limiter = MemLimiter(max_gb=max_gb)
    simgr.use_technique(mem_limiter)

    simgr.run()

    if len(simgr.deadended) != 0:
        dead = simgr.deadended[0]
        stdout = dead.posix.dumps(1).decode()
        ret = get_program_rc(dead)
    else:
        stdout = ""
        ret = "error"

    if mem_limiter.triggered:
        ret = "mem_limit"
    elif simgr.stashes.get("timeout"):
        ret = "timeout"

    return ret, stdout, captured


def get_program_rc(s):
    """
    Resolve the concrete exit code from an angr state.
    """

    if hasattr(s, "exit_code"):
        return s.solver.eval(s.exit_code)

    if "exit_code" in s.globals:
        return s.solver.eval(s.globals["exit_code"])

    ret_reg = s.arch.register_names.get(s.arch.ret_offset)
    return s.solver.eval(getattr(s.regs, ret_reg))
