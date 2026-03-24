"""
Decompiler pipeline helpers: mini-pipeline, full action chain, prototype seeding.

Moved here from decompiler_python.py to keep that file a thin driver.
"""

from __future__ import annotations

from ghidra.core.address import Address


def _run_mini_pipeline(fd) -> None:
    """Run a minimal optimization pipeline on the Funcdata.

    This is a focused subset of the full universalAction pipeline,
    containing only safe transformations that don't require prototype
    recovery, type recovery, block structure, or merge infrastructure.

    Steps:
      1. Heritage (SSA construction)
      2. Rule pool: copy propagation, early removal, constant folding,
         trivial arithmetic, boolean simplification
      3. Dead code elimination
    """
    from ghidra.transform.action import Action, ActionGroup, ActionPool
    from ghidra.transform.coreaction import ActionHeritage, ActionNonzeroMask
    from ghidra.transform.deadcode import ActionDeadCode
    from ghidra.transform.ruleaction import (
        RuleEarlyRemoval, RulePiece2Zext, RulePiece2Sext,
        RuleTermOrder, RuleTrivialArith, RuleTrivialBool,
        RuleBxor2NotEqual,
        RuleShift2Mult,
        RuleIdentityEl, RuleOrMask, RuleAndMask, RuleOrCollapse,
        RuleNegateIdentity, RuleCollapseConstants,
        RulePropagateCopy, Rule2Comp2Mult, RuleSub2Add,
        RuleXorCollapse,
    )
    from ghidra.transform.ruleaction_batch1a import RuleTrivialShift
    from ghidra.transform.ruleaction_batch1d import RuleBoolNegate

    # Build a mini action group: heritage → rules → deadcode
    act = ActionGroup(0, "mini_pipeline")

    # Step 1: Heritage (SSA)
    act.addAction(ActionHeritage("base"))

    # Step 2: Rule pool (runs rules until no more changes)
    pool = ActionPool(Action.rule_repeatapply, "mini_pool")
    pool.addRule(RuleEarlyRemoval("deadcode"))
    pool.addRule(RuleTermOrder("analysis"))
    pool.addRule(RuleTrivialArith("analysis"))
    pool.addRule(RuleTrivialBool("analysis"))
    pool.addRule(RuleTrivialShift("analysis"))
    pool.addRule(RuleIdentityEl("analysis"))
    pool.addRule(RuleOrMask("analysis"))
    pool.addRule(RuleAndMask("analysis"))
    pool.addRule(RuleOrCollapse("analysis"))
    pool.addRule(RuleBxor2NotEqual("analysis"))
    pool.addRule(RuleShift2Mult("analysis"))
    pool.addRule(RuleXorCollapse("analysis"))
    pool.addRule(RuleCollapseConstants("analysis"))
    pool.addRule(RulePropagateCopy("analysis"))
    pool.addRule(RuleSub2Add("analysis"))
    pool.addRule(Rule2Comp2Mult("analysis"))
    pool.addRule(RuleBoolNegate("analysis"))
    pool.addRule(RuleNegateIdentity("analysis"))
    pool.addRule(RulePiece2Zext("analysis"))
    pool.addRule(RulePiece2Sext("analysis"))
    act.addAction(pool)

    # Step 3: Dead code elimination
    act.addAction(ActionDeadCode("deadcode"))

    # Step 4: Non-zero mask
    act.addAction(ActionNonzeroMask("analysis"))

    # Run the pipeline
    act.reset(fd)
    act.perform(fd)


def _run_full_decompile_action(fd) -> None:
    from ghidra.transform.action import ActionDatabase

    allacts = ActionDatabase()
    allacts.universalAction(fd.getArch())
    allacts.resetDefaults()
    root = allacts.getCurrent()
    root.reset(fd)
    root.perform(fd)


def _seed_default_return_output(fd, target: str) -> None:
    """Lock the output prototype with the return register so that
    ActionPrototypeTypes will wire it to RETURN ops before Heritage.

    For the full actions pipeline, ActionPrototypeTypes (which runs before
    Heritage) will add the return register as a free varnode input on each
    RETURN op. Heritage then builds MULTIEQUALs connecting the actual
    register writes to those inputs.

    We must NOT also manually wire varnodes here, as that would create
    duplicate inputs that ActionPrototypeTypes adds on top of.
    """
    parts = target.split(":")
    if len(parts) < 3:
        return
    arch = parts[0].lower()
    if "x86" not in arch:
        return

    bitness = int(parts[2])
    ret_size = 8 if bitness == 64 else 4
    reg_space = fd.getArch().getSpace(1) if fd.getArch() is not None else None
    if reg_space is None or getattr(reg_space, "getName", lambda: "")() != "register":
        try:
            reg_space = fd.getArch()._spc_mgr.getSpaceByName("register")
        except Exception:
            reg_space = None
    if reg_space is None:
        return

    ret_addr = Address(reg_space, 0)

    # Lock the output prototype with the return register so that
    # ActionPrototypeTypes will add it to RETURN ops.
    proto = fd.getFuncProto()
    if not proto.isOutputLocked():
        glb = fd.getArch()
        int_type = None
        if glb is not None and hasattr(glb, 'types'):
            int_type = glb.types.getBase(ret_size, 8)  # TYPE_INT = 8
        from ghidra.fspec.fspec import ProtoParameter
        outparam = ProtoParameter("", int_type, ret_addr, ret_size)
        outparam.setTypeLock(True)
        proto.outparam = outparam
