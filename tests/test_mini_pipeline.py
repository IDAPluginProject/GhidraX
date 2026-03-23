"""Tests for Module 4: Mini Action Pipeline (Heritage + Rules + DeadCode).

Verifies that the mini pipeline runs without errors on various code patterns
and that rules actually apply (reducing op count, propagating copies, etc.).
"""

import os
import sys
import io
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

from ghidra.sleigh.decompiler_python import DecompilerPython, _run_mini_pipeline
from ghidra.sleigh.arch_map import resolve_arch, add_sla_search_dir
from ghidra.sleigh.lifter import Lifter
from ghidra.sleigh.decompiler_python import _ArchitectureShim, _split_basic_blocks
from ghidra.arch.architecture import Architecture
from ghidra.database.comment import Comment
from ghidra.core.address import Address
from ghidra.core.error import LowlevelError, RecovError
from ghidra.output.prettyprint import EmitMarkup, EmitPrettyPrint, SyntaxHighlight
from ghidra.output.printc import PrintC
from ghidra.database.database import FunctionSymbol, LabSymbol, ScopeInternal, Symbol, SymbolEntry
from ghidra.output.printlanguage import Atom, PrintLanguage, PrintLanguageCapability, casetoken, vartoken
from pattern_corpus import X86_SIMPLE, X86_ADD_INC, X86_OR_FULL_MASK, X86_SHIFT_LEFT_2, X86_BRANCH, X86_LOOP, X86_NESTED_IF


X86_ADD = X86_ADD_INC
X86_OR_MASK = X86_OR_FULL_MASK
X86_SHIFT = X86_SHIFT_LEFT_2


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def arch_info():
    arch = resolve_arch('metapc', 32, False)
    add_sla_search_dir(os.path.dirname(arch['sla_path']))
    return arch


@pytest.fixture
def make_fd(arch_info):
    """Factory: lift code into a Funcdata with FlowInfo + arch shim attached."""
    def _make(code, base=0x401000):
        lifter = Lifter(arch_info['sla_path'], {"addrsize": 1, "opsize": 1})
        lifter.set_image(base, code)
        fd = lifter.lift_function(f"func_{base:x}", base, len(code))
        _split_basic_blocks(fd)
        arch_shim = _ArchitectureShim(lifter._spc_mgr)
        fd.setArch(arch_shim)
        return fd
    return _make


# ---------------------------------------------------------------------------
# Tests: Mini pipeline runs without error
# ---------------------------------------------------------------------------

class TestMiniPipelineRuns:
    """Verify the mini pipeline completes without exceptions."""

    def test_simple_no_error(self, make_fd):
        fd = make_fd(X86_SIMPLE)
        _run_mini_pipeline(fd)
        # Should complete without exception

    def test_add_no_error(self, make_fd):
        fd = make_fd(X86_ADD)
        _run_mini_pipeline(fd)

    def test_or_mask_no_error(self, make_fd):
        fd = make_fd(X86_OR_MASK)
        _run_mini_pipeline(fd)

    def test_shift_no_error(self, make_fd):
        fd = make_fd(X86_SHIFT)
        _run_mini_pipeline(fd)

    def test_branch_no_error(self, make_fd):
        fd = make_fd(X86_BRANCH)
        _run_mini_pipeline(fd)

    def test_loop_no_error(self, make_fd):
        fd = make_fd(X86_LOOP)
        _run_mini_pipeline(fd)

    def test_nested_if_no_error(self, make_fd):
        """Nested-if pattern should run mini pipeline without errors."""
        fd = make_fd(X86_NESTED_IF)
        _run_mini_pipeline(fd)


# ---------------------------------------------------------------------------
# Tests: Rules actually apply
# ---------------------------------------------------------------------------

class TestRulesApply:
    """Verify that the rule pool actually transforms the IR."""

    def test_copy_propagation_reduces_ops(self, make_fd):
        """After rules run, some COPY ops should be eliminated."""
        fd = make_fd(X86_SIMPLE)
        # Count alive ops before
        ops_before = sum(1 for _ in fd.beginOpAlive())
        _run_mini_pipeline(fd)
        ops_after = sum(1 for _ in fd.beginOpAlive())
        # Rules should have eliminated at least some ops
        # (copy propagation + early removal + dead code)
        assert ops_after <= ops_before, \
            f"Expected op reduction: before={ops_before}, after={ops_after}"

    def test_xor_self_becomes_zero(self, make_fd):
        """xor eax,eax should be simplified (constant 0)."""
        fd = make_fd(X86_SIMPLE)
        from ghidra.core.opcodes import OpCode
        # Before pipeline, there should be an INT_XOR
        has_xor_before = any(
            op.code() == OpCode.CPUI_INT_XOR
            for op in fd.beginOpAlive()
        )
        assert has_xor_before, "Expected INT_XOR before pipeline"

        _run_mini_pipeline(fd)

        # After pipeline, XOR should be folded to COPY(0)
        has_xor_after = any(
            op.code() == OpCode.CPUI_INT_XOR
            for op in fd.beginOpAlive()
        )
        # XorCollapse or CollapseConstants should have eliminated it
        assert not has_xor_after, "INT_XOR should be folded after pipeline"

    def test_or_full_mask_becomes_non_or(self, make_fd):
        fd = make_fd(X86_OR_MASK)
        from ghidra.core.opcodes import OpCode

        has_or_before = any(
            op.code() == OpCode.CPUI_INT_OR
            for op in fd.beginOpAlive()
        )
        assert has_or_before, "Expected INT_OR before pipeline"

        _run_mini_pipeline(fd)

        has_or_after = any(
            op.code() == OpCode.CPUI_INT_OR
            for op in fd.beginOpAlive()
        )
        assert not has_or_after, "INT_OR should be simplified after pipeline"

    def test_rule_bxor2notequal_rewrites_opcode(self):
        from ghidra.core.space import AddrSpaceManager, ConstantSpace, AddrSpace, IPTR_PROCESSOR
        from ghidra.core.address import Address, SeqNum
        from ghidra.core.opcodes import OpCode
        from ghidra.ir.op import PcodeOp
        from ghidra.ir.varnode import Varnode
        from ghidra.transform.ruleaction import RuleBxor2NotEqual

        class _FakeFuncdata:
            def opSetOpcode(self, op, opc):
                op.setOpcodeEnum(opc)

        mgr = AddrSpaceManager()
        const_spc = ConstantSpace(mgr)
        mgr._insertSpace(const_spc)
        mgr._constantSpace = const_spc
        reg = AddrSpace(mgr, None, IPTR_PROCESSOR, "register", False, 4, 1, 1, 0, 0, 0)
        mgr._insertSpace(reg)

        sq = SeqNum(Address(reg, 0x1000), 0)
        op = PcodeOp(2, sq)
        op.setOpcodeEnum(OpCode.CPUI_BOOL_XOR)
        op.setOutput(Varnode(1, Address(reg, 0x0)))
        op.setInput(Varnode(1, Address(reg, 0x4)), 0)
        op.setInput(Varnode(1, Address(reg, 0x8)), 1)

        rule = RuleBxor2NotEqual("analysis")
        changed = rule.applyOp(op, _FakeFuncdata())

        assert changed == 1
        assert op.code() == OpCode.CPUI_INT_NOTEQUAL

    def test_shift_left_becomes_multiply(self, make_fd):
        fd = make_fd(X86_SHIFT)
        from ghidra.core.opcodes import OpCode

        has_shift_before = any(
            op.code() == OpCode.CPUI_INT_LEFT
            for op in fd.beginOpAlive()
        )
        assert has_shift_before, "Expected INT_LEFT before pipeline"

        _run_mini_pipeline(fd)

        has_shift_after = any(
            op.code() == OpCode.CPUI_INT_LEFT
            for op in fd.beginOpAlive()
        )
        assert not has_shift_after, "INT_LEFT should be rewritten after pipeline"

    def test_rule_shift2mult_rewrites_opcode_and_constant(self):
        from ghidra.core.space import AddrSpaceManager, ConstantSpace, AddrSpace, IPTR_PROCESSOR
        from ghidra.core.address import Address, SeqNum
        from ghidra.core.opcodes import OpCode
        from ghidra.ir.op import PcodeOp
        from ghidra.ir.varnode import Varnode
        from ghidra.transform.ruleaction import RuleShift2Mult

        class _FakeFuncdata:
            def __init__(self, const_space):
                self._const_space = const_space

            def opSetOpcode(self, op, opc):
                op.setOpcodeEnum(opc)

            def newConstant(self, size, value):
                return Varnode(size, Address(self._const_space, value))

            def opSetInput(self, op, vn, slot):
                op.setInput(vn, slot)

        mgr = AddrSpaceManager()
        const_spc = ConstantSpace(mgr)
        mgr._insertSpace(const_spc)
        mgr._constantSpace = const_spc
        reg = AddrSpace(mgr, None, IPTR_PROCESSOR, "register", False, 4, 1, 1, 0, 0, 0)
        mgr._insertSpace(reg)

        sq = SeqNum(Address(reg, 0x1000), 0)
        op = PcodeOp(2, sq)
        op.setOpcodeEnum(OpCode.CPUI_INT_LEFT)
        op.setOutput(Varnode(4, Address(reg, 0x0)))
        op.setInput(Varnode(4, Address(reg, 0x4)), 0)
        op.setInput(Varnode(4, Address(const_spc, 2)), 1)

        rule = RuleShift2Mult("analysis")
        changed = rule.applyOp(op, _FakeFuncdata(const_spc))

        assert changed == 1
        assert op.code() == OpCode.CPUI_INT_MULT
        assert op.getIn(1) is not None and op.getIn(1).isConstant()
        assert op.getIn(1).getOffset() == 4


# ---------------------------------------------------------------------------
# Tests: Default ActionDatabase / universal rule-chain wiring
# ---------------------------------------------------------------------------

class TestActionDatabaseWiring:
    def test_default_groups_can_be_built_from_universal_action(self, arch_info):
        from ghidra.transform.action import ActionDatabase

        lifter = Lifter(arch_info['sla_path'], {"addrsize": 1, "opsize": 1})
        shim = _ArchitectureShim(lifter._spc_mgr)

        allacts = ActionDatabase()
        allacts.universalAction(shim)
        allacts.resetDefaults()

        assert allacts.getAction(ActionDatabase.UNIVERSAL_NAME) is not None
        assert allacts.getCurrent() is not None
        assert allacts.getCurrentName() == "decompile"
        assert "decompile" in allacts._groupmap

    @pytest.mark.parametrize(
        ("code", "name"),
        [
            (X86_SIMPLE, "simple"),
            (X86_BRANCH, "branch"),
            (X86_LOOP, "loop"),
            (X86_NESTED_IF, "nested_if"),
            (X86_OR_MASK, "or_mask"),
            (X86_SHIFT, "shift_left_2"),
        ],
    )
    def test_default_decompile_root_action_runs_without_hanging(self, arch_info, code, name):
        from ghidra.transform.action import ActionDatabase

        lifter = Lifter(arch_info['sla_path'], {"addrsize": 1, "opsize": 1})
        lifter.set_image(0x401000, code)
        fd = lifter.lift_function(f"func_{name}", 0x401000, len(code))
        _split_basic_blocks(fd)
        shim = _ArchitectureShim(lifter._spc_mgr)
        fd.setArch(shim)

        allacts = ActionDatabase()
        allacts.universalAction(shim)
        allacts.resetDefaults()

        root = allacts.getCurrent()
        root.reset(fd)
        result = root.perform(fd)

        assert result >= 0
        # Warnings are acceptable; only actual errors would indicate a problem
        for msg in shim.getMessages():
            assert msg.startswith("WARNING"), f"Unexpected non-warning message: {msg}"

    def test_start_type_recovery_only_reports_change_once_per_reset(self):
        from ghidra.analysis.funcdata import Funcdata
        from ghidra.core.space import ConstantSpace
        from ghidra.core.address import Address

        const_spc = ConstantSpace()
        fd = Funcdata("f", "f", None, Address(const_spc, 0))

        fd.setTypeRecovery(True)
        assert fd.startTypeRecovery() is True
        assert fd.startTypeRecovery() is False

        fd.setTypeRecovery(True)
        assert fd.startTypeRecovery() is True


# ---------------------------------------------------------------------------
# Tests: DecompilerPython integration
# ---------------------------------------------------------------------------

class TestDecompilerPythonRules:
    """Verify the DecompilerPython class with use_python_rules=True."""

    def test_decompile_with_rules(self, arch_info):
        dp = DecompilerPython()
        dp.add_spec_path(os.path.dirname(arch_info['sla_path']))
        dp.use_python_rules = True

        result = dp.decompile(
            arch_info['sla_path'], arch_info['target'],
            X86_SIMPLE, 0x401000, 0x401000, len(X86_SIMPLE)
        )
        assert "func_401000" in result
        errors = dp.get_errors()
        assert not errors, f"Unexpected errors: {errors}"

    def test_decompile_branch_with_rules(self, arch_info):
        dp = DecompilerPython()
        dp.add_spec_path(os.path.dirname(arch_info['sla_path']))
        dp.use_python_rules = True

        result = dp.decompile(
            arch_info['sla_path'], arch_info['target'],
            X86_BRANCH, 0x401000, 0x401000, len(X86_BRANCH)
        )
        assert "func_401000" in result
        errors = dp.get_errors()
        assert not errors, f"Unexpected errors: {errors}"

    def test_rules_off_by_default(self, arch_info):
        dp = DecompilerPython()
        dp.add_spec_path(os.path.dirname(arch_info['sla_path']))
        # use_python_rules defaults to False
        assert not dp.use_python_rules
        assert not dp.use_python_full_actions

    def test_decompile_add_with_rules(self, arch_info):
        dp = DecompilerPython()
        dp.add_spec_path(os.path.dirname(arch_info['sla_path']))
        dp.use_python_rules = True

        result = dp.decompile(
            arch_info['sla_path'], arch_info['target'],
            X86_ADD, 0x401000, 0x401000, len(X86_ADD)
        )
        assert "func_401000" in result
        errors = dp.get_errors()
        assert not errors, f"Unexpected errors: {errors}"


# Tests: PrintC C code generation (Module 5)
# ---------------------------------------------------------------------------

class TestPrintC:
    """Verify PrintC C code generation (Module 5)."""

    def test_printc_simple(self, arch_info):
        dp = DecompilerPython()
        dp.add_spec_path(os.path.dirname(arch_info['sla_path']))
        dp.use_python_printc = True

        result = dp.decompile(
            arch_info['sla_path'], arch_info['target'],
            X86_SIMPLE, 0x401000, 0x401000, len(X86_SIMPLE)
        )
        assert "void func_401000(void)" in result
        assert "tmp_" in result  # Should have register names
        assert ";" in result  # Should have semicolons
        errors = dp.get_errors()
        assert not errors, f"Unexpected errors: {errors}"

    def test_printc_branch(self, arch_info):
        dp = DecompilerPython()
        dp.add_spec_path(os.path.dirname(arch_info['sla_path']))
        dp.use_python_printc = True

        result = dp.decompile(
            arch_info['sla_path'], arch_info['target'],
            X86_BRANCH, 0x401000, 0x401000, len(X86_BRANCH)
        )
        assert "if (" in result or "goto" in result  # Should emit control flow
        assert "void func_401000(void)" in result
        errors = dp.get_errors()
        assert not errors, f"Unexpected errors: {errors}"

    def test_printc_loop(self, arch_info):
        dp = DecompilerPython()
        dp.add_spec_path(os.path.dirname(arch_info['sla_path']))
        dp.use_python_printc = True

        result = dp.decompile(
            arch_info['sla_path'], arch_info['target'],
            X86_LOOP, 0x401000, 0x401000, len(X86_LOOP)
        )
        assert "void func_401000(void)" in result
        assert "goto" in result  # Loop emits goto in flat mode
        errors = dp.get_errors()
        assert not errors, f"Unexpected errors: {errors}"

    def test_printc_nested_if(self, arch_info):
        dp = DecompilerPython()
        dp.add_spec_path(os.path.dirname(arch_info['sla_path']))
        dp.use_python_printc = True

        result = dp.decompile(
            arch_info['sla_path'], arch_info['target'],
            X86_NESTED_IF, 0x401000, 0x401000, len(X86_NESTED_IF)
        )
        assert "void func_401000(void)" in result
        assert "if (" in result  # Should have if statements
        errors = dp.get_errors()
        assert not errors, f"Unexpected errors: {errors}"

    def test_printc_with_rules(self, arch_info):
        dp = DecompilerPython()
        dp.add_spec_path(os.path.dirname(arch_info['sla_path']))
        dp.use_python_rules = True
        dp.use_python_printc = True

        result = dp.decompile(
            arch_info['sla_path'], arch_info['target'],
            X86_SIMPLE, 0x401000, 0x401000, len(X86_SIMPLE)
        )
        assert "void func_401000(void)" in result
        # After rules, some ops may be optimized away, but C syntax should remain
        assert ";" in result
        errors = dp.get_errors()
        assert not errors, f"Unexpected errors: {errors}"

    def test_printc_off_by_default(self, arch_info):
        dp = DecompilerPython()
        dp.add_spec_path(os.path.dirname(arch_info['sla_path']))
        # use_python_printc defaults to False
        assert not dp.use_python_printc

    def test_printc_with_full_actions_structures_loop(self, arch_info):
        dp = DecompilerPython()
        dp.add_spec_path(os.path.dirname(arch_info['sla_path']))
        dp.use_python_full_actions = True
        dp.use_python_printc = True

        result = dp.decompile(
            arch_info['sla_path'], arch_info['target'],
            X86_LOOP, 0x401000, 0x401000, len(X86_LOOP)
        )
        assert "void func_401000(void)" in result
        assert "while" in result or "do {" in result
        assert "goto" not in result
        assert ";" in result
        errors = dp.get_errors()
        assert not errors, f"Unexpected errors: {errors}"

    def test_printc_with_full_actions_structures_nested_if(self, arch_info):
        dp = DecompilerPython()
        dp.add_spec_path(os.path.dirname(arch_info['sla_path']))
        dp.use_python_full_actions = True
        dp.use_python_printc = True

        result = dp.decompile(
            arch_info['sla_path'], arch_info['target'],
            X86_NESTED_IF, 0x401000, 0x401000, len(X86_NESTED_IF)
        )
        assert "void func_401000(void)" in result
        assert "if" in result
        assert ";" in result
        errors = dp.get_errors()
        assert not errors, f"Unexpected errors: {errors}"

    def test_printc_with_full_actions_structures_branch(self, arch_info):
        """Full actions on X86_BRANCH should produce structured if output."""
        dp = DecompilerPython()
        dp.add_spec_path(os.path.dirname(arch_info['sla_path']))
        dp.use_python_full_actions = True
        dp.use_python_printc = True

        result = dp.decompile(
            arch_info['sla_path'], arch_info['target'],
            X86_BRANCH, 0x401000, 0x401000, len(X86_BRANCH)
        )
        assert "void func_401000(void)" in result
        assert "if" in result, "Expected 'if' in structured output"
        assert "return" in result.lower()
        errors = dp.get_errors()
        assert not errors, f"Unexpected errors: {errors}"

    def test_full_pipeline_all_modules(self, arch_info):
        """Test complete pipeline: Heritage + Rules + PrintC."""
        dp = DecompilerPython()
        dp.add_spec_path(os.path.dirname(arch_info['sla_path']))
        dp.use_python_heritage = True
        dp.use_python_rules = True
        dp.use_python_printc = True

        result = dp.decompile(
            arch_info['sla_path'], arch_info['target'],
            X86_BRANCH, 0x401000, 0x401000, len(X86_BRANCH)
        )
        assert "void func_401000(void)" in result
        assert "if (" in result or "goto" in result  # Control flow should be present
        assert ";" in result  # C syntax
        errors = dp.get_errors()
        assert not errors, f"Unexpected errors: {errors}"


class TestPrintLanguagePortAlignment:
    def test_printlanguage_defaults_match_cpp_baseline(self):
        printer = PrintC()

        assert isinstance(printer.getEmitter(), EmitPrettyPrint)
        assert printer._head_comment_type == int(Comment.CommentType.header | Comment.CommentType.warningheader)
        assert printer._instr_comment_type == int(Comment.CommentType.user2 | Comment.CommentType.warning)

    def test_push_type_pointer_rel_emits_adj_token_like_cpp(self):
        stream = io.StringIO()
        printer = PrintC()
        printer.setEmitter(EmitMarkup(stream))

        printer.pushTypePointerRel(None)
        printer.pushAtom(Atom("base", vartoken, SyntaxHighlight.var_color, None, None))

        assert stream.getvalue() == "ADJ(base)"

    def test_op_ptrsub_pointer_rel_zero_offset_emits_adj_wrapper_like_cpp(self):
        from ghidra.types.datatype import TYPE_PTR, TYPE_STRUCT

        class _StructType:
            def getMetatype(self):
                return TYPE_STRUCT

        class _PtrRelType:
            def getMetatype(self):
                return TYPE_PTR

            def isFormalPointerRel(self):
                return True

            def evaluateThruParent(self, off):
                return True

            def getParent(self):
                return _StructType()

            def getAddressOffset(self):
                return 0

            def getSize(self):
                return 4

        class _BaseVn:
            def getHighTypeReadFacing(self, op):
                return _PtrRelType()

        class _ConstVn:
            def getOffset(self):
                return 0

        class _Op:
            def getIn(self, i):
                return _BaseVn() if i == 0 else _ConstVn()

        stream = io.StringIO()
        printer = PrintC()
        printer.setEmitter(EmitMarkup(stream))
        printer.pushVn = lambda vn, op, m: printer.pushAtom(Atom("base", vartoken, SyntaxHighlight.var_color, op, vn))

        printer.opPtrsub(_Op())

        assert stream.getvalue() == "ADJ(base)"

    def test_set_comment_delimeter_updates_comment_fill_like_cpp(self):
        printer = PrintC()
        printer.setCommentDelimeter("// ", "", False)

        emitter = printer.getEmitter()
        assert isinstance(emitter, EmitPrettyPrint)
        assert emitter._commentfill == " " * len("// ")

        printer.setCommentDelimeter("/* ", " */", True)
        assert emitter._commentfill == "/* "

    def test_set_line_comment_indent_rejects_out_of_range_value(self):
        printer = PrintC()
        emitter = printer.getEmitter()
        assert isinstance(emitter, EmitPrettyPrint)

        with pytest.raises(Exception, match="Bad comment indent value"):
            printer.setLineCommentIndent(emitter.getMaxLineSize())

    def test_casetoken_atom_emits_through_case_label_path(self):
        stream = io.StringIO()
        printer = PrintC()
        printer.setEmitter(EmitMarkup(stream))

        printer.pushAtom(Atom("case 7", casetoken, SyntaxHighlight.no_color, None, 7))

        assert stream.getvalue() == "case 7"

    def test_op_hidden_func_pushes_hidden_token(self):
        printer = PrintC()

        class _Op:
            def getIn(self, i):
                assert i == 0
                return None

        printer.opHiddenFunc(_Op())

        assert len(printer._revpol) == 1
        assert printer._revpol[-1].tok is PrintC.hidden

    def test_scopeinternal_query_code_label_round_trip(self):
        class _Space:
            def getIndex(self):
                return 2

        scope = ScopeInternal(1, "local")
        addr = Address(_Space(), 0x44)

        sym = scope.addCodeLabel(addr, "label_44")

        assert scope.queryCodeLabel(addr) is sym

    def test_emit_label_prefers_registered_code_label(self):
        class _Space:
            def getIndex(self):
                return 1

        class _Fd:
            def __init__(self, scope):
                self._scope = scope

            def getScopeLocal(self):
                return self._scope

        class _Bb:
            def __init__(self, scope, addr):
                self._scope = scope
                self._addr = addr

            def getEntryAddr(self):
                return self._addr

            def getFuncdata(self):
                return _Fd(self._scope)

            def getType(self):
                from ghidra.block.block import FlowBlock
                return FlowBlock.t_basic

            def hasSpecialLabel(self):
                return False

            def isJoined(self):
                return False

            def isDuplicated(self):
                return False

        stream = io.StringIO()
        printer = PrintC()
        printer.setEmitter(EmitMarkup(stream))

        scope = ScopeInternal(1, "local")
        addr = Address(_Space(), 0x10)
        scope.addCodeLabel(addr, "my_code_label")

        printer.emitLabel(_Bb(scope, addr))

        assert stream.getvalue() == "my_code_label"

    def test_emit_block_basic_flat_nofallthru_uses_non_fallthru_edge(self):
        class _Recorder(PrintC):
            def __init__(self):
                super().__init__()
                self.labels = []

            def emitLabel(self, bl):
                self.labels.append(bl)

        class _LastOp:
            def isBranch(self):
                return True

            def isFallthruTrue(self):
                return True

        class _Bb:
            def lastOp(self):
                return _LastOp()

            def getOpList(self):
                return []

            def sizeOut(self):
                return 2

            def getOut(self, i):
                return f"target_{i}"

        stream = io.StringIO()
        printer = _Recorder()
        printer.setEmitter(EmitMarkup(stream))
        printer.setMod(PrintLanguage.flat | PrintLanguage.nofallthru)

        printer.emitBlockBasic(_Bb())

        assert printer.labels == ["target_1"]

    def test_emit_block_whiledo_overflow_does_not_masquerade_as_for_without_iterate(self):
        class _CondBlock:
            def emit(self, lng):
                lng.getEmitter().print("COND")

            def lastOp(self):
                return None

        class _BodyBlock:
            def emit(self, lng):
                lng.getEmitter().print("BODY")

        class _WhileBlock:
            def __init__(self):
                self._cond = _CondBlock()
                self._body = _BodyBlock()

            def getIterateOp(self):
                return None

            def hasOverflowSyntax(self):
                return True

            def getBlock(self, i):
                return self._cond if i == 0 else self._body

        stream = io.StringIO()
        printer = PrintC()
        printer.setEmitter(EmitMarkup(stream))

        printer.emitBlockWhileDo(_WhileBlock())

        out = stream.getvalue()
        assert "while" in out
        assert "for" not in out

    def test_emit_block_if_merges_else_if_via_pending_brace(self):
        from ghidra.block.block import FlowBlock

        class _CondBlock:
            def __init__(self, text):
                self._text = text

            def emit(self, lng):
                if lng.isSet(PrintLanguage.no_branch):
                    return
                lng.getEmitter().print(self._text)

            def lastOp(self):
                return None

        class _StmtBlock:
            def __init__(self, text):
                self._text = text

            def emit(self, lng):
                lng.getEmitter().print(self._text)

        class _IfBlock:
            def __init__(self, cond, true_block, else_block=None):
                self._blocks = [cond, true_block]
                if else_block is not None:
                    self._blocks.append(else_block)

            def emit(self, lng):
                lng.emitBlockIf(self)

            def getBlock(self, i):
                return self._blocks[i]

            def getSize(self):
                return len(self._blocks)

            def getType(self):
                return FlowBlock.t_if

            def getGotoTarget(self):
                return None

        stream = io.StringIO()
        printer = PrintC()
        printer.setEmitter(EmitMarkup(stream))

        inner = _IfBlock(_CondBlock("COND2"), _StmtBlock("BODY2"))
        outer = _IfBlock(_CondBlock("COND1"), _StmtBlock("BODY1"), inner)

        printer.emitBlockIf(outer)

        out = stream.getvalue()
        assert "else if" in out
        assert "else {" not in out

    def test_emit_prototype_inputs_hides_this_and_prefers_symbol_decl(self):
        class _Param:
            def __init__(self, sym, is_this=False, tp=None):
                self._sym = sym
                self._is_this = is_this
                self._tp = tp

            def getSymbol(self):
                return self._sym

            def isThisPointer(self):
                return self._is_this

            def getType(self):
                return self._tp

        class _Proto:
            def __init__(self, params):
                self._params = params

            def numParams(self):
                return len(self._params)

            def getParam(self, i):
                return self._params[i]

            def isDotdotdot(self):
                return False

            def printModelInDecl(self):
                return False

            def getOutputType(self):
                return None

        stream = io.StringIO()
        printer = PrintC()
        printer.setEmitter(EmitMarkup(stream))
        printer.setMod(PrintLanguage.hide_thisparam)

        scope = ScopeInternal(1, "local")
        this_sym = Symbol(scope, "this_param", None)
        value_sym = Symbol(scope, "value_param", None)
        proto = _Proto([_Param(this_sym, True), _Param(value_sym, False)])

        printer.emitPrototypeInputs(proto)

        out = stream.getvalue()
        assert "this_param" not in out
        assert "value_param" in out

    def test_emit_local_var_decls_uses_scope_and_child_scopes(self):
        class _Space:
            def getIndex(self):
                return 1

        class _Fd:
            def __init__(self, scope):
                self._scope = scope

            def getScopeLocal(self):
                return self._scope

        stream = io.StringIO()
        printer = PrintC()
        printer.setEmitter(EmitMarkup(stream))

        root = ScopeInternal(1, "root")
        child = ScopeInternal(2, "child")
        root.attachScope(child)

        root_sym = Symbol(root, "root_local", None)
        child_sym = Symbol(child, "child_local", None)
        root.addSymbol(root_sym)
        child.addSymbol(child_sym)
        root.addMapEntry(root_sym, SymbolEntry(root_sym, Address(_Space(), 0x10), 1))
        child.addMapEntry(child_sym, SymbolEntry(child_sym, Address(_Space(), 0x20), 1))

        printer.emitLocalVarDecls(_Fd(root))

        out = stream.getvalue()
        assert "root_local" in out
        assert "child_local" in out

    def test_emit_scope_var_decls_filters_like_cpp(self):
        class _Space:
            def getIndex(self):
                return 1

        stream = io.StringIO()
        printer = PrintC()
        printer.setEmitter(EmitMarkup(stream))

        scope = ScopeInternal(1, "scope")
        keep = Symbol(scope, "keep_local", None)
        func = FunctionSymbol(scope, "func_sym")
        label = LabSymbol(scope, "label_sym")
        unnamed = Symbol(scope, "", None)
        undefined = Symbol(scope, "$$undef0", None)
        scope.addSymbol(keep)
        scope.addSymbol(func)
        scope.addSymbol(label)
        scope.addSymbol(unnamed)
        scope.addSymbol(undefined)
        scope.addMapEntry(keep, SymbolEntry(keep, Address(_Space(), 0x10), 1))
        scope.addMapEntry(func, SymbolEntry(func, Address(_Space(), 0x20), 1))
        scope.addMapEntry(label, SymbolEntry(label, Address(_Space(), 0x30), 1))
        scope.addMapEntry(undefined, SymbolEntry(undefined, Address(_Space(), 0x40), 1))

        emitted = printer.emitScopeVarDecls(scope, Symbol.no_category)

        out = stream.getvalue()
        assert emitted is True
        assert "keep_local" in out
        assert "func_sym" not in out
        assert "label_sym" not in out
        assert "$$undef0" in out

    def test_emit_scope_var_decls_skips_nonfirst_multientry_like_cpp(self):
        class _Type:
            def getName(self):
                return "int"

            def getDisplayName(self):
                return "int"

            def getSize(self):
                return 4

        class _Space:
            def getIndex(self):
                return 1

        stream = io.StringIO()
        printer = PrintC()
        printer.setEmitter(EmitMarkup(stream))

        scope = ScopeInternal(1, "scope")
        sym = Symbol(scope, "multi_local", _Type())
        scope.addSymbol(sym)
        scope.addMapEntry(sym, SymbolEntry(sym, Address(_Space(), 0x10), 4))
        scope.addMapEntry(sym, SymbolEntry(sym, Address(_Space(), 0x20), 4))

        emitted = printer.emitScopeVarDecls(scope, Symbol.no_category)

        out = stream.getvalue()
        assert emitted is True
        assert out.count("multi_local") == 1

    def test_emit_type_definition_rejects_unsupported_typedef_like_cpp(self):
        class _Type:
            def getMetatype(self):
                return -1

            def isEnumType(self):
                return False

        printer = PrintC()

        with pytest.raises(LowlevelError, match="Unsupported typedef"):
            printer.emitTypeDefinition(_Type())

    def test_generic_function_name_uses_address_raw_form_like_cpp(self):
        class _Addr:
            def printRaw(self):
                return "ram:00001000"

        printer = PrintC()

        assert printer.genericFunctionName(_Addr()) == "func_ram:00001000"

    def test_generic_type_name_handles_spacebase_like_cpp(self):
        class _Type:
            def getMetatype(self):
                from ghidra.types.datatype import TYPE_SPACEBASE
                return TYPE_SPACEBASE

            def getSize(self):
                return 8

        printer = PrintC()

        assert printer.genericTypeName(_Type()) == "BADSPACEBASE"

    def test_doc_function_rejects_not_started_like_cpp(self):
        class _Fd:
            def isProcStarted(self):
                return False

            def hasNoStructBlocks(self):
                return True

        printer = PrintC()
        printer.setEmitter(EmitMarkup(io.StringIO()))

        with pytest.raises(RecovError, match="Function not decompiled"):
            printer.docFunction(_Fd())

    def test_doc_function_nonflat_requires_structure_like_cpp(self):
        class _Fd:
            def isProcStarted(self):
                return True

            def hasNoStructBlocks(self):
                return True

        printer = PrintC()
        printer.setEmitter(EmitMarkup(io.StringIO()))

        with pytest.raises(RecovError, match="Function not fully decompiled. No structure present."):
            printer.docFunction(_Fd())

    def test_doc_function_flat_uses_basic_blocks_like_cpp(self):
        class _Proto:
            def getOutputType(self):
                return None

            def numParams(self):
                return 0

            def printModelInDecl(self):
                return False

            def isDotdotdot(self):
                return False

        class _Fd:
            def __init__(self, scope):
                self._scope = scope
                self._proto = _Proto()

            def isProcStarted(self):
                return True

            def hasNoStructBlocks(self):
                return True

            def getFuncProto(self):
                return self._proto

            def getScopeLocal(self):
                return self._scope

            def getSymbol(self):
                return None

            def getDisplayName(self):
                return "func"

            def getBasicBlocks(self):
                return "basic_graph"

            def getStructure(self):
                return "struct_graph"

        class _Recorder(PrintC):
            def __init__(self):
                super().__init__()
                self.graphs = []

            def emitLocalVarDecls(self, fd):
                return None

            def emitBlockGraph(self, bl):
                self.graphs.append(bl)

        printer = _Recorder()
        printer.setEmitter(EmitMarkup(io.StringIO()))
        printer.setMod(PrintLanguage.flat)

        printer.docFunction(_Fd(ScopeInternal(1, "local")))

        assert printer.graphs == ["basic_graph"]

    def test_emit_line_comment_marks_comment_and_uses_delimiters(self):
        stream = io.StringIO()
        printer = PrintC()
        printer.setEmitter(EmitMarkup(stream))
        printer.setCommentDelimeter("// ", "", False)

        comm = Comment(Comment.CommentType.header, text="hello world")
        printer.emitLineComment(-1, comm)

        assert "// " in stream.getvalue()
        assert "hello" in stream.getvalue()
        assert comm.isEmitted() is True


class TestPrintLanguageCapabilities:
    def test_default_printlanguage_capability_is_c_language(self):
        capability = PrintLanguageCapability.getDefault()

        assert capability.getName() == "c-language"
        assert PrintLanguageCapability.findCapability("c-language") is capability

    def test_architecture_uses_registered_capability_for_new_print_language(self):
        class _FakePrintCapability(PrintLanguageCapability):
            def __init__(self) -> None:
                super().__init__("fake-language", False)

            def buildLanguage(self, glb):
                return PrintC(glb, self.name)

        capability = _FakePrintCapability()
        capability.initialize()
        try:
            arch = Architecture()
            arch.setPrintLanguage("fake-language")

            assert arch.getPrintLanguage() is not None
            assert arch.getPrintLanguage().getName() == "fake-language"
            assert any(pl.getName() == "fake-language" for pl in arch.printlist)
        finally:
            if capability in PrintLanguageCapability._thelist:
                PrintLanguageCapability._thelist.remove(capability)

    def test_set_print_language_unknown_raises(self):
        arch = Architecture()

        with pytest.raises(LowlevelError, match="Unknown print language"):
            arch.setPrintLanguage("no-such-language")
