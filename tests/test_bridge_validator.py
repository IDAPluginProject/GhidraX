"""
Test: Bridge A — Snapshot comparison between C++ and Python decompiler pipelines.

Validates that:
1. C++ decompile_staged() returns structured IR snapshots
2. Python pipeline produces comparable IR snapshots
3. BridgeValidator detects matches and differences
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

import pytest
from ghidra.sleigh.arch_map import resolve_arch
from ghidra.core.opcodes import OpCode
from pattern_corpus import X86_SIMPLE, X86_BRANCH

try:
    from ghidra.sleigh.decompiler_native import DecompilerNative
    HAS_NATIVE = True
except ImportError:
    HAS_NATIVE = False

try:
    from ghidra.sleigh.bridge_validator import (
        BridgeValidator, IrSnapshot, NBlock, NOp, NVarnode, _compare_snapshots
    )
    HAS_BRIDGE = True
except ImportError:
    HAS_BRIDGE = False

pytestmark = pytest.mark.skipif(
    not (HAS_NATIVE and HAS_BRIDGE),
    reason="decompiler_native or bridge_validator not available"
)


@pytest.fixture(scope="module")
def arch32():
    return resolve_arch("metapc", 32, False)


@pytest.fixture(scope="module")
def native(arch32):
    d = DecompilerNative()
    spec_dir = os.path.dirname(arch32["sla_path"])
    d.add_spec_path(spec_dir)
    d.initialize()
    return d


# ---- C++ decompile_staged() basic tests ----

class TestCppStagedApi:
    """Verify the C++ decompile_staged() method works."""

    def test_staged_flow_returns_dict(self, native, arch32):
        result = native.decompile_staged(
            arch32["sla_path"], arch32["target"],
            X86_SIMPLE, 0x401000, 0x401000, len(X86_SIMPLE),
            "flow"
        )
        assert isinstance(result, dict)
        assert result["stage"] == "flow"
        assert "ir" in result

    def test_staged_flow_has_blocks(self, native, arch32):
        result = native.decompile_staged(
            arch32["sla_path"], arch32["target"],
            X86_SIMPLE, 0x401000, 0x401000, len(X86_SIMPLE),
            "flow"
        )
        ir = result["ir"]
        assert "blocks" in ir
        assert "num_blocks" in ir
        assert ir["num_blocks"] >= 1

    def test_staged_flow_block_has_ops(self, native, arch32):
        result = native.decompile_staged(
            arch32["sla_path"], arch32["target"],
            X86_SIMPLE, 0x401000, 0x401000, len(X86_SIMPLE),
            "flow"
        )
        blocks = result["ir"]["blocks"]
        assert len(blocks) >= 1
        block0 = blocks[0]
        assert "ops" in block0
        assert "start" in block0
        assert "stop" in block0
        assert "successors" in block0
        assert "predecessors" in block0

    def test_staged_flow_op_has_fields(self, native, arch32):
        result = native.decompile_staged(
            arch32["sla_path"], arch32["target"],
            X86_SIMPLE, 0x401000, 0x401000, len(X86_SIMPLE),
            "flow"
        )
        ops = result["ir"]["blocks"][0]["ops"]
        assert len(ops) >= 1
        op = ops[0]
        assert "opcode" in op
        assert "addr" in op
        assert "inputs" in op

    def test_staged_heritage_returns_dict(self, native, arch32):
        result = native.decompile_staged(
            arch32["sla_path"], arch32["target"],
            X86_SIMPLE, 0x401000, 0x401000, len(X86_SIMPLE),
            "heritage"
        )
        assert result["stage"] == "heritage"
        assert "ir" in result

    def test_staged_full_returns_c_code(self, native, arch32):
        result = native.decompile_staged(
            arch32["sla_path"], arch32["target"],
            X86_SIMPLE, 0x401000, 0x401000, len(X86_SIMPLE),
            "full"
        )
        assert result["stage"] == "full"
        assert "c_code" in result
        assert len(result["c_code"]) > 0

    def test_staged_branch_has_multiple_blocks(self, native, arch32):
        result = native.decompile_staged(
            arch32["sla_path"], arch32["target"],
            X86_BRANCH, 0x401000, 0x401000, len(X86_BRANCH),
            "flow"
        )
        assert result["ir"]["num_blocks"] >= 2


# ---- BridgeValidator comparison tests ----

class TestBridgeDiffClassification:
    """Verify structured diff categories and expected diff tagging."""

    def test_expected_opcode_diff_is_classified(self):
        cpp_op = NOp(OpCode.CPUI_CALL.value, 0x401000, 0, None, [NVarnode("ram", 0x401010, 1)])
        py_op = NOp(OpCode.CPUI_BRANCH.value, 0x401000, 0, None, [NVarnode("ram", 0x401010, 1)])

        cpp_snap = IrSnapshot(
            source="cpp", stage="flow",
            blocks=[NBlock(0, 0x401000, 0x401000, [], [], [cpp_op], 1)],
            num_blocks=1,
            all_ops=[cpp_op],
            num_ops=1,
        )
        py_snap = IrSnapshot(
            source="python", stage="flow",
            blocks=[NBlock(0, 0x401000, 0x401000, [], [], [py_op], 1)],
            num_blocks=1,
            all_ops=[py_op],
            num_ops=1,
        )

        diff = _compare_snapshots(cpp_snap, py_snap, "flow")

        assert diff.is_match
        assert "opcode" in diff.expected_diffs
        assert len(diff.expected_diffs["opcode"]) == 1
        assert not diff.op_diffs
        assert "Expected diff categories: opcode=1" in diff.summary_lines

    def test_unexpected_edge_and_varnode_diffs_are_classified(self):
        cpp_op = NOp(1, 0x401000, 0, NVarnode("register", 0, 4), [NVarnode("const", 1, 4)])
        py_op = NOp(1, 0x401000, 0, NVarnode("register", 0, 4), [NVarnode("const", 2, 4)])

        cpp_snap = IrSnapshot(
            source="cpp", stage="flow",
            blocks=[NBlock(0, 0x401000, 0x401000, [1], [], [cpp_op], 1)],
            num_blocks=1,
            all_ops=[cpp_op],
            num_ops=1,
        )
        py_snap = IrSnapshot(
            source="python", stage="flow",
            blocks=[NBlock(0, 0x401000, 0x401000, [2], [], [py_op], 1)],
            num_blocks=1,
            all_ops=[py_op],
            num_ops=1,
        )

        diff = _compare_snapshots(cpp_snap, py_snap, "flow")

        assert not diff.is_match
        assert "edge" in diff.categorized_diffs
        assert "varnode" in diff.categorized_diffs
        assert len(diff.block_diffs) == 1
        assert len(diff.op_diffs) == 1
        assert any("Unexpected diff categories:" in line for line in diff.summary_lines)


class TestBridgeValidator:
    """Verify the BridgeValidator can compare C++ and Python pipelines."""

    @pytest.fixture(scope="class")
    def validator(self, arch32):
        spec_dir = os.path.dirname(arch32["sla_path"])
        return BridgeValidator(spec_dir=spec_dir)

    def test_compare_flow_simple(self, validator, arch32):
        report = validator.compare(
            sla_path=arch32["sla_path"],
            target=arch32["target"],
            image=X86_SIMPLE,
            base_addr=0x401000,
            entry=0x401000,
            func_size=len(X86_SIMPLE),
            stages=["flow"],
        )
        assert "flow" in report.stage_diffs
        diff = report.stage_diffs["flow"]
        # Print report for debugging
        print(report.summary())
        # Block count should match
        assert diff.block_count_match, f"Block count mismatch: {diff.summary_lines}"

    def test_compare_flow_branch(self, validator, arch32):
        report = validator.compare(
            sla_path=arch32["sla_path"],
            target=arch32["target"],
            image=X86_BRANCH,
            base_addr=0x401000,
            entry=0x401000,
            func_size=len(X86_BRANCH),
            stages=["flow"],
        )
        print(report.summary())
        assert "flow" in report.stage_diffs
        diff = report.stage_diffs["flow"]
        # At minimum, both should detect multiple blocks
        cpp_snap = report.cpp_snapshots["flow"]
        py_snap = report.py_snapshots["flow"]
        assert cpp_snap.num_blocks >= 2, f"C++ should have >=2 blocks, got {cpp_snap.num_blocks}"
        assert py_snap.num_blocks >= 2, f"Python should have >=2 blocks, got {py_snap.num_blocks}"

    def test_compare_report_summary(self, validator, arch32):
        report = validator.compare(
            sla_path=arch32["sla_path"],
            target=arch32["target"],
            image=X86_SIMPLE,
            base_addr=0x401000,
            entry=0x401000,
            func_size=len(X86_SIMPLE),
            stages=["flow"],
        )
        summary = report.summary()
        assert "Bridge Validator Report" in summary
        assert "flow" in summary

    def test_compare_report_exposes_categorized_diffs(self, validator, arch32):
        report = validator.compare(
            sla_path=arch32["sla_path"],
            target=arch32["target"],
            image=X86_BRANCH,
            base_addr=0x401000,
            entry=0x401000,
            func_size=len(X86_BRANCH),
            stages=["flow"],
        )
        diff = report.stage_diffs["flow"]
        assert isinstance(diff.categorized_diffs, dict)
        assert isinstance(diff.expected_diffs, dict)
        assert isinstance(diff.diff_records, list)

    def test_compare_heritage_runs(self, validator, arch32):
        """Heritage stage should at least run without crashing."""
        report = validator.compare(
            sla_path=arch32["sla_path"],
            target=arch32["target"],
            image=X86_SIMPLE,
            base_addr=0x401000,
            entry=0x401000,
            func_size=len(X86_SIMPLE),
            stages=["heritage"],
        )
        print(report.summary())
        # Should have heritage results (even if they differ)
        assert "heritage" in report.stage_diffs or report.errors

    def test_compare_full_has_c_code(self, validator, arch32):
        """Full stage should produce C code from C++ pipeline."""
        report = validator.compare(
            sla_path=arch32["sla_path"],
            target=arch32["target"],
            image=X86_SIMPLE,
            base_addr=0x401000,
            entry=0x401000,
            func_size=len(X86_SIMPLE),
            stages=["full"],
        )
        if "full" in report.cpp_snapshots:
            assert len(report.cpp_snapshots["full"].c_code) > 0
