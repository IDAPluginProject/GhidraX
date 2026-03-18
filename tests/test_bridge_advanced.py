"""
Test: Advanced FlowInfo matching — loops, calls, switch-like patterns.

Uses the BridgeValidator to compare C++ and Python flow analysis
on progressively more complex x86-32 code patterns.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

import pytest
from ghidra.sleigh.arch_map import resolve_arch
from pattern_corpus import (
    CODE_LINEAR, CODE_IFELSE, CODE_LOOP, CODE_CALL, CODE_NESTED_IF, CODE_DOWHILE
)

try:
    from ghidra.sleigh.bridge_validator import BridgeValidator
    HAS_BRIDGE = True
except ImportError:
    HAS_BRIDGE = False

pytestmark = pytest.mark.skipif(not HAS_BRIDGE, reason="bridge not available")


@pytest.fixture(scope="module")
def arch32():
    return resolve_arch("metapc", 32, False)


@pytest.fixture(scope="module")
def validator(arch32):
    spec_dir = os.path.dirname(arch32["sla_path"])
    return BridgeValidator(spec_dir=spec_dir)


# ---- Tests ----

class TestFlowMatchLinear:
    def test_linear_flow_match(self, validator, arch32):
        report = validator.compare(
            sla_path=arch32["sla_path"], target=arch32["target"],
            image=CODE_LINEAR, base_addr=0x401000, entry=0x401000,
            func_size=len(CODE_LINEAR), stages=["flow"]
        )
        diff = report.stage_diffs["flow"]
        assert diff.block_count_match, f"Block count: {diff.summary_lines}"
        assert diff.op_count_match, f"Op count: {diff.summary_lines}"
        assert diff.is_match, f"Diffs found:\n{report.summary()}"


class TestFlowMatchIfElse:
    def test_ifelse_flow_match(self, validator, arch32):
        report = validator.compare(
            sla_path=arch32["sla_path"], target=arch32["target"],
            image=CODE_IFELSE, base_addr=0x401000, entry=0x401000,
            func_size=len(CODE_IFELSE), stages=["flow"]
        )
        diff = report.stage_diffs["flow"]
        assert diff.block_count_match, f"Block count: {diff.summary_lines}"
        assert diff.op_count_match, f"Op count: {diff.summary_lines}"
        assert diff.is_match, f"Diffs found:\n{report.summary()}"


class TestFlowMatchLoop:
    def test_loop_flow_block_count(self, validator, arch32):
        report = validator.compare(
            sla_path=arch32["sla_path"], target=arch32["target"],
            image=CODE_LOOP, base_addr=0x401000, entry=0x401000,
            func_size=len(CODE_LOOP), stages=["flow"]
        )
        diff = report.stage_diffs["flow"]
        print(report.summary())
        assert diff.block_count_match, f"Block count: {diff.summary_lines}"
        assert diff.op_count_match, f"Op count: {diff.summary_lines}"

    def test_loop_flow_match(self, validator, arch32):
        report = validator.compare(
            sla_path=arch32["sla_path"], target=arch32["target"],
            image=CODE_LOOP, base_addr=0x401000, entry=0x401000,
            func_size=len(CODE_LOOP), stages=["flow"]
        )
        diff = report.stage_diffs["flow"]
        assert diff.is_match, f"Diffs found:\n{report.summary()}"


class TestFlowMatchCall:
    def test_call_flow_block_count(self, validator, arch32):
        report = validator.compare(
            sla_path=arch32["sla_path"], target=arch32["target"],
            image=CODE_CALL, base_addr=0x401000, entry=0x401000,
            func_size=len(CODE_CALL), stages=["flow"]
        )
        diff = report.stage_diffs["flow"]
        print(report.summary())
        assert diff.block_count_match, f"Block count: {diff.summary_lines}"

    def test_call_flow_op_count(self, validator, arch32):
        report = validator.compare(
            sla_path=arch32["sla_path"], target=arch32["target"],
            image=CODE_CALL, base_addr=0x401000, entry=0x401000,
            func_size=len(CODE_CALL), stages=["flow"]
        )
        diff = report.stage_diffs["flow"]
        assert diff.op_count_match, f"Op count: {diff.summary_lines}"


class TestFlowMatchNestedIf:
    def test_nested_if_block_count(self, validator, arch32):
        report = validator.compare(
            sla_path=arch32["sla_path"], target=arch32["target"],
            image=CODE_NESTED_IF, base_addr=0x401000, entry=0x401000,
            func_size=len(CODE_NESTED_IF), stages=["flow"]
        )
        diff = report.stage_diffs["flow"]
        print(report.summary())
        assert diff.block_count_match, f"Block count: {diff.summary_lines}"

    def test_nested_if_match(self, validator, arch32):
        report = validator.compare(
            sla_path=arch32["sla_path"], target=arch32["target"],
            image=CODE_NESTED_IF, base_addr=0x401000, entry=0x401000,
            func_size=len(CODE_NESTED_IF), stages=["flow"]
        )
        diff = report.stage_diffs["flow"]
        assert diff.is_match, f"Diffs found:\n{report.summary()}"


class TestFlowMatchDoWhile:
    def test_dowhile_block_count(self, validator, arch32):
        report = validator.compare(
            sla_path=arch32["sla_path"], target=arch32["target"],
            image=CODE_DOWHILE, base_addr=0x401000, entry=0x401000,
            func_size=len(CODE_DOWHILE), stages=["flow"]
        )
        diff = report.stage_diffs["flow"]
        print(report.summary())
        assert diff.block_count_match, f"Block count: {diff.summary_lines}"

    def test_dowhile_match(self, validator, arch32):
        report = validator.compare(
            sla_path=arch32["sla_path"], target=arch32["target"],
            image=CODE_DOWHILE, base_addr=0x401000, entry=0x401000,
            func_size=len(CODE_DOWHILE), stages=["flow"]
        )
        diff = report.stage_diffs["flow"]
        assert diff.is_match, f"Diffs found:\n{report.summary()}"
