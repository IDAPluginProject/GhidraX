"""Tests for ruleaction_batch2d rules and universal action completeness."""
import pytest
import sys
import os
import re

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))


class TestBatch2dRuleInstantiation:
    """Verify all batch2d rules can be instantiated, cloned, and have correct opLists."""

    RULE_CLASSES = [
        'RuleOrPredicate', 'RuleSubfloatConvert',
        'RuleDoubleLoad', 'RuleDoubleStore', 'RuleDoubleIn', 'RuleDoubleOut',
        'RuleDumptyHumpLate',
        'RuleSplitCopy', 'RuleSplitLoad', 'RuleSplitStore',
        'RuleStringCopy', 'RuleStringStore',
        'RuleSubvarAnd', 'RuleSubvarSubpiece', 'RuleSplitFlow',
        'RuleSubvarCompZero', 'RuleSubvarShift', 'RuleSubvarZext', 'RuleSubvarSext',
    ]

    @pytest.fixture
    def batch2d(self):
        from ghidra.transform import ruleaction_batch2d
        return ruleaction_batch2d

    @pytest.mark.parametrize("cls_name", RULE_CLASSES)
    def test_instantiate(self, batch2d, cls_name):
        cls = getattr(batch2d, cls_name)
        inst = cls("testgroup")
        assert inst is not None

    @pytest.mark.parametrize("cls_name", RULE_CLASSES)
    def test_getOpList_nonempty(self, batch2d, cls_name):
        cls = getattr(batch2d, cls_name)
        inst = cls("testgroup")
        ops = inst.getOpList()
        assert isinstance(ops, list)
        assert len(ops) > 0

    @pytest.mark.parametrize("cls_name", RULE_CLASSES)
    def test_clone_with_matching_group(self, batch2d, cls_name):
        cls = getattr(batch2d, cls_name)
        inst = cls("testgroup")

        class FakeGL:
            def contains(self, g):
                return True
        clone = inst.clone(FakeGL())
        assert clone is not None
        assert type(clone).__name__ == cls_name

    @pytest.mark.parametrize("cls_name", RULE_CLASSES)
    def test_clone_with_nonmatching_group(self, batch2d, cls_name):
        cls = getattr(batch2d, cls_name)
        inst = cls("testgroup")

        class FakeGL:
            def contains(self, g):
                return False
        clone = inst.clone(FakeGL())
        assert clone is None


class TestBatch2dOpListCorrectness:
    """Verify each rule's opList matches the C++ definition."""

    def test_rule_or_predicate_ops(self):
        from ghidra.transform.ruleaction_batch2d import RuleOrPredicate
        from ghidra.core.opcodes import OpCode
        ops = RuleOrPredicate("t").getOpList()
        assert OpCode.CPUI_INT_OR in ops
        assert OpCode.CPUI_INT_XOR in ops

    def test_rule_subfloat_convert_ops(self):
        from ghidra.transform.ruleaction_batch2d import RuleSubfloatConvert
        from ghidra.core.opcodes import OpCode
        assert RuleSubfloatConvert("t").getOpList() == [OpCode.CPUI_FLOAT_FLOAT2FLOAT]

    def test_rule_double_load_ops(self):
        from ghidra.transform.ruleaction_batch2d import RuleDoubleLoad
        from ghidra.core.opcodes import OpCode
        assert RuleDoubleLoad("t").getOpList() == [OpCode.CPUI_PIECE]

    def test_rule_double_store_ops(self):
        from ghidra.transform.ruleaction_batch2d import RuleDoubleStore
        from ghidra.core.opcodes import OpCode
        assert RuleDoubleStore("t").getOpList() == [OpCode.CPUI_STORE]

    def test_rule_double_in_ops(self):
        from ghidra.transform.ruleaction_batch2d import RuleDoubleIn
        from ghidra.core.opcodes import OpCode
        assert RuleDoubleIn("t").getOpList() == [OpCode.CPUI_SUBPIECE]

    def test_rule_double_out_ops(self):
        from ghidra.transform.ruleaction_batch2d import RuleDoubleOut
        from ghidra.core.opcodes import OpCode
        assert RuleDoubleOut("t").getOpList() == [OpCode.CPUI_PIECE]

    def test_rule_dumpty_hump_late_ops(self):
        from ghidra.transform.ruleaction_batch2d import RuleDumptyHumpLate
        from ghidra.core.opcodes import OpCode
        assert RuleDumptyHumpLate("t").getOpList() == [OpCode.CPUI_SUBPIECE]

    def test_rule_split_copy_ops(self):
        from ghidra.transform.ruleaction_batch2d import RuleSplitCopy
        from ghidra.core.opcodes import OpCode
        assert RuleSplitCopy("t").getOpList() == [OpCode.CPUI_COPY]

    def test_rule_split_load_ops(self):
        from ghidra.transform.ruleaction_batch2d import RuleSplitLoad
        from ghidra.core.opcodes import OpCode
        assert RuleSplitLoad("t").getOpList() == [OpCode.CPUI_LOAD]

    def test_rule_split_store_ops(self):
        from ghidra.transform.ruleaction_batch2d import RuleSplitStore
        from ghidra.core.opcodes import OpCode
        assert RuleSplitStore("t").getOpList() == [OpCode.CPUI_STORE]

    def test_rule_string_copy_ops(self):
        from ghidra.transform.ruleaction_batch2d import RuleStringCopy
        from ghidra.core.opcodes import OpCode
        assert RuleStringCopy("t").getOpList() == [OpCode.CPUI_COPY]

    def test_rule_string_store_ops(self):
        from ghidra.transform.ruleaction_batch2d import RuleStringStore
        from ghidra.core.opcodes import OpCode
        assert RuleStringStore("t").getOpList() == [OpCode.CPUI_STORE]

    def test_rule_subvar_and_ops(self):
        from ghidra.transform.ruleaction_batch2d import RuleSubvarAnd
        from ghidra.core.opcodes import OpCode
        assert RuleSubvarAnd("t").getOpList() == [OpCode.CPUI_INT_AND]

    def test_rule_subvar_subpiece_ops(self):
        from ghidra.transform.ruleaction_batch2d import RuleSubvarSubpiece
        from ghidra.core.opcodes import OpCode
        assert RuleSubvarSubpiece("t").getOpList() == [OpCode.CPUI_SUBPIECE]

    def test_rule_split_flow_ops(self):
        from ghidra.transform.ruleaction_batch2d import RuleSplitFlow
        from ghidra.core.opcodes import OpCode
        assert RuleSplitFlow("t").getOpList() == [OpCode.CPUI_SUBPIECE]

    def test_rule_subvar_comp_zero_ops(self):
        from ghidra.transform.ruleaction_batch2d import RuleSubvarCompZero
        from ghidra.core.opcodes import OpCode
        ops = RuleSubvarCompZero("t").getOpList()
        assert OpCode.CPUI_INT_NOTEQUAL in ops
        assert OpCode.CPUI_INT_EQUAL in ops

    def test_rule_subvar_shift_ops(self):
        from ghidra.transform.ruleaction_batch2d import RuleSubvarShift
        from ghidra.core.opcodes import OpCode
        assert RuleSubvarShift("t").getOpList() == [OpCode.CPUI_INT_RIGHT]

    def test_rule_subvar_zext_ops(self):
        from ghidra.transform.ruleaction_batch2d import RuleSubvarZext
        from ghidra.core.opcodes import OpCode
        assert RuleSubvarZext("t").getOpList() == [OpCode.CPUI_INT_ZEXT]

    def test_rule_subvar_sext_ops(self):
        from ghidra.transform.ruleaction_batch2d import RuleSubvarSext
        from ghidra.core.opcodes import OpCode
        assert RuleSubvarSext("t").getOpList() == [OpCode.CPUI_INT_SEXT]


class TestUniversalActionCompleteness:
    """Verify the Python universal action matches C++ rule counts."""

    def test_oppool1_rule_count_matches_cpp(self):
        """oppool1 should have exactly 134 rules matching C++."""
        py_path = os.path.join(os.path.dirname(__file__), '..', 'python',
                               'ghidra', 'transform', 'universal.py')
        py = open(py_path).read()
        m1 = re.search(r'actprop = ActionPool.*?oppool1', py)
        m2 = re.search(r'actstackstall\.addAction\(actprop\)', py)
        section = py[m1.start():m2.start()]
        rules = re.findall(r'actprop\.addRule\(Rule\w+', section)
        assert len(rules) == 134

    def test_oppool2_rule_count_matches_cpp(self):
        """oppool2 should have 5 rules (RuleIndirectConcat commented out in C++ too)."""
        py_path = os.path.join(os.path.dirname(__file__), '..', 'python',
                               'ghidra', 'transform', 'universal.py')
        py = open(py_path).read()
        m1 = re.search(r'actprop2 = ActionPool.*?oppool2', py)
        m2 = re.search(r'actmainloop\.addAction\(actprop2\)', py)
        section = py[m1.start():m2.start()]
        rules = re.findall(r'actprop2\.addRule\((\w+)', section)
        assert len(rules) == 5

    def test_cleanup_pool_rule_count_matches_cpp(self):
        """cleanup pool should have exactly 15 rules matching C++."""
        py_path = os.path.join(os.path.dirname(__file__), '..', 'python',
                               'ghidra', 'transform', 'universal.py')
        py = open(py_path).read()
        m1 = re.search(r'actcleanup = ActionPool.*?cleanup', py)
        m2 = re.search(r'act\.addAction\(actcleanup\)', py)
        section = py[m1.start():m2.start()]
        rules = re.findall(r'actcleanup\.addRule\((\w+)', section)
        assert len(rules) == 15


class TestBuildDefaultGroups:
    """Verify buildDefaultGroups creates all 6 groups matching C++."""

    def test_all_six_groups_created(self):
        from ghidra.transform.action import ActionDatabase
        from ghidra.transform.universal import buildDefaultGroups
        db = ActionDatabase()
        buildDefaultGroups(db)
        assert getattr(db, '_isDefaultGroups', False) is True

    def test_decompile_group_exists(self):
        from ghidra.transform.action import ActionDatabase
        from ghidra.transform.universal import buildDefaultGroups
        db = ActionDatabase()
        buildDefaultGroups(db)
        assert "decompile" in db._groupmap

    def test_jumptable_group_exists(self):
        from ghidra.transform.action import ActionDatabase
        from ghidra.transform.universal import buildDefaultGroups
        db = ActionDatabase()
        buildDefaultGroups(db)
        assert "jumptable" in db._groupmap

    def test_normalize_group_exists(self):
        from ghidra.transform.action import ActionDatabase
        from ghidra.transform.universal import buildDefaultGroups
        db = ActionDatabase()
        buildDefaultGroups(db)
        assert "normalize" in db._groupmap

    def test_paramid_group_exists(self):
        from ghidra.transform.action import ActionDatabase
        from ghidra.transform.universal import buildDefaultGroups
        db = ActionDatabase()
        buildDefaultGroups(db)
        assert "paramid" in db._groupmap

    def test_register_group_exists(self):
        from ghidra.transform.action import ActionDatabase
        from ghidra.transform.universal import buildDefaultGroups
        db = ActionDatabase()
        buildDefaultGroups(db)
        assert "register" in db._groupmap

    def test_firstpass_group_exists(self):
        from ghidra.transform.action import ActionDatabase
        from ghidra.transform.universal import buildDefaultGroups
        db = ActionDatabase()
        buildDefaultGroups(db)
        assert "firstpass" in db._groupmap

    def test_idempotent(self):
        from ghidra.transform.action import ActionDatabase
        from ghidra.transform.universal import buildDefaultGroups
        db = ActionDatabase()
        buildDefaultGroups(db)
        buildDefaultGroups(db)  # Second call should be no-op
        assert db._isDefaultGroups is True
