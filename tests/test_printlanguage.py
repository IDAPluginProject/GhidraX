"""Tests for ghidra.output.printlanguage -- OpToken, Atom, PrintLanguage helpers."""
from __future__ import annotations

from ghidra.output.printlanguage import (
    OpToken, ReversePolish, NodePending, Atom, PrintLanguage,
    PrintLanguageCapability,
    syntax, vartoken, functoken, optoken, typetoken, fieldtoken, casetoken, blanktoken,
)


# ---------------------------------------------------------------------------
# OpToken
# ---------------------------------------------------------------------------

class TestOpToken:
    def test_defaults(self):
        t = OpToken()
        assert t.print1 == ""
        assert t.print2 == ""
        assert t.stage == 0
        assert t.precedence == 0
        assert t.associative is False
        assert t.type == 0
        assert t.spacing == 1
        assert t.bump == 0
        assert t.negate is None

    def test_construction(self):
        t = OpToken("+", "", stage=2, prec=10, assoc=True, tp=OpToken.binary, spacing=1, bump=0)
        assert t.print1 == "+"
        assert t.stage == 2
        assert t.precedence == 10
        assert t.associative is True
        assert t.type == OpToken.binary

    def test_type_constants(self):
        assert OpToken.binary == 0
        assert OpToken.unary_prefix == 1
        assert OpToken.postsurround == 2
        assert OpToken.presurround == 3
        assert OpToken.space == 4
        assert OpToken.hiddenfunction == 5

    def test_negate_link(self):
        t1 = OpToken("+")
        t2 = OpToken("-")
        t1.negate = t2
        assert t1.negate is t2


# ---------------------------------------------------------------------------
# ReversePolish
# ---------------------------------------------------------------------------

class TestReversePolish:
    def test_defaults(self):
        rp = ReversePolish()
        assert rp.tok is None
        assert rp.visited == 0
        assert rp.paren is False
        assert rp.op is None
        assert rp.id == 0
        assert rp.id2 == 0


# ---------------------------------------------------------------------------
# NodePending
# ---------------------------------------------------------------------------

class TestNodePending:
    def test_construction(self):
        np = NodePending("vn", "op", 0xFF)
        assert np.vn == "vn"
        assert np.op == "op"
        assert np.vnmod == 0xFF


# ---------------------------------------------------------------------------
# Atom
# ---------------------------------------------------------------------------

class TestAtom:
    def test_construction(self):
        a = Atom("myVar", vartoken, 4, op=None, second="hi", offset=8)
        assert a.name == "myVar"
        assert a.type == vartoken
        assert a.highlight == 4
        assert a.op is None
        assert a.ptr_second == "hi"
        assert a.offset == 8

    def test_defaults(self):
        a = Atom("x", syntax, 0)
        assert a.op is None
        assert a.ptr_second is None
        assert a.offset == 0


# ---------------------------------------------------------------------------
# tagtype constants
# ---------------------------------------------------------------------------

class TestTagtypeConstants:
    def test_values(self):
        assert syntax == 0
        assert vartoken == 1
        assert functoken == 2
        assert optoken == 3
        assert typetoken == 4
        assert fieldtoken == 5
        assert casetoken == 6
        assert blanktoken == 7


# ---------------------------------------------------------------------------
# PrintLanguage modifier constants
# ---------------------------------------------------------------------------

class TestPrintLanguageConstants:
    def test_modifier_constants(self):
        assert PrintLanguage.force_hex == 1
        assert PrintLanguage.force_dec == 2
        assert PrintLanguage.bestfit == 4
        assert PrintLanguage.force_scinote == 8
        assert PrintLanguage.force_pointer == 0x10
        assert PrintLanguage.no_branch == 0x80
        assert PrintLanguage.only_branch == 0x100
        assert PrintLanguage.comma_separate == 0x200
        assert PrintLanguage.flat == 0x400
        assert PrintLanguage.negatetoken == 0x2000
        assert PrintLanguage.hide_thisparam == 0x4000
        assert PrintLanguage.pending_brace == 0x8000

    def test_namespace_constants(self):
        assert PrintLanguage.MINIMAL_NAMESPACES == 0
        assert PrintLanguage.NO_NAMESPACES == 1
        assert PrintLanguage.ALL_NAMESPACES == 2


# ---------------------------------------------------------------------------
# PrintLanguage.mostNaturalBase
# ---------------------------------------------------------------------------

class TestMostNaturalBase:
    def test_zero(self):
        assert PrintLanguage.mostNaturalBase(0) == 10

    def test_small_decimal(self):
        assert PrintLanguage.mostNaturalBase(100) == 10

    def test_hex_value(self):
        assert PrintLanguage.mostNaturalBase(0xDEAD) == 16

    def test_round_decimal(self):
        assert PrintLanguage.mostNaturalBase(1000) == 10
