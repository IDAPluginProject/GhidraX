"""Tests for ghidra.output.prettyprint -- Emit, EmitMarkup, EmitPrettyPrint, SyntaxHighlight."""
from __future__ import annotations

import io
from ghidra.output.prettyprint import (
    SyntaxHighlight, PendPrint, Emit, EmitMarkup, EmitPrettyPrint,
)


# ---------------------------------------------------------------------------
# SyntaxHighlight
# ---------------------------------------------------------------------------

class TestSyntaxHighlight:
    def test_values(self):
        assert SyntaxHighlight.keyword_color == 0
        assert SyntaxHighlight.comment_color == 1
        assert SyntaxHighlight.type_color == 2
        assert SyntaxHighlight.funcname_color == 3
        assert SyntaxHighlight.var_color == 4
        assert SyntaxHighlight.const_color == 5
        assert SyntaxHighlight.param_color == 6
        assert SyntaxHighlight.global_color == 7
        assert SyntaxHighlight.no_color == 8
        assert SyntaxHighlight.error_color == 9
        assert SyntaxHighlight.special_color == 10


# ---------------------------------------------------------------------------
# EmitMarkup
# ---------------------------------------------------------------------------

class TestEmitMarkup:
    def test_defaults(self):
        em = EmitMarkup()
        assert em.indentlevel == 0
        assert em.parenlevel == 0
        assert em.indentincrement == 2
        assert em.getOutput() == ""

    def test_print(self):
        em = EmitMarkup()
        em.print("hello")
        assert em.getOutput() == "hello"

    def test_print_multiple(self):
        em = EmitMarkup()
        em.print("a")
        em.print("b")
        assert em.getOutput() == "ab"

    def test_spaces(self):
        em = EmitMarkup()
        em.spaces(3)
        assert em.getOutput() == "   "

    def test_tag_line(self):
        em = EmitMarkup()
        em.print("line1")
        em.tagLine()
        em.print("line2")
        out = em.getOutput()
        assert "line1" in out
        assert "\n" in out
        assert "line2" in out

    def test_tag_line_with_indent(self):
        em = EmitMarkup()
        em.tagLine(4)
        em.print("indented")
        out = em.getOutput()
        assert "    indented" in out

    def test_paren(self):
        em = EmitMarkup()
        assert em.parenlevel == 0
        em.openParen("(")
        assert em.parenlevel == 1
        em.closeParen(")")
        assert em.parenlevel == 0
        assert em.getOutput() == "()"

    def test_tag_variable(self):
        em = EmitMarkup()
        em.tagVariable("myVar", SyntaxHighlight.var_color, None, None)
        assert em.getOutput() == "myVar"

    def test_tag_op(self):
        em = EmitMarkup()
        em.tagOp("+", SyntaxHighlight.no_color, None)
        assert em.getOutput() == "+"

    def test_tag_func_name(self):
        em = EmitMarkup()
        em.tagFuncName("main", SyntaxHighlight.funcname_color, None, None)
        assert em.getOutput() == "main"

    def test_tag_type(self):
        em = EmitMarkup()
        em.tagType("int", SyntaxHighlight.type_color, None)
        assert em.getOutput() == "int"

    def test_tag_field(self):
        em = EmitMarkup()
        em.tagField("x", SyntaxHighlight.var_color, None, 0, None)
        assert em.getOutput() == "x"

    def test_tag_comment(self):
        em = EmitMarkup()
        em.tagComment("/* hi */", SyntaxHighlight.comment_color, None, 0)
        assert em.getOutput() == "/* hi */"

    def test_tag_label(self):
        em = EmitMarkup()
        em.tagLabel("lbl:", SyntaxHighlight.no_color, None, 0)
        assert em.getOutput() == "lbl:"

    def test_begin_end_document(self):
        em = EmitMarkup()
        did = em.beginDocument()
        assert did > 0
        em.endDocument(did)

    def test_begin_end_function(self):
        em = EmitMarkup()
        fid = em.beginFunction(None)
        em.print("void foo()")
        em.endFunction(fid)
        assert "void foo()" in em.getOutput()
        assert "\n" in em.getOutput()

    def test_set_output_stream(self):
        em = EmitMarkup()
        new_stream = io.StringIO()
        em.setOutputStream(new_stream)
        em.print("test")
        assert new_stream.getvalue() == "test"

    def test_clear(self):
        em = EmitMarkup()
        em.startIndent()
        assert em.indentlevel == 2
        em.clear()
        assert em.indentlevel == 0
        assert em.parenlevel == 0

    def test_emits_markup(self):
        em = EmitMarkup()
        assert em.emitsMarkup() is False


# ---------------------------------------------------------------------------
# Emit base (indent/brace helpers)
# ---------------------------------------------------------------------------

class TestEmitHelpers:
    def test_start_stop_indent(self):
        em = EmitMarkup()
        assert em.indentlevel == 0
        iid = em.startIndent()
        assert em.indentlevel == 2
        em.stopIndent(iid)
        assert em.indentlevel == 0

    def test_indent_increment(self):
        em = EmitMarkup()
        em.setIndentIncrement(4)
        assert em.getIndentIncrement() == 4
        em.startIndent()
        assert em.indentlevel == 4

    def test_reset_defaults(self):
        em = EmitMarkup()
        em.setIndentIncrement(8)
        em.resetDefaults()
        assert em.getIndentIncrement() == 2

    def test_pend_print(self):
        em = EmitMarkup()

        class _FakePend(PendPrint):
            def __init__(self):
                self.called = False
            def callback(self, emit):
                self.called = True
                emit.print("PEND")

        p = _FakePend()
        em.setPendingPrint(p)
        assert em.hasPendingPrint(p) is True
        em.emitPending()
        assert p.called is True
        assert "PEND" in em.getOutput()

    def test_cancel_pending_print(self):
        em = EmitMarkup()

        class _FakePend2(PendPrint):
            def callback(self, emit):
                emit.print("NOPE")

        p = _FakePend2()
        em.setPendingPrint(p)
        em.cancelPendingPrint()
        assert em.hasPendingPrint(p) is False
        em.emitPending()
        assert em.getOutput() == ""

    def test_brace_style_constants(self):
        assert Emit.same_line == 0
        assert Emit.next_line == 1
        assert Emit.skip_line == 2


# ---------------------------------------------------------------------------
# EmitPrettyPrint
# ---------------------------------------------------------------------------

class TestEmitPrettyPrint:
    def test_defaults(self):
        epp = EmitPrettyPrint()
        assert epp.indentlevel == 0
        assert epp.getMaxLineSize() == 100

    def test_set_max_line_size(self):
        epp = EmitPrettyPrint()
        epp.setMaxLineSize(80)
        assert epp.getMaxLineSize() == 80

    def test_simple_print(self):
        low = EmitMarkup()
        epp = EmitPrettyPrint(low)
        epp.print("hello")
        epp.flush()
        assert "hello" in low.getOutput()

    def test_tag_line(self):
        low = EmitMarkup()
        epp = EmitPrettyPrint(low)
        epp.print("a")
        epp.tagLine()
        epp.print("b")
        epp.flush()
        out = low.getOutput()
        assert "a" in out
        assert "b" in out

    def test_token_type_constants(self):
        assert EmitPrettyPrint.TOK_STRING == 0
        assert EmitPrettyPrint.TOK_BREAK == 1
        assert EmitPrettyPrint.TOK_BEGIN == 2
        assert EmitPrettyPrint.TOK_END == 3
        assert EmitPrettyPrint.TOK_LINE == 4
        assert EmitPrettyPrint.TOK_INDENT == 5
        assert EmitPrettyPrint.TOK_UNINDENT == 6
