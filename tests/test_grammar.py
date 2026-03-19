"""Tests for ghidra.core.grammar — C grammar lexer and parser."""
from __future__ import annotations

import io

from ghidra.core.grammar import (
    GrammarToken, GrammarLexer,
    TypeModifier, PointerModifier, ArrayModifier, FunctionModifier,
    TypeDeclarator, TypeSpecifiers, Enumerator,
    CParse,
    parse_toseparator,
)


# ---------------------------------------------------------------------------
# GrammarToken
# ---------------------------------------------------------------------------

class TestGrammarToken:
    def test_default_type(self):
        t = GrammarToken()
        assert t.getType() == GrammarToken.badtoken

    def test_set_type(self):
        t = GrammarToken()
        t.set(GrammarToken.integer, intval=42)
        assert t.getType() == GrammarToken.integer
        assert t.getInteger() == 42

    def test_set_string(self):
        t = GrammarToken()
        t.set(GrammarToken.identifier, "hello")
        assert t.getString() == "hello"

    def test_position(self):
        t = GrammarToken()
        t.setPosition(1, 10, 5)
        assert t.getFileNum() == 1
        assert t.getLineNo() == 10
        assert t.getColNo() == 5

    def test_constants(self):
        assert GrammarToken.openparen == 0x28
        assert GrammarToken.closeparen == 0x29
        assert GrammarToken.star == 0x2a
        assert GrammarToken.comma == 0x2c
        assert GrammarToken.semicolon == 0x3b
        assert GrammarToken.endoffile == 0x101
        assert GrammarToken.dotdotdot == 0x102


# ---------------------------------------------------------------------------
# GrammarLexer
# ---------------------------------------------------------------------------

class TestGrammarLexer:
    def test_empty_stream_eof(self):
        lexer = GrammarLexer()
        lexer.pushFile("test", io.StringIO(""))
        tok = GrammarToken()
        lexer.getNextToken(tok)
        assert tok.getType() == GrammarToken.endoffile

    def test_identifier(self):
        lexer = GrammarLexer()
        lexer.pushFile("test", io.StringIO("hello"))
        tok = GrammarToken()
        lexer.getNextToken(tok)
        assert tok.getType() == GrammarToken.identifier
        assert tok.getString() == "hello"

    def test_number(self):
        lexer = GrammarLexer()
        lexer.pushFile("test", io.StringIO("42"))
        tok = GrammarToken()
        lexer.getNextToken(tok)
        assert tok.getType() == GrammarToken.integer
        assert tok.getInteger() == 42

    def test_hex_number(self):
        lexer = GrammarLexer()
        lexer.pushFile("test", io.StringIO("0xFF"))
        tok = GrammarToken()
        lexer.getNextToken(tok)
        assert tok.getType() == GrammarToken.integer
        assert tok.getInteger() == 0xFF

    def test_punctuation(self):
        lexer = GrammarLexer()
        lexer.pushFile("test", io.StringIO("("))
        tok = GrammarToken()
        lexer.getNextToken(tok)
        assert tok.getType() == GrammarToken.openparen

    def test_semicolon(self):
        lexer = GrammarLexer()
        lexer.pushFile("test", io.StringIO(";"))
        tok = GrammarToken()
        lexer.getNextToken(tok)
        assert tok.getType() == GrammarToken.semicolon

    def test_star(self):
        lexer = GrammarLexer()
        lexer.pushFile("test", io.StringIO("*"))
        tok = GrammarToken()
        lexer.getNextToken(tok)
        assert tok.getType() == GrammarToken.star

    def test_string_literal(self):
        lexer = GrammarLexer()
        lexer.pushFile("test", io.StringIO('"hello"'))
        tok = GrammarToken()
        lexer.getNextToken(tok)
        assert tok.getType() == GrammarToken.stringval
        assert tok.getString() == "hello"

    def test_dotdotdot(self):
        lexer = GrammarLexer()
        lexer.pushFile("test", io.StringIO("..."))
        tok = GrammarToken()
        lexer.getNextToken(tok)
        assert tok.getType() == GrammarToken.dotdotdot

    def test_line_comment_skip(self):
        lexer = GrammarLexer()
        lexer.pushFile("test", io.StringIO("// comment\nfoo"))
        tok = GrammarToken()
        lexer.getNextToken(tok)
        assert tok.getType() == GrammarToken.identifier
        assert tok.getString() == "foo"

    def test_block_comment_skip(self):
        lexer = GrammarLexer()
        lexer.pushFile("test", io.StringIO("/* comment */bar"))
        tok = GrammarToken()
        lexer.getNextToken(tok)
        assert tok.getType() == GrammarToken.identifier
        assert tok.getString() == "bar"

    def test_clear(self):
        lexer = GrammarLexer()
        lexer.pushFile("test", io.StringIO("x"))
        lexer.clear()
        tok = GrammarToken()
        lexer.getNextToken(tok)
        assert tok.getType() == GrammarToken.endoffile

    def test_push_pop_file(self):
        lexer = GrammarLexer()
        lexer.pushFile("a", io.StringIO("hello"))
        assert lexer.getCurStream() is not None
        lexer.popFile()
        assert lexer.getCurStream() is None

    def test_write_location(self):
        lexer = GrammarLexer()
        lexer.pushFile("myfile.c", io.StringIO(""))
        buf = io.StringIO()
        lexer.writeLocation(buf, 10, 0)
        assert "myfile.c" in buf.getvalue()


# ---------------------------------------------------------------------------
# TypeModifier hierarchy
# ---------------------------------------------------------------------------

class TestTypeModifier:
    def test_pointer_type(self):
        pm = PointerModifier()
        assert pm.getType() == TypeModifier.pointer_mod
        assert pm.isValid() is True

    def test_array_valid(self):
        am = ArrayModifier(0, 10)
        assert am.getType() == TypeModifier.array_mod
        assert am.isValid() is True

    def test_array_invalid(self):
        am = ArrayModifier(0, 0)
        assert am.isValid() is False

    def test_function_mod(self):
        fm = FunctionModifier()
        assert fm.getType() == TypeModifier.function_mod
        assert fm.isDotdotdot() is False

    def test_function_mod_dotdotdot(self):
        fm = FunctionModifier(dotdotdot=True)
        assert fm.isDotdotdot() is True


# ---------------------------------------------------------------------------
# TypeDeclarator
# ---------------------------------------------------------------------------

class TestTypeDeclarator:
    def test_default(self):
        td = TypeDeclarator()
        assert td.getIdentifier() == ""
        assert td.numModifiers() == 0
        assert td.getBaseType() is None

    def test_with_name(self):
        td = TypeDeclarator("myvar")
        assert td.getIdentifier() == "myvar"

    def test_not_valid_without_base(self):
        td = TypeDeclarator()
        assert td.isValid() is False

    def test_has_property(self):
        td = TypeDeclarator()
        td._flags = 0x5
        assert td.hasProperty(0x1) is True
        assert td.hasProperty(0x4) is True
        assert td.hasProperty(0x2) is False


# ---------------------------------------------------------------------------
# TypeSpecifiers
# ---------------------------------------------------------------------------

class TestTypeSpecifiers:
    def test_default(self):
        ts = TypeSpecifiers()
        assert ts.type_specifier is None
        assert ts.flags == 0
        assert ts.function_specifier == ""


# ---------------------------------------------------------------------------
# Enumerator
# ---------------------------------------------------------------------------

class TestEnumerator:
    def test_name_only(self):
        e = Enumerator("FOO")
        assert e.enumconstant == "FOO"
        assert e.constantassigned is False

    def test_name_value(self):
        e = Enumerator("BAR", 42)
        assert e.enumconstant == "BAR"
        assert e.constantassigned is True
        assert e.value == 42


# ---------------------------------------------------------------------------
# CParse
# ---------------------------------------------------------------------------

class TestCParse:
    def test_construct(self):
        p = CParse()
        assert p.getError() == ""

    def test_clear(self):
        p = CParse()
        p.clear()
        assert p.getResultDeclarations() is None

    def test_new_specifier(self):
        p = CParse()
        s = p.newSpecifier()
        assert isinstance(s, TypeSpecifiers)

    def test_new_declarator(self):
        p = CParse()
        d = p.newDeclarator("x")
        assert isinstance(d, TypeDeclarator)
        assert d.getIdentifier() == "x"

    def test_parse_stream_returns_true(self):
        # 'int' must be known to the type factory; provide a mock glb
        from types import SimpleNamespace
        int_type = SimpleNamespace(name="int")
        mock_types = SimpleNamespace(findByName=lambda n: int_type if n == "int" else None)
        mock_glb = SimpleNamespace(types=mock_types, hasModel=lambda n: False)
        p = CParse(mock_glb)
        result = p.parseStream(io.StringIO("int x;"))
        assert result is True

    def test_flags(self):
        assert CParse.f_typedef == 1
        assert CParse.f_const == 32
        assert CParse.f_struct == 512
        assert CParse.f_enum == 2048


# ---------------------------------------------------------------------------
# parse_toseparator
# ---------------------------------------------------------------------------

class TestParseToseparator:
    def test_simple(self):
        result = parse_toseparator(io.StringIO("hello world"))
        assert result == "hello"

    def test_semicolon(self):
        result = parse_toseparator(io.StringIO("abc;def"))
        assert result == "abc"

    def test_empty(self):
        result = parse_toseparator(io.StringIO(""))
        assert result == ""
