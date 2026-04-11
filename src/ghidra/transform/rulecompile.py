"""
Rule DSL compiler: lexer, parser, and RuleGeneric.

Corresponds to: rulecompile.hh / rulecompile.cc / ruleparse.y

Provides:
- **RuleLexer** — tokenizes the rule DSL text.
- **RuleCompile** — compiles DSL into a ConstraintGroup tree.
- **RuleGeneric** — a user-configurable Rule built from a DSL string.
"""
from __future__ import annotations

import io
from typing import Dict, List, Optional, TYPE_CHECKING

from ghidra.core.error import LowlevelError
from ghidra.core.opcodes import OpCode
from ghidra.transform.action import Rule
from ghidra.transform.unify import (
    ConstraintGroup, ConstraintOr,
    ConstraintBoolean, ConstraintVarConst, ConstraintNamedExpression,
    ConstraintOpCopy, ConstraintOpcode, ConstraintOpCompare,
    ConstraintOpInput, ConstraintOpInputAny, ConstraintOpOutput,
    ConstraintVarnodeCopy, ConstraintVarCompare,
    ConstraintDef, ConstraintDescend, ConstraintLoneDescend,
    ConstraintConstCompare, ConstraintParamConstVal, ConstraintParamConst,
    ConstraintNewOp, ConstraintNewUniqueOut,
    ConstraintSetInput, ConstraintSetInputConstVal,
    ConstraintRemoveInput, ConstraintSetOpcode,
    DummyOpConstraint, DummyVarnodeConstraint, DummyConstConstraint,
    RHSConstant, ConstantNamed, ConstantAbsolute, ConstantExpression,
    ConstantVarnodeSize, ConstantOffset, ConstantIsConstant,
    ConstantHeritageKnown, ConstantConsumed, ConstantNZMask,
    UnifyState,
)

if TYPE_CHECKING:
    from ghidra.ir.op import PcodeOp
    from ghidra.analysis.funcdata import Funcdata


# =========================================================================
# Token types (internal)
# =========================================================================

class _Tok:
    EOF = -2
    ERROR = -1
    # Punctuation returned as ord(char)
    RIGHT_ARROW = 300
    LEFT_ARROW = 301
    DOUBLE_RIGHT_ARROW = 302
    DOUBLE_LEFT_ARROW = 303
    ACTION_TICK = 304
    BEFORE_KEYWORD = 305
    AFTER_KEYWORD = 306
    REMOVE_KEYWORD = 307
    SET_KEYWORD = 308
    ISTRUE_KEYWORD = 309
    ISFALSE_KEYWORD = 310
    INTB = 311
    BADINTEGER = 312
    OP_IDENTIFIER = 320
    VAR_IDENTIFIER = 321
    CONST_IDENTIFIER = 322
    OP_NEW_IDENTIFIER = 323
    VAR_NEW_IDENTIFIER = 324
    DOT_IDENTIFIER = 325
    # Opcode tokens — use OpCode int values + 1000 offset
    _OP_BASE = 1000


def _opcode_token(opc: int) -> int:
    return _Tok._OP_BASE + opc


def _token_to_opcode(tok: int) -> int:
    return tok - _Tok._OP_BASE


def _is_opcode_token(tok: int) -> bool:
    return tok >= _Tok._OP_BASE


# =========================================================================
# RuleLexer
# =========================================================================

# Character classification table (256 entries)
# bit 0 (1) = valid in identifier continuation
# bit 1 (2) = digit
# bit 2 (4) = valid name char (letter/digit/underscore)
_identlist = [0] * 256
for _c in range(ord('0'), ord('9') + 1):
    _identlist[_c] = 7  # 1|2|4
for _c in range(ord('A'), ord('Z') + 1):
    _identlist[_c] = 5  # 1|4
for _c in range(ord('a'), ord('z') + 1):
    _identlist[_c] = 5  # 1|4
_identlist[ord('_')] = 5

# Keyword -> opcode token mapping
_KEYWORD_MAP: Dict[str, int] = {
    "COPY": _opcode_token(int(OpCode.CPUI_COPY)),
    "ZEXT": _opcode_token(int(OpCode.CPUI_INT_ZEXT)),
    "CARRY": _opcode_token(int(OpCode.CPUI_INT_CARRY)),
    "SCARRY": _opcode_token(int(OpCode.CPUI_INT_SCARRY)),
    "SEXT": _opcode_token(int(OpCode.CPUI_INT_SEXT)),
    "SBORROW": _opcode_token(int(OpCode.CPUI_INT_SBORROW)),
    "NAN": _opcode_token(int(OpCode.CPUI_FLOAT_NAN)),
    "ABS": _opcode_token(int(OpCode.CPUI_FLOAT_ABS)),
    "SQRT": _opcode_token(int(OpCode.CPUI_FLOAT_SQRT)),
    "CEIL": _opcode_token(int(OpCode.CPUI_FLOAT_CEIL)),
    "FLOOR": _opcode_token(int(OpCode.CPUI_FLOAT_FLOOR)),
    "ROUND": _opcode_token(int(OpCode.CPUI_FLOAT_ROUND)),
    "INT2FLOAT": _opcode_token(int(OpCode.CPUI_FLOAT_INT2FLOAT)),
    "FLOAT2FLOAT": _opcode_token(int(OpCode.CPUI_FLOAT_FLOAT2FLOAT)),
    "TRUNC": _opcode_token(int(OpCode.CPUI_FLOAT_TRUNC)),
    "GOTO": _opcode_token(int(OpCode.CPUI_BRANCH)),
    "GOTOIND": _opcode_token(int(OpCode.CPUI_BRANCHIND)),
    "CALL": _opcode_token(int(OpCode.CPUI_CALL)),
    "CALLIND": _opcode_token(int(OpCode.CPUI_CALLIND)),
    "RETURN": _opcode_token(int(OpCode.CPUI_RETURN)),
    "CBRANCH": _opcode_token(int(OpCode.CPUI_CBRANCH)),
    "USEROP": _opcode_token(int(OpCode.CPUI_CALLOTHER)),
    "LOAD": _opcode_token(int(OpCode.CPUI_LOAD)),
    "STORE": _opcode_token(int(OpCode.CPUI_STORE)),
    "CONCAT": _opcode_token(int(OpCode.CPUI_PIECE)),
    "SUBPIECE": _opcode_token(int(OpCode.CPUI_SUBPIECE)),
    "before": _Tok.BEFORE_KEYWORD,
    "after": _Tok.AFTER_KEYWORD,
    "remove": _Tok.REMOVE_KEYWORD,
    "set": _Tok.SET_KEYWORD,
    "istrue": _Tok.ISTRUE_KEYWORD,
    "isfalse": _Tok.ISFALSE_KEYWORD,
}

# Operator tokens for single/multi-character operators
_OP_INT_ADD = _opcode_token(int(OpCode.CPUI_INT_ADD))
_OP_INT_SUB = _opcode_token(int(OpCode.CPUI_INT_SUB))
_OP_INT_MULT = _opcode_token(int(OpCode.CPUI_INT_MULT))
_OP_INT_DIV = _opcode_token(int(OpCode.CPUI_INT_DIV))
_OP_INT_REM = _opcode_token(int(OpCode.CPUI_INT_REM))
_OP_INT_NEGATE = _opcode_token(int(OpCode.CPUI_INT_NEGATE))
_OP_INT_AND = _opcode_token(int(OpCode.CPUI_INT_AND))
_OP_INT_OR = _opcode_token(int(OpCode.CPUI_INT_OR))
_OP_INT_XOR = _opcode_token(int(OpCode.CPUI_INT_XOR))
_OP_INT_LEFT = _opcode_token(int(OpCode.CPUI_INT_LEFT))
_OP_INT_RIGHT = _opcode_token(int(OpCode.CPUI_INT_RIGHT))
_OP_INT_EQUAL = _opcode_token(int(OpCode.CPUI_INT_EQUAL))
_OP_INT_NOTEQUAL = _opcode_token(int(OpCode.CPUI_INT_NOTEQUAL))
_OP_INT_LESS = _opcode_token(int(OpCode.CPUI_INT_LESS))
_OP_INT_LESSEQUAL = _opcode_token(int(OpCode.CPUI_INT_LESSEQUAL))
_OP_INT_SDIV = _opcode_token(int(OpCode.CPUI_INT_SDIV))
_OP_INT_SREM = _opcode_token(int(OpCode.CPUI_INT_SREM))
_OP_INT_SRIGHT = _opcode_token(int(OpCode.CPUI_INT_SRIGHT))
_OP_INT_SLESS = _opcode_token(int(OpCode.CPUI_INT_SLESS))
_OP_INT_SLESSEQUAL = _opcode_token(int(OpCode.CPUI_INT_SLESSEQUAL))
_OP_BOOL_OR = _opcode_token(int(OpCode.CPUI_BOOL_OR))
_OP_BOOL_AND = _opcode_token(int(OpCode.CPUI_BOOL_AND))
_OP_BOOL_XOR = _opcode_token(int(OpCode.CPUI_BOOL_XOR))
_OP_BOOL_NEGATE = _opcode_token(int(OpCode.CPUI_BOOL_NEGATE))
_OP_FLOAT_ADD = _opcode_token(int(OpCode.CPUI_FLOAT_ADD))
_OP_FLOAT_SUB = _opcode_token(int(OpCode.CPUI_FLOAT_SUB))
_OP_FLOAT_MULT = _opcode_token(int(OpCode.CPUI_FLOAT_MULT))
_OP_FLOAT_DIV = _opcode_token(int(OpCode.CPUI_FLOAT_DIV))
_OP_FLOAT_EQUAL = _opcode_token(int(OpCode.CPUI_FLOAT_EQUAL))
_OP_FLOAT_NOTEQUAL = _opcode_token(int(OpCode.CPUI_FLOAT_NOTEQUAL))
_OP_FLOAT_LESS = _opcode_token(int(OpCode.CPUI_FLOAT_LESS))
_OP_FLOAT_LESSEQUAL = _opcode_token(int(OpCode.CPUI_FLOAT_LESSEQUAL))


class RuleLexer:
    """Tokenizer for the rule DSL.

    C++ ref: ``RuleLexer`` in rulecompile.hh/cc
    """

    def __init__(self) -> None:
        self._s: str = ""
        self._pos: int = 0
        self._lineno: int = 1
        self._token_value: object = None

    def initialize(self, text: str) -> None:
        self._s = text
        self._pos = 0
        self._lineno = 1
        self._token_value = None

    def getLineNo(self) -> int:
        return self._lineno

    @property
    def value(self) -> object:
        return self._token_value

    def _peek(self, offset: int = 0) -> int:
        idx = self._pos + offset
        if idx >= len(self._s):
            return -1
        return ord(self._s[idx])

    def _advance(self) -> int:
        if self._pos >= len(self._s):
            return -1
        ch = ord(self._s[self._pos])
        self._pos += 1
        return ch

    def _scanIdentifier(self) -> int:
        start = self._pos - 1
        while self._pos < len(self._s) and (_identlist[ord(self._s[self._pos])] & 1):
            self._pos += 1
        ident = self._s[start:self._pos]
        if not ident:
            return _Tok.ERROR

        first = ident[0]
        if first.isdigit():
            return self._scanNumber(ident)

        if first == 'o':
            self._token_value = ident
            return _Tok.OP_IDENTIFIER
        if first == 'v':
            self._token_value = ident
            return _Tok.VAR_IDENTIFIER
        if first == '#':
            self._token_value = 'c' + ident[1:]
            return _Tok.CONST_IDENTIFIER
        if first == 'O':
            self._token_value = ident
            return _Tok.OP_NEW_IDENTIFIER
        if first == 'V':
            self._token_value = ident
            return _Tok.VAR_NEW_IDENTIFIER
        if first == '.':
            self._token_value = ident[1:]
            return _Tok.DOT_IDENTIFIER

        if ident in _KEYWORD_MAP:
            return _KEYWORD_MAP[ident]
        return _Tok.ERROR

    def _scanNumber(self, numtext: str) -> int:
        try:
            val = int(numtext, 0)
            self._token_value = val
            return _Tok.INTB
        except ValueError:
            return _Tok.BADINTEGER

    def nextToken(self) -> int:
        while True:
            c = self._peek()
            if c == -1:
                return _Tok.EOF

            ch = chr(c)

            if ch in ('(', ')', ',', '[', ']', ';', '{', '}', ':'):
                self._advance()
                self._token_value = ch
                return c

            if ch in ('\r', ' ', '\t', '\v'):
                self._advance()
                continue

            if ch == '\n':
                self._advance()
                self._lineno += 1
                continue

            if ch == '-':
                self._advance()
                if self._peek() == ord('>'):
                    self._advance()
                    return _Tok.RIGHT_ARROW
                if self._peek() == ord('-'):
                    self._advance()
                    if self._peek() == ord('>'):
                        self._advance()
                        return _Tok.DOUBLE_RIGHT_ARROW
                    return _Tok.ACTION_TICK
                return _OP_INT_SUB

            if ch == '<':
                self._advance()
                if self._peek() == ord('-'):
                    self._advance()
                    if self._peek() == ord('-'):
                        self._advance()
                        return _Tok.DOUBLE_LEFT_ARROW
                    return _Tok.LEFT_ARROW
                if self._peek() == ord('<'):
                    self._advance()
                    return _OP_INT_LEFT
                if self._peek() == ord('='):
                    self._advance()
                    return _OP_INT_LESSEQUAL
                return _OP_INT_LESS

            if ch == '|':
                self._advance()
                if self._peek() == ord('|'):
                    self._advance()
                    return _OP_BOOL_OR
                return _OP_INT_OR

            if ch == '&':
                self._advance()
                if self._peek() == ord('&'):
                    self._advance()
                    return _OP_BOOL_AND
                return _OP_INT_AND

            if ch == '^':
                self._advance()
                if self._peek() == ord('^'):
                    self._advance()
                    return _OP_BOOL_XOR
                return _OP_INT_XOR

            if ch == '>':
                if self._peek(1) == ord('>'):
                    self._advance()
                    self._advance()
                    return _OP_INT_RIGHT
                return _Tok.ERROR

            if ch == '=':
                self._advance()
                if self._peek() == ord('='):
                    self._advance()
                    return _OP_INT_EQUAL
                self._token_value = '='
                return ord('=')

            if ch == '!':
                self._advance()
                if self._peek() == ord('='):
                    self._advance()
                    return _OP_INT_NOTEQUAL
                return _OP_BOOL_NEGATE

            if ch == 's':
                p1 = self._peek(1)
                if p1 == ord('/'):
                    self._advance(); self._advance()
                    return _OP_INT_SDIV
                if p1 == ord('%'):
                    self._advance(); self._advance()
                    return _OP_INT_SREM
                if p1 == ord('>') and self._peek(2) == ord('>'):
                    self._advance(); self._advance(); self._advance()
                    return _OP_INT_SRIGHT
                if p1 == ord('<'):
                    self._advance(); self._advance()
                    if self._peek() == ord('='):
                        self._advance()
                        return _OP_INT_SLESSEQUAL
                    return _OP_INT_SLESS
                self._advance()
                return self._scanIdentifier()

            if ch == 'f':
                p1 = self._peek(1)
                if p1 == ord('+'):
                    self._advance(); self._advance()
                    return _OP_FLOAT_ADD
                if p1 == ord('-'):
                    self._advance(); self._advance()
                    return _OP_FLOAT_SUB
                if p1 == ord('*'):
                    self._advance(); self._advance()
                    return _OP_FLOAT_MULT
                if p1 == ord('/'):
                    self._advance(); self._advance()
                    return _OP_FLOAT_DIV
                if p1 == ord('=') and self._peek(2) == ord('='):
                    self._advance(); self._advance(); self._advance()
                    return _OP_FLOAT_EQUAL
                if p1 == ord('!') and self._peek(2) == ord('='):
                    self._advance(); self._advance(); self._advance()
                    return _OP_FLOAT_NOTEQUAL
                if p1 == ord('<'):
                    self._advance(); self._advance()
                    if self._peek() == ord('='):
                        self._advance()
                        return _OP_FLOAT_LESSEQUAL
                    return _OP_FLOAT_LESS
                return _Tok.ERROR

            if ch == '+':
                self._advance()
                return _OP_INT_ADD
            if ch == '*':
                self._advance()
                return _OP_INT_MULT
            if ch == '/':
                self._advance()
                return _OP_INT_DIV
            if ch == '%':
                self._advance()
                return _OP_INT_REM
            if ch == '~':
                self._advance()
                return _OP_INT_NEGATE

            if ch == '#':
                if self._peek(1) != -1 and (_identlist[self._peek(1)] & 6) == 4:
                    self._advance()
                    return self._scanIdentifier()
                self._advance()
                self._token_value = '#'
                return ord('#')

            self._advance()
            return self._scanIdentifier()


# =========================================================================
# RuleCompile — builder + recursive descent parser
# =========================================================================

class RuleCompile:
    """Compiler for the rule DSL.

    C++ ref: ``RuleCompile`` in rulecompile.hh/cc, grammar in ruleparse.y
    """

    def __init__(self) -> None:
        self._errors: int = 0
        self._lexer: RuleLexer = RuleLexer()
        self._namemap: Dict[str, int] = {}
        self._finalrule: Optional[ConstraintGroup] = None
        self._cur_tok: int = _Tok.EOF
        self._cur_val: object = None
        self._error_stream: Optional[io.TextIOBase] = None

    def numErrors(self) -> int:
        return self._errors

    def getLineNo(self) -> int:
        return self._lexer.getLineNo()

    def getRule(self) -> Optional[ConstraintGroup]:
        return self._finalrule

    def releaseRule(self) -> Optional[ConstraintGroup]:
        res = self._finalrule
        self._finalrule = None
        return res

    @property
    def namemap(self) -> Dict[str, int]:
        return self._namemap

    def setErrorStream(self, stream: io.TextIOBase) -> None:
        self._error_stream = stream

    # -- Error reporting ---------------------------------------------------

    def ruleError(self, msg: str) -> None:
        self._errors += 1
        if self._error_stream is not None:
            self._error_stream.write(f"{msg}\n")

    # -- Name management ---------------------------------------------------

    def findIdentifier(self, nm: str) -> int:
        if nm in self._namemap:
            return self._namemap[nm]
        resid = len(self._namemap)
        self._namemap[nm] = resid
        return resid

    # -- Builder methods (mirror C++ RuleCompile methods) ------------------

    def newOp(self, ident: int) -> ConstraintGroup:
        res = ConstraintGroup()
        res.addConstraint(DummyOpConstraint(ident))
        return res

    def newVarnode(self, ident: int) -> ConstraintGroup:
        res = ConstraintGroup()
        res.addConstraint(DummyVarnodeConstraint(ident))
        return res

    def newConst(self, ident: int) -> ConstraintGroup:
        res = ConstraintGroup()
        res.addConstraint(DummyConstConstraint(ident))
        return res

    def opCopy(self, base: ConstraintGroup, opid: int) -> ConstraintGroup:
        opindex = base.getBaseIndex()
        base.addConstraint(ConstraintOpCopy(opindex, opid))
        return base

    def opInput(self, base: ConstraintGroup, slot: int, varid: int) -> ConstraintGroup:
        opindex = base.getBaseIndex()
        base.addConstraint(ConstraintOpInput(opindex, varid, slot))
        return base

    def opInputAny(self, base: ConstraintGroup, varid: int) -> ConstraintGroup:
        opindex = base.getBaseIndex()
        base.addConstraint(ConstraintOpInputAny(opindex, varid))
        return base

    def opInputConstVal(self, base: ConstraintGroup, slot: int, val: RHSConstant) -> ConstraintGroup:
        opindex = base.getBaseIndex()
        if isinstance(val, ConstantAbsolute):
            c = ConstraintParamConstVal(opindex, slot, val.getVal())
        elif isinstance(val, ConstantNamed):
            c = ConstraintParamConst(opindex, slot, val.getId())
        else:
            self.ruleError("Can only use absolute constant here")
            c = ConstraintParamConstVal(opindex, slot, 0)
        base.addConstraint(c)
        return base

    def opOutput(self, base: ConstraintGroup, varid: int) -> ConstraintGroup:
        opindex = base.getBaseIndex()
        base.addConstraint(ConstraintOpOutput(opindex, varid))
        return base

    def varCopy(self, base: ConstraintGroup, varid: int) -> ConstraintGroup:
        varindex = base.getBaseIndex()
        base.addConstraint(ConstraintVarnodeCopy(varid, varindex))
        return base

    def varConst(self, base: ConstraintGroup, ex: RHSConstant, sz: Optional[RHSConstant]) -> ConstraintGroup:
        varindex = base.getBaseIndex()
        base.addConstraint(ConstraintVarConst(varindex, ex, sz))
        return base

    def varDef(self, base: ConstraintGroup, opid: int) -> ConstraintGroup:
        varindex = base.getBaseIndex()
        base.addConstraint(ConstraintDef(opid, varindex))
        return base

    def varDescend(self, base: ConstraintGroup, opid: int) -> ConstraintGroup:
        varindex = base.getBaseIndex()
        base.addConstraint(ConstraintDescend(opid, varindex))
        return base

    def varUniqueDescend(self, base: ConstraintGroup, opid: int) -> ConstraintGroup:
        varindex = base.getBaseIndex()
        base.addConstraint(ConstraintLoneDescend(opid, varindex))
        return base

    def opCodeConstraint(self, base: ConstraintGroup, oplist: List[int]) -> ConstraintGroup:
        if len(oplist) != 1:
            raise LowlevelError("Not currently supporting multiple opcode constraints")
        opindex = base.getBaseIndex()
        base.addConstraint(ConstraintOpcode(opindex, oplist))
        return base

    def opCompareConstraint(self, base: ConstraintGroup, opid: int, opc: int) -> ConstraintGroup:
        op1index = base.getBaseIndex()
        base.addConstraint(ConstraintOpCompare(op1index, opid, opc == int(OpCode.CPUI_INT_EQUAL)))
        return base

    def varCompareConstraint(self, base: ConstraintGroup, varid: int, opc: int) -> ConstraintGroup:
        var1index = base.getBaseIndex()
        base.addConstraint(ConstraintVarCompare(var1index, varid, opc == int(OpCode.CPUI_INT_EQUAL)))
        return base

    def constCompareConstraint(self, base: ConstraintGroup, constid: int, opc: int) -> ConstraintGroup:
        const1index = base.getBaseIndex()
        base.addConstraint(ConstraintConstCompare(const1index, constid, opc))
        return base

    def constNamedExpression(self, ident: int, expr: RHSConstant) -> ConstraintGroup:
        res = ConstraintGroup()
        res.addConstraint(ConstraintNamedExpression(ident, expr))
        return res

    def emptyGroup(self) -> ConstraintGroup:
        return ConstraintGroup()

    def emptyOrGroup(self) -> ConstraintOr:
        return ConstraintOr()

    def mergeGroups(self, a: ConstraintGroup, b: ConstraintGroup) -> ConstraintGroup:
        a.mergeIn(b)
        return a

    def addOr(self, base: ConstraintGroup, newor: ConstraintGroup) -> ConstraintGroup:
        base.addConstraint(newor)
        return base

    # Opcodes that take exactly 1 input (unary)
    _UNARY_OPCODES = {
        int(OpCode.CPUI_COPY), int(OpCode.CPUI_INT_NEGATE), int(OpCode.CPUI_INT_2COMP),
        int(OpCode.CPUI_INT_ZEXT), int(OpCode.CPUI_INT_SEXT),
        int(OpCode.CPUI_BOOL_NEGATE),
        int(OpCode.CPUI_FLOAT_NAN), int(OpCode.CPUI_FLOAT_ABS),
        int(OpCode.CPUI_FLOAT_SQRT), int(OpCode.CPUI_FLOAT_CEIL),
        int(OpCode.CPUI_FLOAT_FLOOR), int(OpCode.CPUI_FLOAT_ROUND),
        int(OpCode.CPUI_FLOAT_INT2FLOAT), int(OpCode.CPUI_FLOAT_FLOAT2FLOAT),
        int(OpCode.CPUI_FLOAT_TRUNC), int(OpCode.CPUI_FLOAT_NEG),
        int(OpCode.CPUI_POPCOUNT), int(OpCode.CPUI_LZCOUNT),
    }

    def opCreation(self, newid: int, opc: int, insertafter: bool, oldid: int) -> ConstraintGroup:
        numparams = 1 if opc in self._UNARY_OPCODES else 2
        res = ConstraintGroup()
        res.addConstraint(ConstraintNewOp(newid, oldid, opc, insertafter, numparams))
        return res

    def newUniqueOut(self, base: ConstraintGroup, varid: int, sz: int) -> ConstraintGroup:
        base.addConstraint(ConstraintNewUniqueOut(base.getBaseIndex(), varid, sz))
        return base

    def newSetInput(self, base: ConstraintGroup, slot: RHSConstant, varid: int) -> ConstraintGroup:
        base.addConstraint(ConstraintSetInput(base.getBaseIndex(), slot, varid))
        return base

    def newSetInputConstVal(self, base: ConstraintGroup, slot: RHSConstant,
                            val: RHSConstant, sz: Optional[RHSConstant]) -> ConstraintGroup:
        base.addConstraint(ConstraintSetInputConstVal(base.getBaseIndex(), slot, val, sz))
        return base

    def removeInput(self, base: ConstraintGroup, slot: RHSConstant) -> ConstraintGroup:
        base.addConstraint(ConstraintRemoveInput(base.getBaseIndex(), slot))
        return base

    def newSetOpcode(self, base: ConstraintGroup, opc: int) -> ConstraintGroup:
        opid = base.getBaseIndex()
        base.addConstraint(ConstraintSetOpcode(opid, opc))
        return base

    def booleanConstraint(self, istrue: bool, expr: RHSConstant) -> ConstraintGroup:
        base = ConstraintGroup()
        base.addConstraint(ConstraintBoolean(istrue, expr))
        return base

    def constNamed(self, ident: int) -> RHSConstant:
        return ConstantNamed(ident)

    def constAbsolute(self, val: int) -> RHSConstant:
        return ConstantAbsolute(val)

    def constBinaryExpression(self, ex1: RHSConstant, opc: int, ex2: RHSConstant) -> RHSConstant:
        return ConstantExpression(ex1, ex2, opc)

    def constVarnodeSize(self, varindex: int) -> RHSConstant:
        return ConstantVarnodeSize(varindex)

    def dotIdentifier(self, ident: int, attr: str) -> RHSConstant:
        if attr == "offset":
            return ConstantOffset(ident)
        if attr == "size":
            return ConstantVarnodeSize(ident)
        if attr == "isconstant":
            return ConstantIsConstant(ident)
        if attr == "heritageknown":
            return ConstantHeritageKnown(ident)
        if attr == "consume":
            return ConstantConsumed(ident)
        if attr == "nzmask":
            return ConstantNZMask(ident)
        self.ruleError(f"Unknown variable attribute: {attr}")
        return ConstantAbsolute(0)

    # -- Post-processing ---------------------------------------------------

    def postProcess(self) -> None:
        id_box = [0]
        self._finalrule.removeDummy()
        self._finalrule.setId(id_box)

    def postProcessRule(self, opcodelist: List[int]) -> int:
        self._finalrule.removeDummy()
        if self._finalrule.numConstraints() == 0:
            raise LowlevelError("Cannot postprocess empty rule")
        subconst = self._finalrule.getConstraint(0)
        if not isinstance(subconst, ConstraintOpcode):
            raise LowlevelError("Rule does not start with opcode constraint")
        opcodelist.clear()
        opcodelist.extend(subconst.getOpCodes())
        opinit = subconst.getMaxNum()
        self._finalrule.deleteConstraint(0)
        id_box = [0]
        self._finalrule.setId(id_box)
        return opinit

    @staticmethod
    def buildUnifyer(rule: str, idlist: List[str], res: List[int]) -> ConstraintGroup:
        ruler = RuleCompile()
        ruler.run(rule)
        if ruler.numErrors() != 0:
            raise LowlevelError("Could not build rule")
        resconst = ruler.releaseRule()
        for nm in idlist:
            ident = -1
            if nm and nm[0] in ('o', 'O', 'v', 'V', '#'):
                if nm in ruler._namemap:
                    ident = ruler._namemap[nm]
            if ident == -1:
                raise LowlevelError(f"Bad initializer name: {nm}")
            res.append(ident)
        return resconst

    # -- Tokenizer interface -----------------------------------------------

    def _next(self) -> None:
        self._cur_tok = self._lexer.nextToken()
        self._cur_val = self._lexer.value

    def _expect(self, tok: int) -> None:
        if self._cur_tok != tok:
            self.ruleError(f"Expected token {tok}, got {self._cur_tok}")

    def _accept(self, tok: int) -> bool:
        if self._cur_tok == tok:
            self._next()
            return True
        return False

    # -- Recursive descent parser ------------------------------------------
    # Grammar from ruleparse.y

    def run(self, text: str, debug: bool = False) -> None:
        self._errors = 0
        self._finalrule = None
        self._lexer.initialize(text)
        self._next()
        try:
            self._finalrule = self._parse_fullrule()
        except Exception as err:
            self._errors += 1
            if self._error_stream is not None:
                self._error_stream.write(f"{err}\n")

    def _parse_fullrule(self) -> ConstraintGroup:
        self._expect(ord('{'))
        self._next()
        stmts = self._parse_statementlist()

        if self._cur_tok == _Tok.ACTION_TICK:
            actions = self._parse_actionlist()
            result = self.mergeGroups(stmts, actions)
        elif self._cur_tok == ord('['):
            self._next()
            mega = self._parse_megaormid()
            self._expect(ord(']'))
            self._next()
            stmts.addConstraint(mega)
            result = stmts
        else:
            self.ruleError("Expected action list or mega-or group")
            result = stmts

        self._expect(ord('}'))
        self._next()
        return result

    def _parse_megaormid(self) -> ConstraintGroup:
        stmts = self._parse_statementlist()
        actions = self._parse_actionlist()
        orgrp = self.emptyOrGroup()
        self.addOr(orgrp, self.mergeGroups(stmts, actions))
        while self._cur_tok == _OP_INT_OR:
            self._next()
            stmts2 = self._parse_statementlist()
            actions2 = self._parse_actionlist()
            self.addOr(orgrp, self.mergeGroups(stmts2, actions2))
        return orgrp

    def _parse_actionlist(self) -> ConstraintGroup:
        self._expect(_Tok.ACTION_TICK)
        self._next()
        result = self.emptyGroup()
        while self._cur_tok not in (_Tok.EOF, ord('}'), ord(']'), _OP_INT_OR):
            act = self._parse_action()
            if act is not None:
                result = self.mergeGroups(result, act)
        return result

    def _parse_statementlist(self) -> ConstraintGroup:
        result = self.emptyGroup()
        while self._cur_tok not in (_Tok.EOF, _Tok.ACTION_TICK, ord('}'), ord(']'), _OP_INT_OR):
            stmt = self._parse_statement()
            if stmt is not None:
                result = self.mergeGroups(result, stmt)
        return result

    def _parse_action(self) -> Optional[ConstraintGroup]:
        result = self._parse_action_item()
        self._expect(ord(';'))
        self._next()
        return result

    def _parse_action_item(self) -> Optional[ConstraintGroup]:
        if self._cur_tok == _Tok.OP_NEW_IDENTIFIER:
            return self._parse_opnewnode_chain()
        if self._cur_tok == _Tok.OP_IDENTIFIER:
            return self._parse_opnewnode_chain()
        self.ruleError("Expected action item")
        self._next()
        return None

    def _parse_opnewnode_chain(self) -> ConstraintGroup:
        node = self._parse_opnewnode()
        if self._cur_tok == _Tok.DOUBLE_RIGHT_ARROW:
            return self._parse_varnewnode(node)
        if self._cur_tok == _Tok.DOUBLE_LEFT_ARROW:
            return self._parse_deadnewnode_or_setinput(node)
        return node

    def _parse_opnewnode(self) -> ConstraintGroup:
        if self._cur_tok == _Tok.OP_NEW_IDENTIFIER:
            nm = self._cur_val
            ident = self.findIdentifier(nm)
            self._next()
            if self._cur_tok == ord('('):
                self._next()
                if _is_opcode_token(self._cur_tok) or self._cur_tok == _Tok.SET_KEYWORD:
                    if self._cur_tok == _Tok.SET_KEYWORD:
                        self.ruleError("SET not valid in op_new_ident creation context directly")
                    opc = _token_to_opcode(self._cur_tok) if _is_opcode_token(self._cur_tok) else 0
                    self._next()
                    insertafter = False
                    if self._cur_tok == _Tok.BEFORE_KEYWORD:
                        insertafter = False
                        self._next()
                    elif self._cur_tok == _Tok.AFTER_KEYWORD:
                        insertafter = True
                        self._next()
                    else:
                        self.ruleError("Expected 'before' or 'after'")
                    if self._cur_tok in (_Tok.OP_IDENTIFIER, _Tok.OP_NEW_IDENTIFIER):
                        oldnm = self._cur_val
                        oldid = self.findIdentifier(oldnm)
                        self._next()
                    else:
                        self.ruleError("Expected op identifier")
                        oldid = 0
                    self._expect(ord(')'))
                    self._next()
                    node = self.opCreation(ident, opc, insertafter, oldid)
                else:
                    self.ruleError("Expected opcode or SET keyword in op_new_ident")
                    self._next()
                    node = self.emptyGroup()
            else:
                node = self.emptyGroup()
                node.addConstraint(DummyOpConstraint(ident))
        elif self._cur_tok == _Tok.OP_IDENTIFIER:
            nm = self._cur_val
            ident = self.findIdentifier(nm)
            self._next()
            node = self.newOp(ident)
        else:
            self.ruleError("Expected op identifier in action")
            self._next()
            node = self.emptyGroup()

        while self._cur_tok == ord('('):
            self._next()
            if self._cur_tok == _Tok.SET_KEYWORD:
                self._next()
                if _is_opcode_token(self._cur_tok):
                    opc = _token_to_opcode(self._cur_tok)
                    self._next()
                else:
                    self.ruleError("Expected opcode after SET")
                    opc = 0
                self._expect(ord(')'))
                self._next()
                node = self.newSetOpcode(node, opc)
            else:
                break
        return node

    def _parse_varnewnode(self, opnode: ConstraintGroup) -> ConstraintGroup:
        self._expect(_Tok.DOUBLE_RIGHT_ARROW)
        self._next()
        if self._cur_tok not in (_Tok.VAR_NEW_IDENTIFIER,):
            self.ruleError("Expected var_new_ident after -->>")
            return opnode
        nm = self._cur_val
        varid = self.findIdentifier(nm)
        self._next()
        self._expect(ord('('))
        self._next()
        if self._cur_tok == _Tok.INTB:
            sz = self._cur_val
            self._next()
            self._expect(ord(')'))
            self._next()
            return self.newUniqueOut(opnode, varid, -sz)
        elif self._cur_tok == _Tok.VAR_IDENTIFIER:
            nm2 = self._cur_val
            szid = self.findIdentifier(nm2)
            self._next()
            self._expect(ord(')'))
            self._next()
            return self.newUniqueOut(opnode, varid, szid)
        else:
            self.ruleError("Expected size in var_new_node")
            return opnode

    def _parse_deadnewnode_or_setinput(self, opnode: ConstraintGroup) -> ConstraintGroup:
        self._expect(_Tok.DOUBLE_LEFT_ARROW)
        self._next()
        self._expect(ord('('))
        self._next()
        slot_expr = self._parse_rhs_const()
        self._expect(ord(')'))
        self._next()

        if self._cur_tok == _Tok.REMOVE_KEYWORD:
            self._next()
            return self.removeInput(opnode, slot_expr)
        if self._cur_tok in (_Tok.VAR_IDENTIFIER, _Tok.VAR_NEW_IDENTIFIER):
            nm = self._cur_val
            varid = self.findIdentifier(nm)
            self._next()
            return self.newSetInput(opnode, slot_expr, varid)
        val_expr = self._parse_rhs_const()
        sz_expr = self._parse_var_size()
        return self.newSetInputConstVal(opnode, slot_expr, val_expr, sz_expr)

    def _parse_statement(self) -> Optional[ConstraintGroup]:
        if self._cur_tok == ord('['):
            self._next()
            orgrp = self._parse_orgroupmid()
            self._expect(ord(']'))
            self._next()
            wrapper = self.emptyGroup()
            wrapper.addConstraint(orgrp)
            return wrapper

        if self._cur_tok == ord('('):
            self._next()
            stmts = self._parse_statementlist()
            self._expect(ord(')'))
            self._next()
            return stmts

        if self._cur_tok == _Tok.ISTRUE_KEYWORD:
            self._next()
            self._expect(ord('('))
            self._next()
            expr = self._parse_rhs_const()
            self._expect(ord(')'))
            self._next()
            self._expect(ord(';'))
            self._next()
            return self.booleanConstraint(True, expr)

        if self._cur_tok == _Tok.ISFALSE_KEYWORD:
            self._next()
            self._expect(ord('('))
            self._next()
            expr = self._parse_rhs_const()
            self._expect(ord(')'))
            self._next()
            self._expect(ord(';'))
            self._next()
            return self.booleanConstraint(False, expr)

        if self._cur_tok == _Tok.CONST_IDENTIFIER:
            nm = self._cur_val
            cid = self.findIdentifier(nm)
            self._next()
            if self._cur_tok == ord('='):
                self._next()
                expr = self._parse_rhs_const()
                self._expect(ord(';'))
                self._next()
                return self.constNamedExpression(cid, expr)
            self.ruleError("Expected '=' after const_ident")
            return None

        if self._cur_tok == _Tok.OP_IDENTIFIER:
            return self._parse_opnode_statement()

        if self._cur_tok == _Tok.VAR_IDENTIFIER:
            return self._parse_varnode_statement()

        self.ruleError(f"Unexpected token in statement: {self._cur_tok}")
        self._next()
        return None

    def _parse_opnode_statement(self) -> ConstraintGroup:
        nm = self._cur_val
        ident = self.findIdentifier(nm)
        self._next()
        node = self.newOp(ident)
        node = self._parse_opnode_tail(node)

        if self._cur_tok == ord('='):
            self._next()
            if self._cur_tok == _Tok.OP_IDENTIFIER:
                nm2 = self._cur_val
                opid2 = self.findIdentifier(nm2)
                self._next()
                node = self.opCopy(node, opid2)
            else:
                self.ruleError("Expected op_ident after '=' in op context")

        if self._cur_tok == _Tok.LEFT_ARROW:
            self._next()
            if self._cur_tok == ord('('):
                self._next()
                slot_val = self._cur_val
                if self._cur_tok == _Tok.INTB:
                    slot = slot_val
                    self._next()
                else:
                    self.ruleError("Expected integer slot")
                    slot = 0
                self._expect(ord(')'))
                self._next()
                if self._cur_tok == _Tok.VAR_IDENTIFIER:
                    nm2 = self._cur_val
                    varid = self.findIdentifier(nm2)
                    self._next()
                    node = self.opInput(node, slot, varid)
                else:
                    rhs = self._parse_rhs_const()
                    node = self.opInputConstVal(node, slot, rhs)
            elif self._cur_tok == _Tok.VAR_IDENTIFIER:
                nm2 = self._cur_val
                varid = self.findIdentifier(nm2)
                self._next()
                node = self.opInputAny(node, varid)
            else:
                self.ruleError("Expected '(' or var_ident after '<-'")

        if self._cur_tok == _Tok.RIGHT_ARROW:
            self._next()
            if self._cur_tok == _Tok.VAR_IDENTIFIER:
                nm2 = self._cur_val
                varid = self.findIdentifier(nm2)
                self._next()
                node = self.opOutput(node, varid)
            else:
                self.ruleError("Expected var_ident after '->'")

        self._expect(ord(';'))
        self._next()
        return node

    def _parse_opnode_tail(self, node: ConstraintGroup) -> ConstraintGroup:
        while self._cur_tok == ord('('):
            saved_pos = self._lexer._pos
            saved_tok = self._cur_tok
            saved_val = self._cur_val
            self._next()

            if _is_opcode_token(self._cur_tok):
                opcodes = self._parse_op_list()
                self._expect(ord(')'))
                self._next()
                node = self.opCodeConstraint(node, opcodes)
            elif self._cur_tok == _OP_INT_EQUAL:
                self._next()
                if self._cur_tok == _Tok.OP_IDENTIFIER:
                    nm = self._cur_val
                    opid = self.findIdentifier(nm)
                    self._next()
                    self._expect(ord(')'))
                    self._next()
                    node = self.opCompareConstraint(node, opid, int(OpCode.CPUI_INT_EQUAL))
                else:
                    self.ruleError("Expected op_ident after '=='")
            elif self._cur_tok == _OP_INT_NOTEQUAL:
                self._next()
                if self._cur_tok == _Tok.OP_IDENTIFIER:
                    nm = self._cur_val
                    opid = self.findIdentifier(nm)
                    self._next()
                    self._expect(ord(')'))
                    self._next()
                    node = self.opCompareConstraint(node, opid, int(OpCode.CPUI_INT_NOTEQUAL))
                else:
                    self.ruleError("Expected op_ident after '!='")
            else:
                self._lexer._pos = saved_pos
                self._cur_tok = saved_tok
                self._cur_val = saved_val
                break
        return node

    def _parse_varnode_statement(self) -> ConstraintGroup:
        nm = self._cur_val
        ident = self.findIdentifier(nm)
        self._next()
        node = self.newVarnode(ident)
        node = self._parse_varnode_tail(node)

        if self._cur_tok == ord('='):
            self._next()
            if self._cur_tok == _Tok.VAR_IDENTIFIER:
                nm2 = self._cur_val
                varid = self.findIdentifier(nm2)
                self._next()
                node = self.varCopy(node, varid)
            else:
                rhs = self._parse_rhs_const()
                sz = self._parse_var_size()
                node = self.varConst(node, rhs, sz)

        if self._cur_tok == _Tok.LEFT_ARROW:
            self._next()
            if self._cur_tok == _Tok.OP_IDENTIFIER:
                nm2 = self._cur_val
                opid = self.findIdentifier(nm2)
                self._next()
                node = self.varDef(node, opid)
            else:
                self.ruleError("Expected op_ident after '<-' in var context")

        if self._cur_tok == _Tok.RIGHT_ARROW:
            self._next()
            if self._cur_tok == _OP_BOOL_NEGATE:
                self._next()
                if self._cur_tok == _Tok.OP_IDENTIFIER:
                    nm2 = self._cur_val
                    opid = self.findIdentifier(nm2)
                    self._next()
                    node = self.varUniqueDescend(node, opid)
                else:
                    self.ruleError("Expected op_ident after '->!'")
            elif self._cur_tok == _Tok.OP_IDENTIFIER:
                nm2 = self._cur_val
                opid = self.findIdentifier(nm2)
                self._next()
                node = self.varDescend(node, opid)
            else:
                self.ruleError("Expected op_ident or '!' after '->' in var context")

        self._expect(ord(';'))
        self._next()
        return node

    def _parse_varnode_tail(self, node: ConstraintGroup) -> ConstraintGroup:
        while self._cur_tok == ord('('):
            saved_pos = self._lexer._pos
            saved_tok = self._cur_tok
            saved_val = self._cur_val
            self._next()
            if self._cur_tok == _OP_INT_EQUAL:
                self._next()
                if self._cur_tok == _Tok.VAR_IDENTIFIER:
                    nm = self._cur_val
                    varid = self.findIdentifier(nm)
                    self._next()
                    self._expect(ord(')'))
                    self._next()
                    node = self.varCompareConstraint(node, varid, int(OpCode.CPUI_INT_EQUAL))
                else:
                    self.ruleError("Expected var_ident after '=='")
            elif self._cur_tok == _OP_INT_NOTEQUAL:
                self._next()
                if self._cur_tok == _Tok.VAR_IDENTIFIER:
                    nm = self._cur_val
                    varid = self.findIdentifier(nm)
                    self._next()
                    self._expect(ord(')'))
                    self._next()
                    node = self.varCompareConstraint(node, varid, int(OpCode.CPUI_INT_NOTEQUAL))
                else:
                    self.ruleError("Expected var_ident after '!='")
            else:
                self._lexer._pos = saved_pos
                self._cur_tok = saved_tok
                self._cur_val = saved_val
                break
        return node

    def _parse_orgroupmid(self) -> ConstraintGroup:
        stmts = self._parse_statementlist()
        orgrp = self.emptyOrGroup()
        self.addOr(orgrp, stmts)
        while self._cur_tok == _OP_INT_OR:
            self._next()
            stmts2 = self._parse_statementlist()
            self.addOr(orgrp, stmts2)
        return orgrp

    def _parse_op_list(self) -> List[int]:
        result = []
        while _is_opcode_token(self._cur_tok):
            result.append(_token_to_opcode(self._cur_tok))
            self._next()
        return result

    def _parse_rhs_const(self) -> RHSConstant:
        return self._parse_rhs_or()

    def _parse_rhs_or(self) -> RHSConstant:
        left = self._parse_rhs_xor()
        while self._cur_tok == _OP_INT_OR:
            self._next()
            right = self._parse_rhs_xor()
            left = self.constBinaryExpression(left, int(OpCode.CPUI_INT_OR), right)
        return left

    def _parse_rhs_xor(self) -> RHSConstant:
        left = self._parse_rhs_and()
        while self._cur_tok == _OP_INT_XOR:
            self._next()
            right = self._parse_rhs_and()
            left = self.constBinaryExpression(left, int(OpCode.CPUI_INT_XOR), right)
        return left

    def _parse_rhs_and(self) -> RHSConstant:
        left = self._parse_rhs_equality()
        while self._cur_tok == _OP_INT_AND:
            self._next()
            right = self._parse_rhs_equality()
            left = self.constBinaryExpression(left, int(OpCode.CPUI_INT_AND), right)
        return left

    def _parse_rhs_equality(self) -> RHSConstant:
        left = self._parse_rhs_comparison()
        while self._cur_tok in (_OP_INT_EQUAL, _OP_INT_NOTEQUAL):
            opc = _token_to_opcode(self._cur_tok)
            self._next()
            right = self._parse_rhs_comparison()
            left = self.constBinaryExpression(left, opc, right)
        return left

    def _parse_rhs_comparison(self) -> RHSConstant:
        left = self._parse_rhs_shift()
        while self._cur_tok in (_OP_INT_LESS, _OP_INT_LESSEQUAL,
                                _OP_INT_SLESS, _OP_INT_SLESSEQUAL):
            opc = _token_to_opcode(self._cur_tok)
            self._next()
            right = self._parse_rhs_shift()
            left = self.constBinaryExpression(left, opc, right)
        return left

    def _parse_rhs_shift(self) -> RHSConstant:
        left = self._parse_rhs_add()
        while self._cur_tok in (_OP_INT_LEFT, _OP_INT_RIGHT, _OP_INT_SRIGHT):
            opc = _token_to_opcode(self._cur_tok)
            self._next()
            right = self._parse_rhs_add()
            left = self.constBinaryExpression(left, opc, right)
        return left

    def _parse_rhs_add(self) -> RHSConstant:
        left = self._parse_rhs_mult()
        while self._cur_tok in (_OP_INT_ADD, _OP_INT_SUB):
            opc = _token_to_opcode(self._cur_tok)
            self._next()
            right = self._parse_rhs_mult()
            left = self.constBinaryExpression(left, opc, right)
        return left

    def _parse_rhs_mult(self) -> RHSConstant:
        left = self._parse_rhs_primary()
        while self._cur_tok in (_OP_INT_MULT, _OP_INT_DIV, _OP_INT_REM,
                                _OP_INT_SDIV, _OP_INT_SREM):
            opc = _token_to_opcode(self._cur_tok)
            self._next()
            right = self._parse_rhs_primary()
            left = self.constBinaryExpression(left, opc, right)
        return left

    def _parse_rhs_primary(self) -> RHSConstant:
        if self._cur_tok == ord('('):
            self._next()
            expr = self._parse_rhs_const()
            self._expect(ord(')'))
            self._next()
            return expr

        if self._cur_tok == _Tok.INTB:
            val = self._cur_val
            self._next()
            return self.constAbsolute(val)

        if self._cur_tok == _OP_INT_SUB:
            self._next()
            if self._cur_tok == _Tok.INTB:
                val = self._cur_val
                self._next()
                return self.constAbsolute(-val)
            self.ruleError("Expected integer after '-'")
            return self.constAbsolute(0)

        if self._cur_tok == _Tok.CONST_IDENTIFIER:
            nm = self._cur_val
            cid = self.findIdentifier(nm)
            self._next()
            return self.constNamed(cid)

        if self._cur_tok == _Tok.VAR_IDENTIFIER:
            nm = self._cur_val
            vid = self.findIdentifier(nm)
            self._next()
            if self._cur_tok == _Tok.DOT_IDENTIFIER:
                attr = self._cur_val
                self._next()
                return self.dotIdentifier(vid, attr)
            self.ruleError("Expected .attribute after var_ident in const context")
            return self.constAbsolute(0)

        self.ruleError(f"Unexpected token in rhs_const: {self._cur_tok}")
        self._next()
        return self.constAbsolute(0)

    def _parse_var_size(self) -> Optional[RHSConstant]:
        if self._cur_tok == ord(':'):
            self._next()
            return self._parse_rhs_const()
        return None


# =========================================================================
# RuleGeneric
# =========================================================================

class RuleGeneric(Rule):
    """A user-configurable rule read from a DSL string.

    C++ ref: ``RuleGeneric`` in rulecompile.hh/cc
    """

    def __init__(self, g: str, nm: str, starterops: List[int],
                 opinit: int, constraint: ConstraintGroup) -> None:
        super().__init__(g, 0, nm)
        self._starterops: List[int] = list(starterops)
        self._opinit: int = opinit
        self._constraint: ConstraintGroup = constraint
        self._state: UnifyState = UnifyState(constraint)

    def clone(self, grouplist) -> Optional[RuleGeneric]:
        if not grouplist.contains(self._basegroup):
            return None
        return RuleGeneric(
            self._basegroup, self._name,
            self._starterops, self._opinit,
            self._constraint.clone()
        )

    def getOpList(self) -> List[int]:
        return list(self._starterops)

    def applyOp(self, op, data) -> int:
        self._state.setFunction(data)
        self._state.initialize(self._opinit, op)
        self._constraint.initialize(self._state)
        return 1 if self._constraint.step(self._state) else 0

    @staticmethod
    def build(nm: str, gp: str, content: str) -> RuleGeneric:
        compiler = RuleCompile()
        compiler.run(content)
        if compiler.numErrors() != 0:
            raise LowlevelError(f"Unable to parse dynamic rule: {nm}")
        opcodelist: List[int] = []
        opinit = compiler.postProcessRule(opcodelist)
        return RuleGeneric(gp, nm, opcodelist, opinit, compiler.releaseRule())
