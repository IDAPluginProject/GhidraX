"""
Corresponds to: grammar.hh / grammar.cc

C grammar lexer and parser for type declarations.
Implements the full recursive-descent parser equivalent to the Bison
LALR(1) grammar in the C++ code.  Provides GrammarToken, GrammarLexer,
TypeModifier hierarchy, TypeDeclarator, TypeSpecifiers, Enumerator, and
CParse with complete parsing logic.
"""

from __future__ import annotations

import io
from typing import Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ghidra.arch.architecture import Architecture
    from ghidra.types.type_base import Datatype


# =========================================================================
# GrammarToken
# =========================================================================

class GrammarToken:
    """A single token from the C grammar lexer."""

    # Token type constants — match C++ char codes for single-character tokens
    openparen = 0x28       # '('
    closeparen = 0x29      # ')'
    star = 0x2a            # '*'
    comma = 0x2c           # ','
    semicolon = 0x3b       # ';'
    equals = 0x3d          # '='
    openbracket = 0x5b     # '['
    closebracket = 0x5d    # ']'
    openbrace = 0x7b       # '{'
    closebrace = 0x7d      # '}'

    badtoken = 0x100
    endoffile = 0x101
    dotdotdot = 0x102

    integer = 0x103
    charconstant = 0x104
    identifier = 0x105
    stringval = 0x106

    def __init__(self) -> None:
        self._type: int = self.badtoken
        self._intval: int = 0
        self._strval: Optional[str] = None
        self._lineno: int = 0
        self._colno: int = 0
        self._filenum: int = 0

    def getType(self) -> int:
        return self._type

    def getInteger(self) -> int:
        return self._intval

    def getString(self) -> Optional[str]:
        return self._strval

    def getLineNo(self) -> int:
        return self._lineno

    def getColNo(self) -> int:
        return self._colno

    def getFileNum(self) -> int:
        return self._filenum

    def set(self, tp: int, strval: Optional[str] = None, intval: int = 0) -> None:
        self._type = tp
        self._strval = strval
        self._intval = intval

    def setPosition(self, filenum: int, lineno: int, colno: int) -> None:
        self._filenum = filenum
        self._lineno = lineno
        self._colno = colno


# =========================================================================
# GrammarLexer  —  faithful port of the C++ finite-state lexer
# =========================================================================

class GrammarLexer:
    """Lexer for C-like grammar tokens.

    Re-implements the character-by-character finite-state machine from
    ``grammar.cc`` (``GrammarLexer::moveState``, ``getNextToken``, etc.).
    """

    # Lexer FSM states matching C++ enum
    start = 0
    slash = 1
    dot1 = 2
    dot2 = 3
    dot3 = 4
    punctuation = 7
    endofline_comment = 8
    c_comment = 9
    doublequote = 10
    doublequoteend = 11
    singlequote = 12
    singlequoteend = 13
    singlebackslash = 14
    number = 15
    identifier = 16

    def __init__(self, maxbuffer: int = 1024) -> None:
        self._filenamemap: Dict[int, str] = {}
        self._streammap: Dict[int, object] = {}
        self._filestack: List[int] = []
        self._maxbuffer: int = maxbuffer
        self._buffer: List[str] = []
        self._bufstart: int = 0
        self._bufend: int = 0
        self._curlineno: int = 0
        self._in: object = None
        self._endoffile: bool = True
        self._state: int = self.start
        self._error: str = ""

    # -- housekeeping -------------------------------------------------------

    def clear(self) -> None:
        self._filenamemap.clear()
        self._streammap.clear()
        self._filestack.clear()
        self._buffer.clear()
        self._bufstart = 0
        self._bufend = 0
        self._curlineno = 0
        self._in = None
        self._endoffile = True
        self._state = self.start
        self._error = ""

    def getCurStream(self):
        return self._in

    def getError(self) -> str:
        return self._error

    def setError(self, msg: str) -> None:
        self._error = msg

    def pushFile(self, filename: str, stream) -> None:
        fid = len(self._filenamemap)
        self._filenamemap[fid] = filename
        self._streammap[fid] = stream
        self._filestack.append(fid)
        self._in = stream
        self._endoffile = False
        self._curlineno = 1

    def popFile(self) -> None:
        if self._filestack:
            self._filestack.pop()
        if self._filestack:
            fid = self._filestack[-1]
            self._in = self._streammap.get(fid)
        else:
            self._in = None
            self._endoffile = True

    def writeLocation(self, s, line: int, filenum: int) -> None:
        fname = self._filenamemap.get(filenum, "<unknown>")
        s.write(f" at line {line} in {fname}")

    def writeTokenLocation(self, s, line: int, colno: int) -> None:
        if line != self._curlineno:
            return
        buf_text = ''.join(self._buffer[:self._bufend])
        s.write(buf_text + "\n")
        s.write(' ' * colno + "^--\n")

    # -- FSM ----------------------------------------------------------------

    def _bumpLine(self) -> None:
        self._curlineno += 1
        self._bufstart = 0
        self._bufend = 0
        self._buffer.clear()

    def _moveState(self, ch: str) -> int:
        """Advance the FSM by one lookahead character.

        Returns a non-zero GrammarToken type when a complete token has been
        recognised, or 0 to keep consuming.
        """
        newline = False
        o = ord(ch)

        # Normalise control characters
        if o < 32:
            if o in (9, 11, 12, 13):  # tab, vtab, ff, cr
                ch = ' '
            elif ch == '\n':
                newline = True
                ch = ' '
            else:
                self.setError("Illegal character")
                return GrammarToken.badtoken
        elif o >= 127:
            self.setError("Illegal character")
            return GrammarToken.badtoken

        res = 0
        syntaxerror = False
        st = self._state

        if st == self.start:
            if ch == '/':
                self._state = self.slash
            elif ch == '.':
                self._state = self.dot1
            elif ch in ('*', ',', '(', ')', '[', ']', '{', '}', ';', '='):
                self._state = self.punctuation
                self._bufstart = self._bufend - 1
            elif ch == '-' or ch.isdigit():
                self._state = self.number
                self._bufstart = self._bufend - 1
            elif ch == ' ':
                pass  # ignore
            elif ch == '"':
                self._state = self.doublequote
                self._bufstart = self._bufend - 1
            elif ch == "'":
                self._state = self.singlequote
            elif ch.isalpha() or ch == '_':
                self._state = self.identifier
                self._bufstart = self._bufend - 1
            else:
                self.setError("Illegal character")
                return GrammarToken.badtoken

        elif st == self.slash:
            if ch == '*':
                self._state = self.c_comment
            elif ch == '/':
                self._state = self.endofline_comment
            else:
                syntaxerror = True

        elif st == self.dot1:
            if ch == '.':
                self._state = self.dot2
            else:
                syntaxerror = True

        elif st == self.dot2:
            if ch == '.':
                self._state = self.dot3
            else:
                syntaxerror = True

        elif st == self.dot3:
            self._state = self.start
            res = GrammarToken.dotdotdot

        elif st == self.punctuation:
            self._state = self.start
            res = ord(self._buffer[self._bufstart])

        elif st == self.endofline_comment:
            if newline:
                self._state = self.start

        elif st == self.c_comment:
            if ch == '/' and self._bufend > 1 and self._buffer[self._bufend - 2] == '*':
                self._state = self.start

        elif st == self.doublequote:
            if ch == '"':
                self._state = self.doublequoteend

        elif st == self.doublequoteend:
            self._state = self.start
            res = GrammarToken.stringval

        elif st == self.singlequote:
            if ch == '\\':
                self._state = self.singlebackslash
            elif ch == "'":
                self._state = self.singlequoteend

        elif st == self.singlequoteend:
            self._state = self.start
            res = GrammarToken.charconstant

        elif st == self.singlebackslash:
            self._state = self.singlequote

        elif st == self.number:
            if ch == 'x':
                if (self._bufend - self._bufstart) != 2 or self._buffer[self._bufstart] != '0':
                    syntaxerror = True
            elif ch.isdigit():
                pass
            elif ch.isalpha():
                pass  # hex digits etc.
            elif ch == '_':
                pass
            else:
                self._state = self.start
                res = GrammarToken.integer

        elif st == self.identifier:
            if ch.isalnum() or ch in ('_', ':'):
                pass
            else:
                self._state = self.start
                res = GrammarToken.identifier

        if syntaxerror:
            self.setError("Syntax error")
            return GrammarToken.badtoken

        if newline:
            self._bumpLine()
        return res

    def _establishToken(self, token: GrammarToken, val: int) -> None:
        """Fill *token* from the buffer after the FSM recognised *val*."""
        if val < GrammarToken.integer:
            # Single-char punctuation / dotdotdot
            token.set(val)
        else:
            raw = ''.join(self._buffer[self._bufstart:self._bufend - 1])
            if val == GrammarToken.integer:
                try:
                    token.set(val, intval=int(raw, 0))
                except ValueError:
                    token.set(GrammarToken.badtoken)
                    return
            elif val in (GrammarToken.identifier, GrammarToken.stringval):
                if val == GrammarToken.stringval:
                    # strip surrounding quotes
                    if raw.startswith('"'):
                        raw = raw[1:]
                    if raw.endswith('"'):
                        raw = raw[:-1]
                token.set(val, raw)
            elif val == GrammarToken.charconstant:
                # raw is the character(s) between single quotes
                if len(raw) == 1:
                    token.set(val, intval=ord(raw))
                elif len(raw) >= 2 and raw[0] == '\\':
                    _esc = {'n': 10, '0': 0, 'a': 7, 'b': 8, 't': 9,
                            'v': 11, 'f': 12, 'r': 13}
                    token.set(val, intval=_esc.get(raw[1], ord(raw[1])))
                else:
                    token.set(val, intval=ord(raw[0]) if raw else 0)
            else:
                token.set(val)

        filenum = self._filestack[-1] if self._filestack else 0
        token.setPosition(filenum, self._curlineno, self._bufstart)

    def getNextToken(self, token: GrammarToken) -> None:
        """Read the next complete token from the input stream."""
        if self._endoffile:
            token.set(GrammarToken.endoffile)
            return

        tok = GrammarToken.badtoken
        firsttime = True

        while True:
            if (not firsttime) or (self._bufend == 0):
                if self._bufend >= self._maxbuffer:
                    self.setError("Line too long")
                    tok = GrammarToken.badtoken
                    break
                ch = self._in.read(1) if self._in else ''
                if not ch:
                    self._endoffile = True
                    break
                if self._bufend >= len(self._buffer):
                    self._buffer.append(ch)
                else:
                    self._buffer[self._bufend] = ch
                self._bufend += 1
            else:
                ch = self._buffer[self._bufend - 1]

            tok = self._moveState(ch)
            firsttime = False
            if tok != 0:
                break

        if self._endoffile:
            # Simulate trailing space so the FSM can resolve the last token
            if self._bufend >= len(self._buffer):
                self._buffer.append(' ')
            else:
                self._buffer[self._bufend] = ' '
            self._bufend += 1
            tok = self._moveState(' ')
            if tok == 0 and self._state not in (self.start, self.endofline_comment):
                self.setError("Incomplete token")
                tok = GrammarToken.badtoken

        if tok == 0 or tok == GrammarToken.badtoken:
            if tok == 0:
                token.set(GrammarToken.endoffile)
            else:
                token.set(GrammarToken.badtoken)
            return
        self._establishToken(token, tok)


# =========================================================================
# TypeModifier hierarchy
# =========================================================================

class TypeModifier:
    """Base class for type modifiers (pointer, array, function)."""
    pointer_mod = 0
    array_mod = 1
    function_mod = 2

    def getType(self) -> int:
        raise NotImplementedError

    def isValid(self) -> bool:
        raise NotImplementedError

    def modType(self, base, decl, glb):
        raise NotImplementedError


class PointerModifier(TypeModifier):
    """Pointer modifier — ``*`` possibly with qualifiers."""

    def __init__(self, flags: int = 0) -> None:
        self._flags: int = flags

    def getType(self) -> int:
        return TypeModifier.pointer_mod

    def isValid(self) -> bool:
        return True

    def modType(self, base, decl, glb):
        if glb is not None and hasattr(glb, 'types') and glb.types is not None:
            spc = glb.getDefaultDataSpace()
            addrsize = spc.getAddrSize() if spc else 4
            ws = spc.getWordSize() if spc else 1
            return glb.types.getTypePointer(addrsize, base, ws)
        return base


class ArrayModifier(TypeModifier):
    """Array modifier — ``[N]``."""

    def __init__(self, flags: int = 0, arraysize: int = 0) -> None:
        self._flags: int = flags
        self._arraysize: int = arraysize

    def getType(self) -> int:
        return TypeModifier.array_mod

    def isValid(self) -> bool:
        return self._arraysize > 0

    def modType(self, base, decl, glb):
        if glb is not None and hasattr(glb, 'types') and glb.types is not None:
            return glb.types.getTypeArray(self._arraysize, base)
        return base


class FunctionModifier(TypeModifier):
    """Function modifier — ``(param, param, ...)``."""

    def __init__(self, paramlist: Optional[List] = None, dotdotdot: bool = False) -> None:
        self._paramlist: List = list(paramlist) if paramlist else []
        self._dotdotdot: bool = dotdotdot
        # C++: if single void param with no modifiers, clear the list
        if len(self._paramlist) == 1:
            p = self._paramlist[0]
            if p is not None and p.numModifiers() == 0:
                bt = p.getBaseType()
                if bt is not None and hasattr(bt, 'getMetatype'):
                    from ghidra.types.type_base import TYPE_VOID  # noqa: F811
                    if bt.getMetatype() == TYPE_VOID:
                        self._paramlist.clear()

    def getType(self) -> int:
        return TypeModifier.function_mod

    def isValid(self) -> bool:
        for p in self._paramlist:
            if p is None:
                continue
            if not p.isValid():
                return False
            if p.numModifiers() == 0:
                bt = p.getBaseType()
                if bt is not None and hasattr(bt, 'getMetatype'):
                    from ghidra.types.type_base import TYPE_VOID  # noqa: F811
                    if bt.getMetatype() == TYPE_VOID:
                        return False
        return True

    def isDotdotdot(self) -> bool:
        return self._dotdotdot

    def getInTypes(self, glb) -> list:
        return [p.buildType(glb) for p in self._paramlist]

    def getInNames(self) -> list:
        return [p.getIdentifier() for p in self._paramlist]

    def modType(self, base, decl, glb):
        if glb is not None and hasattr(glb, 'types') and glb.types is not None:
            from ghidra.fspec.fspec import PrototypePieces
            proto = PrototypePieces()
            proto.outtype = base if base is not None else glb.types.getTypeVoid()
            proto.intypes = self.getInTypes(glb)
            proto.firstVarArgSlot = len(proto.intypes) if self._dotdotdot else -1
            if hasattr(decl, '_model') and decl._model:
                proto.model = glb.getModel(decl._model) if hasattr(glb, 'getModel') else None
            if proto.model is None and hasattr(glb, 'defaultfp'):
                proto.model = glb.defaultfp
            return glb.types.getTypeCode(proto)
        return base


# =========================================================================
# TypeDeclarator
# =========================================================================

class TypeDeclarator:
    """A parsed C type declaration: base type + chain of modifiers + name."""

    def __init__(self, ident: str = "") -> None:
        self._mods: List[TypeModifier] = []
        self._basetype = None
        self._ident: str = ident
        self._model: str = ""
        self._flags: int = 0

    def getBaseType(self):
        return self._basetype

    def numModifiers(self) -> int:
        return len(self._mods)

    def getIdentifier(self) -> str:
        return self._ident

    def hasProperty(self, mask: int) -> bool:
        return (self._flags & mask) != 0

    def isValid(self) -> bool:
        if self._basetype is None:
            return False
        # Check for multiple storage specifiers
        count = 0
        for f in (CParse.f_typedef, CParse.f_extern, CParse.f_static,
                  CParse.f_auto, CParse.f_register):
            if self._flags & f:
                count += 1
        if count > 1:
            return False
        # Check for multiple type qualifiers
        count = 0
        for f in (CParse.f_const, CParse.f_restrict, CParse.f_volatile):
            if self._flags & f:
                count += 1
        if count > 1:
            return False
        return all(m.isValid() for m in self._mods)

    def buildType(self, glb):
        """Apply modifiers in reverse binding order and return final type."""
        tp = self._basetype
        for mod in reversed(self._mods):
            tp = mod.modType(tp, self, glb)
        return tp

    def getModel(self, glb):
        pm = None
        if self._model and hasattr(glb, 'getModel'):
            pm = glb.getModel(self._model)
        if pm is None and hasattr(glb, 'defaultfp'):
            pm = glb.defaultfp
        return pm

    def getPrototype(self, pieces, glb) -> bool:
        """Fill *pieces* with this declarator's function prototype (if any)."""
        if not self._mods or self._mods[0].getType() != TypeModifier.function_mod:
            return False
        fmod = self._mods[0]
        pieces.model = self.getModel(glb)
        pieces.name = self._ident
        pieces.intypes = fmod.getInTypes(glb)
        pieces.innames = fmod.getInNames()
        pieces.firstVarArgSlot = len(pieces.intypes) if fmod.isDotdotdot() else -1
        # Build output type from remaining modifiers
        pieces.outtype = self._basetype
        for mod in reversed(self._mods[1:]):
            pieces.outtype = mod.modType(pieces.outtype, self, glb)
        return True


# =========================================================================
# TypeSpecifiers
# =========================================================================

class TypeSpecifiers:
    """Accumulated type specifiers during parsing."""

    def __init__(self) -> None:
        self.type_specifier = None
        self.function_specifier: str = ""
        self.flags: int = 0


# =========================================================================
# Enumerator
# =========================================================================

class Enumerator:
    """An enum constant with optional explicit value."""

    def __init__(self, name: str, value: Optional[int] = None) -> None:
        self.enumconstant: str = name
        self.constantassigned: bool = value is not None
        self.value: int = value if value is not None else 0


# =========================================================================
# CParse  — recursive-descent parser
# =========================================================================

# Internal token IDs used by the parser (matching the Bison token enum)
_DOTDOTDOT = 258
_BADTOKEN = 259
_STRUCT = 260
_UNION = 261
_ENUM = 262
_DECLARATION_RESULT = 263
_PARAM_RESULT = 264
_NUMBER = 265
_IDENTIFIER = 266
_STORAGE_CLASS_SPECIFIER = 267
_TYPE_QUALIFIER = 268
_FUNCTION_SPECIFIER = 269
_TYPE_NAME = 270
_EOF = -1


class CParse:
    """Full recursive-descent C type declaration parser.

    Faithfully implements the grammar encoded in the Bison ``grammar.y``
    whose generated tables live in ``grammar.cc``.
    """

    # Specifier flags  (must be accessible as CParse.f_xxx by TypeDeclarator)
    f_typedef = 1
    f_extern = 2
    f_static = 4
    f_auto = 8
    f_register = 16
    f_const = 32
    f_restrict = 64
    f_volatile = 128
    f_inline = 256
    f_struct = 512
    f_union = 1024
    f_enum = 2048

    # Document types
    doc_declaration = 0
    doc_parameter_declaration = 1

    _KEYWORDS: Dict[str, int] = {
        'typedef': f_typedef,
        'extern': f_extern,
        'static': f_static,
        'auto': f_auto,
        'register': f_register,
        'const': f_const,
        'restrict': f_restrict,
        'volatile': f_volatile,
        'inline': f_inline,
        'struct': f_struct,
        'union': f_union,
        'enum': f_enum,
    }

    def __init__(self, glb=None, maxbuf: int = 1024) -> None:
        self._glb = glb
        self._lexer: GrammarLexer = GrammarLexer(maxbuf)
        self._lastdecls: Optional[List[TypeDeclarator]] = None
        self._lasterror: str = ""
        self._curtok: int = _EOF
        self._curval: object = None   # str, int, Datatype, or None
        self._firsttoken: int = -1
        self._lineno: int = -1
        self._colno: int = -1
        self._filenum: int = -1

    # -- public API ---------------------------------------------------------

    def clear(self) -> None:
        self._lexer.clear()
        self._lastdecls = None
        self._lasterror = ""
        self._firsttoken = -1

    def getError(self) -> str:
        return self._lasterror

    def setError(self, msg: str) -> None:
        s = io.StringIO()
        s.write(msg)
        self._lexer.writeLocation(s, self._lineno, self._filenum)
        s.write('\n')
        self._lexer.writeTokenLocation(s, self._lineno, self._colno)
        self._lasterror = s.getvalue()

    def setResultDeclarations(self, val: Optional[List[TypeDeclarator]]) -> None:
        self._lastdecls = val

    def getResultDeclarations(self) -> Optional[List[TypeDeclarator]]:
        return self._lastdecls

    # -- factory helpers (match C++ CParse methods) -------------------------

    def newSpecifier(self) -> TypeSpecifiers:
        return TypeSpecifiers()

    def newDeclarator(self, name: str = "") -> TypeDeclarator:
        return TypeDeclarator(name)

    def newVecDeclarator(self) -> List[TypeDeclarator]:
        return []

    def newPointer(self) -> List[int]:
        return []

    def newEnumerator(self, ident: str, val: Optional[int] = None) -> Enumerator:
        return Enumerator(ident, val)

    def newVecEnumerator(self) -> List[Enumerator]:
        return []

    def convertFlag(self, name: str) -> int:
        f = self._KEYWORDS.get(name)
        if f is not None:
            return f
        self.setError("Unknown qualifier")
        return 0

    def addSpecifier(self, spec: TypeSpecifiers, name: str) -> TypeSpecifiers:
        spec.flags |= self.convertFlag(name)
        return spec

    def addTypeSpecifier(self, spec: TypeSpecifiers, tp) -> TypeSpecifiers:
        if spec.type_specifier is not None:
            self.setError("Multiple type specifiers")
        spec.type_specifier = tp
        return spec

    def addFuncSpecifier(self, spec: TypeSpecifiers, name: str) -> TypeSpecifiers:
        f = self._KEYWORDS.get(name)
        if f is not None:
            spec.flags |= f
        else:
            if spec.function_specifier:
                self.setError("Multiple parameter models")
            spec.function_specifier = name
        return spec

    def mergeSpecDec(self, spec: TypeSpecifiers,
                     dec: Optional[TypeDeclarator] = None) -> TypeDeclarator:
        if dec is None:
            dec = TypeDeclarator()
        dec._basetype = spec.type_specifier
        dec._model = spec.function_specifier
        dec._flags |= spec.flags
        return dec

    def mergeSpecDecVec(self, spec: TypeSpecifiers,
                        declist: Optional[List[TypeDeclarator]] = None) -> List[TypeDeclarator]:
        if declist is None:
            declist = [TypeDeclarator()]
        for d in declist:
            self.mergeSpecDec(spec, d)
        return declist

    def mergePointer(self, ptrspec: List[int], dec: TypeDeclarator) -> TypeDeclarator:
        for flags in ptrspec:
            dec._mods.append(PointerModifier(flags))
        return dec

    def newArray(self, dec: TypeDeclarator, flags: int, num: int) -> TypeDeclarator:
        dec._mods.append(ArrayModifier(flags, num))
        return dec

    def newFunc(self, dec: TypeDeclarator, declist: List) -> TypeDeclarator:
        dotdotdot = False
        if declist and declist[-1] is None:
            dotdotdot = True
            declist.pop()
        dec._mods.append(FunctionModifier(declist, dotdotdot))
        return dec

    def newStruct(self, ident: str, declist: List[TypeDeclarator]):
        if self._glb is not None and hasattr(self._glb, 'types'):
            return self._glb.types.getTypeStruct(ident)
        return None

    def oldStruct(self, ident: str):
        if self._glb is not None and hasattr(self._glb, 'types'):
            return self._glb.types.findByName(ident)
        return None

    def newUnion(self, ident: str, declist: List[TypeDeclarator]):
        if self._glb is not None and hasattr(self._glb, 'types'):
            return self._glb.types.getTypeUnion(ident)
        return None

    def oldUnion(self, ident: str):
        if self._glb is not None and hasattr(self._glb, 'types'):
            return self._glb.types.findByName(ident)
        return None

    def newEnum(self, ident: str, vecenum: List[Enumerator]):
        if self._glb is not None and hasattr(self._glb, 'types'):
            return self._glb.types.getTypeEnum(ident)
        return None

    def oldEnum(self, ident: str):
        if self._glb is not None and hasattr(self._glb, 'types'):
            return self._glb.types.findByName(ident)
        return None

    # -- lexer bridge -------------------------------------------------------

    def _lookupIdentifier(self, name: str) -> int:
        """Classify an identifier the same way C++ ``lookupIdentifier`` does."""
        kw = self._KEYWORDS.get(name)
        if kw is not None:
            if kw in (self.f_typedef, self.f_extern, self.f_static,
                      self.f_auto, self.f_register):
                return _STORAGE_CLASS_SPECIFIER
            if kw in (self.f_const, self.f_restrict, self.f_volatile):
                return _TYPE_QUALIFIER
            if kw == self.f_inline:
                return _FUNCTION_SPECIFIER
            if kw == self.f_struct:
                return _STRUCT
            if kw == self.f_union:
                return _UNION
            if kw == self.f_enum:
                return _ENUM
        # Check if it is a known type name
        if self._glb is not None and hasattr(self._glb, 'types') and self._glb.types is not None:
            tp = self._glb.types.findByName(name)
            if tp is not None:
                self._curval = tp
                return _TYPE_NAME
        # Check for a prototype model name
        if self._glb is not None and hasattr(self._glb, 'hasModel') and self._glb.hasModel(name):
            return _FUNCTION_SPECIFIER
        return _IDENTIFIER

    def _lex(self) -> int:
        """Get the next parser token (Bison-style integer)."""
        if self._firsttoken != -1:
            rv = self._firsttoken
            self._firsttoken = -1
            return rv

        if self._lasterror:
            return _BADTOKEN

        tok = GrammarToken()
        self._lexer.getNextToken(tok)
        self._lineno = tok.getLineNo()
        self._colno = tok.getColNo()
        self._filenum = tok.getFileNum()

        tt = tok.getType()
        if tt in (GrammarToken.integer, GrammarToken.charconstant):
            self._curval = tok.getInteger()
            return _NUMBER
        if tt == GrammarToken.identifier:
            nm = tok.getString()
            self._curval = nm
            return self._lookupIdentifier(nm)
        if tt == GrammarToken.stringval:
            self.setError("Illegal string constant")
            return _BADTOKEN
        if tt == GrammarToken.dotdotdot:
            return _DOTDOTDOT
        if tt == GrammarToken.badtoken:
            self.setError(self._lexer.getError())
            return _BADTOKEN
        if tt == GrammarToken.endoffile:
            return _EOF
        # Punctuation: return the char code directly
        return tt

    def _advance(self) -> None:
        self._curtok = self._lex()

    def _expect(self, tok: int) -> bool:
        if self._curtok == tok:
            self._advance()
            return True
        return False

    # -- recursive-descent productions --------------------------------------

    def _parse_declaration_specifiers(self) -> Optional[TypeSpecifiers]:
        """Parse declaration_specifiers (cases 6-13)."""
        spec: Optional[TypeSpecifiers] = None
        while True:
            t = self._curtok
            if t == _STORAGE_CLASS_SPECIFIER:
                name = self._curval
                self._advance()
                if spec is None:
                    spec = self.newSpecifier()
                self.addSpecifier(spec, name)
            elif t == _TYPE_QUALIFIER:
                name = self._curval
                self._advance()
                if spec is None:
                    spec = self.newSpecifier()
                self.addSpecifier(spec, name)
            elif t == _FUNCTION_SPECIFIER:
                name = self._curval
                self._advance()
                if spec is None:
                    spec = self.newSpecifier()
                self.addFuncSpecifier(spec, name)
            elif t == _TYPE_NAME:
                tp = self._curval
                self._advance()
                if spec is None:
                    spec = self.newSpecifier()
                self.addTypeSpecifier(spec, tp)
            elif t == _STRUCT:
                tp = self._parse_struct_or_union_specifier(is_struct=True)
                if spec is None:
                    spec = self.newSpecifier()
                self.addTypeSpecifier(spec, tp)
            elif t == _UNION:
                tp = self._parse_struct_or_union_specifier(is_struct=False)
                if spec is None:
                    spec = self.newSpecifier()
                self.addTypeSpecifier(spec, tp)
            elif t == _ENUM:
                tp = self._parse_enum_specifier()
                if spec is None:
                    spec = self.newSpecifier()
                self.addTypeSpecifier(spec, tp)
            else:
                break
        return spec

    def _parse_struct_or_union_specifier(self, is_struct: bool):
        """Parse struct/union specifier (cases 20-25)."""
        self._advance()  # consume STRUCT/UNION
        name = ""
        if self._curtok == _IDENTIFIER:
            name = self._curval
            self._advance()

        if self._curtok == GrammarToken.openbrace:
            self._advance()  # consume '{'
            declist = self._parse_struct_declaration_list()
            if not self._expect(GrammarToken.closebrace):
                self.setError("Expected '}'")
            if is_struct:
                return self.newStruct(name, declist)
            else:
                return self.newUnion(name, declist)
        else:
            # Forward reference: struct/union IDENT without body
            if not name:
                self.setError("Expected identifier or '{'")
                return None
            if is_struct:
                return self.oldStruct(name)
            else:
                return self.oldUnion(name)

    def _parse_struct_declaration_list(self) -> List[TypeDeclarator]:
        """Parse struct_declaration_list (cases 26-28)."""
        result: List[TypeDeclarator] = []
        while self._curtok != GrammarToken.closebrace and self._curtok != _EOF:
            spec = self._parse_specifier_qualifier_list()
            if spec is None:
                break
            declist = self._parse_struct_declarator_list()
            if not self._expect(GrammarToken.semicolon):
                self.setError("Expected ';'")
            merged = self.mergeSpecDecVec(spec, declist if declist else None)
            result.extend(merged)
        return result

    def _parse_specifier_qualifier_list(self) -> Optional[TypeSpecifiers]:
        """Parse specifier_qualifier_list (cases 29-32)."""
        spec: Optional[TypeSpecifiers] = None
        while True:
            t = self._curtok
            if t == _TYPE_NAME:
                tp = self._curval
                self._advance()
                if spec is None:
                    spec = self.newSpecifier()
                self.addTypeSpecifier(spec, tp)
            elif t == _TYPE_QUALIFIER:
                name = self._curval
                self._advance()
                if spec is None:
                    spec = self.newSpecifier()
                self.addSpecifier(spec, name)
            elif t in (_STRUCT, _UNION, _ENUM):
                if t == _STRUCT:
                    tp = self._parse_struct_or_union_specifier(True)
                elif t == _UNION:
                    tp = self._parse_struct_or_union_specifier(False)
                else:
                    tp = self._parse_enum_specifier()
                if spec is None:
                    spec = self.newSpecifier()
                self.addTypeSpecifier(spec, tp)
            else:
                break
        return spec

    def _parse_struct_declarator_list(self) -> Optional[List[TypeDeclarator]]:
        """Parse struct_declarator_list (cases 33-35)."""
        dec = self._parse_declarator()
        if dec is None:
            return None
        result = [dec]
        while self._curtok == GrammarToken.comma:
            self._advance()
            dec = self._parse_declarator()
            if dec is None:
                break
            result.append(dec)
        return result

    def _parse_enum_specifier(self):
        """Parse enum specifier (cases 36-40)."""
        self._advance()  # consume ENUM
        name = ""
        if self._curtok == _IDENTIFIER:
            name = self._curval
            self._advance()

        if self._curtok == GrammarToken.openbrace:
            self._advance()
            vecenum = self._parse_enumerator_list()
            # Allow optional trailing comma
            if self._curtok == GrammarToken.comma:
                self._advance()
            if not self._expect(GrammarToken.closebrace):
                self.setError("Expected '}'")
            return self.newEnum(name, vecenum)
        else:
            if not name:
                self.setError("Expected identifier or '{'")
                return None
            return self.oldEnum(name)

    def _parse_enumerator_list(self) -> List[Enumerator]:
        """Parse enumerator_list (cases 41-44)."""
        result: List[Enumerator] = []
        e = self._parse_enumerator()
        if e is not None:
            result.append(e)
        while self._curtok == GrammarToken.comma:
            self._advance()
            if self._curtok == GrammarToken.closebrace:
                break  # trailing comma
            e = self._parse_enumerator()
            if e is not None:
                result.append(e)
        return result

    def _parse_enumerator(self) -> Optional[Enumerator]:
        """Parse a single enumerator (cases 43-44)."""
        if self._curtok != _IDENTIFIER:
            return None
        name = self._curval
        self._advance()
        if self._curtok == GrammarToken.equals:
            self._advance()
            if self._curtok != _NUMBER:
                self.setError("Expected number after '='")
                return self.newEnumerator(name)
            val = self._curval
            self._advance()
            return self.newEnumerator(name, val)
        return self.newEnumerator(name)

    def _parse_declarator(self) -> Optional[TypeDeclarator]:
        """Parse declarator (cases 45-51)."""
        ptrspec: Optional[List[int]] = None
        if self._curtok == GrammarToken.star:
            ptrspec = self._parse_pointer()

        dec = self._parse_direct_declarator()
        if dec is None:
            if ptrspec is not None:
                # pointer with no direct declarator → abstract
                dec = TypeDeclarator()
            else:
                return None

        if ptrspec is not None:
            dec = self.mergePointer(ptrspec, dec)
        return dec

    def _parse_direct_declarator(self) -> Optional[TypeDeclarator]:
        """Parse direct_declarator (cases 47-51)."""
        dec: Optional[TypeDeclarator] = None

        if self._curtok == _IDENTIFIER:
            dec = TypeDeclarator(self._curval)
            self._advance()
        elif self._curtok == GrammarToken.openparen:
            self._advance()
            dec = self._parse_declarator()
            if not self._expect(GrammarToken.closeparen):
                self.setError("Expected ')'")

        if dec is None:
            return None

        # Postfix: arrays and functions
        while True:
            if self._curtok == GrammarToken.openbracket:
                self._advance()
                flags = 0
                if self._curtok == _TYPE_QUALIFIER:
                    flags = self.convertFlag(self._curval)
                    self._advance()
                num = 0
                if self._curtok == _NUMBER:
                    num = self._curval
                    self._advance()
                if not self._expect(GrammarToken.closebracket):
                    self.setError("Expected ']'")
                dec = self.newArray(dec, flags, num)
            elif self._curtok == GrammarToken.openparen:
                self._advance()
                paramlist = self._parse_parameter_list()
                if not self._expect(GrammarToken.closeparen):
                    self.setError("Expected ')'")
                dec = self.newFunc(dec, paramlist)
            else:
                break
        return dec

    def _parse_pointer(self) -> List[int]:
        """Parse pointer specifiers (cases 52-55)."""
        result: List[int] = []
        while self._curtok == GrammarToken.star:
            self._advance()
            flags = 0
            while self._curtok == _TYPE_QUALIFIER:
                flags |= self.convertFlag(self._curval)
                self._advance()
            result.append(flags)
        return result

    def _parse_parameter_list(self) -> List:
        """Parse parameter_list (cases 58-61)."""
        result: List = []
        dec = self._parse_parameter_declaration()
        if dec is not None:
            result.append(dec)
        while self._curtok == GrammarToken.comma:
            self._advance()
            if self._curtok == _DOTDOTDOT:
                self._advance()
                result.append(None)  # sentinel for varargs
                break
            dec = self._parse_parameter_declaration()
            if dec is not None:
                result.append(dec)
        return result

    def _parse_parameter_declaration(self) -> Optional[TypeDeclarator]:
        """Parse parameter_declaration (cases 62-67)."""
        spec = self._parse_declaration_specifiers()
        if spec is None:
            return None
        # Try to parse a declarator (named or abstract)
        dec = self._parse_declarator()
        if dec is not None:
            return self.mergeSpecDec(spec, dec)
        # No declarator → abstract parameter with just the type specifier
        return self.mergeSpecDec(spec)

    def _parse_init_declarator_list(self) -> Optional[List[TypeDeclarator]]:
        """Parse init_declarator_list (cases 14-16)."""
        dec = self._parse_declarator()
        if dec is None:
            return None
        result = [dec]
        while self._curtok == GrammarToken.comma:
            self._advance()
            dec = self._parse_declarator()
            if dec is None:
                break
            result.append(dec)
        return result

    # -- top-level parse ----------------------------------------------------

    def _runParse(self, doctype: int) -> bool:
        if doctype == self.doc_declaration:
            self._firsttoken = _DECLARATION_RESULT
        elif doctype == self.doc_parameter_declaration:
            self._firsttoken = _PARAM_RESULT
        else:
            self.setError("Bad document type")
            return False

        self._advance()

        if self._curtok == _DECLARATION_RESULT:
            self._advance()
            return self._parseDeclaration()
        elif self._curtok == _PARAM_RESULT:
            self._advance()
            return self._parseParamDeclaration()
        else:
            # Fall through to declaration mode
            return self._parseDeclaration()

    def _parseDeclaration(self) -> bool:
        """Parse a top-level declaration (cases 2, 4, 5)."""
        spec = self._parse_declaration_specifiers()
        if spec is None:
            self.setError("Expected declaration specifiers")
            return False
        # Optional declarator list
        if self._curtok == GrammarToken.semicolon or self._curtok == _EOF:
            self._lastdecls = self.mergeSpecDecVec(spec)
            return True
        declist = self._parse_init_declarator_list()
        self._lastdecls = self.mergeSpecDecVec(spec, declist)
        return True

    def _parseParamDeclaration(self) -> bool:
        """Parse a single parameter declaration (case 3)."""
        spec = self._parse_declaration_specifiers()
        if spec is None:
            self.setError("Expected declaration specifiers")
            return False
        dec = self._parse_declarator()
        if dec is not None:
            d = self.mergeSpecDec(spec, dec)
        else:
            d = self.mergeSpecDec(spec)
        self._lastdecls = [d]
        return True

    # -- public entry points ------------------------------------------------

    def parseStream(self, s, doctype: int = 0) -> bool:
        """Parse C type declarations from *s*."""
        self.clear()
        self._lexer.pushFile("stream", s)
        return self._runParse(doctype)

    def parseFile(self, filename: str, doctype: int = 0) -> bool:
        """Parse C type declarations from file *filename*."""
        self.clear()
        try:
            f = open(filename, 'r', encoding='utf-8')
        except OSError:
            self._lasterror = f"Unable to open file for parsing: {filename}"
            return False
        self._lexer.pushFile(filename, f)
        result = self._runParse(doctype)
        f.close()
        return result


# =========================================================================
# Module-level helpers  (match C++ free functions)
# =========================================================================

def parse_type(s, glb) -> tuple:
    """Parse a single type from stream *s*.  Returns ``(Datatype, name)``."""
    parser = CParse(glb, 4096)
    if not parser.parseStream(s, CParse.doc_parameter_declaration):
        from ghidra.core.error import ParseError
        raise ParseError(parser.getError())
    decls = parser.getResultDeclarations()
    if not decls:
        from ghidra.core.error import ParseError
        raise ParseError("Did not parse a datatype")
    if len(decls) > 1:
        from ghidra.core.error import ParseError
        raise ParseError("Parsed multiple declarations")
    d = decls[0]
    if not d.isValid():
        from ghidra.core.error import ParseError
        raise ParseError("Parsed type is invalid")
    return (d.buildType(glb), d.getIdentifier())


def parse_C(glb, s) -> None:
    """Parse C declarations from *s* into architecture *glb*."""
    parser = CParse(glb, 4096)
    if not parser.parseStream(s, CParse.doc_declaration):
        from ghidra.core.error import ParseError
        raise ParseError(parser.getError())
    decls = parser.getResultDeclarations()
    if not decls:
        from ghidra.core.error import ParseError
        raise ParseError("Did not parse a datatype")


def parse_toseparator(s) -> str:
    """Read from *s* until a C separator is encountered."""
    parts: List[str] = []
    # skip leading whitespace
    while True:
        ch = s.read(1)
        if not ch:
            return ''
        if not ch.isspace():
            break
    # read until non-alnum/non-underscore
    while ch and (ch.isalnum() or ch == '_'):
        parts.append(ch)
        ch = s.read(1)
    return ''.join(parts)
