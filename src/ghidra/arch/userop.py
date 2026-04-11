"""
Corresponds to: userop.hh / userop.cc

User defined p-code operations (CALLOTHER) and UserOpManage registry.
"""

from __future__ import annotations
from typing import Optional, List, Dict

from ghidra.core.error import LowlevelError
from ghidra.core.pcoderaw import VarnodeData


class UserPcodeOp:
    """Base class for user defined p-code operations."""
    annotation_assignment = 1
    no_operator = 2
    display_string = 4
    unspecialized = 1
    injected = 2
    volatile_read = 3
    volatile_write = 4
    segment = 5
    jumpassist = 6
    string_data = 7
    datatype = 8
    BUILTIN_STRINGDATA = 0x10000000
    BUILTIN_VOLATILE_READ = 0x10000001
    BUILTIN_VOLATILE_WRITE = 0x10000002
    BUILTIN_MEMCPY = 0x10000003
    BUILTIN_STRNCPY = 0x10000004
    BUILTIN_WCSNCPY = 0x10000005

    def __init__(self, nm, glb, tp, ind):
        self.name = nm
        self.glb = glb
        self.type = tp
        self.useropindex = ind
        self.flags = 0

    def getName(self): return self.name
    def getIndex(self): return self.useropindex
    def getDisplay(self):
        return self.flags & (
            self.annotation_assignment | self.no_operator | self.display_string
        )
    def getOperatorName(self, op=None): return self.name
    def getOutputLocal(self, op=None): return None
    def getInputLocal(self, op=None, slot=0): return None
    def extractAnnotationSize(self, vn, op):
        raise LowlevelError("Unexpected annotation input for CALLOTHER " + self.name)
    def setIndex(self, ind: int) -> None: self.useropindex = ind
    def setDisplay(self, flags: int) -> None: self.flags = (self.flags & ~7) | (flags & 7)
    def getType(self) -> int: return self.type
    def __del__(self) -> None:
        pass
    def encode(self, encoder) -> None: pass
    def decode(self, decoder) -> None:
        raise NotImplementedError("UserPcodeOp.decode is pure virtual")


class UnspecializedPcodeOp(UserPcodeOp):
    def __init__(self, nm, glb, ind):
        super().__init__(nm, glb, UserPcodeOp.unspecialized, ind)

    def decode(self, decoder) -> None:
        pass


class InjectedUserOp(UserPcodeOp):
    def __init__(self, nm, glb, ind, injid):
        super().__init__(nm, glb, UserPcodeOp.injected, ind)
        self.injectid = injid
    def getInjectId(self): return self.injectid

    def decode(self, decoder) -> None:
        from ghidra.arch.inject import InjectPayload

        self.injectid = self.glb.pcodeinjectlib.decodeInject(
            "userop", "", InjectPayload.CALLOTHERFIXUP_TYPE, decoder
        )
        self.name = self.glb.pcodeinjectlib.getCallOtherTarget(self.injectid)
        base = self.glb.userops.getOp(self.name)
        if base is None:
            raise LowlevelError("Unknown userop name in <callotherfixup>: " + self.name)
        if not isinstance(base, UnspecializedPcodeOp):
            raise LowlevelError("<callotherfixup> overloads userop with another purpose: " + self.name)
        self.useropindex = base.getIndex()


class VolatileOp(UserPcodeOp):
    """Base for volatile read/write ops."""

    @staticmethod
    def appendSize(base: str, size: int) -> str:
        if size == 1:
            return base + "_1"
        if size == 2:
            return base + "_2"
        if size == 4:
            return base + "_4"
        if size == 8:
            return base + "_8"
        return f"{base}_{size}"

    def __init__(self, nm, glb, tp, ind):
        super().__init__(nm, glb, tp, ind)

    def decode(self, decoder) -> None:
        pass


class VolatileReadOp(VolatileOp):
    def __init__(self, nm, glb, functional: bool):
        super().__init__(nm, glb, UserPcodeOp.volatile_read, UserPcodeOp.BUILTIN_VOLATILE_READ)
        if functional:
            self.flags = 0
        else:
            self.flags = UserPcodeOp.no_operator

    def getOperatorName(self, op=None) -> str:
        """C++ ref: ``VolatileReadOp::getOperatorName``"""
        if op is None:
            return self.name
        out = op.getOut() if hasattr(op, 'getOut') else None
        if out is None:
            return self.name
        return self.appendSize(self.name, out.getSize())

    def getOutputLocal(self, op=None):
        if not op.doesSpecialPropagation():
            return None
        addr = op.getIn(1).getAddr()
        size = op.getOut().getSize()
        vflags = [0]
        entry = self.glb.symboltab.getGlobalScope().queryProperties(
            addr, size, op.getAddr(), vflags
        )
        if entry is not None:
            return entry.getSizedType(addr, size)
        return None

    def extractAnnotationSize(self, vn, op) -> int:
        outvn = op.getOut() if hasattr(op, 'getOut') else None
        if outvn is not None:
            return outvn.getSize()
        return 1


class VolatileWriteOp(VolatileOp):
    def __init__(self, nm, glb, functional: bool):
        super().__init__(nm, glb, UserPcodeOp.volatile_write, UserPcodeOp.BUILTIN_VOLATILE_WRITE)
        if functional:
            self.flags = 0
        else:
            self.flags = UserPcodeOp.annotation_assignment

    def getOperatorName(self, op=None) -> str:
        """C++ ref: ``VolatileWriteOp::getOperatorName``"""
        if op is None:
            return self.name
        if not hasattr(op, 'numInput') or op.numInput() < 3:
            return self.name
        return self.appendSize(self.name, op.getIn(2).getSize())

    def getInputLocal(self, op=None, slot=0):
        if not op.doesSpecialPropagation() or slot != 2:
            return None
        addr = op.getIn(1).getAddr()
        size = op.getIn(2).getSize()
        vflags = [0]
        entry = self.glb.symboltab.getGlobalScope().queryProperties(
            addr, size, op.getAddr(), vflags
        )
        if entry is not None:
            return entry.getSizedType(addr, size)
        return None

    def extractAnnotationSize(self, vn, op) -> int:
        return op.getIn(2).getSize()


class UserOpManage:
    """Registry for user defined p-code ops, indexed by CALLOTHER id."""

    def __init__(self):
        self.glb = None
        self._useroplist: List[Optional[UserPcodeOp]] = []
        self._useropmap: Dict[str, UserPcodeOp] = {}
        self._builtinmap: Dict[int, UserPcodeOp] = {}
        self._segmentop: List[Optional["SegmentOp"]] = []

    def __del__(self) -> None:
        self._segmentop.clear()
        self._builtinmap.clear()
        self._useropmap.clear()
        self._useroplist.clear()

    def initialize(self, glb) -> None:
        self.glb = glb
        basicops = glb.translate.getUserOpNames()
        for i, nm in enumerate(basicops):
            if len(nm) == 0:
                continue
            self.registerOp(UnspecializedPcodeOp(nm, glb, i))

    def getOp(self, i) -> Optional[UserPcodeOp]:
        if isinstance(i, str):
            return self._useropmap.get(i)
        if isinstance(i, int):
            if 0 <= i < len(self._useroplist):
                return self._useroplist[i]
            return self._builtinmap.get(i)
        return None

    def registerOp(self, op: UserPcodeOp) -> None:
        idx = op.getIndex()
        if idx < 0:
            raise LowlevelError("UserOp not assigned an index")
        other = self._useropmap.get(op.getName())
        if other is not None and other.getIndex() != idx:
            raise LowlevelError("Conflicting indices for userop name " + op.getName())

        while idx >= len(self._useroplist):
            self._useroplist.append(None)
        if self._useroplist[idx] is not None:
            if self._useroplist[idx].getName() != op.getName():
                raise LowlevelError(
                    "User op "
                    + op.getName()
                    + " has same index as "
                    + self._useroplist[idx].getName()
                )
        self._useropmap[op.getName()] = op
        self._useroplist[idx] = op
        if isinstance(op, SegmentOp) and op.getSpace() is not None:
            spc_index = op.getSpace().getIndex()
            while len(self._segmentop) <= spc_index:
                self._segmentop.append(None)
            if self._segmentop[spc_index] is not None:
                raise LowlevelError("Multiple segmentops defined for same space")
            self._segmentop[spc_index] = op

    def numOps(self) -> int:
        return len(self._useroplist)

    def getOpByName(self, nm: str) -> Optional[UserPcodeOp]:
        return self._useropmap.get(nm)

    def numUserOps(self) -> int:
        return len(self._useroplist)

    def decodeSegmentOp(self, decoder, glb) -> None:
        s_op = SegmentOp("", glb, len(self._useroplist))
        s_op.decode(decoder)
        self.registerOp(s_op)

    def decodeJumpAssist(self, decoder, glb) -> None:
        op = JumpAssistOp(glb)
        op.decode(decoder)
        self.registerOp(op)

    def decodeCallOtherFixup(self, decoder, glb) -> None:
        op = InjectedUserOp("", glb, 0, 0)
        op.decode(decoder)
        self.registerOp(op)

    def manualCallOtherFixup(self, useropname: str, outname: str,
                             inname: list, snippet: str, glb) -> None:
        userop = self.getOp(useropname)
        if userop is None:
            raise LowlevelError("Unknown userop: " + useropname)
        if not isinstance(userop, UnspecializedPcodeOp):
            raise LowlevelError("Cannot fixup userop: " + useropname)
        injectid = glb.pcodeinjectlib.manualCallOtherFixup(
            useropname, outname, inname, snippet
        )
        op = InjectedUserOp(useropname, glb, userop.getIndex(), injectid)
        self.registerOp(op)

    def getSegmentOp(self, i: int = 0):
        """Get the SegmentOp registered for the given space index."""
        if i >= len(self._segmentop):
            return None
        return self._segmentop[i]

    def numSegmentOps(self) -> int:
        """Return the size of the SegmentOp vector indexed by space."""
        return len(self._segmentop)

    def registerBuiltin(self, i: int) -> Optional[UserPcodeOp]:
        if i in self._builtinmap:
            return self._builtinmap[i]
        glb = self.glb
        if i == UserPcodeOp.BUILTIN_STRINGDATA:
            res = InternalStringOp(glb)
        elif i == UserPcodeOp.BUILTIN_VOLATILE_READ:
            res = VolatileReadOp("read_volatile", glb, False)
        elif i == UserPcodeOp.BUILTIN_VOLATILE_WRITE:
            res = VolatileWriteOp("write_volatile", glb, False)
        elif i == UserPcodeOp.BUILTIN_MEMCPY:
            from ghidra.types.datatype import TYPE_INT

            ptr_size = glb.types.getSizeOfPointer()
            word_size = glb.getDefaultDataSpace().getWordSize()
            void_type = glb.types.getTypeVoid()
            ptr_type = glb.types.getTypePointer(ptr_size, void_type, word_size)
            int_type = glb.types.getBase(4, TYPE_INT)
            res = DatatypeUserOp(
                "builtin_memcpy", glb, UserPcodeOp.BUILTIN_MEMCPY,
                ptr_type, ptr_type, ptr_type, int_type
            )
        elif i == UserPcodeOp.BUILTIN_STRNCPY:
            from ghidra.types.datatype import TYPE_INT

            ptr_size = glb.types.getSizeOfPointer()
            word_size = glb.getDefaultDataSpace().getWordSize()
            char_type = glb.types.getTypeChar()
            ptr_type = glb.types.getTypePointer(ptr_size, char_type, word_size)
            int_type = glb.types.getBase(4, TYPE_INT)
            res = DatatypeUserOp(
                "builtin_strncpy", glb, UserPcodeOp.BUILTIN_STRNCPY,
                ptr_type, ptr_type, ptr_type, int_type
            )
        elif i == UserPcodeOp.BUILTIN_WCSNCPY:
            from ghidra.types.datatype import TYPE_INT

            ptr_size = glb.types.getSizeOfPointer()
            word_size = glb.getDefaultDataSpace().getWordSize()
            wchar_type = (
                glb.types.findByName("wchar2")
                or glb.types.findByName("wchar4")
                or glb.types.getTypeChar()
            )
            ptr_type = glb.types.getTypePointer(ptr_size, wchar_type, word_size)
            int_type = glb.types.getBase(4, TYPE_INT)
            res = DatatypeUserOp(
                "builtin_wcsncpy", glb, UserPcodeOp.BUILTIN_WCSNCPY,
                ptr_type, ptr_type, ptr_type, int_type
            )
        else:
            raise LowlevelError("Bad built-in userop id")
        self._builtinmap[i] = res
        return res

    def decodeVolatile(self, decoder, glb) -> None:
        from ghidra.core.marshal import ATTRIB_INPUTOP, ATTRIB_OUTPUTOP, ATTRIB_FORMAT
        readOpName = ""
        writeOpName = ""
        functionalDisplay = False
        while True:
            attribId = decoder.getNextAttributeId()
            if attribId == 0:
                break
            if attribId == ATTRIB_INPUTOP.id:
                readOpName = decoder.readString()
            elif attribId == ATTRIB_OUTPUTOP.id:
                writeOpName = decoder.readString()
            elif attribId == ATTRIB_FORMAT.id:
                fmt = decoder.readString()
                if fmt == "functional":
                    functionalDisplay = True
        if not readOpName or not writeOpName:
            raise LowlevelError("Missing inputop/outputop attributes in <volatile> element")
        if UserPcodeOp.BUILTIN_VOLATILE_READ in self._builtinmap:
            raise LowlevelError("read_volatile user-op registered more than once")
        if UserPcodeOp.BUILTIN_VOLATILE_WRITE in self._builtinmap:
            raise LowlevelError("write_volatile user-op registered more than once")
        vr_op = VolatileReadOp(readOpName, glb, functionalDisplay)
        self._builtinmap[UserPcodeOp.BUILTIN_VOLATILE_READ] = vr_op
        vw_op = VolatileWriteOp(writeOpName, glb, functionalDisplay)
        self._builtinmap[UserPcodeOp.BUILTIN_VOLATILE_WRITE] = vw_op


class TermPatternOp(UserPcodeOp):
    def __init__(self, nm, glb, tp, ind):
        super().__init__(nm, glb, tp, ind)

    def getNumVariableTerms(self) -> int:
        raise NotImplementedError("TermPatternOp.getNumVariableTerms is pure virtual")

    def unify(self, data, op, bindlist: list) -> bool:
        raise NotImplementedError("TermPatternOp.unify is pure virtual")

    def execute(self, inputs: list) -> int:
        raise NotImplementedError("TermPatternOp.execute is pure virtual")


class SegmentOp(TermPatternOp):
    """A user-op representing a segment calculation."""
    def __init__(self, nm, glb, ind):
        super().__init__(nm, glb, UserPcodeOp.segment, ind)
        self.spc = None
        self.injectId: int = -1
        self.baseinsize: int = 0
        self.innerinsize: int = 0
        self.supportsfarpointer = False
        self.constresolve = VarnodeData()

    def getResolve(self):
        return self.constresolve

    def getSpace(self):
        return self.spc

    def hasFarPointerSupport(self) -> bool:
        return self.supportsfarpointer

    def getBaseSize(self) -> int:
        return self.baseinsize

    def getInnerSize(self) -> int:
        return self.innerinsize

    def getInjectId(self) -> int:
        return self.injectId

    def decode(self, decoder) -> None:
        from ghidra.core.marshal import (
            ELEM_SEGMENTOP, ELEM_CONSTRESOLVE, ELEM_PCODE,
            ATTRIB_SPACE, ATTRIB_FARPOINTER, ATTRIB_USEROP,
        )
        from ghidra.arch.inject import InjectPayload
        elemId = decoder.openElement(ELEM_SEGMENTOP)
        self.spc = None
        self.injectId = -1
        self.baseinsize = 0
        self.innerinsize = 0
        self.supportsfarpointer = False
        self.constresolve = VarnodeData()
        self.name = "segment"
        while True:
            attribId = decoder.getNextAttributeId()
            if attribId == 0:
                break
            if attribId == ATTRIB_SPACE.id:
                self.spc = decoder.readSpace()
            elif attribId == ATTRIB_FARPOINTER.id:
                self.supportsfarpointer = True
            elif attribId == ATTRIB_USEROP.id:
                self.name = decoder.readString()
        if self.spc is None:
            raise LowlevelError("<segmentop> expecting space attribute")
        otherop = self.glb.userops.getOp(self.name)
        if otherop is None:
            raise LowlevelError("<segmentop> unknown userop " + self.name)
        self.useropindex = otherop.getIndex()
        if not isinstance(otherop, UnspecializedPcodeOp):
            raise LowlevelError("Redefining userop " + self.name)
        while True:
            subId = decoder.peekElement()
            if subId == 0:
                break
            if subId == ELEM_CONSTRESOLVE.id:
                decoder.openElement()
                if decoder.peekElement() != 0:
                    from ghidra.core.address import Address
                    addr, size = Address.decode(decoder, with_size=True)
                    self.constresolve.space = addr.getSpace()
                    self.constresolve.offset = addr.getOffset()
                    self.constresolve.size = size
                decoder.closeElement(subId)
            elif subId == ELEM_PCODE.id:
                nm = self.name + "_pcode"
                self.injectId = self.glb.pcodeinjectlib.decodeInject(
                    "cspec", nm, InjectPayload.EXECUTABLEPCODE_TYPE, decoder
                )
            else:
                decoder.openElement()
                decoder.closeElement(subId)
        decoder.closeElement(elemId)
        if self.injectId < 0:
            raise LowlevelError("Missing <pcode> child in <segmentop> tag")
        payload = self.glb.pcodeinjectlib.getPayload(self.injectId)
        if payload.sizeOutput() != 1:
            raise LowlevelError("<pcode> child of <segmentop> tag must declare one <output>")
        if payload.sizeInput() == 1:
            self.innerinsize = payload.getInput(0).getSize()
        elif payload.sizeInput() == 2:
            self.baseinsize = payload.getInput(0).getSize()
            self.innerinsize = payload.getInput(1).getSize()
        else:
            raise LowlevelError("<pcode> child of <segmentop> tag must declare one or two <input> tags")

    def getNumVariableTerms(self) -> int:
        if self.baseinsize != 0:
            return 2
        return 1

    def unify(self, data, op, bindlist: list) -> bool:
        """Match a CALLOTHER op to this segment operation.

        C++ ref: ``SegmentOp::unify``
        """
        from ghidra.core.opcodes import OpCode
        if op.code() != OpCode.CPUI_CALLOTHER:
            return False
        if op.getIn(0).getOffset() != self.useropindex:
            return False
        if op.numInput() != 3:
            return False
        innervn = op.getIn(1)
        if self.baseinsize != 0:
            basevn = op.getIn(1)
            innervn = op.getIn(2)
            if basevn.isConstant():
                basevn = data.newConstant(self.baseinsize, basevn.getOffset())
            bindlist[0] = basevn
        else:
            bindlist[0] = None
        if innervn.isConstant():
            innervn = data.newConstant(self.innerinsize, innervn.getOffset())
        bindlist[1] = innervn
        return True

    def execute(self, inputs: list) -> int:
        pcodeScript = self.glb.pcodeinjectlib.getPayload(self.injectId)
        return pcodeScript.evaluate(inputs)


class JumpAssistOp(UserPcodeOp):
    """A user-op for jump-table assist."""
    def __init__(self, glb):
        super().__init__("", glb, UserPcodeOp.jumpassist, 0)
        self.index2addr: int = -1
        self.index2case: int = -1
        self.calcsize: int = -1
        self.defaultaddr: int = -1

    def getIndex2Addr(self) -> int:
        return self.index2addr

    def getIndex2Case(self) -> int:
        return self.index2case

    def getCalcSize(self) -> int:
        return self.calcsize

    def getDefaultAddr(self) -> int:
        return self.defaultaddr

    def setIndex2Addr(self, val: int) -> None:
        self.index2addr = val

    def setCalcSize(self, val: int) -> None:
        self.calcsize = val

    def setIndex2Case(self, val: int) -> None:
        self.index2case = val

    def decode(self, decoder) -> None:
        from ghidra.core.marshal import (
            ELEM_JUMPASSIST, ELEM_CASE_PCODE, ELEM_ADDR_PCODE,
            ELEM_DEFAULT_PCODE, ELEM_SIZE_PCODE, ATTRIB_NAME,
        )
        from ghidra.arch.inject import InjectPayload
        elemId = decoder.openElement(ELEM_JUMPASSIST)
        self.name = decoder.readString(ATTRIB_NAME)
        self.index2case = -1
        self.index2addr = -1
        self.defaultaddr = -1
        self.calcsize = -1
        while True:
            subId = decoder.peekElement()
            if subId == 0:
                break
            if subId == ELEM_CASE_PCODE.id:
                if self.index2case != -1:
                    raise LowlevelError("Too many <case_pcode> tags")
                self.index2case = self.glb.pcodeinjectlib.decodeInject(
                    "jumpassistop",
                    self.name + "_index2case",
                    InjectPayload.EXECUTABLEPCODE_TYPE,
                    decoder,
                )
            elif subId == ELEM_ADDR_PCODE.id:
                if self.index2addr != -1:
                    raise LowlevelError("Too many <addr_pcode> tags")
                self.index2addr = self.glb.pcodeinjectlib.decodeInject(
                    "jumpassistop",
                    self.name + "_index2addr",
                    InjectPayload.EXECUTABLEPCODE_TYPE,
                    decoder,
                )
            elif subId == ELEM_DEFAULT_PCODE.id:
                if self.defaultaddr != -1:
                    raise LowlevelError("Too many <default_pcode> tags")
                self.defaultaddr = self.glb.pcodeinjectlib.decodeInject(
                    "jumpassistop",
                    self.name + "_defaultaddr",
                    InjectPayload.EXECUTABLEPCODE_TYPE,
                    decoder,
                )
            elif subId == ELEM_SIZE_PCODE.id:
                if self.calcsize != -1:
                    raise LowlevelError("Too many <size_pcode> tags")
                self.calcsize = self.glb.pcodeinjectlib.decodeInject(
                    "jumpassistop",
                    self.name + "_calcsize",
                    InjectPayload.EXECUTABLEPCODE_TYPE,
                    decoder,
                )
            else:
                decoder.openElement()
                decoder.closeElement(subId)
        decoder.closeElement(elemId)
        if self.index2addr == -1:
            raise LowlevelError("userop: " + self.name + " is missing <addr_pcode>")
        if self.defaultaddr == -1:
            raise LowlevelError("userop: " + self.name + " is missing <default_pcode>")
        base = self.glb.userops.getOp(self.name)
        if base is None:
            raise LowlevelError("Unknown userop name in <jumpassist>: " + self.name)
        if not isinstance(base, UnspecializedPcodeOp):
            raise LowlevelError("<jumpassist> overloads userop with another purpose: " + self.name)
        self.useropindex = base.getIndex()


class InternalStringOp(UserPcodeOp):
    """A user-op for internal string operations."""
    def __init__(self, glb):
        super().__init__("stringdata", glb, UserPcodeOp.string_data, UserPcodeOp.BUILTIN_STRINGDATA)
        self.flags |= UserPcodeOp.display_string

    def getOutputLocal(self, op=None):
        return op.getOut().getType()

    def decode(self, decoder) -> None:
        pass


class DatatypeUserOp(UserPcodeOp):
    """Generic user-op that provides input/output data-types."""
    def __init__(self, nm, glb, ind, outType, in0=None, in1=None, in2=None, in3=None):
        super().__init__(nm, glb, UserPcodeOp.datatype, ind)
        self.outType = outType
        self.inTypes = []
        for in_type in (in0, in1, in2, in3):
            if in_type is not None:
                self.inTypes.append(in_type)

    def getOutputLocal(self, op=None):
        return self.outType

    def getInputLocal(self, op=None, slot=0):
        slot -= 1
        if 0 <= slot < len(self.inTypes):
            return self.inTypes[slot]
        return None

    def getInTypes(self) -> list:
        return self.inTypes

    def setOutType(self, t) -> None:
        self.outType = t

    def addInType(self, t) -> None:
        self.inTypes.append(t)

    def decode(self, decoder) -> None:
        pass
