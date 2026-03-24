"""
Corresponds to: userop.hh / userop.cc

User defined p-code operations (CALLOTHER) and UserOpManage registry.
"""

from __future__ import annotations
from typing import Optional, List, Dict


class UserPcodeOp:
    """Base class for user defined p-code operations."""
    annotation_assignment = 1
    no_operator = 2
    display_string = 4
    unspecialized = 1
    injected = 2
    volatile_read = 3
    volatile_write = 4
    BUILTIN_VOLATILE_READ = 1
    BUILTIN_VOLATILE_WRITE = 2

    def __init__(self, nm="", glb=None, tp=1, ind=-1):
        self.name = nm
        self.glb = glb
        self.type = tp
        self.useropindex = ind
        self.flags = 0

    def getName(self): return self.name
    def getIndex(self): return self.useropindex
    def getDisplay(self): return self.flags & 7
    def getOperatorName(self, op=None): return self.name
    def getOutputLocal(self, op=None): return None
    def getInputLocal(self, op=None, slot=0): return None
    def extractAnnotationSize(self, vn, op): return 0
    def setIndex(self, ind: int) -> None: self.useropindex = ind
    def setDisplay(self, flags: int) -> None: self.flags = (self.flags & ~7) | (flags & 7)
    def getType(self) -> int: return self.type
    def encode(self, encoder) -> None: pass
    def decode(self, decoder) -> None: pass


class UnspecializedPcodeOp(UserPcodeOp):
    def __init__(self, nm="", glb=None, ind=-1):
        super().__init__(nm, glb, UserPcodeOp.unspecialized, ind)


class InjectedUserOp(UserPcodeOp):
    def __init__(self, nm="", glb=None, ind=-1, injid=-1):
        super().__init__(nm, glb, UserPcodeOp.injected, ind)
        self.injectid = injid
    def getInjectId(self): return self.injectid


class VolatileReadOp(UserPcodeOp):
    def __init__(self, nm="read_volatile", glb=None):
        super().__init__(nm, glb, UserPcodeOp.volatile_read, UserPcodeOp.BUILTIN_VOLATILE_READ)
        self.flags = UserPcodeOp.no_operator


class VolatileWriteOp(UserPcodeOp):
    def __init__(self, nm="write_volatile", glb=None):
        super().__init__(nm, glb, UserPcodeOp.volatile_write, UserPcodeOp.BUILTIN_VOLATILE_WRITE)
        self.flags = UserPcodeOp.annotation_assignment


class UserOpManage:
    """Registry for user defined p-code ops, indexed by CALLOTHER id."""

    def __init__(self):
        self.glb = None
        self._useroplist: List[Optional[UserPcodeOp]] = []
        self._useropmap: Dict[str, UserPcodeOp] = {}
        self._builtinmap: Dict[int, UserPcodeOp] = {}

    def initialize(self, glb) -> None:
        self.glb = glb
        trans = glb.translate if hasattr(glb, 'translate') else None
        if trans is not None and hasattr(trans, 'numUserOps'):
            n = trans.numUserOps()
            self._useroplist = [None] * n
            for i in range(n):
                nm = trans.getUserOpName(i) if hasattr(trans, 'getUserOpName') else f"userop_{i}"
                if nm:
                    op = UnspecializedPcodeOp(nm, glb, i)
                    self._useroplist[i] = op
                    self._useropmap[nm] = op

    def getOp(self, i) -> Optional[UserPcodeOp]:
        if isinstance(i, str):
            return self._useropmap.get(i)
        if isinstance(i, int) and 0 <= i < len(self._useroplist):
            return self._useroplist[i]
        return None

    def registerOp(self, op: UserPcodeOp) -> None:
        idx = op.getIndex()
        if idx >= 0:
            while idx >= len(self._useroplist):
                self._useroplist.append(None)
            self._useroplist[idx] = op
        self._useropmap[op.getName()] = op

    def numOps(self) -> int:
        return len(self._useroplist)

    def getOpByName(self, nm: str) -> Optional[UserPcodeOp]:
        return self._useropmap.get(nm)

    def numUserOps(self) -> int:
        return len(self._useroplist)

    def decodeSegmentOp(self, decoder, glb) -> None:
        """Decode a <segmentop> element and register it.

        C++ ref: ``UserOpManage::decodeSegmentOp``
        """
        s_op = SegmentOp("", glb, len(self._useroplist))
        s_op.decode(decoder)
        self.registerOp(s_op)

    def decodeJumpAssist(self, decoder, glb) -> None:
        """Decode a <jumpassist> element and register it.

        C++ ref: ``UserOpManage::decodeJumpAssist``
        """
        op = JumpAssistOp("", glb)
        op.decode(decoder)
        self.registerOp(op)

    def decodeCallOtherFixup(self, decoder, glb) -> None:
        """Decode a <callotherfixup> element and register it.

        C++ ref: ``UserOpManage::decodeCallOtherFixup``
        """
        op = InjectedUserOp("", glb, 0, 0)
        op.decode(decoder)
        self.registerOp(op)

    def manualCallOtherFixup(self, useropname: str, outname: str,
                              inname: list, snippet: str, glb=None) -> None:
        """Manually define a CALLOTHER fixup.

        C++ ref: ``UserOpManage::manualCallOtherFixup``
        """
        userop = self.getOp(useropname)
        if userop is None:
            raise Exception("Unknown userop: " + useropname)
        if not isinstance(userop, UnspecializedPcodeOp):
            raise Exception("Cannot fixup userop: " + useropname)
        if glb is None:
            glb = self.glb
        injectid = -1
        if glb is not None and hasattr(glb, 'pcodeinjectlib'):
            injectid = glb.pcodeinjectlib.manualCallOtherFixup(
                useropname, outname, inname, snippet)
        op = InjectedUserOp(useropname, glb, userop.getIndex(), injectid)
        self.registerOp(op)

    def getSegmentOp(self, i: int = 0):
        """Get the i-th SegmentOp (if any)."""
        for op in self._useroplist:
            if op is not None and isinstance(op, SegmentOp):
                if i == 0:
                    return op
                i -= 1
        return None

    def numSegmentOps(self) -> int:
        """Return the number of SegmentOps registered."""
        return sum(1 for op in self._useroplist if op is not None and isinstance(op, SegmentOp))

    def registerBuiltin(self, i: int) -> Optional[UserPcodeOp]:
        """Register a built-in user-op by id.

        C++ ref: ``UserOpManage::registerBuiltin``
        """
        # Check if already registered
        if not hasattr(self, '_builtinmap'):
            self._builtinmap: Dict[int, UserPcodeOp] = {}
        if i in self._builtinmap:
            return self._builtinmap[i]
        glb = self.glb
        if i == UserPcodeOp.BUILTIN_VOLATILE_READ:
            res = VolatileReadOp("read_volatile", glb)
        elif i == UserPcodeOp.BUILTIN_VOLATILE_WRITE:
            res = VolatileWriteOp("write_volatile", glb)
        else:
            res = UnspecializedPcodeOp(f"builtin_{i}", glb, i)
        self._builtinmap[i] = res
        return res

    def decodeVolatile(self, decoder, glb) -> None:
        """Decode volatile read/write ops from a <volatile> element.

        C++ ref: ``UserOpManage::decodeVolatile``
        """
        from ghidra.core.marshal import ATTRIB_INPUTOP, ATTRIB_OUTPUTOP, ATTRIB_FORMAT
        if not hasattr(self, '_builtinmap'):
            self._builtinmap: Dict[int, UserPcodeOp] = {}
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
            raise Exception("Missing inputop/outputop attributes in <volatile> element")
        vr_op = VolatileReadOp(readOpName, glb)
        self._builtinmap[UserPcodeOp.BUILTIN_VOLATILE_READ] = vr_op
        vw_op = VolatileWriteOp(writeOpName, glb)
        self._builtinmap[UserPcodeOp.BUILTIN_VOLATILE_WRITE] = vw_op


class SegmentOp(UserPcodeOp):
    """A user-op representing a segment calculation."""
    def __init__(self, nm="segment", glb=None, ind=-1):
        super().__init__(nm, glb, 5, ind)  # segment=5
        self.spc = None
        self.injectId: int = -1
        self.baseinsize: int = 0
        self.innerinsize: int = 0

    def getResolve(self):
        return self

    def getSpace(self):
        return self.spc

    def getBaseSize(self) -> int:
        return self.baseinsize

    def getInnerSize(self) -> int:
        return self.innerinsize

    def getInjectId(self) -> int:
        return self.injectId

    def decode(self, decoder) -> None:
        """Decode a <segmentop> element.

        C++ ref: ``SegmentOp::decode``
        """
        from ghidra.core.marshal import (
            ELEM_SEGMENTOP, ELEM_CONSTRESOLVE, ELEM_PCODE,
            ATTRIB_SPACE, ATTRIB_FARPOINTER, ATTRIB_USEROP,
        )
        elemId = decoder.openElement(ELEM_SEGMENTOP)
        self.spc = None
        self.injectId = -1
        self.baseinsize = 0
        self.innerinsize = 0
        self.supportsfarpointer = False
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
            raise Exception("<segmentop> expecting space attribute")
        if self.glb is not None and hasattr(self.glb, 'userops'):
            otherop = self.glb.userops.getOp(self.name)
            if otherop is not None:
                self.useropindex = otherop.getIndex()
        while True:
            subId = decoder.peekElement()
            if subId == 0:
                break
            if subId == ELEM_CONSTRESOLVE.id:
                decoder.openElement()
                if decoder.peekElement() != 0:
                    from ghidra.core.address import Address
                    addr = Address.decode(decoder)
                    self.constresolve = addr
                decoder.closeElement(subId)
            elif subId == ELEM_PCODE.id:
                if self.glb is not None and hasattr(self.glb, 'pcodeinjectlib'):
                    nm = self.name + "_pcode"
                    self.injectId = self.glb.pcodeinjectlib.decodeInject(
                        "cspec", nm, 2, decoder)  # EXECUTABLEPCODE_TYPE=2
                else:
                    decoder.openElement()
                    decoder.closeElement(subId)
            else:
                decoder.openElement()
                decoder.closeElement(subId)
        decoder.closeElement(elemId)

    def getNumVariableTerms(self) -> int:
        return 0


class JumpAssistOp(UserPcodeOp):
    """A user-op for jump-table assist."""
    def __init__(self, nm="", glb=None, ind=-1):
        super().__init__(nm, glb, 6, ind)  # jumpassist=6
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
        """Decode a <jumpassist> element.

        C++ ref: ``JumpAssistOp::decode``
        """
        from ghidra.core.marshal import (
            ELEM_JUMPASSIST, ELEM_CASE_PCODE, ELEM_ADDR_PCODE,
            ELEM_DEFAULT_PCODE, ELEM_SIZE_PCODE, ATTRIB_NAME,
        )
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
                if self.glb is not None and hasattr(self.glb, 'pcodeinjectlib'):
                    self.index2case = self.glb.pcodeinjectlib.decodeInject(
                        "jumpassistop", self.name + "_index2case", 2, decoder)
                else:
                    decoder.openElement()
                    decoder.closeElement(subId)
            elif subId == ELEM_ADDR_PCODE.id:
                if self.glb is not None and hasattr(self.glb, 'pcodeinjectlib'):
                    self.index2addr = self.glb.pcodeinjectlib.decodeInject(
                        "jumpassistop", self.name + "_index2addr", 2, decoder)
                else:
                    decoder.openElement()
                    decoder.closeElement(subId)
            elif subId == ELEM_DEFAULT_PCODE.id:
                if self.glb is not None and hasattr(self.glb, 'pcodeinjectlib'):
                    self.defaultaddr = self.glb.pcodeinjectlib.decodeInject(
                        "jumpassistop", self.name + "_defaultaddr", 2, decoder)
                else:
                    decoder.openElement()
                    decoder.closeElement(subId)
            elif subId == ELEM_SIZE_PCODE.id:
                if self.glb is not None and hasattr(self.glb, 'pcodeinjectlib'):
                    self.calcsize = self.glb.pcodeinjectlib.decodeInject(
                        "jumpassistop", self.name + "_calcsize", 2, decoder)
                else:
                    decoder.openElement()
                    decoder.closeElement(subId)
            else:
                decoder.openElement()
                decoder.closeElement(subId)
        decoder.closeElement(elemId)
        if self.glb is not None and hasattr(self.glb, 'userops'):
            base = self.glb.userops.getOp(self.name)
            if base is not None:
                self.useropindex = base.getIndex()


class InternalStringOp(UserPcodeOp):
    """A user-op for internal string operations."""
    def __init__(self, nm="", glb=None, ind=-1):
        super().__init__(nm, glb, 7, ind)  # string_data=7


class DatatypeUserOp(UserPcodeOp):
    """Generic user-op that provides input/output data-types."""
    def __init__(self, nm="", glb=None, ind=-1, outType=None, *inTypes):
        super().__init__(nm, glb, 8, ind)  # datatype=8
        self.outType = outType
        self.inTypes = list(inTypes)

    def getOutputLocal(self, op=None):
        return self.outType

    def getInputLocal(self, op=None, slot=0):
        if slot < len(self.inTypes):
            return self.inTypes[slot]
        return None

    def getInTypes(self) -> list:
        return self.inTypes

    def setOutType(self, t) -> None:
        self.outType = t

    def addInType(self, t) -> None:
        self.inTypes.append(t)
