"""
Corresponds to: fspec.hh / fspec.cc

Definitions for specifying function prototypes.
Core classes: ParamEntry, ParamListStandard, ProtoModel, FuncProto, FuncCallSpecs.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import IntEnum
from typing import TYPE_CHECKING, Optional, List, Dict
from weakref import WeakValueDictionary

from ghidra.core.address import Address, Range, RangeList
from ghidra.core.pcoderaw import VarnodeData
from ghidra.core.error import LowlevelError
from ghidra.core.space import IPTR_FSPEC, IPTR_SPACEBASE
from ghidra.ir.op import OpCode
from ghidra.types.datatype import (
    Datatype, TypeFactory, MetaType, TypeClass,
    TYPE_VOID, TYPE_UNKNOWN, TYPE_INT, TYPE_UINT, TYPE_FLOAT, TYPE_PTR, TYPE_CODE,
    TYPECLASS_GENERAL, TYPECLASS_FLOAT,
    string2typeclass,
)

from ghidra.core.marshal import (
    ELEM_PROTOTYPE, ELEM_RETURNSYM, ELEM_INTERNALLIST, ELEM_PARAM,
    ELEM_RETPARAM, ELEM_UNAFFECTED, ELEM_KILLEDBYCALL, ELEM_LIKELYTRASH,
    ELEM_INJECT, ELEM_ADDR, ELEM_VOID, ELEM_INPUT, ELEM_OUTPUT,
    ELEM_RETURNADDRESS, ELEM_LOCALRANGE, ELEM_PARAMRANGE, ELEM_PCODE,
    ELEM_INTERNAL_STORAGE, ELEM_PENTRY, ELEM_GROUP,
    ELEM_RESOLVEPROTOTYPE, ELEM_MODEL,
    ATTRIB_NAME, ATTRIB_EXTRAPOP, ATTRIB_MODEL, ATTRIB_MODELLOCK,
    ATTRIB_DOTDOTDOT, ATTRIB_VOIDLOCK, ATTRIB_INLINE, ATTRIB_NORETURN,
    ATTRIB_CUSTOM, ATTRIB_CONSTRUCTOR, ATTRIB_DESTRUCTOR, ATTRIB_TYPELOCK,
    ATTRIB_NAMELOCK, ATTRIB_THISPTR, ATTRIB_HIDDENRETPARM,
    ATTRIB_INDIRECTSTORAGE, ATTRIB_HASTHIS, ATTRIB_KILLEDBYCALL,
    ATTRIB_CONTENT, ATTRIB_FIRST, ATTRIB_STACKSHIFT, ATTRIB_STRATEGY,
    ATTRIB_MINSIZE, ATTRIB_MAXSIZE, ATTRIB_ALIGN, ATTRIB_SIZE,
    ATTRIB_EXTENSION, ATTRIB_METATYPE, ATTRIB_STORAGE, ATTRIB_SEPARATEFLOAT,
    ATTRIB_POINTERMAX, ATTRIB_THISBEFORERETPOINTER, ELEM_RULE,
)

if TYPE_CHECKING:
    from ghidra.core.space import AddrSpace
    from ghidra.core.marshal import Encoder, Decoder


_FSPEC_REF_LOOKUP: "WeakValueDictionary[int, FuncCallSpecs]" = WeakValueDictionary()


class ParamUnassignedError(LowlevelError):
    """Exception thrown when a prototype can't be modeled properly."""

    def getMessage(self) -> str:
        return str(self)


class EffectRecord:
    """Description of the indirect effect a sub-function has on a memory range."""
    unaffected = 1
    killedbycall = 2
    return_address = 3
    unknown_effect = 4

    def __init__(self, addr=None, size: int = 0, tp: int = 4) -> None:
        self._addr = addr if addr is not None else Address()
        self._size: int = size
        self._type: int = tp

    def getType(self) -> int:
        return self._type

    def getAddress(self) -> Address:
        return self._addr

    def getSize(self) -> int:
        return self._size

    def __eq__(self, other) -> bool:
        if not isinstance(other, EffectRecord):
            return NotImplemented
        return self._addr == other._addr and self._size == other._size and self._type == other._type

    def __ne__(self, other) -> bool:
        return not self.__eq__(other)

    def setType(self, tp: int) -> None:
        self._type = tp

    def encode(self, encoder) -> None:
        """Encode just an <addr> element. The effect type is indicated by the parent element.

        C++ ref: ``EffectRecord::encode``
        """
        if self._type in (EffectRecord.unaffected, EffectRecord.killedbycall, EffectRecord.return_address):
            self._addr.encode(encoder, self._size)
        else:
            raise LowlevelError("Bad EffectRecord type")

    def decode(self, grouptype_or_decoder, decoder=None) -> None:
        """Decode from stream. Supports two calling conventions:
        - decode(grouptype, decoder) — C++ style with inherited type
        - decode(decoder) — simple decode from stream

        C++ ref: ``EffectRecord::decode``
        """
        if decoder is None:
            dec = grouptype_or_decoder
            self._type = EffectRecord.unknown_effect
        else:
            dec = decoder
            self._type = grouptype_or_decoder
        elemId = dec.openElement()
        vd = VarnodeData()
        vd.decode(dec)
        dec.closeElement(elemId)
        self._addr = Address(vd.space, vd.offset)
        self._size = vd.size

    @staticmethod
    def compareByAddress(op1, op2) -> bool:
        return op1._addr < op2._addr


class ParameterPieces:
    """Basic elements of a parameter: address, data-type, properties."""
    isthis = 1
    hiddenretparm = 2
    indirectstorage = 4
    namelock = 8
    typelock = 16
    sizelock = 32

    def __init__(self) -> None:
        self.addr: Address = Address()
        self.type = None  # Datatype
        self.flags: int = 0

    def swapMarkup(self, op) -> None:
        self.type, op.type = op.type, self.type


class PrototypePieces:
    """Raw components of a function prototype (obtained from parsing source code)."""
    def __init__(self) -> None:
        self.model = None  # ProtoModel
        self.name: str = ""
        self.outtype = None  # Datatype
        self.intypes: list = []  # List[Datatype]
        self.innames: list = []  # List[str]
        self.firstVarArgSlot: int = -1


class ParameterBasic:
    """A stand-alone parameter with no backing symbol."""
    def __init__(self, nm: str = "", addr=None, tp=None, fl: int = 0) -> None:
        self._name: str = nm
        self._addr = addr if addr is not None else Address()
        self._type = tp
        self._flags: int = fl

    def getName(self) -> str:
        return self._name

    def getType(self):
        return self._type

    def getAddress(self):
        return self._addr

    def getSize(self) -> int:
        return self._type.getSize() if self._type is not None and hasattr(self._type, 'getSize') else 0

    def isTypeLocked(self) -> bool:
        return (self._flags & ParameterPieces.typelock) != 0

    def isNameLocked(self) -> bool:
        return (self._flags & ParameterPieces.namelock) != 0

    def isSizeTypeLocked(self) -> bool:
        return (self._flags & ParameterPieces.sizelock) != 0

    def isThisPointer(self) -> bool:
        return (self._flags & ParameterPieces.isthis) != 0

    def isIndirectStorage(self) -> bool:
        return (self._flags & ParameterPieces.indirectstorage) != 0

    def isHiddenReturn(self) -> bool:
        return (self._flags & ParameterPieces.hiddenretparm) != 0

    def isNameUndefined(self) -> bool:
        return len(self._name) == 0

    def setTypeLock(self, val: bool) -> None:
        if val:
            self._flags |= ParameterPieces.typelock
        else:
            self._flags &= ~ParameterPieces.typelock

    def setNameLock(self, val: bool) -> None:
        if val:
            self._flags |= ParameterPieces.namelock
        else:
            self._flags &= ~ParameterPieces.namelock

    def setThisPointer(self, val: bool) -> None:
        if val:
            self._flags |= ParameterPieces.isthis
        else:
            self._flags &= ~ParameterPieces.isthis

    def clone(self):
        return ParameterBasic(self._name, self._addr, self._type, self._flags)


class ProtoStore:
    """A collection of parameter descriptions making up a function prototype."""
    def getNumInputs(self) -> int:
        return 0

    def getInput(self, i: int):
        return None

    def getOutput(self):
        return None

    def setInput(self, i: int, nm: str, pieces) -> None:
        pass

    def setOutput(self, piece) -> None:
        pass

    def clearInput(self, i: int) -> None:
        pass

    def clearAllInputs(self) -> None:
        pass

    def clearOutput(self) -> None:
        pass

    def clone(self):
        return ProtoStore()


class ProtoStoreInternal(ProtoStore):
    """Internal storage for parameters without backing symbols."""
    def __init__(self) -> None:
        self._inparam: list = []
        self._outparam = None

    def getNumInputs(self) -> int:
        return len(self._inparam)

    def getInput(self, i: int):
        if 0 <= i < len(self._inparam):
            return self._inparam[i]
        return None

    def getOutput(self):
        return self._outparam

    def setInput(self, i: int, nm: str, pieces) -> None:
        while i >= len(self._inparam):
            self._inparam.append(None)
        addr = pieces.addr if hasattr(pieces, 'addr') else Address()
        tp = pieces.type if hasattr(pieces, 'type') else None
        fl = pieces.flags if hasattr(pieces, 'flags') else 0
        self._inparam[i] = ParameterBasic(nm, addr, tp, fl)

    def setOutput(self, piece) -> None:
        addr = piece.addr if hasattr(piece, 'addr') else Address()
        tp = piece.type if hasattr(piece, 'type') else None
        fl = piece.flags if hasattr(piece, 'flags') else 0
        self._outparam = ParameterBasic("", addr, tp, fl)

    def clearInput(self, i: int) -> None:
        if 0 <= i < len(self._inparam):
            del self._inparam[i]

    def clearAllInputs(self) -> None:
        self._inparam.clear()

    def clearOutput(self) -> None:
        self._outparam = None

    def encode(self, encoder) -> None:
        """Encode this parameter store to stream.

        C++ ref: ``ProtoStoreInternal::encode``
        """
        encoder.openElement(ELEM_INTERNALLIST)
        if self._outparam is not None:
            encoder.openElement(ELEM_RETPARAM)
            if self._outparam.isTypeLocked():
                encoder.writeBool(ATTRIB_TYPELOCK, True)
            self._outparam.getAddress().encode(encoder)
            tp = self._outparam.getType()
            if tp is not None and hasattr(tp, 'encodeRef'):
                tp.encodeRef(encoder)
            encoder.closeElement(ELEM_RETPARAM)
        else:
            encoder.openElement(ELEM_RETPARAM)
            encoder.openElement(ELEM_ADDR)
            encoder.closeElement(ELEM_ADDR)
            encoder.openElement(ELEM_VOID)
            encoder.closeElement(ELEM_VOID)
            encoder.closeElement(ELEM_RETPARAM)
        for param in self._inparam:
            if param is None:
                continue
            encoder.openElement(ELEM_PARAM)
            nm = param.getName()
            if nm:
                encoder.writeString(ATTRIB_NAME, nm)
            if param.isTypeLocked():
                encoder.writeBool(ATTRIB_TYPELOCK, True)
            if param.isNameLocked():
                encoder.writeBool(ATTRIB_NAMELOCK, True)
            if param.isThisPointer():
                encoder.writeBool(ATTRIB_THISPTR, True)
            if param.isIndirectStorage():
                encoder.writeBool(ATTRIB_INDIRECTSTORAGE, True)
            if param.isHiddenReturn():
                encoder.writeBool(ATTRIB_HIDDENRETPARM, True)
            param.getAddress().encode(encoder)
            tp = param.getType()
            if tp is not None and hasattr(tp, 'encodeRef'):
                tp.encodeRef(encoder)
            encoder.closeElement(ELEM_PARAM)
        encoder.closeElement(ELEM_INTERNALLIST)

    def decode(self, decoder, model=None) -> None:
        """Decode this parameter store from an <internallist> element.

        C++ ref: ``ProtoStoreInternal::decode``
        """
        elemId = decoder.openElement(ELEM_INTERNALLIST)
        firstAttr = decoder.getNextAttributeId()
        firstVarArgSlot = -1
        if firstAttr == ATTRIB_FIRST:
            firstVarArgSlot = decoder.readSignedInteger()
        innames = []
        pieces = []
        # Placeholder for output pieces
        pieces.append(ParameterPieces())
        if self._outparam is not None:
            pieces[0].type = self._outparam.getType()
            pieces[0].flags = 0
            if self._outparam.isTypeLocked():
                pieces[0].flags |= ParameterPieces.typelock
            if self._outparam.isIndirectStorage():
                pieces[0].flags |= ParameterPieces.indirectstorage
        while True:
            subId = decoder.peekElement()
            if subId == 0:
                break
            decoder.openElement()
            nm = ""
            fl = 0
            while True:
                attribId = decoder.getNextAttributeId()
                if attribId == 0:
                    break
                if attribId == ATTRIB_NAME:
                    nm = decoder.readString()
                elif attribId == ATTRIB_TYPELOCK:
                    if decoder.readBool():
                        fl |= ParameterPieces.typelock
                elif attribId == ATTRIB_NAMELOCK:
                    if decoder.readBool():
                        fl |= ParameterPieces.namelock
                elif attribId == ATTRIB_THISPTR:
                    if decoder.readBool():
                        fl |= ParameterPieces.isthis
                elif attribId == ATTRIB_INDIRECTSTORAGE:
                    if decoder.readBool():
                        fl |= ParameterPieces.indirectstorage
                elif attribId == ATTRIB_HIDDENRETPARM:
                    if decoder.readBool():
                        fl |= ParameterPieces.hiddenretparm
            if (fl & ParameterPieces.hiddenretparm) == 0:
                innames.append(nm)
            pp = ParameterPieces()
            pp.addr = Address.decode(decoder)
            pp.flags = fl
            # Try to decode type if available
            try:
                tpId = decoder.peekElement()
                if tpId != 0:
                    decoder.openElement()
                    decoder.closeElement(tpId)
            except Exception:
                pass
            pieces.append(pp)
            decoder.closeElement(subId)
        decoder.closeElement(elemId)
        # Rebuild from pieces
        if len(pieces) > 0 and pieces[0].type is not None:
            self.setOutput(pieces[0])
            out = self._outparam
            if out is not None:
                out.setTypeLock((pieces[0].flags & ParameterPieces.typelock) != 0)
        j = 0
        for i in range(1, len(pieces)):
            if (pieces[i].flags & ParameterPieces.hiddenretparm) != 0:
                self.setInput(i - 1, "rethidden", pieces[i])
                inp = self.getInput(i - 1)
                if inp is not None and hasattr(inp, 'setTypeLock'):
                    inp.setTypeLock((pieces[0].flags & ParameterPieces.typelock) != 0)
                continue
            nm = innames[j] if j < len(innames) else ""
            self.setInput(i - 1, nm, pieces[i])
            inp = self.getInput(i - 1)
            if inp is not None and hasattr(inp, 'setTypeLock'):
                inp.setTypeLock((pieces[i].flags & ParameterPieces.typelock) != 0)
            if inp is not None and hasattr(inp, 'setNameLock'):
                inp.setNameLock((pieces[i].flags & ParameterPieces.namelock) != 0)
            j += 1

    def clone(self):
        c = ProtoStoreInternal()
        for p in self._inparam:
            c._inparam.append(p.clone() if p is not None else None)
        if self._outparam is not None:
            c._outparam = self._outparam.clone()
        return c


class ScoreProtoModel:
    """Class for calculating 'goodness of fit' of parameter trials against a prototype model."""
    def __init__(self, isinput: bool, model, numparam: int) -> None:
        self._isinputscore: bool = isinput
        self._model = model
        self._finalscore: int = -1
        self._mismatch: int = 0
        self._entries: list = []

    def addParameter(self, addr, sz: int) -> None:
        self._entries.append((addr, sz))

    def doScore(self) -> None:
        """Compute the fitness score."""
        self._finalscore = 0
        self._mismatch = 0
        if self._model is None:
            self._finalscore = 500
            return
        for addr, sz in self._entries:
            if self._isinputscore:
                if hasattr(self._model, 'possibleInputParam') and not self._model.possibleInputParam(addr, sz):
                    self._mismatch += 1
                    self._finalscore += 500
            else:
                if hasattr(self._model, 'possibleOutputParam') and not self._model.possibleOutputParam(addr, sz):
                    self._mismatch += 1
                    self._finalscore += 500

    def getScore(self) -> int:
        return self._finalscore

    def getNumMismatch(self) -> int:
        return self._mismatch

    def getModel(self):
        return self._model

    def getEntries(self) -> list:
        return self._entries


class UnknownProtoModel:
    """An unrecognized prototype model that adopts placeholder behavior."""
    def __init__(self, nm: str, placeHolder) -> None:
        self._name = nm
        self._placeholderModel = placeHolder

    def getName(self) -> str:
        return self._name

    def getPlaceholderModel(self):
        return self._placeholderModel

    def isUnknown(self) -> bool:
        return True

    def setName(self, nm: str) -> None:
        self._name = nm

    def encode(self, encoder) -> None:
        """Encode this unknown prototype model.

        C++ ref: The C++ UnknownProtoModel doesn't have a separate encode;
        it delegates to ProtoModel::encode. We encode the name for identification.
        """
        encoder.openElement(ELEM_PROTOTYPE)
        encoder.writeString(ATTRIB_NAME, self._name)
        encoder.closeElement(ELEM_PROTOTYPE)


class ProtoModelMerged:
    """A prototype model made by merging together other models."""
    def __init__(self, glb=None) -> None:
        self._glb = glb
        self._modellist: list = []

    def numModels(self) -> int:
        return len(self._modellist)

    def getModel(self, i: int):
        return self._modellist[i]

    def foldIn(self, model) -> None:
        self._modellist.append(model)

    def selectModel(self, active) -> Optional[object]:
        """Select the best model given a set of trials."""
        if not self._modellist:
            return None
        best = None
        bestScore = 500
        for model in self._modellist:
            scorer = ScoreProtoModel(True, model, active.getNumTrials() if hasattr(active, 'getNumTrials') else 0)
            for i in range(active.getNumTrials() if hasattr(active, 'getNumTrials') else 0):
                trial = active.getTrial(i) if hasattr(active, 'getTrial') else None
                if trial is not None and trial.isActive():
                    scorer.addParameter(trial.getAddress(), trial.getSize())
            scorer.doScore()
            score = scorer.getScore()
            if score < bestScore:
                bestScore = score
                best = model
                if bestScore == 0:
                    break
        return best

    def isMerged(self) -> bool:
        return True

    def getGlb(self):
        return self._glb

    def clearModels(self) -> None:
        self._modellist.clear()

    def decode(self, decoder) -> None:
        """Decode this merged prototype model from a <resolveprototype> element.

        C++ ref: ``ProtoModelMerged::decode``
        """
        elemId = decoder.openElement(ELEM_RESOLVEPROTOTYPE)
        self._name = decoder.readString(ATTRIB_NAME)
        while True:
            subId = decoder.peekElement()
            if subId != ELEM_MODEL:
                break
            decoder.openElement()
            modelName = decoder.readString(ATTRIB_NAME)
            if self._glb is not None and hasattr(self._glb, 'getModel'):
                mymodel = self._glb.getModel(modelName)
                if mymodel is None:
                    raise LowlevelError("Missing prototype model: " + modelName)
                self.foldIn(mymodel)
            decoder.closeElement(subId)
        decoder.closeElement(elemId)

    def encode(self, encoder) -> None:
        """Encode this merged prototype model.

        C++ ref: ProtoModelMerged has no encode in C++; this is for round-trip.
        """
        encoder.openElement(ELEM_RESOLVEPROTOTYPE)
        encoder.writeString(ATTRIB_NAME, getattr(self, '_name', ''))
        for model in self._modellist:
            encoder.openElement(ELEM_MODEL)
            encoder.writeString(ATTRIB_NAME, model.getName())
            encoder.closeElement(ELEM_MODEL)
        encoder.closeElement(ELEM_RESOLVEPROTOTYPE)


# =========================================================================
# ParamEntry
# =========================================================================

class ParamEntry:
    """A contiguous range of memory that can be used to pass parameters."""

    force_left_justify = 1
    reverse_stack = 2
    smallsize_zext = 4
    smallsize_sext = 8
    smallsize_inttype = 0x20
    smallsize_floatext = 0x40
    extracheck_high = 0x80
    extracheck_low = 0x100
    is_grouped = 0x200
    overlapping = 0x400
    first_storage = 0x800

    # Containment characterization codes
    no_containment = 0
    contains_unjustified = 1
    contains_justified = 2
    contained_by = 3

    def __init__(self, group: int = 0) -> None:
        self.flags: int = 0
        self.type: TypeClass = TypeClass.TYPECLASS_GENERAL
        self.groupSet: List[int] = [group]
        self.spaceid: Optional[AddrSpace] = None
        self.addressbase: int = 0
        self.size: int = 0
        self.minsize: int = 1
        self.alignment: int = 0
        self.numslots: int = 0

    def getGroup(self) -> int:
        return self.groupSet[0]

    def getAllGroups(self) -> List[int]:
        return self.groupSet

    def getSize(self) -> int:
        return self.size

    def getMinSize(self) -> int:
        return self.minsize

    def getAlign(self) -> int:
        return self.alignment

    def getType(self) -> TypeClass:
        return self.type

    def isExclusion(self) -> bool:
        return self.alignment == 0

    def isReverseStack(self) -> bool:
        return (self.flags & ParamEntry.reverse_stack) != 0

    def isGrouped(self) -> bool:
        return (self.flags & ParamEntry.is_grouped) != 0

    def isOverlap(self) -> bool:
        return (self.flags & ParamEntry.overlapping) != 0

    def isFirstInClass(self) -> bool:
        return (self.flags & ParamEntry.first_storage) != 0

    def isParamCheckHigh(self) -> bool:
        return (self.flags & ParamEntry.extracheck_high) != 0

    def isParamCheckLow(self) -> bool:
        return (self.flags & ParamEntry.extracheck_low) != 0

    @staticmethod
    def findEntryByStorage(entryList: list, vn) -> Optional['ParamEntry']:
        """Find a ParamEntry matching the given VarnodeData storage.

        C++ ref: ParamEntry::findEntryByStorage in fspec.cc
        """
        for entry in reversed(entryList):
            if (entry.spaceid is vn.space and entry.addressbase == vn.offset
                    and entry.size == vn.size):
                return entry
        return None

    def resolveFirst(self, curList: list) -> None:
        """Set first_storage flag if this is the first entry of its storage class.

        C++ ref: ParamEntry::resolveFirst in fspec.cc
        """
        if len(curList) <= 1:
            self.flags |= ParamEntry.first_storage
            return
        prev = curList[-2]
        if self.type != prev.type:
            self.flags |= ParamEntry.first_storage

    def resolveJoin(self, curList: list) -> None:
        """Cache join record and adjust group based on overlapped entries.

        C++ ref: ParamEntry::resolveJoin in fspec.cc
        """
        from ghidra.core.space import IPTR_JOIN
        self.joinrec = None
        if self.spaceid is None or self.spaceid.getType() != IPTR_JOIN:
            return
        mgr = self.spaceid.getManager() if hasattr(self.spaceid, 'getManager') else None
        if mgr is None:
            return
        self.joinrec = mgr.findJoin(self.addressbase) if hasattr(mgr, 'findJoin') else None
        if self.joinrec is None:
            return
        self.groupSet = []
        npieces = self.joinrec.numPieces() if hasattr(self.joinrec, 'numPieces') else 0
        for i in range(npieces):
            piece = self.joinrec.getPiece(i)
            entry = ParamEntry.findEntryByStorage(curList, piece)
            if entry is not None:
                self.groupSet.extend(entry.groupSet)
                self.flags |= ParamEntry.extracheck_low if i == 0 else ParamEntry.extracheck_high
        if not self.groupSet:
            raise LowlevelError("<pentry> join must overlap at least one previous entry")
        self.groupSet.sort()
        self.flags |= ParamEntry.overlapping

    def resolveOverlap(self, curList: list) -> None:
        """Search for overlaps with previous entries and adjust groups.

        C++ ref: ParamEntry::resolveOverlap in fspec.cc
        """
        if getattr(self, 'joinrec', None) is not None:
            return
        overlapSet = []
        addr = Address(self.spaceid, self.addressbase)
        for entry in curList[:-1]:
            if not entry.intersects(addr, self.size):
                continue
            if self.contains(entry):
                if entry.isOverlap():
                    continue
                overlapSet.extend(entry.groupSet)
                if self.addressbase == entry.addressbase:
                    self.flags |= ParamEntry.extracheck_low if self.spaceid.isBigEndian() else ParamEntry.extracheck_high
                else:
                    self.flags |= ParamEntry.extracheck_high if self.spaceid.isBigEndian() else ParamEntry.extracheck_low
            else:
                raise LowlevelError("Illegal overlap of <pentry> in compiler spec")
        if not overlapSet:
            return
        overlapSet.sort()
        self.groupSet = overlapSet
        self.flags |= ParamEntry.overlapping

    def subsumesDefinition(self, op2: 'ParamEntry') -> bool:
        """Check if this entry subsumes the definition of another.

        C++ ref: ParamEntry::subsumesDefinition in fspec.cc
        """
        if self.type != TYPECLASS_GENERAL and op2.type != self.type:
            return False
        if self.spaceid is not op2.spaceid:
            return False
        if op2.addressbase < self.addressbase:
            return False
        if (op2.addressbase + op2.size - 1) > (self.addressbase + self.size - 1):
            return False
        if self.alignment != op2.alignment:
            return False
        return True

    def contains(self, op2: 'ParamEntry') -> bool:
        """Check if this entry contains the given entry.

        C++ ref: ParamEntry::contains in fspec.cc
        """
        if getattr(op2, 'joinrec', None) is not None:
            return False
        if getattr(self, 'joinrec', None) is None:
            addr = Address(self.spaceid, self.addressbase)
            return op2.containedBy(addr, self.size)
        npieces = self.joinrec.numPieces() if hasattr(self.joinrec, 'numPieces') else 0
        for i in range(npieces):
            vdata = self.joinrec.getPiece(i)
            addr = vdata.getAddr() if hasattr(vdata, 'getAddr') else Address(vdata.space, vdata.offset)
            if op2.containedBy(addr, vdata.size):
                return True
        return False

    def getSpace(self) -> Optional[AddrSpace]:
        return self.spaceid

    def getBase(self) -> int:
        return self.addressbase

    def containedBy(self, addr: Address, sz: int) -> bool:
        if addr.getSpace() is not self.spaceid:
            return False
        if self.addressbase < addr.getOffset():
            return False
        entryend = self.addressbase + self.size - 1
        rangeend = addr.getOffset() + sz - 1
        return entryend <= rangeend

    def intersects(self, addr: Address, sz: int) -> bool:
        if addr.getSpace() is not self.spaceid:
            return False
        end1 = self.addressbase + self.size
        end2 = addr.getOffset() + sz
        return not (addr.getOffset() >= end1 or self.addressbase >= end2)

    def getNumSlots(self) -> int:
        return self.numslots

    def isLeftJustified(self) -> bool:
        return (self.flags & ParamEntry.force_left_justify) != 0

    def justifiedContain(self, addr: Address, sz: int) -> int:
        """Check if the given range is contained within this entry (justified).

        C++ ref: ``ParamEntry::justifiedContain`` (fspec.cc)
        For exclusion entries (alignment==0), delegates to Address-style
        justified containment: returns the endian-aware offset of the
        query within this entry, or -1 if not contained.
        """
        if self.alignment == 0:
            # Exclusion entry (register): check [addr,addr+sz) ⊆ [base,base+size)
            if addr.getSpace() is not self.spaceid:
                return -1
            if addr.getOffset() < self.addressbase:
                return -1
            entryend = self.addressbase + self.size - 1
            queryend = addr.getOffset() + sz - 1
            if queryend > entryend:
                return -1
            # Contained — return justified offset
            if self.isLeftJustified():
                return addr.getOffset() - self.addressbase
            # Right-justified (big-endian default): distance from end
            return entryend - queryend
        # Stack-like entry
        if addr.getSpace() is not self.spaceid:
            return -1
        startaddr = addr.getOffset()
        if startaddr < self.addressbase:
            return -1
        endaddr = startaddr + sz - 1
        if endaddr < startaddr:
            return -1
        if endaddr > (self.addressbase + self.size - 1):
            return -1
        startaddr -= self.addressbase
        endaddr -= self.addressbase
        if not self.isLeftJustified():
            res = int((endaddr + 1) % self.alignment) if self.alignment else 0
            if res == 0:
                return 0
            return self.alignment - res
        return int(startaddr % self.alignment) if self.alignment else 0

    def getAddrBySlotInfo(self, slot: int, sz: int, align: int = 1,
                          justifyRight: bool = False) -> tuple[Address, int]:
        """Get an address for a parameter and the updated slot count.

        C++ ref: ``ParamEntry::getAddrBySlot``
        """
        res = Address()
        if self.spaceid is None:
            return res, slot
        if sz < self.minsize:
            return res, slot

        if self.alignment == 0:
            if slot != 0:
                return res, slot
            if sz > self.size:
                return res, slot
            res = Address(self.spaceid, self.addressbase)
            spaceused = self.size
        else:
            if align > self.alignment:
                tmp = (slot * self.alignment) % align
                if tmp != 0:
                    slot += (align - tmp) // self.alignment
            slotsused = sz // self.alignment
            if (sz % self.alignment) != 0:
                slotsused += 1
            if slot + slotsused > self.numslots:
                return res, slot
            spaceused = slotsused * self.alignment
            if self.isReverseStack():
                index = self.numslots - slot - slotsused
            else:
                index = slot
            res = Address(self.spaceid, self.addressbase + index * self.alignment)
            slot += slotsused

        if justifyRight:
            res = res + (spaceused - sz)
        return res, slot

    def getAddrBySlot(self, slot: int, sz: int, align: int = 1,
                      justifyRight: bool = False) -> Address:
        """Get an address for a parameter given current slot consumption.

        C++ ref: ``ParamEntry::getAddrBySlot``
        """
        res, _ = self.getAddrBySlotInfo(slot, sz, align, justifyRight)
        return res

    def getSlot(self, addr: Address, skip: int) -> int:
        """Calculate the slot occupied by a specific address.

        C++ ref: ``ParamEntry::getSlot``
        """
        res = self.groupSet[0]
        if self.alignment != 0:
            diff = addr.getOffset() + skip - self.addressbase
            baseslot = int(diff) // self.alignment
            if self.isReverseStack():
                res += (self.numslots - 1) - baseslot
            else:
                res += baseslot
        elif skip != 0:
            res = self.groupSet[-1]
        return res

    def groupOverlap(self, op2: 'ParamEntry') -> bool:
        """Check if this and op2 occupy any of the same groups.

        C++ ref: ``ParamEntry::groupOverlap``
        """
        i = 0
        j = 0
        valThis = self.groupSet[i]
        valOther = op2.groupSet[j]
        while valThis != valOther:
            if valThis < valOther:
                i += 1
                if i >= len(self.groupSet):
                    return False
                valThis = self.groupSet[i]
            else:
                j += 1
                if j >= len(op2.groupSet):
                    return False
                valOther = op2.groupSet[j]
        return True

    def getContainer(self, addr: Address, sz: int, res) -> bool:
        """Calculate the containing memory range.

        C++ ref: ``ParamEntry::getContainer``
        """
        if self.spaceid is None:
            return False
        if addr.getSpace() is not self.spaceid:
            return False
        if addr.getOffset() < self.addressbase:
            return False
        endoff = addr.getOffset() + sz - 1
        if endoff > self.addressbase + self.size - 1:
            return False
        if self.alignment == 0:
            res.space = self.spaceid
            res.offset = self.addressbase
            res.size = self.size
            return True
        al = (addr.getOffset() - self.addressbase) % self.alignment
        res.space = self.spaceid
        res.offset = addr.getOffset() - al
        res.size = int(endoff - res.offset) + 1
        al2 = res.size % self.alignment
        if al2 != 0:
            res.size += (self.alignment - al2)
        return True

    def assumedExtension(self, addr: Address, sz: int, res) -> 'OpCode':
        """Calculate the type of extension for a small value.

        C++ ref: ``ParamEntry::assumedExtension``
        """
        if (self.flags & (ParamEntry.smallsize_zext | ParamEntry.smallsize_sext | ParamEntry.smallsize_inttype)) == 0:
            return OpCode.CPUI_COPY
        if self.alignment != 0:
            if sz >= self.alignment:
                return OpCode.CPUI_COPY
        elif sz >= self.size:
            return OpCode.CPUI_COPY
        if self.justifiedContain(addr, sz) != 0:
            return OpCode.CPUI_COPY
        if self.alignment == 0:
            res.space = self.spaceid
            res.offset = self.addressbase
            res.size = self.size
        else:
            res.space = self.spaceid
            alignAdjust = (addr.getOffset() - self.addressbase) % self.alignment
            res.offset = addr.getOffset() - alignAdjust
            res.size = self.alignment
        if (self.flags & ParamEntry.smallsize_zext) != 0:
            return OpCode.CPUI_INT_ZEXT
        if (self.flags & ParamEntry.smallsize_inttype) != 0:
            return OpCode.CPUI_PIECE
        return OpCode.CPUI_INT_SEXT

    def slotGroup(self) -> int:
        """Get the group of this entry's first slot."""
        return self.groupSet[0]

    def encode(self, encoder) -> None:
        """Encode this parameter entry to stream as a <pentry> element.

        C++ ref: ParamEntry has no encode in C++; this is a Python addition for round-trip.
        """
        encoder.openElement(ELEM_PENTRY)
        encoder.writeSignedInteger(ATTRIB_MINSIZE, self.minsize)
        encoder.writeSignedInteger(ATTRIB_MAXSIZE, self.size)
        if self.alignment != 0:
            encoder.writeSignedInteger(ATTRIB_ALIGN, self.alignment)
        if self.type != TYPECLASS_GENERAL:
            tc_map = {
                TypeClass.TYPECLASS_FLOAT: "float",
                TypeClass.TYPECLASS_PTR: "ptr",
                TypeClass.TYPECLASS_HIDDENRET: "hiddenret",
                TypeClass.TYPECLASS_VECTOR: "vector",
            }
            encoder.writeString(ATTRIB_METATYPE, tc_map.get(self.type, "general"))
        if (self.flags & ParamEntry.smallsize_sext) != 0:
            encoder.writeString(ATTRIB_EXTENSION, "sign")
        elif (self.flags & ParamEntry.smallsize_zext) != 0:
            encoder.writeString(ATTRIB_EXTENSION, "zero")
        elif (self.flags & ParamEntry.smallsize_inttype) != 0:
            encoder.writeString(ATTRIB_EXTENSION, "inttype")
        elif (self.flags & ParamEntry.smallsize_floatext) != 0:
            encoder.writeString(ATTRIB_EXTENSION, "float")
        addr = Address(self.spaceid, self.addressbase)
        addr.encode(encoder)
        encoder.closeElement(ELEM_PENTRY)

    def decode(self, decoder, normalstack: bool = True, grouped: bool = False, curList=None) -> None:
        """Decode this parameter entry from a <pentry> element.

        C++ ref: ``ParamEntry::decode``
        """
        self.flags = 0
        self.type = TYPECLASS_GENERAL
        self.size = -1
        self.minsize = -1
        self.alignment = 0
        self.numslots = 1

        elemId = decoder.openElement(ELEM_PENTRY)
        while True:
            attribId = decoder.getNextAttributeId()
            if attribId == 0:
                break
            if attribId == ATTRIB_MINSIZE:
                self.minsize = decoder.readSignedInteger()
            elif attribId == ATTRIB_SIZE or attribId == ATTRIB_ALIGN:
                self.alignment = decoder.readSignedInteger()
            elif attribId == ATTRIB_MAXSIZE:
                self.size = decoder.readSignedInteger()
            elif attribId == ATTRIB_STORAGE or attribId == ATTRIB_METATYPE:
                self.type = string2typeclass(decoder.readString())
            elif attribId == ATTRIB_EXTENSION:
                self.flags &= ~(ParamEntry.smallsize_zext | ParamEntry.smallsize_sext | ParamEntry.smallsize_inttype)
                ext = decoder.readString()
                if ext == "sign":
                    self.flags |= ParamEntry.smallsize_sext
                elif ext == "zero":
                    self.flags |= ParamEntry.smallsize_zext
                elif ext == "inttype":
                    self.flags |= ParamEntry.smallsize_inttype
                elif ext == "float":
                    self.flags |= ParamEntry.smallsize_floatext
                elif ext != "none":
                    raise LowlevelError("Bad extension attribute")
            else:
                raise LowlevelError("Unknown <pentry> attribute")
        if self.size == -1 or self.minsize == -1:
            raise LowlevelError("ParamEntry not fully specified")
        if self.alignment == self.size:
            self.alignment = 0
        addr = Address.decode(decoder)
        decoder.closeElement(elemId)
        self.spaceid = addr.getSpace()
        self.addressbase = addr.getOffset()
        if self.alignment != 0:
            self.numslots = self.size // self.alignment
        if self.spaceid is not None:
            if hasattr(self.spaceid, 'isReverseJustified') and self.spaceid.isReverseJustified():
                if self.spaceid.isBigEndian():
                    self.flags |= ParamEntry.force_left_justify
                else:
                    raise LowlevelError("No support for right justification in little endian encoding")
        if not normalstack:
            self.flags |= ParamEntry.reverse_stack
            if self.alignment != 0:
                if (self.size % self.alignment) != 0:
                    raise LowlevelError("For positive stack growth, <pentry> size must match alignment")
        if grouped:
            self.flags |= ParamEntry.is_grouped
        self.groupSet = [getattr(self, '_group', 0)]


# =========================================================================
# ParamList (abstract)
# =========================================================================

class ParamList(ABC):
    """An ordered list of parameter storage locations."""

    @abstractmethod
    def getNumParamEntry(self) -> int: ...

    @abstractmethod
    def getEntry(self, i: int) -> ParamEntry: ...


class ParamListStandard(ParamList):
    """A standard ordered list of parameter entries."""

    def __init__(self) -> None:
        self.entry: List[ParamEntry] = []
        self.spacebase: Optional[AddrSpace] = None
        self.maxdelay: int = 0
        self.pointermax: int = 0
        self.thisbeforeret: bool = False
        self.nonfloatgroup: int = 0
        self.numgroup: int = 0
        self.autoKilledByCall: bool = False
        self.resourceStart: List[int] = []
        self.modelRules: list = []

    def getNumParamEntry(self) -> int:
        return len(self.entry)

    def getEntry(self, i: int) -> ParamEntry:
        return self.entry[i]

    def addEntry(self, e: ParamEntry) -> None:
        self.entry.append(e)

    def getSpacebase(self):
        return self.spacebase

    def getMaxDelay(self) -> int:
        return self.maxdelay

    def getPointerMax(self) -> int:
        return self.pointermax

    def possibleParam(self, loc, size: int) -> bool:
        return self.findEntry(loc, size, True) is not None

    p_standard = 1
    p_standard_out = 2
    p_register = 3
    p_register_out = 4

    def isBigEndian(self) -> bool:
        """Return True if the parameter list is big-endian."""
        if self.spacebase is not None:
            return self.spacebase.isBigEndian()
        if self.entry:
            spc = self.entry[0].getSpace()
            if spc is not None:
                return spc.isBigEndian()
        return False

    def getType(self) -> int:
        """Return the list type (input vs output, register vs standard)."""
        return getattr(self, '_listtype', ParamListStandard.p_standard)

    def extractTiles(self, tiles: list, tp: 'TypeClass') -> None:
        """Extract ParamEntry objects matching the given type class.

        C++ ref: ``ParamListStandard::extractTiles``
        """
        tiles.clear()
        for e in self.entry:
            if e.getType() == tp and e.isExclusion():
                tiles.append(e)

    def getStackEntry(self) -> Optional['ParamEntry']:
        """Return the ParamEntry representing stack storage, or None.

        C++ ref: ``ParamListStandard::getStackEntry``
        """
        for e in self.entry:
            if not e.isExclusion():
                return e
        return None

    def assignAddress(self, dt, proto, pos: int, tlist, status: list, res) -> int:
        """Assign address for a parameter by running through model rules.

        C++ ref: ``ParamListStandard::assignAddress``
        """
        from ghidra.fspec.modelrules import AssignAction
        for rule in getattr(self, 'modelRules', []):
            resp = rule.assignAddress(dt, proto, pos, tlist, status, res)
            if resp != AssignAction.fail:
                return resp
        return self.assignAddressFallback(dt.getMetatype(), dt, True, status, res)

    def assignAddressFallback(self, resource_type, dt, noFallback: bool,
                              status: list, res) -> int:
        """Fallback address assignment from a specific resource list.

        C++ ref: ``ParamListStandard::assignAddressFallback``
        """
        from ghidra.fspec.modelrules import AssignAction
        for e in self.entry:
            if e.getType() != resource_type:
                continue
            grp = e.getGroup()
            if status[grp] != 0:
                continue
            if e.isExclusion():
                if e.getSize() >= dt.getSize():
                    res.addr = Address(e.getSpace(), e.getBase())
                    res.type = dt
                    res.flags = 0
                    for group_id in e.getAllGroups():
                        status[group_id] = -1
                    return AssignAction.success
            else:
                addr, next_status = e.getAddrBySlotInfo(status[grp], dt.getSize(), dt.getAlignment())
                if not addr.isInvalid():
                    res.addr = addr
                    res.type = dt
                    res.flags = 0
                    status[grp] = next_status
                    return AssignAction.success
        if not noFallback:
            se = self.getStackEntry()
            if se is not None:
                grp = se.getGroup()
                addr, next_status = se.getAddrBySlotInfo(status[grp], dt.getSize(), dt.getAlignment())
                if not addr.isInvalid():
                    res.addr = addr
                    res.type = dt
                    res.flags = 0
                    status[grp] = next_status
                    return AssignAction.success
        return AssignAction.fail

    def findEntry(self, loc: Address, size: int, just: bool = True):
        """Find the first ParamEntry containing the given memory range.

        C++ ref: ``ParamListStandard::findEntry``
        """
        if hasattr(loc, "getSpace") and loc.getSpace() is not None and hasattr(loc.getSpace(), "getIndex"):
            resolvers = getattr(self, "_resolvers", None)
            if resolvers is not None:
                matches = resolvers.get(loc.getSpace().getIndex())
                if matches is not None:
                    off = loc.getOffset()
                    for first, last, testEntry, _position in matches:
                        if off < first or off > last:
                            continue
                        if testEntry.getMinSize() > size:
                            continue
                        if not just or testEntry.justifiedContain(loc, size) == 0:
                            return testEntry
                    return None
        for e in self.entry:
            if e.getSpace() is not loc.getSpace():
                continue
            if e.getMinSize() > size:
                continue
            if not just or e.justifiedContain(loc, size) == 0:
                return e
        return None

    def selectUnreferenceEntry(self, grp: int, prefType):
        """Select entry to fill an unreferenced param in a given group.

        C++ ref: ``ParamListStandard::selectUnreferenceEntry``
        """
        bestScore = -1
        bestEntry = None
        for e in self.entry:
            if e.getGroup() != grp:
                continue
            if e.getType() == prefType:
                curScore = 2
            elif prefType == TYPECLASS_GENERAL:
                curScore = 1
            else:
                curScore = 0
            if curScore > bestScore:
                bestScore = curScore
                bestEntry = e
        return bestEntry

    def buildTrialMap(self, active) -> None:
        """Associate trials with model ParamEntrys, fill holes with unreferenced trials.

        C++ ref: ``ParamListStandard::buildTrialMap``
        """
        hitlist = []
        floatCount = 0
        intCount = 0

        for i in range(active.getNumTrials()):
            trial = active.getTrial(i)
            entrySlot = self.findEntry(trial.getAddress(), trial.getSize(), True)
            if entrySlot is None:
                trial.markNoUse()
            else:
                trial.setEntry(entrySlot, 0)
                if trial.isActive():
                    if entrySlot.getType() == TYPECLASS_FLOAT:
                        floatCount += 1
                    else:
                        intCount += 1
                grp = entrySlot.getGroup()
                while len(hitlist) <= grp:
                    hitlist.append(None)
                if hitlist[grp] is None:
                    hitlist[grp] = entrySlot

        for i in range(len(hitlist)):
            curentry = hitlist[i]
            if curentry is None:
                prefType = TYPECLASS_FLOAT if floatCount > intCount else TYPECLASS_GENERAL
                curentry = self.selectUnreferenceEntry(i, prefType)
                if curentry is None:
                    continue
                sz = curentry.getSize() if curentry.isExclusion() else curentry.getAlign()
                nextslot = 0
                addr, _ = curentry.getAddrBySlotInfo(nextslot, sz, 1)
                trialpos = active.getNumTrials()
                active.registerTrial(addr, sz)
                paramtrial = active.getTrial(trialpos)
                paramtrial.markUnref()
                paramtrial.setEntry(curentry, 0)
            elif not curentry.isExclusion():
                # For non-exclusion groups, synthesize unreferenced trials for any
                # alignment slots that are skipped between active trials.
                slotlist = []
                for j in range(active.getNumTrials()):
                    paramtrial = active.getTrial(j)
                    if paramtrial.getEntry() is not curentry:
                        continue
                    slot = curentry.getSlot(paramtrial.getAddress(), 0) - curentry.getGroup()
                    endslot = curentry.getSlot(
                        paramtrial.getAddress(), paramtrial.getSize() - 1
                    ) - curentry.getGroup()
                    if endslot < slot:
                        slot, endslot = endslot, slot
                    while len(slotlist) <= endslot:
                        slotlist.append(0)
                    while slot <= endslot:
                        slotlist[slot] = 1
                        slot += 1
                for j, present in enumerate(slotlist):
                    if present != 0:
                        continue
                    nextslot = j
                    addr, _ = curentry.getAddrBySlotInfo(nextslot, curentry.getAlign(), 1)
                    trialpos = active.getNumTrials()
                    active.registerTrial(addr, curentry.getAlign())
                    paramtrial = active.getTrial(trialpos)
                    paramtrial.markUnref()
                    paramtrial.setEntry(curentry, 0)
        active.sortTrials()

    def separateSections(self, active, trialStart: list) -> None:
        """Calculate the range of trials in each resource section.

        C++ ref: ``ParamListStandard::separateSections``
        """
        numtrials = active.getNumTrials()
        currentTrial = 0
        rs = getattr(self, 'resourceStart', [0])
        nextGroup = rs[1] if len(rs) > 1 else 0x7FFFFFFF
        nextSection = 2
        trialStart.append(currentTrial)
        for currentTrial in range(numtrials):
            trial = active.getTrial(currentTrial)
            ent = trial.getEntry() if hasattr(trial, 'getEntry') else None
            if ent is None:
                continue
            if ent.getGroup() >= nextGroup:
                if nextSection < len(rs):
                    nextGroup = rs[nextSection]
                    nextSection += 1
                else:
                    nextGroup = 0x7FFFFFFF
                trialStart.append(currentTrial)
        trialStart.append(numtrials)

    @staticmethod
    def markGroupNoUse(active, activeTrial: int, trialStart: int) -> None:
        """Mark all trials in exclusion groups as not used, except one.

        C++ ref: ``ParamListStandard::markGroupNoUse``
        """
        numTrials = active.getNumTrials()
        activeEntry = active.getTrial(activeTrial).getEntry()
        for i in range(trialStart, numTrials):
            if i == activeTrial:
                continue
            othertrial = active.getTrial(i)
            if othertrial.isDefinitelyNotUsed():
                continue
            otherEntry = othertrial.getEntry()
            if otherEntry is None or not otherEntry.groupOverlap(activeEntry):
                break
            othertrial.markNoUse()

    @staticmethod
    def markBestInactive(active, group: int, groupStart: int, prefType) -> None:
        """From multiple inactive trials, select the most likely active and mark others.

        C++ ref: ``ParamListStandard::markBestInactive``
        """
        numTrials = active.getNumTrials()
        bestTrial = -1
        bestScore = -1
        for i in range(groupStart, numTrials):
            trial = active.getTrial(i)
            if trial.isDefinitelyNotUsed():
                continue
            ent = trial.getEntry()
            if ent is None:
                continue
            grp = ent.getGroup()
            if grp != group:
                break
            if len(ent.getAllGroups()) > 1:
                continue
            score = 0
            if hasattr(trial, 'hasAncestorRealistic') and trial.hasAncestorRealistic():
                score += 5
                if hasattr(trial, 'hasAncestorSolid') and trial.hasAncestorSolid():
                    score += 5
            if ent.getType() == prefType:
                score += 1
            if score > bestScore:
                bestScore = score
                bestTrial = i
        if bestTrial >= 0:
            ParamListStandard.markGroupNoUse(active, bestTrial, groupStart)

    @staticmethod
    def forceExclusionGroup(active) -> None:
        """Enforce exclusion rules for the given set of parameter trials.

        C++ ref: ``ParamListStandard::forceExclusionGroup``
        """
        numTrials = active.getNumTrials()
        curGroup = -1
        groupStart = -1
        inactiveCount = 0
        for i in range(numTrials):
            curtrial = active.getTrial(i)
            ent = curtrial.getEntry() if hasattr(curtrial, 'getEntry') else None
            if curtrial.isDefinitelyNotUsed() or ent is None or not ent.isExclusion():
                continue
            grp = ent.getGroup()
            if grp != curGroup:
                if inactiveCount > 1:
                    ParamListStandard.markBestInactive(active, curGroup, groupStart, TYPECLASS_GENERAL)
                curGroup = grp
                groupStart = i
                inactiveCount = 0
            if curtrial.isActive():
                ParamListStandard.markGroupNoUse(active, i, groupStart)
            else:
                inactiveCount += 1
        if inactiveCount > 1:
            ParamListStandard.markBestInactive(active, curGroup, groupStart, TYPECLASS_GENERAL)

    @staticmethod
    def forceNoUse(active, start: int, stop: int) -> None:
        """Mark trials above the first 'definitely not used' group as inactive.

        C++ ref: ``ParamListStandard::forceNoUse``
        """
        seendefnouse = False
        curgroup = -1
        alldefnouse = False
        for i in range(start, stop):
            curtrial = active.getTrial(i)
            ent = curtrial.getEntry() if hasattr(curtrial, 'getEntry') else None
            if ent is None:
                continue
            grp = ent.getGroup()
            exclusion = ent.isExclusion()
            if grp <= curgroup and exclusion:
                if not curtrial.isDefinitelyNotUsed():
                    alldefnouse = False
            else:
                if alldefnouse:
                    seendefnouse = True
                alldefnouse = curtrial.isDefinitelyNotUsed()
                curgroup = grp
            if seendefnouse:
                curtrial.markInactive()

    @staticmethod
    def forceInactiveChain(active, maxchain: int, start: int, stop: int, groupstart: int) -> None:
        """Enforce rules about chains of inactive slots.

        C++ ref: ``ParamListStandard::forceInactiveChain``
        """
        seenchain = False
        chainlength = 0
        maxIdx = -1
        for i in range(start, stop):
            trial = active.getTrial(i)
            if trial.isDefinitelyNotUsed():
                continue
            if not trial.isActive():
                if trial.isUnref() and active.isRecoverSubcall():
                    addr = trial.getAddress()
                    spc = addr.getSpace() if hasattr(addr, "getSpace") else None
                    if spc is not None and hasattr(spc, "getType") and spc.getType() == IPTR_SPACEBASE:
                        seenchain = True
                sg = trial.slotGroup() if hasattr(trial, 'slotGroup') else 0
                if i == start:
                    chainlength += (sg - groupstart + 1)
                else:
                    prevsg = active.getTrial(i - 1).slotGroup() if hasattr(active.getTrial(i - 1), 'slotGroup') else 0
                    chainlength += sg - prevsg
                if chainlength > maxchain:
                    seenchain = True
            else:
                chainlength = 0
                if not seenchain:
                    maxIdx = i
            if seenchain:
                trial.markInactive()
        for i in range(start, maxIdx + 1):
            trial = active.getTrial(i)
            if trial.isDefinitelyNotUsed():
                continue
            if not trial.isActive():
                trial.markActive()

    def fillinMap(self, active) -> None:
        """Given an unordered list of trials, calculate a formal parameter list.

        C++ ref: ``ParamListStandard::fillinMap``
        """
        if active.getNumTrials() == 0:
            return
        if not self.entry:
            raise LowlevelError("Cannot derive parameter storage for prototype model without parameter entries")

        self.buildTrialMap(active)
        self.forceExclusionGroup(active)

        trialStart = []
        self.separateSections(active, trialStart)
        numSection = len(trialStart) - 1
        rs = getattr(self, 'resourceStart', [0])
        for i in range(numSection):
            self.forceNoUse(active, trialStart[i], trialStart[i + 1])
        for i in range(numSection):
            gs = rs[i] if i < len(rs) else 0
            self.forceInactiveChain(active, 2, trialStart[i], trialStart[i + 1], gs)

        for i in range(active.getNumTrials()):
            paramtrial = active.getTrial(i)
            if paramtrial.isActive():
                paramtrial.markUsed()

    def checkJoin(self, hiaddr, hisize: int, loaddr, losize: int) -> bool:
        """Check if two storage locations can represent a single logical parameter.

        C++ ref: ``ParamListStandard::checkJoin``
        """
        entryHi = self.findEntry(hiaddr, hisize, True)
        if entryHi is None:
            return False
        entryLo = self.findEntry(loaddr, losize, True)
        if entryLo is None:
            return False
        if entryHi.getGroup() == entryLo.getGroup():
            if entryHi.isExclusion() or entryLo.isExclusion():
                return False
            if not hiaddr.isContiguous(hisize, loaddr, losize):
                return False
            if ((hiaddr.getOffset() - entryHi.getBase()) % entryHi.getAlign()) != 0:
                return False
            if ((loaddr.getOffset() - entryLo.getBase()) % entryLo.getAlign()) != 0:
                return False
            return True
        else:
            sizesum = hisize + losize
            for e in self.entry:
                if e.getSize() < sizesum:
                    continue
                if e.justifiedContain(loaddr, losize) != 0:
                    continue
                if e.justifiedContain(hiaddr, hisize) != losize:
                    continue
                return True
        return False

    def checkSplit(self, loc, size: int, splitpoint: int) -> bool:
        """Check if a storage location can be split into two parameters.

        C++ ref: ``ParamListStandard::checkSplit``
        """
        loc2 = loc + splitpoint
        size2 = size - splitpoint
        entryNum = self.findEntry(loc, splitpoint, True)
        if entryNum is None:
            return False
        entryNum = self.findEntry(loc2, size2, True)
        if entryNum is None:
            return False
        return True

    def characterizeAsParam(self, loc, size: int) -> int:
        """Characterize whether the given range overlaps parameter storage.

        C++ ref: ``ParamListStandard::characterizeAsParam``
        """
        resContains = False
        resContainedBy = False
        for e in self.entry:
            if e.getSpace() is not loc.getSpace():
                continue
            off = e.justifiedContain(loc, size)
            if off == 0:
                return ParamEntry.contains_justified
            elif off > 0:
                resContains = True
            if e.isExclusion() and e.containedBy(loc, size):
                resContainedBy = True
        if resContains:
            return ParamEntry.contains_unjustified
        if resContainedBy:
            return ParamEntry.contained_by
        return ParamEntry.no_containment

    def possibleParamWithSlot(self, loc, size: int, slot_out: list, slotsize_out: list) -> bool:
        """Test if the given location is a parameter, returning slot info.

        C++ ref: ``ParamListStandard::possibleParamWithSlot``
        """
        entryNum = self.findEntry(loc, size, True)
        if entryNum is None:
            return False
        slot_out.append(entryNum.getSlot(loc, 0))
        if entryNum.isExclusion():
            slotsize_out.append(len(entryNum.getAllGroups()))
        else:
            slotsize_out.append(((size - 1) // entryNum.getAlign()) + 1)
        return True

    def getBiggestContainedParam(self, loc, size: int, res) -> bool:
        """Pass-back the biggest parameter contained within the given range.

        C++ ref: ``ParamListStandard::getBiggestContainedParam``
        """
        maxEntry = None
        for e in self.entry:
            if not e.isExclusion():
                continue
            if e.getSpace() is not loc.getSpace():
                continue
            if e.containedBy(loc, size):
                if maxEntry is None or e.getSize() > maxEntry.getSize():
                    maxEntry = e
        if maxEntry is not None:
            res.space = maxEntry.getSpace()
            res.offset = maxEntry.getBase()
            res.size = maxEntry.getSize()
            return True
        return False

    def unjustifiedContainer(self, loc, size: int, res) -> bool:
        """Check if location is unjustified within a parameter container.

        C++ ref: ``ParamListStandard::unjustifiedContainer``
        """
        for e in self.entry:
            if e.getMinSize() > size:
                continue
            just = e.justifiedContain(loc, size)
            if just < 0:
                continue
            if just == 0:
                return False
            e.getContainer(loc, size, res)
            return True
        return False

    def assumedExtension(self, addr, size: int, res) -> 'OpCode':
        """Get the type of extension and containing parameter for the given storage.

        C++ ref: ``ParamListStandard::assumedExtension``
        """
        for e in self.entry:
            if e.getMinSize() > size:
                continue
            ext = e.assumedExtension(addr, size, res)
            if ext != OpCode.CPUI_COPY:
                return ext
        return OpCode.CPUI_COPY

    def getRangeList(self, spc, res) -> None:
        """Collect parameter ranges in the given address space.

        C++ ref: ``ParamListStandard::getRangeList``
        """
        for e in self.entry:
            if e.getSpace() is not spc:
                continue
            baseoff = e.getBase()
            endoff = baseoff + e.getSize() - 1
            if hasattr(res, 'insertRange'):
                res.insertRange(spc, baseoff, endoff)

    def isThisBeforeRetPointer(self) -> bool:
        """Return True if 'this' parameter comes before a hidden return pointer."""
        return self.thisbeforeret

    def isAutoKilledByCall(self) -> bool:
        """Return True if parameters are automatically killed by call."""
        return self.autoKilledByCall

    def parsePentry(self, decoder, effectlist: list, groupid: int,
                    normalstack: bool, splitFloat: bool, grouped: bool) -> None:
        """Parse a single <pentry> element and add to the entry list.

        C++ ref: ``ParamListStandard::parsePentry``
        """
        lastClass = TYPECLASS_GENERAL
        if self.entry:
            lastClass = TYPECLASS_GENERAL if self.entry[-1].isGrouped() else self.entry[-1].getType()
        pe = ParamEntry(groupid)
        pe.decode(decoder, normalstack, grouped, self.entry)
        self.entry.append(pe)
        if splitFloat:
            currentClass = TYPECLASS_GENERAL if grouped else pe.getType()
            if lastClass != currentClass:
                if lastClass < currentClass:
                    raise LowlevelError("parameter list entries must be ordered by storage class")
                self.resourceStart.append(groupid)
        spc = pe.getSpace()
        if spc is not None and hasattr(spc, 'getType'):
            from ghidra.core.space import IPTR_SPACEBASE
            if spc.getType() == IPTR_SPACEBASE:
                self.spacebase = spc
            elif self.autoKilledByCall:
                effectlist.append(EffectRecord(pe, EffectRecord.killedbycall))
        maxgroup = pe.getAllGroups()[-1] + 1 if pe.getAllGroups() else groupid + 1
        if maxgroup > self.numgroup:
            self.numgroup = maxgroup

    def parseGroup(self, decoder, effectlist: list, groupid: int,
                   normalstack: bool, splitFloat: bool) -> None:
        """Parse a <group> element containing multiple <pentry> elements.

        C++ ref: ``ParamListStandard::parseGroup``
        """
        basegroup = self.numgroup
        elemId = decoder.openElement(ELEM_GROUP)
        while decoder.peekElement() != 0:
            self.parsePentry(decoder, effectlist, basegroup, normalstack, splitFloat, True)
        decoder.closeElement(elemId)

    def calcDelay(self) -> None:
        """Calculate the maximum delay for this parameter list.

        C++ ref: ``ParamListStandard::calcDelay`` in fspec.cc:1153-1163
        """
        self.maxdelay = 0
        for e in self.entry:
            spc = e.getSpace()
            if spc is not None and hasattr(spc, 'getDelay'):
                delay = spc.getDelay()
                if delay > self.maxdelay:
                    self.maxdelay = delay

    def populateResolver(self) -> None:
        """Enter all ParamEntry objects into an interval map.

        C++ ref: ``ParamListStandard::populateResolver``
        """
        self._resolvers = {}
        position = 0
        for paramEntry in self.entry:
            spc = paramEntry.getSpace()
            if spc is None:
                continue
            joinrec = getattr(paramEntry, "joinrec", None)
            if joinrec is not None and hasattr(joinrec, "numPieces"):
                for i in range(joinrec.numPieces()):
                    vdata = joinrec.getPiece(i)
                    first = vdata.offset
                    last = first + (vdata.size - 1)
                    self.addResolverRange(vdata.space, first, last, paramEntry, position)
                    position += 1
            else:
                first = paramEntry.getBase()
                last = first + (paramEntry.getSize() - 1)
                self.addResolverRange(spc, first, last, paramEntry, position)
                position += 1
        for idx, ranges in self._resolvers.items():
            self._resolvers[idx] = sorted(ranges, key=lambda item: item[3])

    def decode(self, decoder, effectlist: list, normalstack: bool = True) -> None:
        """Decode this parameter list from an <input> or <output> element.

        C++ ref: ``ParamListStandard::decode``
        """
        self.numgroup = 0
        self.spacebase = None
        pointermax = 0
        self.thisbeforeret = False
        self.autoKilledByCall = False
        splitFloat = True
        elemId = decoder.openElement()
        while True:
            attribId = decoder.getNextAttributeId()
            if attribId == 0:
                break
            if attribId == ATTRIB_POINTERMAX:
                pointermax = decoder.readSignedInteger()
            elif attribId == ATTRIB_THISBEFORERETPOINTER:
                self.thisbeforeret = decoder.readBool()
            elif attribId == ATTRIB_KILLEDBYCALL:
                self.autoKilledByCall = decoder.readBool()
            elif attribId == ATTRIB_SEPARATEFLOAT:
                splitFloat = decoder.readBool()
        while True:
            subId = decoder.peekElement()
            if subId == 0:
                break
            if subId == ELEM_PENTRY:
                self.parsePentry(decoder, effectlist, self.numgroup, normalstack, splitFloat, False)
            elif subId == ELEM_GROUP:
                self.parseGroup(decoder, effectlist, self.numgroup, normalstack, splitFloat)
            elif subId == ELEM_RULE:
                break
            else:
                break
        while True:
            subId = decoder.peekElement()
            if subId == 0:
                break
            if subId == ELEM_RULE:
                decoder.openElement()
                decoder.closeElement(subId)
            else:
                raise LowlevelError("<pentry> and <group> elements must come before any <modelrule>")
        decoder.closeElement(elemId)
        self.resourceStart.append(self.numgroup)
        self.calcDelay()
        self.populateResolver()
        self.pointermax = pointermax

    def assignMap(self, proto, typefactory, res: list) -> None:
        """Assign addresses to input parameters of a prototype.

        C++ ref: ParamListStandard::assignMap in fspec.cc
        """
        from ghidra.fspec.modelrules import AssignAction
        status = [0] * self.numgroup

        if len(res) == 2:
            dt = res[-1].type
            if (res[-1].flags & ParameterPieces.hiddenretparm) != 0:
                if self.assignAddressFallback(TYPECLASS_HIDDENRET, dt, False, status, res[-1]) == AssignAction.fail:
                    raise LowlevelError("Cannot assign parameter address for " + (dt.getName() if dt else "unknown"))
            else:
                if self.assignAddress(dt, proto, 0, typefactory, status, res[-1]) == AssignAction.fail:
                    raise LowlevelError("Cannot assign parameter address for " + (dt.getName() if dt else "unknown"))
            res[-1].flags |= ParameterPieces.hiddenretparm
        for i in range(len(proto.intypes)):
            pp = ParameterPieces()
            res.append(pp)
            dt = proto.intypes[i]
            responseCode = self.assignAddress(dt, proto, i, typefactory, status, res[-1])
            if responseCode == AssignAction.fail or responseCode == AssignAction.no_assignment:
                raise LowlevelError("Cannot assign parameter address for " + (dt.getName() if dt else "unknown"))

    def addResolverRange(self, spc, first: int, last: int, paramEntry, position: int) -> None:
        """Add a range to the resolver interval map.

        C++ ref: ParamListStandard::addResolverRange in fspec.cc
        """
        if not hasattr(self, '_resolvers'):
            self._resolvers = {}
        idx = spc.getIndex()
        if idx not in self._resolvers:
            self._resolvers[idx] = []
        self._resolvers[idx].append((first, last, paramEntry, position))


class ParamListStandardOut(ParamListStandard):
    """Standard output (return value) parameter list.

    C++ ref: ParamListStandardOut in fspec.hh
    """

    def __init__(self) -> None:
        super().__init__()
        self.useFillinFallback: bool = True

    def getType(self) -> int:
        return ParamListStandard.p_standard_out

    def possibleParam(self, loc, size: int) -> bool:
        for e in self.entry:
            if e.justifiedContain(loc, size) >= 0:
                return True
        return False

    def assignMap(self, proto, typefactory, res: list) -> None:
        """Assign address for the return value of a prototype.

        C++ ref: ParamListStandardOut::assignMap in fspec.cc
        """
        from ghidra.fspec.modelrules import AssignAction
        from ghidra.types.datatype import TYPE_VOID
        status = [0] * self.numgroup

        pp = ParameterPieces()
        res.append(pp)
        if proto.outtype.getMetatype() == TYPE_VOID:
            res[-1].type = proto.outtype
            res[-1].flags = 0
            return

        responseCode = self.assignAddress(proto.outtype, proto, -1, typefactory, status, res[-1])
        if responseCode == AssignAction.fail:
            responseCode = AssignAction.hiddenret_ptrparam

        if responseCode in (AssignAction.hiddenret_ptrparam, AssignAction.hiddenret_specialreg,
                            AssignAction.hiddenret_specialreg_void):
            spc = self.spacebase
            if spc is None:
                spc = typefactory.getArch().getDefaultDataSpace() if hasattr(typefactory, 'getArch') else None
            if spc is None:
                raise LowlevelError("Cannot assign return value as a pointer: no space")
            pointersize = spc.getAddrSize()
            wordsize = spc.getWordSize()
            pointertp = typefactory.getTypePointer(pointersize, proto.outtype, wordsize)
            if responseCode == AssignAction.hiddenret_specialreg_void:
                res[-1].type = typefactory.getTypeVoid()
            else:
                res[-1].type = pointertp
                if self.assignAddress(pointertp, proto, -1, typefactory, status, res[-1]) == AssignAction.fail:
                    raise LowlevelError("Cannot assign return value as a pointer")
            res[-1].flags = ParameterPieces.indirectstorage

            pp2 = ParameterPieces()
            res.append(pp2)
            res[-1].type = pointertp
            isSpecial = (responseCode == AssignAction.hiddenret_specialreg or
                         responseCode == AssignAction.hiddenret_specialreg_void)
            res[-1].flags = ParameterPieces.hiddenretparm if isSpecial else 0

    def initialize(self) -> None:
        """Initialize the output parameter list.

        C++ ref: ParamListStandardOut::initialize in fspec.cc
        """
        self.useFillinFallback = True
        for rule in self.modelRules:
            if hasattr(rule, 'canAffectFillinOutput') and rule.canAffectFillinOutput():
                self.useFillinFallback = False
                break
        if self.useFillinFallback:
            self.autoKilledByCall = True

    def fillinMap(self, active) -> None:
        """Determine the return value from active output trials.

        C++ ref: ParamListStandardOut::fillinMap in fspec.cc
        """
        if active.getNumTrials() == 0:
            return
        if self.useFillinFallback:
            self.fillinMapFallback(active, False)
            return
        for i in range(active.getNumTrials()):
            trial = active.getTrial(i)
            trial.setEntry(None, 0)
            if not trial.isActive():
                continue
            entry = self.findEntry(trial.getAddress(), trial.getSize(), False)
            if entry is None:
                trial.markNoUse()
                continue
            res = entry.justifiedContain(trial.getAddress(), trial.getSize())
            if (trial.isRemFormed() or trial.isIndCreateFormed()) and not entry.isFirstInClass():
                trial.markNoUse()
                continue
            trial.setEntry(entry, res)
        active.sortTrials()
        for rule in self.modelRules:
            if hasattr(rule, 'fillinOutputMap') and rule.fillinOutputMap(active):
                for i in range(active.getNumTrials()):
                    trial = active.getTrial(i)
                    if trial.isActive():
                        trial.markUsed()
                    else:
                        trial.markNoUse()
                        trial.setEntry(None, 0)
                return
        self.fillinMapFallback(active, True)

    def fillinMapFallback(self, active, firstOnly: bool) -> None:
        """Fallback method for determining return value from trials.

        C++ ref: ParamListStandardOut::fillinMapFallback in fspec.cc
        """
        bestEntry = None
        for i in range(active.getNumTrials()):
            trial = active.getTrial(i)
            if not trial.isActive():
                continue
            entry = self.findEntry(trial.getAddress(), trial.getSize(), True)
            if entry is None:
                continue
            if bestEntry is None or entry.getGroup() < bestEntry.getGroup():
                bestEntry = entry
            if firstOnly:
                break
        if bestEntry is None:
            for i in range(active.getNumTrials()):
                active.getTrial(i).markNoUse()
            return
        for i in range(active.getNumTrials()):
            trial = active.getTrial(i)
            if not trial.isActive():
                trial.markNoUse()
                trial.setEntry(None, 0)
                continue
            entry = self.findEntry(trial.getAddress(), trial.getSize(), True)
            if entry is bestEntry or (entry is not None and entry.getGroup() == bestEntry.getGroup()):
                trial.markUsed()
                trial.setEntry(bestEntry, bestEntry.justifiedContain(trial.getAddress(), trial.getSize()))
            else:
                trial.markNoUse()
                trial.setEntry(None, 0)
        active.sortTrials()


class ParamListRegister(ParamListStandard):
    """A parameter list using only registers (no stack).

    C++ ref: ParamListRegister in fspec.hh
    """

    def __init__(self) -> None:
        super().__init__()

    def getType(self) -> int:
        return ParamListStandard.p_register

    def fillinMap(self, active) -> None:
        """Given an unordered list of trials, mark active ones as used.

        C++ ref: ParamListRegister::fillinMap in fspec.cc
        """
        if active.getNumTrials() == 0:
            return
        for i in range(active.getNumTrials()):
            paramtrial = active.getTrial(i)
            entrySlot = self.findEntry(paramtrial.getAddress(), paramtrial.getSize(), True)
            if entrySlot is None:
                paramtrial.markNoUse()
            else:
                paramtrial.setEntry(entrySlot, 0)
                if paramtrial.isActive():
                    paramtrial.markUsed()
        active.sortTrials()


class ParamListRegisterOut(ParamListStandardOut):
    """Output parameter list using only registers.

    C++ ref: ParamListRegisterOut in fspec.hh
    """

    def __init__(self) -> None:
        super().__init__()

    def getType(self) -> int:
        return ParamListStandard.p_register_out


class ParamListMerged(ParamListStandard):
    """A merged parameter list from multiple calling conventions.

    C++ ref: ParamListMerged in fspec.hh
    """

    def __init__(self) -> None:
        super().__init__()

    def foldIn(self, op2: ParamListStandard) -> None:
        """Fold another parameter list into this one.

        C++ ref: ParamListMerged::foldIn in fspec.cc
        """
        for e in op2.entry:
            if e not in self.entry:
                self.entry.append(e)
        if op2.spacebase is not None:
            self.spacebase = op2.spacebase
        if op2.numgroup > self.numgroup:
            self.numgroup = op2.numgroup


# =========================================================================
# ProtoModel
# =========================================================================

class ProtoModel:
    """A prototype model: calling convention description.

    Describes how parameters and return values are passed for a given
    calling convention (e.g. cdecl, stdcall, fastcall, etc.)
    """

    extrapop_unknown = 0x8000

    def __init__(self, name: str = "", glb=None) -> None:
        self.name: str = name
        self.glb = glb  # Architecture
        self.input: Optional[ParamListStandard] = None
        self.output: Optional[ParamListStandard] = None
        self.extrapop: int = 0
        self.stackshift: int = 0
        self.hasThis: bool = False
        self.isConstruct: bool = False
        self.hasUponEntry: bool = False
        self.hasUponReturn: bool = False
        self.defaultLocalRange: RangeList = RangeList()
        self.defaultParamRange: RangeList = RangeList()
        self.unaffected: List[VarnodeData] = []
        self.killedbycall: List[VarnodeData] = []
        self.likelytrash: List[VarnodeData] = []
        self.internalStorage: List[VarnodeData] = []
        self.compatModel: Optional[ProtoModel] = None

    def getName(self) -> str:
        return self.name

    def getArch(self):
        return self.glb

    def getAliasParent(self):
        return self.compatModel

    def getExtraPop(self) -> int:
        return self.extrapop

    def setExtraPop(self, ep: int) -> None:
        self.extrapop = ep

    def getStackshift(self) -> int:
        return self.stackshift

    def hasThisPointer(self) -> bool:
        return self.hasThis

    def isConstructor(self) -> bool:
        return self.isConstruct

    def printInDecl(self) -> bool:
        return getattr(self, '_isPrinted', False)

    def setPrintInDecl(self, val: bool) -> None:
        self._isPrinted = val

    def getInjectUponEntry(self) -> int:
        return getattr(self, '_injectUponEntry', -1)

    def getInjectUponReturn(self) -> int:
        return getattr(self, '_injectUponReturn', -1)

    def isCompatible(self, op2) -> bool:
        if op2 is self:
            return True
        if self.compatModel is not None and self.compatModel is op2:
            return True
        if op2 is not None and op2.compatModel is self:
            return True
        return False

    def hasEffect(self, addr, size: int):
        """Determine side-effect of this model on the given memory range.

        Matches C++ ``ProtoModel::lookupEffect`` semantics:
        - Unique (IPTR_INTERNAL) space is always unaffected.
        - A size-0 entry means the entire space is unaffected.
        - Otherwise check range containment.

        Returns a string: 'unaffected', 'killedbycall', 'return_address', or 'unknown'.
        """
        # Unique space is always local to function
        a_spc = addr.getSpace()
        if a_spc is not None:
            stype = a_spc.getType()
            if stype == 3:  # IPTR_INTERNAL
                return 'unaffected'

        _TYPE_TO_STR = {
            EffectRecord.unaffected: 'unaffected',
            EffectRecord.killedbycall: 'killedbycall',
            EffectRecord.return_address: 'return_address',
            EffectRecord.unknown_effect: 'unknown',
        }

        efflist = getattr(self, '_effectlist', [])
        if not efflist:
            return 'unknown'

        a_off = addr.getOffset()

        for eff in efflist:
            e_addr = eff.getAddress()
            e_size = eff.getSize()
            e_spc = e_addr.getSpace()
            if e_spc is not a_spc:
                continue
            # Size 0 means whole space is unaffected
            if e_size == 0:
                return 'unaffected'
            e_off = e_addr.getOffset()
            # Check containment: [a_off, a_off+size) ⊆ [e_off, e_off+e_size)
            if a_off >= e_off and (a_off + size) <= (e_off + e_size):
                return _TYPE_TO_STR.get(eff.getType(), 'unknown')

        return 'unknown'

    def deriveInputMap(self, active) -> None:
        if self.input is not None and hasattr(self.input, 'fillinMap'):
            self.input.fillinMap(active)

    def deriveOutputMap(self, active) -> None:
        if self.output is not None and hasattr(self.output, 'fillinMap'):
            self.output.fillinMap(active)

    def assignParameterStorage(self, proto, res: list, ignoreOutputError: bool = False) -> None:
        """Assign storage locations for all parameters in the prototype.

        The first entry in *res* corresponds to the output parameter (return value),
        and the remaining entries correspond to input parameters.

        C++ ref: ``ProtoModel::assignParameterStorage``
        """
        typefactory = self.glb.types if self.glb is not None else None
        if ignoreOutputError:
            try:
                if self.output is not None and hasattr(self.output, 'assignMap'):
                    self.output.assignMap(proto, typefactory, res)
                else:
                    self._assignOutputFallback(proto, typefactory, res)
            except ParamUnassignedError:
                res.clear()
                pp = ParameterPieces()
                pp.flags = 0
                pp.type = typefactory.getTypeVoid() if typefactory else None
                res.append(pp)
        else:
            if self.output is not None and hasattr(self.output, 'assignMap'):
                self.output.assignMap(proto, typefactory, res)
            else:
                self._assignOutputFallback(proto, typefactory, res)
        if self.input is not None and hasattr(self.input, 'assignMap'):
            self.input.assignMap(proto, typefactory, res)
        else:
            self._assignInputFallback(proto, typefactory, res)

        if self.hasThis and len(res) > 1:
            thisIndex = 1
            if (res[1].flags & ParameterPieces.hiddenretparm) != 0 and len(res) > 2:
                if hasattr(self.input, 'isThisBeforeRetPointer') and self.input.isThisBeforeRetPointer():
                    res[1].swapMarkup(res[2])
                else:
                    thisIndex = 2
            res[thisIndex].flags |= ParameterPieces.isthis

    def _assignOutputFallback(self, proto, typefactory, res: list) -> None:
        """Fallback output assignment when output ParamList lacks assignMap."""
        pp = ParameterPieces()
        outtype = proto.outtype if hasattr(proto, 'outtype') else None
        if outtype is not None and self.output is not None:
            status = [0] * (max(e.getGroup() for e in self.output.entry) + 1 if self.output.entry else 1)
            resp = self.output.assignAddress(outtype, proto, -1, typefactory, status, pp)
            from ghidra.fspec.modelrules import AssignAction
            if resp == AssignAction.fail:
                pp.type = typefactory.getTypeVoid() if typefactory else None
                pp.flags = 0
        else:
            pp.type = typefactory.getTypeVoid() if typefactory else None
            pp.flags = 0
        res.append(pp)

    def _assignInputFallback(self, proto, typefactory, res: list) -> None:
        """Fallback input assignment when input ParamList lacks assignMap."""
        if self.input is None:
            return
        intypes = proto.intypes if hasattr(proto, 'intypes') else []
        numgroups = max((e.getGroup() for e in self.input.entry), default=0) + 1
        status = [0] * numgroups
        for i, dt in enumerate(intypes):
            pp = ParameterPieces()
            self.input.assignAddress(dt, proto, i, typefactory, status, pp)
            res.append(pp)

    def checkInputJoin(self, hiaddr, hisize: int, loaddr, losize: int) -> bool:
        if self.input is not None and hasattr(self.input, 'checkJoin'):
            return self.input.checkJoin(hiaddr, hisize, loaddr, losize)
        return False

    def checkOutputJoin(self, hiaddr, hisize: int, loaddr, losize: int) -> bool:
        if self.output is not None and hasattr(self.output, 'checkJoin'):
            return self.output.checkJoin(hiaddr, hisize, loaddr, losize)
        return False

    def checkInputSplit(self, loc, size: int, splitpoint: int) -> bool:
        if self.input is not None and hasattr(self.input, 'checkSplit'):
            return self.input.checkSplit(loc, size, splitpoint)
        return False

    def characterizeAsInputParam(self, loc, size: int) -> int:
        if self.input is not None and hasattr(self.input, 'characterizeAsParam'):
            return self.input.characterizeAsParam(loc, size)
        return 0

    def characterizeAsOutput(self, loc, size: int) -> int:
        if self.output is not None and hasattr(self.output, 'characterizeAsParam'):
            return self.output.characterizeAsParam(loc, size)
        return 0

    def possibleInputParam(self, loc, size: int) -> bool:
        if self.input is not None and hasattr(self.input, 'possibleParam'):
            return self.input.possibleParam(loc, size)
        return False

    def possibleOutputParam(self, loc, size: int) -> bool:
        if self.output is not None and hasattr(self.output, 'possibleParam'):
            return self.output.possibleParam(loc, size)
        return False

    def getBiggestContainedInputParam(self, loc, size: int, res) -> bool:
        if self.input is not None and hasattr(self.input, 'getBiggestContainedParam'):
            return self.input.getBiggestContainedParam(loc, size, res)
        return False

    def getBiggestContainedOutput(self, loc, size: int, res) -> bool:
        if self.output is not None and hasattr(self.output, 'getBiggestContainedParam'):
            return self.output.getBiggestContainedParam(loc, size, res)
        return False

    def unjustifiedInputParam(self, addr, size: int, res=None) -> bool:
        if self.input is not None and hasattr(self.input, 'unjustifiedContainer'):
            return self.input.unjustifiedContainer(addr, size, res)
        return False

    def unjustifiedOutputParam(self, addr, size: int, res=None) -> bool:
        if self.output is not None and hasattr(self.output, 'unjustifiedContainer'):
            return self.output.unjustifiedContainer(addr, size, res)
        return False

    def getSpacebase(self):
        if self.input is not None:
            return self.input.spacebase
        return None

    def isStackGrowsNegative(self) -> bool:
        return getattr(self, '_stackgrowsnegative', True)

    def getLocalRange(self):
        return self.defaultLocalRange

    def getParamRange(self):
        return self.defaultParamRange

    def getMaxInputDelay(self) -> int:
        if self.input is not None:
            return self.input.maxdelay
        return 0

    def getMaxOutputDelay(self) -> int:
        if self.output is not None:
            return self.output.maxdelay
        return 0

    def isAutoKilledByCall(self) -> bool:
        return False

    def isMerged(self) -> bool:
        return False

    def isUnknown(self) -> bool:
        return False

    @staticmethod
    def lookupEffect(efflist: list, addr, size: int) -> int:
        for eff in efflist:
            if hasattr(eff, 'getAddress') and eff.getAddress() == addr:
                if hasattr(eff, 'getSize') and eff.getSize() >= size:
                    return eff.getType() if hasattr(eff, 'getType') else 4
        return 4  # unknown_effect

    def deriveInputMap(self, active) -> None:
        """Given input trials, derive the most likely input prototype.

        Trials are sorted and marked as used or not.
        C++ ref: ``ProtoModel::deriveInputMap`` (fspec.hh:791-792)
        """
        if self.input is not None:
            self.input.fillinMap(active)

    def deriveOutputMap(self, active) -> None:
        """Given output trials, derive the most likely output prototype.

        C++ ref: ``ProtoModel::deriveOutputMap`` (fspec.hh:798-799)
        """
        if self.output is not None:
            self.output.fillinMap(active)

    def getInput(self) -> Optional[ParamListStandard]:
        return self.input

    def getOutput(self) -> Optional[ParamListStandard]:
        return self.output

    def getUnaffected(self) -> List[VarnodeData]:
        return self.unaffected

    def getKilledByCall(self) -> List[VarnodeData]:
        return self.killedbycall

    def getLikelyTrash(self) -> List[VarnodeData]:
        return self.likelytrash

    def getInternalStorage(self) -> List[VarnodeData]:
        return self.internalStorage

    def numEffects(self) -> int:
        return len(getattr(self, '_effectlist', []))

    def encode(self, encoder) -> None:
        """Encode this prototype model to stream.

        C++ ref: ProtoModel has no encode in C++; this is a Python addition for round-trip.
        """
        encoder.openElement(ELEM_PROTOTYPE)
        encoder.writeString(ATTRIB_NAME, self.name)
        if self.extrapop == ProtoModel.extrapop_unknown:
            encoder.writeString(ATTRIB_EXTRAPOP, "unknown")
        else:
            encoder.writeSignedInteger(ATTRIB_EXTRAPOP, self.extrapop)
        if self.hasThis:
            encoder.writeBool(ATTRIB_HASTHIS, True)
        if self.isConstruct:
            encoder.writeBool(ATTRIB_CONSTRUCTOR, True)
        # Encode input/output param lists
        if self.input is not None and hasattr(self.input, 'encode'):
            self.input.encode(encoder, ELEM_INPUT)
        if self.output is not None and hasattr(self.output, 'encode'):
            self.output.encode(encoder, ELEM_OUTPUT)
        # Encode effect list
        effectlist = getattr(self, 'effectlist', [])
        if effectlist:
            unaffected = [r for r in effectlist if r.getType() == EffectRecord.unaffected]
            killed = [r for r in effectlist if r.getType() == EffectRecord.killedbycall]
            retaddr = [r for r in effectlist if r.getType() == EffectRecord.return_address]
            if unaffected:
                encoder.openElement(ELEM_UNAFFECTED)
                for rec in unaffected:
                    rec.encode(encoder)
                encoder.closeElement(ELEM_UNAFFECTED)
            if killed:
                encoder.openElement(ELEM_KILLEDBYCALL)
                for rec in killed:
                    rec.encode(encoder)
                encoder.closeElement(ELEM_KILLEDBYCALL)
            if retaddr:
                encoder.openElement(ELEM_RETURNADDRESS)
                for rec in retaddr:
                    rec.encode(encoder)
                encoder.closeElement(ELEM_RETURNADDRESS)
        encoder.closeElement(ELEM_PROTOTYPE)

    def decode(self, decoder) -> None:
        """Decode this prototype model from a <prototype> element.

        C++ ref: ``ProtoModel::decode``
        """
        sawlocalrange = False
        sawparamrange = False
        sawretaddr = False
        self._stackgrowsnegative = True
        if self.glb is not None:
            stackspc = self.glb.getStackSpace() if hasattr(self.glb, 'getStackSpace') else None
            if stackspc is not None and hasattr(stackspc, 'stackGrowsNegative'):
                self._stackgrowsnegative = stackspc.stackGrowsNegative()
        else:
            stackspc = None
        strategystring = ""
        self.defaultLocalRange = RangeList()
        self.defaultParamRange = RangeList()
        self.extrapop = -300
        self.hasThis = False
        self.isConstruct = False
        self.isPrinted = True
        self.effectlist = []
        self.injectUponEntry = -1
        self.injectUponReturn = -1
        self.likelytrash = []
        self.internalStorage = []
        elemId = decoder.openElement(ELEM_PROTOTYPE)
        while True:
            attribId = decoder.getNextAttributeId()
            if attribId == 0:
                break
            if attribId == ATTRIB_NAME:
                self.name = decoder.readString()
            elif attribId == ATTRIB_EXTRAPOP:
                self.extrapop = decoder.readSignedIntegerExpectString("unknown", ProtoModel.extrapop_unknown)
            elif attribId == ATTRIB_STACKSHIFT:
                pass  # backward compat
            elif attribId == ATTRIB_STRATEGY:
                strategystring = decoder.readString()
            elif attribId == ATTRIB_HASTHIS:
                self.hasThis = decoder.readBool()
            elif attribId == ATTRIB_CONSTRUCTOR:
                self.isConstruct = decoder.readBool()
            else:
                raise LowlevelError("Unknown prototype attribute")
        if self.name == "__thiscall":
            self.hasThis = True
        if self.extrapop == -300:
            raise LowlevelError("Missing prototype attributes")
        self._buildParamList(strategystring)
        while True:
            subId = decoder.peekElement()
            if subId == 0:
                break
            if subId == ELEM_INPUT:
                if self.input is not None and hasattr(self.input, 'decode'):
                    self.input.decode(decoder, self.effectlist, self._stackgrowsnegative)
                    if stackspc is not None:
                        self.input.getRangeList(stackspc, self.defaultParamRange)
                        if not self.defaultParamRange.empty():
                            sawparamrange = True
                else:
                    decoder.openElement()
                    decoder.closeElement(subId)
            elif subId == ELEM_OUTPUT:
                if self.output is not None and hasattr(self.output, 'decode'):
                    self.output.decode(decoder, self.effectlist, self._stackgrowsnegative)
                else:
                    decoder.openElement()
                    decoder.closeElement(subId)
            elif subId == ELEM_UNAFFECTED:
                decoder.openElement()
                while decoder.peekElement() != 0:
                    rec = EffectRecord()
                    rec.decode(EffectRecord.unaffected, decoder)
                    self.effectlist.append(rec)
                decoder.closeElement(subId)
            elif subId == ELEM_KILLEDBYCALL:
                decoder.openElement()
                while decoder.peekElement() != 0:
                    rec = EffectRecord()
                    rec.decode(EffectRecord.killedbycall, decoder)
                    self.effectlist.append(rec)
                decoder.closeElement(subId)
            elif subId == ELEM_RETURNADDRESS:
                decoder.openElement()
                while decoder.peekElement() != 0:
                    rec = EffectRecord()
                    rec.decode(EffectRecord.return_address, decoder)
                    self.effectlist.append(rec)
                decoder.closeElement(subId)
                sawretaddr = True
            elif subId == ELEM_LOCALRANGE:
                sawlocalrange = True
                decoder.openElement()
                while decoder.peekElement() != 0:
                    r = Range()
                    r.decode(decoder)
                    self.defaultLocalRange.insertRange(r.getSpace(), r.getFirst(), r.getLast())
                decoder.closeElement(subId)
            elif subId == ELEM_PARAMRANGE:
                sawparamrange = True
                decoder.openElement()
                while decoder.peekElement() != 0:
                    r = Range()
                    r.decode(decoder)
                    self.defaultParamRange.insertRange(r.getSpace(), r.getFirst(), r.getLast())
                decoder.closeElement(subId)
            elif subId == ELEM_LIKELYTRASH:
                decoder.openElement()
                while decoder.peekElement() != 0:
                    childId = decoder.openElement()
                    vd = VarnodeData()
                    vd.decode(decoder)
                    decoder.closeElement(childId)
                    self.likelytrash.append(vd)
                decoder.closeElement(subId)
            elif subId == ELEM_INTERNAL_STORAGE:
                decoder.openElement()
                while decoder.peekElement() != 0:
                    childId = decoder.openElement()
                    vd = VarnodeData()
                    vd.decode(decoder)
                    decoder.closeElement(childId)
                    self.internalStorage.append(vd)
                decoder.closeElement(subId)
            elif subId == ELEM_PCODE:
                decoder.openElement()
                decoder.closeElement(subId)
            else:
                raise LowlevelError("Unknown element in prototype")
        decoder.closeElement(elemId)
        if not sawretaddr and self.glb is not None:
            defret = getattr(self.glb, 'defaultReturnAddr', None)
            if defret is not None and hasattr(defret, 'space') and defret.space is not None:
                self.effectlist.append(EffectRecord(
                    Address(defret.space, defret.offset), defret.size, EffectRecord.return_address))
        self.effectlist.sort(key=lambda r: (id(r.getAddress().getSpace()), r.getAddress().getOffset()))
        self.likelytrash.sort(key=lambda v: (id(v.space), v.offset))
        self.internalStorage.sort(key=lambda v: (id(v.space), v.offset))
        if not sawlocalrange:
            self._defaultLocalRange()
        if not sawparamrange:
            self._defaultParamRange()

    def _buildParamList(self, strategystring: str = "") -> None:
        """Allocate input/output ParamLists based on strategy.

        C++ ref: ``ProtoModel::buildParamList``
        """
        if self.input is None:
            self.input = ParamListStandard()
        if self.output is None:
            self.output = ParamListStandard()

    def _defaultLocalRange(self) -> None:
        """Set default local variable range based on stack space.

        C++ ref: ``ProtoModel::defaultLocalRange``
        """
        if self.glb is None:
            return
        stackspc = self.glb.getStackSpace() if hasattr(self.glb, 'getStackSpace') else None
        if stackspc is None:
            return
        if self._stackgrowsnegative:
            last = stackspc.getHighest() if hasattr(stackspc, 'getHighest') else 0xFFFFFFFF
            addrsize = stackspc.getAddrSize() if hasattr(stackspc, 'getAddrSize') else 4
            if addrsize >= 4:
                first = last - 999999
            elif addrsize >= 2:
                first = last - 9999
            else:
                first = last - 99
            self.defaultLocalRange.insertRange(stackspc, first, last)
        else:
            first = 0
            addrsize = stackspc.getAddrSize() if hasattr(stackspc, 'getAddrSize') else 4
            if addrsize >= 4:
                last = 999999
            elif addrsize >= 2:
                last = 9999
            else:
                last = 99
            self.defaultLocalRange.insertRange(stackspc, first, last)

    def _defaultParamRange(self) -> None:
        """Set default parameter range based on stack space.

        C++ ref: ``ProtoModel::defaultParamRange``
        """
        if self.glb is None:
            return
        stackspc = self.glb.getStackSpace() if hasattr(self.glb, 'getStackSpace') else None
        if stackspc is None:
            return
        if self._stackgrowsnegative:
            first = 0
            addrsize = stackspc.getAddrSize() if hasattr(stackspc, 'getAddrSize') else 4
            if addrsize >= 4:
                last = 999999
            elif addrsize >= 2:
                last = 9999
            else:
                last = 99
            self.defaultParamRange.insertRange(stackspc, first, last)
        else:
            last = stackspc.getHighest() if hasattr(stackspc, 'getHighest') else 0xFFFFFFFF
            addrsize = stackspc.getAddrSize() if hasattr(stackspc, 'getAddrSize') else 4
            if addrsize >= 4:
                first = last - 999999
            elif addrsize >= 2:
                first = last - 9999
            else:
                first = last - 99
            self.defaultParamRange.insertRange(stackspc, first, last)

    def __repr__(self) -> str:
        return f"ProtoModel({self.name!r})"


# =========================================================================
# ParameterPieces
# =========================================================================

class ParameterPieces:
    """Raw pieces of a function parameter or return value."""

    # Flag constants (must be present so ParameterBasic can reference them)
    isthis = 1
    hiddenretparm = 2
    indirectstorage = 4
    namelock = 8
    typelock = 16
    sizelock = 32

    def __init__(self) -> None:
        self.type: Optional[Datatype] = None
        self.addr: Address = Address()
        self.name: str = ""
        self.flags: int = 0

    def getType(self):
        return self.type

    def getAddress(self) -> Address:
        return self.addr

    def getName(self) -> str:
        return self.name

    def getFlags(self) -> int:
        return self.flags

    def setFlags(self, fl: int) -> None:
        self.flags = fl

    def swapMarkup(self, op) -> None:
        self.type, op.type = op.type, self.type


class PrototypePieces:
    """Raw pieces of a function prototype."""

    def __init__(self) -> None:
        self.model: Optional[ProtoModel] = None
        self.name: str = ""
        self.intypes: List[Datatype] = []
        self.innames: List[str] = []
        self.outtype: Optional[Datatype] = None
        self.dotdotdot: bool = False
        self.firstVarArgSlot: int = -1

    def getModel(self):
        return self.model

    def getName(self) -> str:
        return self.name

    def getOuttype(self):
        return self.outtype

    def getNumInputs(self) -> int:
        return len(self.intypes)

    def isDotdotdot(self) -> bool:
        return self.dotdotdot


# =========================================================================
# ProtoParameter
# =========================================================================

class ProtoParameter:
    """A single parameter in a function prototype."""

    def __init__(self, name: str = "", tp: Optional[Datatype] = None,
                 addr: Optional[Address] = None, sz: int = 0) -> None:
        self.name: str = name
        self.type: Optional[Datatype] = tp
        self.addr: Address = addr if addr is not None else Address()
        self.size: int = sz
        self.flags: int = 0

    def getName(self) -> str:
        return self.name

    def getType(self) -> Optional[Datatype]:
        return self.type

    def getAddress(self) -> Address:
        return self.addr

    def getSize(self) -> int:
        return self.size

    def isTypeLocked(self) -> bool:
        return (self.flags & ParameterPieces.typelock) != 0

    def isNameLocked(self) -> bool:
        return (self.flags & ParameterPieces.namelock) != 0

    def isThisPointer(self) -> bool:
        return (self.flags & ParameterPieces.isthis) != 0

    def isIndirectStorage(self) -> bool:
        return (self.flags & ParameterPieces.indirectstorage) != 0

    def isHiddenReturn(self) -> bool:
        return (self.flags & ParameterPieces.hiddenretparm) != 0

    def setTypeLock(self, val: bool) -> None:
        if val:
            self.flags |= ParameterPieces.typelock
        else:
            self.flags &= ~ParameterPieces.typelock

    def setName(self, nm: str) -> None:
        self.name = nm

    def setType(self, tp) -> None:
        self.type = tp

    def setAddress(self, addr: Address) -> None:
        self.addr = addr

    def setSize(self, sz: int) -> None:
        self.size = sz

    def clone(self):
        p = ProtoParameter(self.name, self.type, self.addr, self.size)
        p.flags = self.flags
        return p


# =========================================================================
# FuncProto
# =========================================================================

class FuncProto:
    """A function prototype: return type + parameters + calling convention.

    Describes the formal interface to a function.
    """

    voidinputlock = 1
    modellock = 2
    is_inline = 4
    no_return = 8
    paramshift_applied = 16
    error_inputparam = 32
    error_outputparam = 64
    custom_storage = 128
    unknown_model = 256
    is_constructor = 0x200
    is_destructor = 0x400
    has_thisptr = 0x800
    is_override = 0x1000

    def __init__(self) -> None:
        self.model: Optional[ProtoModel] = None
        self.store: List[ProtoParameter] = []
        self.outparam: Optional[ProtoParameter] = None
        self.flags: int = 0
        self.extrapop: int = ProtoModel.extrapop_unknown
        self.injectId: int = -1

    def getModel(self) -> Optional[ProtoModel]:
        return self.model

    def setModel(self, m: ProtoModel) -> None:
        """Establish a specific prototype model.

        Some basic properties are inherited from the model.

        C++ ref: ``FuncProto::setModel``
        """
        if m is not None:
            expop = m.getExtraPop()
            if self.model is None or expop != ProtoModel.extrapop_unknown:
                self.extrapop = expop
            if m.hasThisPointer():
                self.flags |= FuncProto.has_thisptr
            if m.isConstructor():
                self.flags |= FuncProto.is_constructor
            if hasattr(m, 'isAutoKilledByCall') and m.isAutoKilledByCall():
                self.flags |= FuncProto.auto_killedbycall
            self.model = m
        else:
            self.model = m
            self.extrapop = ProtoModel.extrapop_unknown

    def numParams(self) -> int:
        return len(self.store)

    def getParam(self, i: int) -> ProtoParameter:
        return self.store[i]

    def getOutput(self) -> Optional[ProtoParameter]:
        return self.outparam

    def setOutput(self, p: ProtoParameter) -> None:
        self.outparam = p

    def addParam(self, p: ProtoParameter) -> None:
        self.store.append(p)

    def clearParams(self) -> None:
        self.store.clear()

    def isModelLocked(self) -> bool:
        return (self.flags & FuncProto.modellock) != 0

    def isInputLocked(self) -> bool:
        return (self.flags & FuncProto.voidinputlock) != 0 or len(self.store) > 0

    def isOutputLocked(self) -> bool:
        return self.outparam is not None and self.outparam.isTypeLocked()

    def isInline(self) -> bool:
        return (self.flags & FuncProto.is_inline) != 0

    def isNoReturn(self) -> bool:
        return (self.flags & FuncProto.no_return) != 0

    def isConstructor(self) -> bool:
        return (self.flags & FuncProto.is_constructor) != 0

    def isDestructor(self) -> bool:
        return (self.flags & FuncProto.is_destructor) != 0

    def hasThisPointer(self) -> bool:
        return (self.flags & FuncProto.has_thisptr) != 0

    dotdotdot = 0x2000
    auto_killedbycall = 0x4000

    def isDotdotdot(self) -> bool:
        return (self.flags & FuncProto.dotdotdot) != 0

    def setDotdotdot(self, val: bool) -> None:
        if val:
            self.flags |= FuncProto.dotdotdot
        else:
            self.flags &= ~FuncProto.dotdotdot

    def isOverride(self) -> bool:
        return (self.flags & FuncProto.is_override) != 0

    def setOverride(self, val: bool) -> None:
        if val:
            self.flags |= FuncProto.is_override
        else:
            self.flags &= ~FuncProto.is_override

    def hasCustomStorage(self) -> bool:
        return (self.flags & FuncProto.custom_storage) != 0

    def getSpacebase(self):
        return self.model.getSpacebase() if self.model else None

    def isStackGrowsNegative(self) -> bool:
        return self.model.isStackGrowsNegative() if self.model else True

    def getLocalRange(self):
        return self.model.getLocalRange() if self.model else None

    def getParamRange(self):
        return self.model.getParamRange() if self.model else None

    def getArch(self):
        return self.model.getArch() if self.model else None

    def characterizeAsInputParam(self, addr, size: int) -> int:
        return self.model.characterizeAsInputParam(addr, size) if self.model else 0

    def characterizeAsOutput(self, addr, size: int) -> int:
        return self.model.characterizeAsOutput(addr, size) if self.model else 0

    def possibleInputParam(self, addr, size: int) -> bool:
        if not self.isDotdotdot():
            if (self.flags & FuncProto.voidinputlock) != 0:
                return False
            num = self.numParams()
            if num > 0:
                locktest = False
                for i in range(num):
                    param = self.getParam(i)
                    if not param.isTypeLocked():
                        continue
                    locktest = True
                    iaddr = param.getAddress()
                    if iaddr.justifiedContain(param.getSize(), addr, size, False) == 0:
                        return True
                if locktest:
                    return False
        return self.model.possibleInputParam(addr, size) if self.model else False

    def possibleOutputParam(self, addr, size: int) -> bool:
        if self.isOutputLocked():
            outparam = self.getOutput()
            if outparam is None:
                return False
            outtype = outparam.getType()
            if outtype is None or outtype.getMetatype() == TYPE_VOID:
                return False
            iaddr = outparam.getAddress()
            return iaddr.justifiedContain(outparam.getSize(), addr, size, False) == 0
        return self.model.possibleOutputParam(addr, size) if self.model else False

    def getBiggestContainedInputParam(self, loc, size: int, res) -> bool:
        return self.model.getBiggestContainedInputParam(loc, size, res) if self.model else False

    def getBiggestContainedOutput(self, loc, size: int, res) -> bool:
        return self.model.getBiggestContainedOutput(loc, size, res) if self.model else False

    def hasEffect(self, addr, size: int):
        """Determine effect of the function on the given memory range.

        Matches C++ ``FuncProto::hasEffect``: delegates to model if own
        effectlist is empty.  Returns a string for consistency with
        ``guardCalls`` which uses string comparisons.
        """
        effectlist = getattr(self, 'effectlist', [])
        if effectlist:
            effect = ProtoModel.lookupEffect(effectlist, addr, size)
            return {
                EffectRecord.unaffected: 'unaffected',
                EffectRecord.killedbycall: 'killedbycall',
                EffectRecord.return_address: 'return_address',
            }.get(effect, 'unknown')
        if self.model is not None:
            return self.model.hasEffect(addr, size)
        return 'unknown'

    def deriveInputMap(self, active) -> None:
        if self.model is not None:
            self.model.deriveInputMap(active)

    def deriveOutputMap(self, active) -> None:
        if self.model is not None:
            self.model.deriveOutputMap(active)

    def checkInputJoin(self, hiaddr, hisz: int, loaddr, losz: int) -> bool:
        return self.model.checkInputJoin(hiaddr, hisz, loaddr, losz) if self.model else False

    def checkInputSplit(self, loc, size: int, splitpoint: int) -> bool:
        return self.model.checkInputSplit(loc, size, splitpoint) if self.model else False

    def assumedInputExtension(self, addr, size: int, res=None):
        """Get the type of extension for an input parameter.

        C++ ref: ``ProtoModel::assumedInputExtension``
        """
        if self.model is not None and self.model.input is not None:
            return self.model.input.assumedExtension(addr, size, res)
        return OpCode.CPUI_COPY

    def assumedOutputExtension(self, addr, size: int, res=None):
        """Get the type of extension for an output parameter.

        C++ ref: ``ProtoModel::assumedOutputExtension``
        """
        if self.model is not None and self.model.output is not None:
            return self.model.output.assumedExtension(addr, size, res)
        return OpCode.CPUI_COPY

    def unjustifiedInputParam(self, addr, size: int, res=None) -> bool:
        """Check if the given storage is unjustified within its parameter container.

        C++ ref: ``FuncProto::unjustifiedInputParam``
        """
        if not self.isDotdotdot():
            if (self.flags & FuncProto.voidinputlock) != 0:
                return False
            num = self.numParams()
            if num > 0:
                locktest = False
                for i in range(num):
                    param = self.getParam(i)
                    if not param.isTypeLocked():
                        continue
                    locktest = True
                    iaddr = param.getAddress()
                    just = iaddr.justifiedContain(param.getSize(), addr, size, False)
                    if just == 0:
                        return False
                    if just > 0:
                        if res is not None:
                            res.space = iaddr.getSpace()
                            res.offset = iaddr.getOffset()
                            res.size = param.getSize()
                        return True
                if locktest:
                    return False
        if self.model is not None:
            return self.model.unjustifiedInputParam(addr, size, res)
        return False

    def getThisPointerStorage(self, dt=None):
        """Get the storage location for the 'this' pointer.

        C++ ref: ``FuncProto::getThisPointerStorage``
        """
        if self.model is None or not self.model.hasThisPointer():
            return Address()
        proto = PrototypePieces()
        proto.model = self.model
        proto.firstVarArgSlot = -1
        proto.outtype = self.getOutputType()
        proto.intypes = [dt] if dt is not None else []
        res = []
        try:
            self.model.assignParameterStorage(proto, res, True)
        except Exception:
            return Address()
        for i in range(1, len(res)):
            if hasattr(res[i], 'flags') and (res[i].flags & ParameterPieces.hiddenretparm) != 0:
                continue
            return res[i].addr
        return Address()

    def isCompatible(self, op2) -> bool:
        if self.model is not None and op2.model is not None:
            return self.model.isCompatible(op2.model)
        return False

    def isAutoKilledByCall(self) -> bool:
        if self.model is not None and hasattr(self.model, 'isAutoKilledByCall'):
            return self.model.isAutoKilledByCall()
        return (self.flags & FuncProto.auto_killedbycall) != 0

    def resolveModel(self, active) -> None:
        """Pick a specific model from a merged set based on active trials.

        C++ ref: ``FuncProto::resolveModel`` (fspec.cc:3767-3776)
        """
        if self.model is None:
            return
        if not self.model.isMerged():
            return
        if hasattr(self.model, 'selectModel'):
            newmodel = self.model.selectModel(active)
            self.setModel(newmodel)

    def deriveInputMap(self, active) -> None:
        """Given input trials, derive the most likely inputs for this prototype.

        C++ ref: ``FuncProto::deriveInputMap`` (fspec.hh:1494-1495)
        """
        if self.model is not None:
            self.model.deriveInputMap(active)

    def deriveOutputMap(self, active) -> None:
        """Given output trials, derive the most likely return value.

        C++ ref: ``FuncProto::deriveOutputMap`` (fspec.hh:1501-1502)
        """
        if self.model is not None:
            self.model.deriveOutputMap(active)

    def getMaxInputDelay(self) -> int:
        return self.model.getMaxInputDelay() if self.model else 0

    def getMaxOutputDelay(self) -> int:
        return self.model.getMaxOutputDelay() if self.model else 0

    def getPieces(self, pieces) -> None:
        """Get the raw pieces of the prototype."""
        if pieces is not None:
            pieces.model = self.model
            pieces.outtype = self.outparam.getType() if self.outparam else None
            pieces.intypes = [p.getType() for p in self.store if p is not None]
            pieces.innames = [p.getName() for p in self.store if p is not None]

    def setPieces(self, pieces) -> None:
        """Set this prototype based on raw pieces.

        The full function prototype is (re)set from a model, names, and data-types.
        The new input and output parameters are both assumed to be locked.

        C++ ref: ``FuncProto::setPieces``
        """
        if pieces is not None:
            if pieces.model is not None:
                self.setModel(pieces.model)
            self.updateAllTypes(pieces)
            self.setInputLock(True)
            self.setOutputLock(True)
            self.setModelLock(True)

    def setScope(self, s, startpoint) -> None:
        """Set a backing symbol Scope for this.

        C++ ref: ``FuncProto::setScope``
        """
        self.store = ProtoStoreInternal()
        if self.model is None:
            arch = s.getArch() if hasattr(s, 'getArch') else None
            if arch is not None and hasattr(arch, 'defaultfp'):
                self.setModel(arch.defaultfp)

    def resolveModel(self, active) -> None:
        """Resolve the prototype model from active trials.

        If this has a merged model, pick the most likely model
        from the merged set based on the given parameter trials.

        C++ ref: ``FuncProto::resolveModel``
        """
        if self.model is None:
            return
        if not hasattr(self.model, 'isMerged') or not self.model.isMerged():
            return
        newmodel = self.model.selectModel(active)
        self.setModel(newmodel)

    def updateInputTypes(self, data, triallist: list, activeinput) -> None:
        """Update input parameters based on Varnode trials.

        Given a list of Varnodes and their associated trial information,
        create an input parameter for each trial in order, grabbing data-type
        information from the Varnode.  Any old input parameters are cleared.

        C++ ref: ``FuncProto::updateInputTypes``
        """
        if self.isInputLocked():
            return
        self.store.clear()
        count = 0
        numtrials = activeinput.getNumTrials()
        for i in range(numtrials):
            trial = activeinput.getTrial(i)
            if trial.isUsed():
                slot = trial.getSlot()
                vn = triallist[slot - 1]
                if hasattr(vn, 'isMark') and vn.isMark():
                    continue
                if hasattr(vn, 'isPersist') and vn.isPersist():
                    sz = [0]
                    addr = data.findDisjointCover(vn, sz) if hasattr(data, 'findDisjointCover') else vn.getAddr()
                    actual_sz = sz[0] if isinstance(sz, list) else sz
                    if actual_sz == vn.getSize():
                        tp = vn.getHigh().getType() if hasattr(vn, 'getHigh') and vn.getHigh() is not None else None
                    else:
                        tp = data.getArch().types.getBase(actual_sz, TYPE_UNKNOWN)
                else:
                    addr = trial.getAddress()
                    tp = vn.getHigh().getType() if hasattr(vn, 'getHigh') and vn.getHigh() is not None else None
                p = ProtoParameter("", tp, addr, tp.getSize() if tp is not None else 0)
                self.store.append(p)
                count += 1
                if hasattr(vn, 'setMark'):
                    vn.setMark()
        for vn in triallist:
            if hasattr(vn, 'clearMark'):
                vn.clearMark()
        self._updateThisPointer()

    def updateInputNoTypes(self, data, triallist: list, activeinput) -> None:
        """Update input parameters based on Varnode trials, without storing data-types.

        Instead of pulling a data-type from the Varnode, only the size is used.
        Undefined data-types are pulled from the given TypeFactory.

        C++ ref: ``FuncProto::updateInputNoTypes``
        """
        if self.isInputLocked():
            return
        self.store.clear()
        count = 0
        numtrials = activeinput.getNumTrials()
        factory = data.getArch().types if hasattr(data, 'getArch') and data.getArch() is not None else None
        for i in range(numtrials):
            trial = activeinput.getTrial(i)
            if trial.isUsed():
                slot = trial.getSlot()
                vn = triallist[slot - 1]
                if hasattr(vn, 'isMark') and vn.isMark():
                    continue
                if hasattr(vn, 'isPersist') and vn.isPersist():
                    sz = [0]
                    addr = data.findDisjointCover(vn, sz) if hasattr(data, 'findDisjointCover') else vn.getAddr()
                    actual_sz = sz[0] if isinstance(sz, list) else sz
                    tp = factory.getBase(actual_sz, TYPE_UNKNOWN) if factory else None
                else:
                    addr = trial.getAddress()
                    tp = factory.getBase(vn.getSize(), TYPE_UNKNOWN) if factory else None
                p = ProtoParameter("", tp, addr, tp.getSize() if tp is not None else 0)
                self.store.append(p)
                count += 1
                if hasattr(vn, 'setMark'):
                    vn.setMark()
        for vn in triallist:
            if hasattr(vn, 'clearMark'):
                vn.clearMark()

    def updateOutputTypes(self, triallist: list) -> None:
        """Update the return value based on Varnode trials.

        If the output parameter is locked, don't do anything. Otherwise,
        given a list of (at most 1) Varnode, create a return value, grabbing
        data-type information from the Varnode.

        C++ ref: ``FuncProto::updateOutputTypes``
        """
        outparm = self.outparam
        if outparm is None or not outparm.isTypeLocked():
            # Not locked (or no output yet)
            if not triallist:
                self.outparam = None
                return
        elif hasattr(outparm, 'isSizeTypeLocked') and outparm.isSizeTypeLocked():
            if not triallist:
                return
            vn = triallist[0]
            if (vn.getAddr() == outparm.getAddress() and
                    vn.getSize() == outparm.getSize()):
                tp = vn.getHigh().getType() if hasattr(vn, 'getHigh') and vn.getHigh() is not None else None
                if tp is not None and hasattr(outparm, 'setType'):
                    outparm.setType(tp)
            return
        else:
            return  # Locked
        if not triallist:
            return
        vn = triallist[0]
        tp = vn.getHigh().getType() if hasattr(vn, 'getHigh') and vn.getHigh() is not None else None
        self.outparam = ProtoParameter("", tp, vn.getAddr(), vn.getSize())

    def updateOutputNoTypes(self, triallist: list, factory=None) -> None:
        """Update the return value based on Varnode trials, without storing data-types.

        An undefined data-type is created from the given TypeFactory.

        C++ ref: ``FuncProto::updateOutputNoTypes``
        """
        if self.isOutputLocked():
            return
        if not triallist:
            self.outparam = None
            return
        vn = triallist[0]
        tp = factory.getBase(vn.getSize(), TYPE_UNKNOWN) if factory is not None else None
        self.outparam = ProtoParameter("", tp, vn.getAddr(), vn.getSize())

    def _updateThisPointer(self) -> None:
        """Mark the appropriate parameter as 'this' if the model requires it.

        C++ ref: ``FuncProto::updateThisPointer``
        """
        if self.model is None or not self.model.hasThisPointer():
            return
        numInputs = len(self.store)
        if numInputs == 0:
            return
        param = self.store[0]
        if hasattr(param, 'isHiddenReturn') and param.isHiddenReturn():
            if numInputs < 2:
                return
            param = self.store[1]
        if hasattr(param, 'setThisPointer'):
            param.setThisPointer(True)

    def updateAllTypes(self, proto) -> None:
        """Set this entire function prototype based on a list of names and data-types.

        Storage locations and hidden return parameters are calculated,
        creating a complete function prototype. Existing locks are overridden.

        C++ ref: ``FuncProto::updateAllTypes``
        """
        if self.model is not None:
            self.setModel(self.model)  # resets extrapop
        self.store.clear()
        self.outparam = None
        self.flags &= ~FuncProto.voidinputlock
        self.setDotdotdot(hasattr(proto, 'firstVarArgSlot') and proto.firstVarArgSlot >= 0)

        pieces = []
        try:
            if self.model is not None:
                self.model.assignParameterStorage(proto, pieces, False)
            if pieces:
                # First piece is output
                outpiece = pieces[0]
                self.outparam = ProtoParameter("",
                    outpiece.type if hasattr(outpiece, 'type') else None,
                    outpiece.addr if hasattr(outpiece, 'addr') else Address(),
                    outpiece.type.getSize() if hasattr(outpiece, 'type') and outpiece.type is not None else 0)
                j = 0
                for i in range(1, len(pieces)):
                    pc = pieces[i]
                    fl = pc.flags if hasattr(pc, 'flags') else 0
                    if (fl & ParameterPieces.hiddenretparm) != 0:
                        nm = "rethidden"
                    else:
                        nm = proto.innames[j] if j < len(proto.innames) else ""
                        j += 1
                    tp = pc.type if hasattr(pc, 'type') else None
                    addr = pc.addr if hasattr(pc, 'addr') else Address()
                    p = ProtoParameter(nm, tp, addr,
                        tp.getSize() if tp is not None else 0)
                    p.flags = fl
                    self.store.append(p)
        except ParamUnassignedError:
            self.flags |= FuncProto.error_inputparam
        self._updateThisPointer()

    def resolveExtraPop(self) -> None:
        """Resolve the extrapop value."""
        if self.model is not None:
            self.extrapop = self.model.getExtraPop()

    def paramShift(self, shift: int) -> None:
        """Add parameters to the front of the input parameter list.

        The new parameters have a data-type of unknown (size 4).
        If the inputs were originally locked, existing parameters are preserved.

        C++ ref: ``FuncProto::paramShift``
        """
        if self.model is None:
            raise LowlevelError("Cannot parameter shift without a model")

        proto = PrototypePieces()
        proto.model = self.model
        proto.firstVarArgSlot = -1
        typefactory = self.model.getArch().types if self.model.getArch() is not None else None

        if self.isOutputLocked() and self.outparam is not None:
            proto.outtype = self.outparam.getType()
        else:
            proto.outtype = typefactory.getTypeVoid() if typefactory else None

        extra = typefactory.getBase(4, TYPE_UNKNOWN) if typefactory else None
        for i in range(shift):
            proto.innames.append("")
            proto.intypes.append(extra)

        if self.isInputLocked():
            num = len(self.store)
            for i in range(num):
                param = self.store[i]
                proto.innames.append(param.getName())
                proto.intypes.append(param.getType())
        else:
            proto.firstVarArgSlot = shift

        pieces = []
        self.model.assignParameterStorage(proto, pieces, False)

        self.store.clear()
        self.outparam = None

        if pieces:
            outpc = pieces[0]
            tp = outpc.type if hasattr(outpc, 'type') else None
            addr = outpc.addr if hasattr(outpc, 'addr') else Address()
            self.outparam = ProtoParameter("", tp, addr,
                tp.getSize() if tp is not None else 0)
            j = 0
            for i in range(1, len(pieces)):
                pc = pieces[i]
                fl = pc.flags if hasattr(pc, 'flags') else 0
                if (fl & ParameterPieces.hiddenretparm) != 0:
                    nm = "rethidden"
                else:
                    nm = proto.innames[j] if j < len(proto.innames) else ""
                    j += 1
                tp = pc.type if hasattr(pc, 'type') else None
                addr = pc.addr if hasattr(pc, 'addr') else Address()
                p = ProtoParameter(nm, tp, addr,
                    tp.getSize() if tp is not None else 0)
                p.flags = fl
                self.store.append(p)
        self.setInputLock(True)
        self.setDotdotdot(proto.firstVarArgSlot >= 0)

    def setReturnBytesConsumed(self, val: int) -> bool:
        """Provide a hint about how many bytes of the return value are consumed.

        C++ ref: ``FuncProto::setReturnBytesConsumed``
        """
        if val == 0:
            return False
        rbc = getattr(self, 'returnBytesConsumed', 0)
        if rbc == 0 or val < rbc:
            self.returnBytesConsumed = val
            return True
        return False

    def encode(self, encoder) -> None:
        """Encode this prototype to stream.

        C++ ref: ``FuncProto::encode``
        """
        encoder.openElement(ELEM_PROTOTYPE)
        model = getattr(self, 'model', None)
        if model is not None:
            encoder.writeString(ATTRIB_MODEL, model.getName())
        extrapop = getattr(self, 'extrapop', ProtoModel.extrapop_unknown)
        if extrapop == ProtoModel.extrapop_unknown:
            encoder.writeString(ATTRIB_EXTRAPOP, "unknown")
        else:
            encoder.writeSignedInteger(ATTRIB_EXTRAPOP, extrapop)
        flags = getattr(self, 'flags', 0)
        if (flags & FuncProto.dotdotdot) != 0:
            encoder.writeBool(ATTRIB_DOTDOTDOT, True)
        if (flags & FuncProto.modellock) != 0:
            encoder.writeBool(ATTRIB_MODELLOCK, True)
        if (flags & FuncProto.voidinputlock) != 0:
            encoder.writeBool(ATTRIB_VOIDLOCK, True)
        if (flags & FuncProto.is_inline) != 0:
            encoder.writeBool(ATTRIB_INLINE, True)
        if (flags & FuncProto.no_return) != 0:
            encoder.writeBool(ATTRIB_NORETURN, True)
        if (flags & FuncProto.custom_storage) != 0:
            encoder.writeBool(ATTRIB_CUSTOM, True)
        if (flags & FuncProto.is_constructor) != 0:
            encoder.writeBool(ATTRIB_CONSTRUCTOR, True)
        if (flags & FuncProto.is_destructor) != 0:
            encoder.writeBool(ATTRIB_DESTRUCTOR, True)
        # Encode return symbol
        outparam = getattr(self, 'outparam', None)
        encoder.openElement(ELEM_RETURNSYM)
        if outparam is not None:
            if outparam.isTypeLocked():
                encoder.writeBool(ATTRIB_TYPELOCK, True)
            outparam.getAddress().encode(encoder, outparam.getSize())
            tp = outparam.getType()
            if tp is not None and hasattr(tp, 'encodeRef'):
                tp.encodeRef(encoder)
        encoder.closeElement(ELEM_RETURNSYM)
        # Encode effect list overrides
        self._encodeEffect(encoder)
        self._encodeLikelyTrash(encoder)
        # Encode inject
        if getattr(self, 'injectId', -1) >= 0:
            encoder.openElement(ELEM_INJECT)
            encoder.writeString(ATTRIB_CONTENT, str(self.injectId))
            encoder.closeElement(ELEM_INJECT)
        # Encode internal parameters
        store = getattr(self, 'store', [])
        if hasattr(self, '_protostore') and self._protostore is not None:
            self._protostore.encode(encoder)
        elif len(store) > 0:
            encoder.openElement(ELEM_INTERNALLIST)
            for p in store:
                encoder.openElement(ELEM_PARAM)
                nm = p.getName()
                if nm:
                    encoder.writeString(ATTRIB_NAME, nm)
                if p.isTypeLocked():
                    encoder.writeBool(ATTRIB_TYPELOCK, True)
                if p.isNameLocked():
                    encoder.writeBool(ATTRIB_NAMELOCK, True)
                if p.isThisPointer():
                    encoder.writeBool(ATTRIB_THISPTR, True)
                if p.isIndirectStorage():
                    encoder.writeBool(ATTRIB_INDIRECTSTORAGE, True)
                if p.isHiddenReturn():
                    encoder.writeBool(ATTRIB_HIDDENRETPARM, True)
                p.getAddress().encode(encoder, p.getSize())
                tp = p.getType()
                if tp is not None and hasattr(tp, 'encodeRef'):
                    tp.encodeRef(encoder)
                encoder.closeElement(ELEM_PARAM)
            encoder.closeElement(ELEM_INTERNALLIST)
        encoder.closeElement(ELEM_PROTOTYPE)

    def _encodeEffect(self, encoder) -> None:
        """Encode effect records that override the model.

        C++ ref: ``FuncProto::encodeEffect``
        """
        effectlist = getattr(self, 'effectlist', [])
        if not effectlist:
            return
        unaffected = []
        killedbycall = []
        retaddr = None
        for rec in effectlist:
            if self.model is not None:
                mtype = self.model.hasEffect(rec.getAddress(), rec.getSize())
                if mtype == rec.getType():
                    continue
            if rec.getType() == EffectRecord.unaffected:
                unaffected.append(rec)
            elif rec.getType() == EffectRecord.killedbycall:
                killedbycall.append(rec)
            elif rec.getType() == EffectRecord.return_address:
                retaddr = rec
        if unaffected:
            encoder.openElement(ELEM_UNAFFECTED)
            for rec in unaffected:
                rec.encode(encoder)
            encoder.closeElement(ELEM_UNAFFECTED)
        if killedbycall:
            encoder.openElement(ELEM_KILLEDBYCALL)
            for rec in killedbycall:
                rec.encode(encoder)
            encoder.closeElement(ELEM_KILLEDBYCALL)
        if retaddr is not None:
            encoder.openElement(ELEM_RETURNADDRESS)
            retaddr.encode(encoder)
            encoder.closeElement(ELEM_RETURNADDRESS)

    def _encodeLikelyTrash(self, encoder) -> None:
        """Encode likely-trash records that override the model.

        C++ ref: ``FuncProto::encodeLikelyTrash``
        """
        likelytrash = getattr(self, 'likelytrash', [])
        if not likelytrash:
            return
        encoder.openElement(ELEM_LIKELYTRASH)
        for vd in likelytrash:
            encoder.openElement(ELEM_ADDR)
            if hasattr(vd, 'space') and vd.space is not None:
                vd.space.encodeAttributes(encoder, vd.offset, vd.size)
            encoder.closeElement(ELEM_ADDR)
        encoder.closeElement(ELEM_LIKELYTRASH)

    def decode(self, decoder, glb=None) -> None:
        """Decode this prototype from a <prototype> element.

        C++ ref: ``FuncProto::decode``
        """
        mod = None
        seenextrapop = False
        readextrapop = 0
        self.flags = 0
        self.injectId = -1
        elemId = decoder.openElement(ELEM_PROTOTYPE)
        while True:
            attribId = decoder.getNextAttributeId()
            if attribId == 0:
                break
            if attribId == ATTRIB_MODEL:
                modelname = decoder.readString()
                if glb is not None:
                    if not modelname or modelname == "default":
                        mod = getattr(glb, 'defaultfp', None)
                    else:
                        mod = glb.getModel(modelname) if hasattr(glb, 'getModel') else None
            elif attribId == ATTRIB_EXTRAPOP:
                seenextrapop = True
                readextrapop = decoder.readSignedIntegerExpectString("unknown", ProtoModel.extrapop_unknown)
            elif attribId == ATTRIB_MODELLOCK:
                if decoder.readBool():
                    self.flags |= FuncProto.modellock
            elif attribId == ATTRIB_DOTDOTDOT:
                if decoder.readBool():
                    self.flags |= FuncProto.dotdotdot
            elif attribId == ATTRIB_VOIDLOCK:
                if decoder.readBool():
                    self.flags |= FuncProto.voidinputlock
            elif attribId == ATTRIB_INLINE:
                if decoder.readBool():
                    self.flags |= FuncProto.is_inline
            elif attribId == ATTRIB_NORETURN:
                if decoder.readBool():
                    self.flags |= FuncProto.no_return
            elif attribId == ATTRIB_CUSTOM:
                if decoder.readBool():
                    self.flags |= FuncProto.custom_storage
            elif attribId == ATTRIB_CONSTRUCTOR:
                if decoder.readBool():
                    self.flags |= FuncProto.is_constructor
            elif attribId == ATTRIB_DESTRUCTOR:
                if decoder.readBool():
                    self.flags |= FuncProto.is_destructor
        if mod is not None:
            self.setModel(mod)
        if seenextrapop:
            self.extrapop = readextrapop
        # Decode return symbol
        subId = decoder.peekElement()
        if subId != 0:
            outputlock = False
            if subId == ELEM_RETURNSYM:
                decoder.openElement()
                while True:
                    attribId = decoder.getNextAttributeId()
                    if attribId == 0:
                        break
                    if attribId == ATTRIB_TYPELOCK:
                        outputlock = decoder.readBool()
                outaddr = Address.decode(decoder)
                outtype = None
                if glb is not None and hasattr(glb, 'types'):
                    outtype = glb.types.decodeType(decoder)
                decoder.closeElement(subId)
                self.outparam = ProtoParameter("", outtype, outaddr,
                    outtype.getSize() if outtype is not None else 0)
                if outputlock:
                    self.outparam.setTypeLock(True)
        # Decode remaining sub-elements (effects, inject, internal params)
        while True:
            subId = decoder.peekElement()
            if subId == 0:
                break
            if subId == ELEM_UNAFFECTED:
                decoder.openElement()
                effectlist = getattr(self, 'effectlist', [])
                while decoder.peekElement() != 0:
                    rec = EffectRecord()
                    rec.decode(EffectRecord.unaffected, decoder)
                    effectlist.append(rec)
                self.effectlist = effectlist
                decoder.closeElement(subId)
            elif subId == ELEM_KILLEDBYCALL:
                decoder.openElement()
                effectlist = getattr(self, 'effectlist', [])
                while decoder.peekElement() != 0:
                    rec = EffectRecord()
                    rec.decode(EffectRecord.killedbycall, decoder)
                    effectlist.append(rec)
                self.effectlist = effectlist
                decoder.closeElement(subId)
            elif subId == ELEM_RETURNADDRESS:
                decoder.openElement()
                effectlist = getattr(self, 'effectlist', [])
                while decoder.peekElement() != 0:
                    rec = EffectRecord()
                    rec.decode(EffectRecord.return_address, decoder)
                    effectlist.append(rec)
                self.effectlist = effectlist
                decoder.closeElement(subId)
            elif subId == ELEM_LIKELYTRASH:
                decoder.openElement()
                likelytrash = getattr(self, 'likelytrash', [])
                while decoder.peekElement() != 0:
                    childId = decoder.openElement()
                    vd = VarnodeData()
                    vd.decode(decoder)
                    decoder.closeElement(childId)
                    likelytrash.append(vd)
                self.likelytrash = likelytrash
                decoder.closeElement(subId)
            elif subId == ELEM_INJECT:
                decoder.openElement()
                injectString = decoder.readString(ATTRIB_CONTENT)
                self.injectId = int(injectString) if injectString.isdigit() else -1
                self.flags |= FuncProto.is_inline
                decoder.closeElement(subId)
            elif subId == ELEM_INTERNALLIST:
                self._decodeInternalList(decoder, glb)
            else:
                decoder.openElement()
                decoder.closeElement(subId)
        decoder.closeElement(elemId)
        if (self.flags & FuncProto.voidinputlock) != 0 or self.isOutputLocked():
            self.flags |= FuncProto.modellock
        if not self.isModelLocked():
            if self.isInputLocked():
                self.flags |= FuncProto.modellock
        if self.extrapop == ProtoModel.extrapop_unknown:
            self.resolveExtraPop()
        self._updateThisPointer()

    def _decodeInternalList(self, decoder, glb=None) -> None:
        """Decode <internallist> element to restore internally backed parameters.

        C++ ref: ``ProtoStoreInternal::decode``
        """
        elemId = decoder.openElement(ELEM_INTERNALLIST)
        while True:
            subId = decoder.peekElement()
            if subId == 0:
                break
            decoder.openElement()
            nm = ""
            fl = 0
            while True:
                attribId = decoder.getNextAttributeId()
                if attribId == 0:
                    break
                if attribId == ATTRIB_NAME:
                    nm = decoder.readString()
                elif attribId == ATTRIB_TYPELOCK:
                    if decoder.readBool():
                        fl |= ParameterPieces.typelock
                elif attribId == ATTRIB_NAMELOCK:
                    if decoder.readBool():
                        fl |= ParameterPieces.namelock
                elif attribId == ATTRIB_THISPTR:
                    if decoder.readBool():
                        fl |= ParameterPieces.isthis
                elif attribId == ATTRIB_INDIRECTSTORAGE:
                    if decoder.readBool():
                        fl |= ParameterPieces.indirectstorage
                elif attribId == ATTRIB_HIDDENRETPARM:
                    if decoder.readBool():
                        fl |= ParameterPieces.hiddenretparm
            paddr = Address.decode(decoder)
            ptype = None
            if glb is not None and hasattr(glb, 'types'):
                ptype = glb.types.decodeType(decoder)
            p = ProtoParameter(nm, ptype, paddr,
                ptype.getSize() if ptype is not None else 0)
            p.flags = fl
            if subId == ELEM_RETPARAM:
                self.outparam = p
            else:
                self.store.append(p)
            decoder.closeElement(subId)
        decoder.closeElement(elemId)

    def printRaw(self, funcname: str = "") -> str:
        parts = []
        if self.outparam is not None and self.outparam.getType() is not None:
            parts.append(str(self.outparam.getType()))
        else:
            parts.append("void")
        parts.append(f" {funcname}(")
        for i, p in enumerate(self.store):
            if i > 0:
                parts.append(", ")
            if p.getType() is not None:
                parts.append(str(p.getType()))
            if hasattr(p, 'getName') and p.getName():
                parts.append(f" {p.getName()}")
        parts.append(")")
        return "".join(parts)

    def copyFlowEffects(self, op2) -> None:
        """Copy properties that affect data-flow."""
        if op2 is not None:
            if op2.isInline():
                self.setInline(True)
            if op2.isNoReturn():
                self.setNoReturn(True)
            self.injectId = op2.injectId

    def getExtraPop(self) -> int:
        return self.extrapop

    def setExtraPop(self, val: int) -> None:
        self.extrapop = val

    def setNoReturn(self, val: bool) -> None:
        if val:
            self.flags |= FuncProto.no_return
        else:
            self.flags &= ~FuncProto.no_return

    def setInline(self, val: bool) -> None:
        if val:
            self.flags |= FuncProto.is_inline
        else:
            self.flags &= ~FuncProto.is_inline

    def getOutputType(self):
        if self.outparam is not None:
            return self.outparam.getType()
        return None

    def getModelName(self):
        return self.model.getName() if self.model else ""

    def isModelUnknown(self):
        return (self.flags & FuncProto.unknown_model) != 0

    def printModelInDecl(self):
        return self.model is not None and (self.flags & FuncProto.modellock) != 0

    def getInjectId(self):
        return self.injectId

    def setInjectId(self, val):
        self.injectId = val

    def cancelInjectId(self):
        self.injectId = -1

    def getReturnBytesConsumed(self):
        if self.outparam is not None and self.outparam.getType() is not None:
            return self.outparam.getType().getSize()
        return 0

    def setParamshift(self, val):
        self.paramshift = val if hasattr(self, 'paramshift') else 0

    def isParamshiftApplied(self):
        return (self.flags & FuncProto.paramshift_applied) != 0

    def setParamshiftApplied(self):
        self.flags |= FuncProto.paramshift_applied

    def hasInputErrors(self):
        return (self.flags & FuncProto.error_inputparam) != 0

    def hasOutputErrors(self):
        return (self.flags & FuncProto.error_outputparam) != 0

    def setInputErrors(self, val):
        if val: self.flags |= FuncProto.error_inputparam
        else: self.flags &= ~FuncProto.error_inputparam

    def setOutputErrors(self, val):
        if val: self.flags |= FuncProto.error_outputparam
        else: self.flags &= ~FuncProto.error_outputparam

    def setModelLock(self, val):
        if val: self.flags |= FuncProto.modellock
        else: self.flags &= ~FuncProto.modellock

    def setConstructor(self, val):
        if val: self.flags |= FuncProto.is_constructor
        else: self.flags &= ~FuncProto.is_constructor

    def setDestructor(self, val):
        if val: self.flags |= FuncProto.is_destructor
        else: self.flags &= ~FuncProto.is_destructor

    def setThisPointer(self, val):
        if val: self.flags |= FuncProto.has_thisptr
        else: self.flags &= ~FuncProto.has_thisptr

    def getComparableFlags(self):
        return self.flags & (FuncProto.voidinputlock | FuncProto.modellock | FuncProto.is_inline | FuncProto.no_return | FuncProto.has_thisptr | FuncProto.is_constructor | FuncProto.is_destructor)

    def getModelExtraPop(self):
        return self.model.getExtraPop() if self.model else 0

    def clearInput(self):
        self.store.clear()

    def clearUnlockedInput(self):
        self.store = [p for p in self.store if p.isTypeLocked()]

    def clearUnlockedOutput(self):
        if self.outparam and not self.outparam.isTypeLocked():
            self.outparam = None

    def hasModel(self) -> bool:
        """Does this prototype have a model."""
        return self.model is not None

    def hasMatchingModel(self, op2) -> bool:
        """Does this use the given model."""
        return self.model is op2

    def setInternal(self, m, vt) -> None:
        """Set internal backing storage for this."""
        if self.model is None:
            self.setModel(m)
        if vt is not None:
            self.outparam = ProtoParameter("", vt, Address(), vt.getSize() if hasattr(vt, 'getSize') else 0)

    def setInputLock(self, val: bool) -> None:
        """Toggle the data-type lock on input parameters."""
        if val:
            self.flags |= FuncProto.voidinputlock
            for p in self.store:
                if hasattr(p, 'setTypeLock'):
                    p.setTypeLock(True)
        else:
            self.flags &= ~FuncProto.voidinputlock
            for p in self.store:
                if hasattr(p, 'setTypeLock'):
                    p.setTypeLock(False)

    def setOutputLock(self, val: bool) -> None:
        """Toggle the data-type lock on the return value."""
        if self.outparam is not None and hasattr(self.outparam, 'setTypeLock'):
            self.outparam.setTypeLock(val)

    def setParam(self, i: int, name: str, piece) -> None:
        """Set parameter storage directly."""
        while len(self.store) <= i:
            self.store.append(ProtoParameter())
        p = self.store[i]
        if hasattr(p, '_name'):
            p._name = name
        if piece is not None and hasattr(piece, 'type'):
            p._type = piece.type

    def removeParam(self, i: int) -> None:
        """Remove the i-th input parameter."""
        if 0 <= i < len(self.store):
            del self.store[i]

    def effectBegin(self):
        """Get iterator to front of EffectRecord list."""
        effectlist = getattr(self, 'effectlist', [])
        if effectlist:
            return iter(effectlist)
        if self.model is not None and hasattr(self.model, 'effectlist'):
            return iter(self.model.effectlist)
        return iter([])

    def effectEnd(self):
        """Get iterator end sentinel (use effectBegin as iterator)."""
        effectlist = getattr(self, 'effectlist', [])
        if effectlist:
            return len(effectlist)
        if self.model is not None and hasattr(self.model, 'effectlist'):
            return len(self.model.effectlist)
        return 0

    def trashBegin(self):
        """Get iterator to front of likelytrash list."""
        if self.model is not None and hasattr(self.model, 'likelytrash'):
            return iter(self.model.likelytrash)
        return iter([])

    def trashEnd(self):
        """Get iterator end sentinel (use trashBegin as iterator)."""
        return None

    def internalBegin(self):
        """Get iterator to front of internalstorage list."""
        if self.model is not None:
            if hasattr(self.model, 'internalStorage'):
                return iter(self.model.internalStorage)
            if hasattr(self.model, 'internalstorage'):
                return iter(self.model.internalstorage)
        return iter([])

    def internalEnd(self):
        """Get iterator end sentinel (use internalBegin as iterator)."""
        return None

    def getInjectUponEntry(self) -> int:
        """Get any upon-entry injection id (or -1)."""
        if self.model is not None and hasattr(self.model, 'getInjectUponEntry'):
            return self.model.getInjectUponEntry()
        return -1

    def getInjectUponReturn(self) -> int:
        """Get any upon-return injection id (or -1)."""
        if self.model is not None and hasattr(self.model, 'getInjectUponReturn'):
            return self.model.getInjectUponReturn()
        return -1

    def copy(self, other):
        self.model = other.model
        self.store = list(other.store)
        self.outparam = other.outparam
        self.flags = other.flags
        self.extrapop = other.extrapop
        self.injectId = other.injectId

    def setCustomStorage(self, val: bool) -> None:
        if val:
            self.flags |= FuncProto.custom_storage
        else:
            self.flags &= ~FuncProto.custom_storage

    def setVoidInputLock(self, val: bool) -> None:
        if val:
            self.flags |= FuncProto.voidinputlock
        else:
            self.flags &= ~FuncProto.voidinputlock

    def getFlags(self) -> int:
        return self.flags

    def __repr__(self) -> str:
        model_name = self.model.getName() if self.model else "?"
        return f"FuncProto(model={model_name}, params={len(self.store)})"


# =========================================================================
# FuncCallSpecs
# =========================================================================

class FuncCallSpecs:
    """Specifications for a particular function call site.

    Holds the prototype information and parameter/return assignments
    for a specific CALL operation within a function body.
    """

    def __init__(self, op=None) -> None:
        self.op = op  # PcodeOp (the CALL op)
        self.fd = None  # Funcdata of the called function (if known)
        self.entryaddress: Address = Address()
        self.name: str = ""
        self.proto: FuncProto = FuncProto()
        self.effective_extrapop: int = ProtoModel.extrapop_unknown
        self.stackoffset: int = FuncCallSpecs.offset_unknown
        self.paramshift: int = 0
        self.matchCallCount: int = 0
        self.isinputactive: bool = False
        self.isoutputactive: bool = False
        if op is not None and op.code() == OpCode.CPUI_CALL:
            target_vn = op.getIn(0)
            if target_vn is not None:
                self.entryaddress = target_vn.getAddr()
                target_space = self.entryaddress.getSpace()
                if target_space is not None and target_space.getType() == IPTR_FSPEC:
                    otherfc = FuncCallSpecs.getFspecFromConst(self.entryaddress)
                    if otherfc is not None:
                        self.entryaddress = otherfc.entryaddress

    def getOp(self):
        return self.op

    def getEntryAddress(self) -> Address:
        return self.entryaddress

    def setAddress(self, addr: Address) -> None:
        self.entryaddress = addr

    def getName(self) -> str:
        return self.name

    def setName(self, nm: str) -> None:
        self.name = nm

    def getFuncdata(self):
        return self.fd

    def setFuncdata(self, f) -> None:
        self.fd = f

    def getProto(self) -> FuncProto:
        return self.proto

    def numParams(self) -> int:
        return self.proto.numParams()

    def getParam(self, i: int) -> ProtoParameter:
        return self.proto.getParam(i)

    def getEffectiveExtraPop(self) -> int:
        return self.effective_extrapop

    def isInputActive(self) -> bool:
        return self.isinputactive

    def isOutputActive(self) -> bool:
        return self.isoutputactive

    def hasThisPointer(self):
        return self.proto.hasThisPointer()

    def getSymbol(self):
        return getattr(self, '_symbol', None)

    def setSymbol(self, sym):
        self._symbol = sym

    def getStackOffset(self):
        return self.stackoffset

    def setStackOffset(self, val):
        self.stackoffset = val

    def getParamshift(self):
        return self.paramshift

    def setParamshift(self, val):
        self.paramshift = val

    def getMatchCallCount(self):
        return self.matchCallCount

    def setMatchCallCount(self, val):
        self.matchCallCount = val

    def setInputActive(self, val):
        self.isinputactive = val

    def setOutputActive(self, val):
        self.isoutputactive = val

    def isInline(self):
        return self.proto.isInline()

    def isNoReturn(self):
        return self.proto.isNoReturn()

    def getExtraPop(self):
        return self.proto.getExtraPop()

    def getModelExtraPop(self):
        return self.proto.getModelExtraPop() if self.proto is not None else 0

    def setEffectiveExtraPop(self, val):
        self.effective_extrapop = val

    def hasModel(self):
        return self.proto.getModel() is not None

    def getModelName(self):
        return self.proto.getModelName()

    offset_unknown = 0x80000000

    def copyFlowEffects(self, proto) -> None:
        """Copy flow effects (inline, noreturn) from given prototype."""
        if proto is not None:
            if hasattr(proto, 'isInline') and proto.isInline():
                self.proto.setInline(True)
            if hasattr(proto, 'isNoReturn') and proto.isNoReturn():
                self.proto.setNoReturn(True)
            if hasattr(proto, 'getInjectId'):
                self.proto.setInjectId(proto.getInjectId())

    def hasEffect(self, addr, size: int):
        """Determine the effect of the call on the given memory range."""
        if self.proto.model is not None:
            return self.proto.model.hasEffect(addr, size)
        return 'unknown'

    def hasEffectTranslate(self, addr, size: int):
        """Determine effect, translating for stack-based addresses."""
        return self.hasEffect(addr, size)

    def getSpacebase(self):
        """Get the stack address space associated with this call.

        C++ ref: ``FuncProto::getSpacebase`` — delegates to model->getSpacebase()
        """
        return self.proto.getSpacebase() if self.proto is not None else None

    def getSpacebaseOffset(self) -> int:
        """Get the offset for stack-based parameters."""
        return self.stackoffset

    def getActiveInput(self):
        """Get the active input ParamActive, or None."""
        return getattr(self, '_activeInput', None)

    def getActiveOutput(self):
        """Get the active output ParamActive, or None."""
        return getattr(self, '_activeOutput', None)

    def isStackOutputLock(self) -> bool:
        return False

    def characterizeAsOutput(self, addr, size: int) -> int:
        """Characterize whether the given range overlaps output storage."""
        if self.proto.model is not None and hasattr(self.proto.model, 'characterizeAsOutput'):
            return self.proto.model.characterizeAsOutput(addr, size)
        return ParamEntry.no_containment if hasattr(ParamEntry, 'no_containment') else 0

    def characterizeAsInputParam(self, addr, size: int) -> int:
        """Characterize whether the given range overlaps input parameter storage."""
        if self.proto.model is not None and hasattr(self.proto.model, 'characterizeAsInputParam'):
            return self.proto.model.characterizeAsInputParam(addr, size)
        return 0

    def getBiggestContainedInputParam(self, addr, size: int, res) -> bool:
        """Pass-back the biggest input parameter contained within the given range.

        C++ ref: ``FuncCallSpecs::getBiggestContainedInputParam``
        """
        if self.proto.isInputLocked():
            return self.proto.getBiggestContainedInputParam(addr, size, res)
        if self.proto.model is not None:
            return self.proto.model.getBiggestContainedInputParam(addr, size, res)
        return False

    def getBiggestContainedOutput(self, addr, size: int, res) -> bool:
        """Pass-back the biggest possible output contained within the given range.

        C++ ref: ``FuncCallSpecs::getBiggestContainedOutput``
        """
        if self.proto.isOutputLocked():
            return self.proto.getBiggestContainedOutput(addr, size, res)
        if self.proto.model is not None:
            return self.proto.model.getBiggestContainedOutput(addr, size, res)
        return False

    def getOutput(self):
        """Get the output parameter."""
        return self.proto.outparam

    def getInjectId(self) -> int:
        return self.proto.getInjectId()

    def setNoReturn(self, val: bool) -> None:
        self.proto.setNoReturn(val)

    def setBadJumpTable(self, val: bool) -> None:
        self._badJumpTable = val

    def setInternal(self, model, rettype) -> None:
        """Set internal calling convention."""
        self.proto.setInternal(model, rettype)

    def setInputLock(self, val: bool) -> None:
        if val:
            self.proto.flags |= FuncProto.voidinputlock

    def setOutputLock(self, val: bool) -> None:
        """Toggle the data-type lock on the return value."""
        if self.proto.outparam is not None and hasattr(self.proto.outparam, 'setTypeLock'):
            self.proto.outparam.setTypeLock(val)

    def abortSpacebaseRelative(self, data) -> None:
        """Remove the spacebase placeholder input from this call.

        Does NOT reset stackoffset — it was already set by resolveSpacebaseRelative.

        C++ ref: ``FuncCallSpecs::abortSpacebaseRelative`` in fspec.cc:4910-4921
        """
        if hasattr(self, '_stackPlaceholderSlot') and self._stackPlaceholderSlot >= 0:
            if self.op is None or not hasattr(self.op, 'numInput') or self._stackPlaceholderSlot >= self.op.numInput():
                self.clearStackPlaceholderSlot()
                return
            vn = self.op.getIn(self._stackPlaceholderSlot)
            if hasattr(data, 'opRemoveInput'):
                data.opRemoveInput(self.op, self._stackPlaceholderSlot)
            self.clearStackPlaceholderSlot()
            # Remove the op producing the placeholder as well
            from ghidra.core.space import IPTR_INTERNAL
            if (vn is not None and vn.hasNoDescend()
                    and vn.getSpace().getType() == IPTR_INTERNAL
                    and vn.isWritten()):
                if hasattr(data, 'opDestroy'):
                    data.opDestroy(vn.getDef())

    def isAutoKilledByCall(self) -> bool:
        if self.proto.model is not None and hasattr(self.proto.model, 'isAutoKilledByCall'):
            return self.proto.model.isAutoKilledByCall()
        return False

    def initActiveInput(self) -> None:
        """Turn on analysis recovering input parameters.

        C++ ref: ``FuncCallSpecs::initActiveInput`` in fspec.cc
        """
        self.isinputactive = True
        if not hasattr(self, '_activeInput') or self._activeInput is None:
            from ghidra.fspec.paramactive import ParamActive
            self._activeInput = ParamActive(True)
        maxdelay = self.proto.getMaxInputDelay() if self.proto is not None else 0
        if maxdelay > 0:
            maxdelay = 3
        self._activeInput.setMaxPass(maxdelay)

    def clearActiveInput(self) -> None:
        """Turn off analysis recovering input parameters."""
        self.isinputactive = False

    def initActiveOutput(self) -> None:
        """Turn on analysis recovering the return value."""
        self.isoutputactive = True
        if not hasattr(self, '_activeOutput') or self._activeOutput is None:
            from ghidra.fspec.paramactive import ParamActive
            self._activeOutput = ParamActive(False)

    def clearActiveOutput(self) -> None:
        """Turn off analysis recovering the return value."""
        self.isoutputactive = False

    def isBadJumpTable(self) -> bool:
        return getattr(self, '_badJumpTable', False)

    def setStackOutputLock(self, val: bool) -> None:
        self._isstackoutputlock = val

    def getStackPlaceholderSlot(self) -> int:
        return getattr(self, '_stackPlaceholderSlot', -1)

    def setStackPlaceholderSlot(self, slot: int) -> None:
        self._stackPlaceholderSlot = slot
        if self.isinputactive and hasattr(self, '_activeInput') and self._activeInput is not None:
            self._activeInput.setPlaceholderSlot()

    def clearStackPlaceholderSlot(self) -> None:
        self._stackPlaceholderSlot = -1
        if self.isinputactive and hasattr(self, '_activeInput') and self._activeInput is not None:
            self._activeInput.freePlaceholderSlot()

    def clone(self, newop=None):
        """Clone this FuncCallSpecs given the mirrored p-code CALL."""
        fc = FuncCallSpecs(newop if newop is not None else self.op)
        fc.name = self.name
        fc.entryaddress = self.entryaddress
        fc.fd = self.fd
        fc.proto.copy(self.proto)
        fc.effective_extrapop = self.effective_extrapop
        fc.stackoffset = self.stackoffset
        fc.paramshift = self.paramshift
        fc.matchCallCount = self.matchCallCount
        return fc

    def deindirect(self, data, newfd) -> None:
        """Convert an indirect call to a direct call."""
        if newfd is not None:
            self.fd = newfd
            if hasattr(newfd, 'getName'):
                self.name = newfd.getName()
            if hasattr(newfd, 'getAddress'):
                self.entryaddress = newfd.getAddress()

    def forceSet(self, data, fp) -> None:
        """Force the prototype to match a given FuncProto."""
        self.proto.copy(fp)

    def insertPcode(self, data) -> None:
        """Insert p-code for this call (e.g. inject callfixup).

        If the prototype has an injection id, inject the pcode.
        C++ ref: ``FuncCallSpecs::insertPcode``
        """
        injectId = self.proto.getInjectId()
        if injectId < 0:
            return
        arch = data.getArch() if hasattr(data, 'getArch') else None
        if arch is None:
            return
        injectlib = getattr(arch, 'pcodeinjectlib', None)
        if injectlib is None:
            return
        if hasattr(injectlib, 'getPayload'):
            payload = injectlib.getPayload(injectId)
            if payload is not None and hasattr(payload, 'inject'):
                payload.inject(data, self.op)

    def createPlaceholder(self, data, spacebase) -> None:
        """Create a stack-pointer placeholder input for this call.

        Uses opStackLoad to create INT_ADD(spacebase_reg, 0) + LOAD,
        matching C++ FuncCallSpecs::createPlaceholder which calls
        data.opStackLoad(spacebase, 0, 1, op, NULL, false).

        C++ ref: ``FuncCallSpecs::createPlaceholder``
        """
        if spacebase is None:
            return
        if hasattr(data, 'opStackLoad') and hasattr(data, 'opInsertInput'):
            slot = self.op.numInput() if hasattr(self.op, 'numInput') else 1
            loadval = data.opStackLoad(spacebase, 0, 1, self.op, None, False)
            data.opInsertInput(self.op, loadval, slot)
            self.setStackPlaceholderSlot(slot)
            if hasattr(loadval, 'setSpacebasePlaceholder'):
                loadval.setSpacebasePlaceholder()

    def resolveSpacebaseRelative(self, data, phvn) -> None:
        """Resolve the spacebase-relative placeholder.

        After RuleLoadVarnode converts LOAD→COPY, phvn is the COPY output.
        We trace phvn->getDef()->getIn(0) to get the direct stack varnode,
        then set stackoffset from its offset.

        C++ ref: ``FuncCallSpecs::resolveSpacebaseRelative`` in fspec.cc
        """
        if phvn is None or not phvn.isWritten():
            return
        defop = phvn.getDef()
        if defop is None or defop.numInput() < 1:
            return
        refvn = defop.getIn(0)
        from ghidra.core.space import IPTR_SPACEBASE
        spacebase = refvn.getSpace()
        if spacebase.getType() != IPTR_SPACEBASE:
            if hasattr(data, 'warningHeader'):
                data.warningHeader("This function may have set the stack pointer")
        self.stackoffset = refvn.getOffset()

        # If the placeholder is still at its designated slot, abort (remove it)
        if hasattr(self, '_stackPlaceholderSlot') and self._stackPlaceholderSlot >= 0:
            if self.op is None or not hasattr(self.op, 'numInput') or self._stackPlaceholderSlot >= self.op.numInput():
                self.clearStackPlaceholderSlot()
            elif self.op.getIn(self._stackPlaceholderSlot) == phvn:
                self.abortSpacebaseRelative(data)
                return

        if self.isInputLocked():
            slot = self.op.getSlot(phvn) - 1
            if slot >= self.numParams():
                raise LowlevelError("Stack placeholder does not line up with locked parameter")
            param = self.getParam(slot)
            addr = param.getAddress()
            if addr.getSpace() != spacebase:
                if spacebase.getType() == IPTR_SPACEBASE:
                    raise LowlevelError("Stack placeholder does not match locked space")
            self.stackoffset -= addr.getOffset()
            if hasattr(spacebase, 'wrapOffset'):
                self.stackoffset = spacebase.wrapOffset(self.stackoffset)
            return
        raise LowlevelError("Unresolved stack placeholder")

    def finalInputCheck(self) -> None:
        """Perform final check on trials affected by conditional execution.

        Re-checks trials that might be affected by conditional execution,
        which may then be converted to 'not used'.

        C++ ref: ``FuncCallSpecs::finalInputCheck``
        """
        activeIn = self.getActiveInput()
        if activeIn is None:
            return
        from ghidra.analysis.ancestor import AncestorRealistic

        ancestorReal = AncestorRealistic()
        for i in range(activeIn.getNumTrials()):
            trial = activeIn.getTrial(i)
            if not trial.isActive():
                continue
            if not trial.hasCondExeEffect():
                continue
            slot = trial.getSlot()
            if self.op is None or slot < 0 or slot >= self.op.numInput():
                continue
            if not ancestorReal.execute(self.op, slot, trial, False):
                trial.markNoUse()

    def resolveModel(self, active) -> None:
        """Pick a specific model from merged set based on active trials.

        C++ ref: ``FuncCallSpecs::resolveModel`` (fspec.hh:1488)
        """
        if self.proto is not None:
            self.proto.resolveModel(active)

    def deriveInputMap(self, active) -> None:
        """Given input trials, derive the most likely inputs for this prototype.

        C++ ref: ``FuncCallSpecs::deriveInputMap`` (fspec.hh:1494-1495)
        """
        if self.proto is not None:
            self.proto.deriveInputMap(active)

    def deriveOutputMap(self, active) -> None:
        """Given output trials, derive the most likely return value.

        C++ ref: ``FuncCallSpecs::deriveOutputMap`` (fspec.hh:1501-1502)
        """
        if self.proto is not None:
            self.proto.deriveOutputMap(active)

    def checkInputTrialUse(self, data, aliascheck=None) -> None:
        """Mark if input trials are being actively used.

        Run through each input trial and try to make a determination
        if the trial is active or not, meaning basically that a write
        has occurred on the trial with no intervening reads between
        the write and the call.

        C++ ref: ``FuncCallSpecs::checkInputTrialUse``
        """
        if self.op is not None and hasattr(self.op, 'isDead') and self.op.isDead():
            raise LowlevelError("Function call in dead code")

        activeIn = self.getActiveInput()
        if activeIn is None:
            return
        from ghidra.analysis.ancestor import AncestorRealistic
        from ghidra.core.space import IPTR_SPACEBASE

        maxancestor = data.getArch().trim_recurse_max if hasattr(data, 'getArch') and data.getArch() is not None else 0
        callee_pop = False
        expop = 0
        if self.hasModel():
            callee_pop = (self.getModelExtraPop() == ProtoModel.extrapop_unknown)
            if callee_pop:
                expop = self.getExtraPop()
                if expop == ProtoModel.extrapop_unknown or expop <= 4:
                    callee_pop = False

        if aliascheck is None:
            try:
                from ghidra.database.varmap import AliasChecker
                aliascheck = AliasChecker()
                stack_space = data.getArch().getStackSpace() if hasattr(data, 'getArch') and data.getArch() is not None else None
                if stack_space is not None:
                    aliascheck.gather(data, stack_space, True)
            except Exception:
                aliascheck = None

        ancestorReal = AncestorRealistic()
        local_range = data.getFuncProto().getLocalRange() if hasattr(data, 'getFuncProto') else None

        for i in range(activeIn.getNumTrials()):
            trial = activeIn.getTrial(i)
            if trial.isChecked():
                continue
            slot = trial.getSlot()
            if self.op is None or not hasattr(self.op, 'getIn') or slot >= self.op.numInput():
                continue
            vn = self.op.getIn(slot)
            if vn is None:
                continue
            spc = vn.getSpace() if hasattr(vn, 'getSpace') else None
            if spc is not None and hasattr(spc, 'getType') and spc.getType() == IPTR_SPACEBASE:
                if aliascheck is not None and hasattr(aliascheck, 'hasLocalAlias') and aliascheck.hasLocalAlias(vn):
                    trial.markNoUse()
                elif local_range is not None and hasattr(local_range, 'inRange') and not local_range.inRange(vn.getAddr(), 1):
                    trial.markNoUse()
                elif callee_pop:
                    if int(trial.getAddress().getOffset() + (trial.getSize() - 1)) < expop:
                        trial.markActive()
                    else:
                        trial.markNoUse()
                elif ancestorReal.execute(self.op, slot, trial, False):
                    if data.ancestorOpUse(maxancestor, vn, self.op, trial, 0, 0):
                        trial.markActive()
                    else:
                        trial.markInactive()
                else:
                    trial.markNoUse()
            else:
                if ancestorReal.execute(self.op, slot, trial, True):
                    if data.ancestorOpUse(maxancestor, vn, self.op, trial, 0, 0):
                        trial.markActive()
                        if hasattr(trial, 'hasCondExeEffect') and trial.hasCondExeEffect():
                            activeIn.markNeedsFinalCheck()
                    else:
                        trial.markInactive()
                elif vn.isInput() if hasattr(vn, 'isInput') else False:
                    trial.markInactive()
                else:
                    trial.markNoUse()
            if trial.isDefinitelyNotUsed() and hasattr(data, 'opSetInput'):
                data.opSetInput(self.op, data.newConstant(vn.getSize(), 0), slot)

    def checkOutputTrialUse(self, data, trialvn: list = None) -> None:
        """Mark if output trials are being actively used.

        The location is either used or not. Whether the trial is present
        as a varnode determines whether we consider the trial active or not.

        C++ ref: ``FuncCallSpecs::checkOutputTrialUse``
        """
        if trialvn is None:
            trialvn = []
        self.collectOutputTrialVarnodes(trialvn)
        activeOut = self.getActiveOutput()
        if activeOut is None:
            return
        for i in range(len(trialvn)):
            curtrial = activeOut.getTrial(i)
            if trialvn[i] is not None:
                curtrial.markActive()
            else:
                curtrial.markInactive()

    def buildInputFromTrials(self, data) -> None:
        """Set the final input Varnodes to this CALL based on ParamActive analysis.

        Varnodes that don't look like parameters are removed.
        Parameters that are unreferenced are filled in.

        C++ ref: ``FuncCallSpecs::buildInputFromTrials``
        """
        activeIn = self.getActiveInput()
        if activeIn is None:
            return

        newparam = []
        if self.op is not None and hasattr(self.op, 'getIn'):
            newparam.append(self.op.getIn(0))  # Preserve the fspec parameter

        if self.proto.isDotdotdot() and self.proto.isInputLocked():
            activeIn.sortFixedPosition()

        for i in range(activeIn.getNumTrials()):
            paramtrial = activeIn.getTrial(i)
            if not paramtrial.isUsed():
                continue
            sz = paramtrial.getSize()
            addr = paramtrial.getAddress()
            spc = addr.getSpace()
            off = addr.getOffset()
            isspacebase = False
            if spc is not None and hasattr(spc, 'getType'):
                from ghidra.core.space import IPTR_SPACEBASE
                if spc.getType() == IPTR_SPACEBASE:
                    isspacebase = True
                    off = (self.stackoffset + off) & ((1 << (spc.getAddrSize() * 8)) - 1)
            if paramtrial.isUnref():
                if hasattr(data, 'newVarnode'):
                    vn = data.newVarnode(sz, Address(spc, off))
                else:
                    continue
            else:
                slot = paramtrial.getSlot()
                if self.op is not None and hasattr(self.op, 'getIn'):
                    vn = self.op.getIn(slot)
                else:
                    continue
                if vn.getSize() > sz:
                    newop = data.newOp(2, self.op.getAddr())
                    arch = data.getArch() if hasattr(data, 'getArch') else None
                    translate = getattr(arch, 'translate', None)
                    if translate is not None and hasattr(translate, 'isBigEndian') and translate.isBigEndian():
                        outaddr = vn.getAddr() + (vn.getSize() - sz)
                    else:
                        outaddr = vn.getAddr()
                    outvn = data.newVarnodeOut(sz, outaddr, newop)
                    data.opSetOpcode(newop, OpCode.CPUI_SUBPIECE)
                    data.opSetInput(newop, vn, 0)
                    data.opSetInput(newop, data.newConstant(1, 0), 1)
                    data.opInsertBefore(newop, self.op)
                    vn = outvn
            newparam.append(vn)
            if isspacebase and hasattr(data, 'getScopeLocal'):
                scope = data.getScopeLocal()
                if hasattr(scope, 'markNotMapped'):
                    scope.markNotMapped(spc, off, sz, True)

        if hasattr(data, 'opSetAllInput') and self.op is not None:
            data.opSetAllInput(self.op, newparam)
        activeIn.deleteUnusedTrials()

    def buildOutputFromTrials(self, data, trialvn: list = None) -> None:
        """Set the final output Varnode of this CALL based on ParamActive analysis.

        If it exists, the active output trial is moved to be the output
        Varnode of this CALL. INDIRECT ops holding active trials are removed.

        C++ ref: ``FuncCallSpecs::buildOutputFromTrials``
        """
        if trialvn is None:
            return
        activeOut = self.getActiveOutput()
        if activeOut is None:
            return

        finalvn = []
        for i in range(activeOut.getNumTrials()):
            curtrial = activeOut.getTrial(i)
            if not curtrial.isUsed():
                break
            slot = curtrial.getSlot()
            vn = trialvn[slot - 1] if 0 < slot <= len(trialvn) else None
            finalvn.append(vn)
        activeOut.deleteUnusedTrials()
        if activeOut.getNumTrials() == 0:
            return

        if activeOut.getNumTrials() == 1 and finalvn:
            finaloutvn = finalvn[0]
            if finaloutvn is not None and hasattr(data, 'opSetOutput') and self.op is not None:
                indop = finaloutvn.getDef() if hasattr(finaloutvn, 'getDef') else None
                data.opSetOutput(self.op, finaloutvn)
                if indop is not None and hasattr(data, 'opDestroy'):
                    data.opDestroy(indop)

    def collectOutputTrialVarnodes(self, trialvn: list) -> None:
        """Collect Varnodes for each output trial from preceding INDIRECTs.

        C++ ref: ``FuncCallSpecs::collectOutputTrialVarnodes``
        """
        activeOut = self.getActiveOutput()
        if activeOut is None:
            return
        while len(trialvn) < activeOut.getNumTrials():
            trialvn.append(None)
        if self.op is None:
            return
        indop = self.op.previousOp() if hasattr(self.op, 'previousOp') else None
        while indop is not None:
            if hasattr(indop, 'code') and indop.code() != OpCode.CPUI_INDIRECT:
                break
            if hasattr(indop, 'isIndirectCreation') and indop.isIndirectCreation():
                vn = indop.getOut() if hasattr(indop, 'getOut') else None
                if vn is not None:
                    index = activeOut.whichTrial(vn.getAddr(), vn.getSize())
                    if 0 <= index < len(trialvn):
                        trialvn[index] = vn
                        activeOut.getTrial(index).setAddress(vn.getAddr(), vn.getSize())
            indop = indop.previousOp() if hasattr(indop, 'previousOp') else None

    def getInputBytesConsumed(self, slot: int) -> int:
        """Get number of bytes consumed by sub-function for given input slot.

        C++ ref: ``FuncCallSpecs::getInputBytesConsumed``
        """
        ic = getattr(self, '_inputConsume', [])
        if slot >= len(ic):
            return 0
        return ic[slot]

    def setInputBytesConsumed(self, slot: int, val: int) -> bool:
        """Set number of bytes consumed by sub-function for given input slot.

        C++ ref: ``FuncCallSpecs::setInputBytesConsumed``
        """
        if not hasattr(self, '_inputConsume'):
            self._inputConsume = []
        while len(self._inputConsume) <= slot:
            self._inputConsume.append(0)
        oldVal = self._inputConsume[slot]
        if oldVal == 0 or val < oldVal:
            self._inputConsume[slot] = val
            return True
        return False

    def paramshiftModifyStart(self) -> None:
        """Prepend any extra parameters if a paramshift is required.

        C++ ref: ``FuncCallSpecs::paramshiftModifyStart``
        """
        if self.paramshift == 0:
            return
        self.proto.paramShift(self.paramshift)

    def paramshiftModifyStop(self, data) -> bool:
        """Throw out any paramshift parameters.

        C++ ref: ``FuncCallSpecs::paramshiftModifyStop``
        """
        if self.paramshift == 0:
            return False
        if self.getParamshiftApplied():
            return False
        self.setParamshiftApplied(True)
        if self.op is not None and hasattr(self.op, 'numInput'):
            if self.op.numInput() < self.paramshift + 1:
                raise LowlevelError("Paramshift mechanism is confused")
        for i in range(self.paramshift):
            if hasattr(data, 'opRemoveInput') and self.op is not None:
                data.opRemoveInput(self.op, 1)
            self.proto.removeParam(0)
        return True

    def checkInputJoin(self, slot1: int, ishislot: bool, vn1, vn2) -> bool:
        """Check if two input Varnodes can be joined into a single parameter.

        C++ ref: ``FuncCallSpecs::checkInputJoin``
        """
        if vn1 is None or vn2 is None:
            return False
        if ishislot:
            hiaddr = vn1.getAddr()
            hisize = vn1.getSize()
            loaddr = vn2.getAddr()
            losize = vn2.getSize()
        else:
            hiaddr = vn2.getAddr()
            hisize = vn2.getSize()
            loaddr = vn1.getAddr()
            losize = vn1.getSize()
        if self.proto.model is not None:
            return self.proto.model.checkInputJoin(hiaddr, hisize, loaddr, losize)
        return False

    def doInputJoin(self, slot1: int, ishislot: bool) -> None:
        """Join two input trials into a single parameter.

        C++ ref: ``FuncCallSpecs::doInputJoin``
        """
        activeIn = self.getActiveInput()
        if activeIn is None:
            return
        if self.op is None:
            return
        slot2 = slot1 + 1
        if hasattr(self.op, 'getIn'):
            vn1 = self.op.getIn(slot1)
            vn2 = self.op.getIn(slot2)
            if vn1 is not None and vn2 is not None:
                if ishislot:
                    hiaddr = vn1.getAddr()
                    hisz = vn1.getSize()
                    losz = vn2.getSize()
                else:
                    hiaddr = vn2.getAddr()
                    hisz = vn2.getSize()
                    losz = vn1.getSize()
                if hasattr(activeIn, 'joinTrial'):
                    activeIn.joinTrial(slot1, hiaddr, hisz + losz)

    def lateRestriction(self, restrictedProto, newinput: list, newoutput: list) -> bool:
        """Apply a late restriction from a resolved prototype.

        C++ ref: ``FuncCallSpecs::lateRestriction``
        """
        if restrictedProto is None:
            return False
        if self.proto.isInputLocked() and self.proto.isOutputLocked():
            return False
        self.proto.copy(restrictedProto)
        return True

    @staticmethod
    def compareByEntryAddress(a, b) -> bool:
        """Compare FuncCallSpecs by function entry address."""
        return a.entryaddress < b.entryaddress

    @staticmethod
    def countMatchingCalls(qlst: list) -> None:
        """Count how many calls target the same sub-function."""
        counts = {}
        for fc in qlst:
            key = fc.entryaddress
            counts[key] = counts.get(key, 0) + 1
        for fc in qlst:
            fc.matchCallCount = counts.get(fc.entryaddress, 1)

    @staticmethod
    def findPreexistingWhole(vn1, vn2):
        """Find a pre-existing whole Varnode from two pieces."""
        return None

    @staticmethod
    def getFspecFromConst(addr):
        """Retrieve the FuncCallSpecs from an encoded constant address."""
        if addr is None:
            return None
        return _FSPEC_REF_LOOKUP.get(addr.getOffset())

    @staticmethod
    def registerFspecRef(fc) -> None:
        """Register a live FuncCallSpecs object for FSPEC-space lookups."""
        if fc is None:
            return
        _FSPEC_REF_LOOKUP[id(fc)] = fc

    @staticmethod
    def unregisterFspecRef(fc) -> None:
        """Remove a FuncCallSpecs from FSPEC-space lookups."""
        if fc is None:
            return
        _FSPEC_REF_LOOKUP.pop(id(fc), None)

    def getProtoModel(self):
        return self.proto.getModel()

    def isInputLocked(self) -> bool:
        return self.proto.isInputLocked()

    def isOutputLocked(self) -> bool:
        return self.proto.isOutputLocked()

    def getInputErrors(self) -> list:
        return []

    def getOutputErrors(self) -> list:
        return []

    def setInputBestfit(self, val: bool) -> None:
        self._inputbestfit = val

    def setOutputBestfit(self, val: bool) -> None:
        self._outputbestfit = val

    def hasInputErrors(self) -> bool:
        return False

    def hasOutputErrors(self) -> bool:
        return False

    def getParamshiftApplied(self) -> bool:
        return self._paramshift_applied if hasattr(self, '_paramshift_applied') else False

    def setParamshiftApplied(self, val: bool) -> None:
        self._paramshift_applied = val

    def getIsTailCall(self) -> bool:
        return self._isTailCall if hasattr(self, '_isTailCall') else False

    def setIsTailCall(self, val: bool) -> None:
        self._isTailCall = val

    def isCalculatedBool(self) -> bool:
        return self._calculatedBool if hasattr(self, '_calculatedBool') else False

    def setCalculatedBool(self, val: bool) -> None:
        self._calculatedBool = val

    def getCallOp(self):
        return self._callop if hasattr(self, '_callop') else None

    def setCallOp(self, op) -> None:
        self._callop = op

    def getNumInputTrials(self) -> int:
        return self._numInputTrials if hasattr(self, '_numInputTrials') else 0

    def getNumOutputTrials(self) -> int:
        return self._numOutputTrials if hasattr(self, '_numOutputTrials') else 0

    def isOverride(self) -> bool:
        return self._isOverride if hasattr(self, '_isOverride') else False

    def setOverride(self, val: bool) -> None:
        self._isOverride = val

    def getSpacebaseRelative(self):
        """Get stack-pointer Varnode active at the point of this CALL.

        C++ ref: FuncCallSpecs::getSpacebaseRelative in fspec.cc
        """
        slot = self.getStackPlaceholderSlot()
        if slot < 0:
            return None
        tmpvn = self.op.getIn(slot)
        if not hasattr(tmpvn, 'isSpacebasePlaceholder') or not tmpvn.isSpacebasePlaceholder():
            return None
        if not tmpvn.isWritten():
            return None
        loadop = tmpvn.getDef()
        if loadop.code() != OpCode.CPUI_LOAD:
            return None
        return loadop.getIn(1)

    def buildParam(self, data, vn, param, stackref):
        """Build a Varnode representing a specific parameter.

        If vn is None, build a spacebase-relative varnode.
        If vn size doesn't match, create a SUBPIECE truncation.
        C++ ref: FuncCallSpecs::buildParam in fspec.cc
        """
        if vn is None:
            spc = param.getAddress().getSpace()
            off = param.getAddress().getOffset()
            sz = param.getSize()
            vn = data.opStackLoad(spc, off, sz, self.op, stackref, False)
            return vn
        if vn.getSize() == param.getSize():
            return vn
        newop = data.newOp(2, self.op.getAddr())
        data.opSetOpcode(newop, OpCode.CPUI_SUBPIECE)
        newout = data.newUniqueOut(param.getSize(), newop)
        if vn.isFree() and not vn.isConstant() and not vn.hasNoDescend():
            vn = data.newVarnode(vn.getSize(), vn.getAddr())
        data.opSetInput(newop, vn, 0)
        data.opSetInput(newop, data.newConstant(4, 0), 1)
        data.opInsertBefore(newop, self.op)
        return newout

    def transferLockedInputParam(self, param) -> int:
        """Get the index of the CALL input Varnode matching the given parameter.

        Returns slot# to reuse, -1 for stack parameter, 0 if can't be built.
        C++ ref: FuncCallSpecs::transferLockedInputParam in fspec.cc
        """
        activeIn = self.getActiveInput()
        if activeIn is None:
            return 0
        numtrials = activeIn.getNumTrials()
        startaddr = param.getAddress()
        sz = param.getSize()
        lastaddr = startaddr + (sz - 1)
        for i in range(numtrials):
            curtrial = activeIn.getTrial(i)
            if startaddr < curtrial.getAddress():
                continue
            trialend = curtrial.getAddress() + (curtrial.getSize() - 1)
            if trialend < lastaddr:
                continue
            if curtrial.isDefinitelyNotUsed():
                return 0
            return curtrial.getSlot()
        from ghidra.core.space import IPTR_SPACEBASE
        if startaddr.getSpace().getType() == IPTR_SPACEBASE:
            return -1
        return 0

    def transferLockedOutputParam(self, param, newoutput: list) -> None:
        """Return any outputs of this CALL that overlap the given return value parameter.

        C++ ref: FuncCallSpecs::transferLockedOutputParam in fspec.cc
        """
        vn = self.op.getOut() if self.op is not None else None
        if vn is not None:
            if param.getAddress().justifiedContain(param.getSize(), vn.getAddr(), vn.getSize(), False) >= 0:
                newoutput.append(vn)
            elif vn.getAddr().justifiedContain(vn.getSize(), param.getAddress(), param.getSize(), False) >= 0:
                newoutput.append(vn)
        indop = self.op.previousOp() if self.op is not None and hasattr(self.op, 'previousOp') else None
        while indop is not None and indop.code() == OpCode.CPUI_INDIRECT:
            if hasattr(indop, 'isIndirectCreation') and indop.isIndirectCreation():
                vn = indop.getOut()
                if param.getAddress().justifiedContain(param.getSize(), vn.getAddr(), vn.getSize(), False) >= 0:
                    newoutput.append(vn)
                elif vn.getAddr().justifiedContain(vn.getSize(), param.getAddress(), param.getSize(), False) >= 0:
                    newoutput.append(vn)
            indop = indop.previousOp() if hasattr(indop, 'previousOp') else None

    def transferLockedInput(self, newinput: list, source) -> bool:
        """List/create Varnodes for each input parameter matching a source prototype.

        C++ ref: FuncCallSpecs::transferLockedInput in fspec.cc
        """
        newinput.append(self.op.getIn(0))  # Always keep the call destination address
        numparams = source.numParams()
        stackref = None
        for i in range(numparams):
            reuse = self.transferLockedInputParam(source.getParam(i))
            if reuse == 0:
                return False
            if reuse > 0:
                newinput.append(self.op.getIn(reuse))
            else:
                if stackref is None:
                    stackref = self.getSpacebaseRelative()
                if stackref is None:
                    return False
                newinput.append(None)
        return True

    def transferLockedOutput(self, newoutput: list, source) -> bool:
        """Pass back the Varnode needed to match the output parameter of a source prototype.

        C++ ref: FuncCallSpecs::transferLockedOutput in fspec.cc
        """
        param = source.getOutput()
        from ghidra.types.datatype import TYPE_VOID
        if param.getType().getMetatype() == TYPE_VOID:
            return True
        self.transferLockedOutputParam(param, newoutput)
        return True

    def commitNewInputs(self, data, newinput: list) -> None:
        """Update input Varnodes to this CALL to reflect the formal input parameters.

        C++ ref: FuncCallSpecs::commitNewInputs in fspec.cc
        """
        if not self.isInputLocked():
            return
        stackref = self.getSpacebaseRelative()
        placeholder = None
        slot = self.getStackPlaceholderSlot()
        if slot >= 0:
            placeholder = self.op.getIn(slot)
        noplacehold = True

        # Clear activeinput and old placeholder
        self.clearStackPlaceholderSlot()
        activeIn = self.getActiveInput()
        numPasses = 0
        if activeIn is not None:
            numPasses = activeIn.getNumPasses() if hasattr(activeIn, 'getNumPasses') else 0
            activeIn.clear()

        from ghidra.core.space import IPTR_SPACEBASE
        numparams = self.numParams()
        for i in range(numparams):
            param = self.getParam(i)
            vn = self.buildParam(data, newinput[1 + i], param, stackref)
            newinput[1 + i] = vn
            if activeIn is not None:
                activeIn.registerTrial(param.getAddress(), param.getSize())
                activeIn.getTrial(i).markActive()
            if noplacehold and param.getAddress().getSpace().getType() == IPTR_SPACEBASE:
                if hasattr(vn, 'setSpacebasePlaceholder'):
                    vn.setSpacebasePlaceholder()
                noplacehold = False
                placeholder = None
        if placeholder is not None:
            newinput.append(placeholder)
            self.setStackPlaceholderSlot(len(newinput) - 1)
        data.opSetAllInput(self.op, newinput)
        if not self.proto.isDotdotdot():
            self.clearActiveInput()
        else:
            if activeIn is not None and numPasses > 0:
                if hasattr(activeIn, 'finishPass'):
                    activeIn.finishPass()

    def commitNewOutputs(self, data, newoutput: list) -> None:
        """Update output Varnode to this CALL to reflect the formal return value.

        C++ ref: FuncCallSpecs::commitNewOutputs in fspec.cc
        """
        if not self.isOutputLocked():
            return
        activeOut = self.getActiveOutput()
        if activeOut is not None:
            activeOut.clear()

        if newoutput:
            param = self.getOutput()
            if activeOut is not None:
                activeOut.registerTrial(param.getAddress(), param.getSize())
            from ghidra.types.datatype import TYPE_BOOL
            if (param.getSize() == 1 and param.getType().getMetatype() == TYPE_BOOL
                    and hasattr(data, 'isTypeRecoveryOn') and data.isTypeRecoveryOn()):
                if hasattr(data, 'opMarkCalculatedBool'):
                    data.opMarkCalculatedBool(self.op)

            # Find exact match
            exactMatch = None
            for i in range(len(newoutput)):
                if newoutput[i].getSize() == param.getSize():
                    exactMatch = newoutput[i]
                    break

            if exactMatch is not None:
                indOp = exactMatch.getDef() if exactMatch.isWritten() else None
                if indOp is not None and self.op is not indOp:
                    data.opSetOutput(self.op, exactMatch)
                    data.opUnlink(indOp)
                realOut = exactMatch
            else:
                data.opUnsetOutput(self.op)
                realOut = data.newVarnodeOut(param.getSize(), param.getAddress(), self.op)

            for i in range(len(newoutput)):
                oldOut = newoutput[i]
                if oldOut is exactMatch:
                    continue
                indOp = oldOut.getDef() if oldOut.isWritten() else None
                if indOp is self.op:
                    indOp = None
                if oldOut.getSize() < param.getSize():
                    # Truncation: create SUBPIECE
                    if indOp is not None:
                        data.opUninsert(indOp)
                        data.opSetOpcode(indOp, OpCode.CPUI_SUBPIECE)
                    else:
                        indOp = data.newOp(2, self.op.getAddr())
                        data.opSetOpcode(indOp, OpCode.CPUI_SUBPIECE)
                        data.opSetOutput(indOp, oldOut)
                    overlap = oldOut.overlap(realOut.getAddr(), realOut.getSize()) if hasattr(oldOut, 'overlap') else 0
                    data.opSetInput(indOp, realOut, 0)
                    data.opSetInput(indOp, data.newConstant(4, overlap), 1)
                    data.opInsertAfter(indOp, self.op)
                elif param.getSize() < oldOut.getSize():
                    # Extension: check for natural extension
                    overlap_val = oldOut.getAddr().justifiedContain(
                        oldOut.getSize(), param.getAddress(), param.getSize(), False) if hasattr(oldOut.getAddr(), 'justifiedContain') else 0
                    opc = self.proto.assumedOutputExtension(param.getAddress(), param.getSize()) if hasattr(self.proto, 'assumedOutputExtension') else OpCode.CPUI_COPY
                    if opc != OpCode.CPUI_COPY and overlap_val == 0:
                        from ghidra.types.datatype import TYPE_INT
                        if opc == OpCode.CPUI_PIECE:
                            if param.getType().getMetatype() == TYPE_INT:
                                opc = OpCode.CPUI_INT_SEXT
                            else:
                                opc = OpCode.CPUI_INT_ZEXT
                        if indOp is not None:
                            data.opUninsert(indOp)
                            if indOp.numInput() > 1:
                                data.opRemoveInput(indOp, 1)
                            data.opSetOpcode(indOp, opc)
                            data.opSetInput(indOp, realOut, 0)
                            data.opInsertAfter(indOp, self.op)
                        else:
                            extop = data.newOp(1, self.op.getAddr())
                            data.opSetOpcode(extop, opc)
                            data.opSetOutput(extop, oldOut)
                            data.opSetInput(extop, realOut, 0)
                            data.opInsertAfter(extop, self.op)
                    else:
                        # Fallback: unlink and create indirect+PIECE chain
                        if indOp is not None:
                            data.opUnlink(indOp)
                        # Simplified: just create a SUBPIECE for the overlap portion
                        subOp = data.newOp(2, self.op.getAddr())
                        data.opSetOpcode(subOp, OpCode.CPUI_SUBPIECE)
                        data.opSetOutput(subOp, oldOut)
                        data.opSetInput(subOp, realOut, 0)
                        data.opSetInput(subOp, data.newConstant(4, 0), 1)
                        data.opInsertAfter(subOp, self.op)

        self.clearActiveOutput()

    def __repr__(self) -> str:
        return f"FuncCallSpecs({self.name!r} @ {self.entryaddress})"
