"""
Corresponds to: cpool.hh / cpool.cc

Definitions to support a constant pool for deferred compilation languages (e.g. Java byte-code).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Tuple

from ghidra.core.error import LowlevelError
from ghidra.types.datatype import Datatype


class CPoolRecord:
    """A description of a byte-code object referenced by a constant."""

    # Tag types
    primitive = 0
    string_literal = 1
    class_reference = 2
    pointer_method = 3
    pointer_field = 4
    array_length = 5
    instance_of = 6
    check_cast = 7

    # Flags
    is_constructor = 0x1
    is_destructor = 0x2

    def __init__(self) -> None:
        self.tag: int = 0
        self.flags: int = 0
        self.token: str = ""
        self.value: int = 0
        self.type: Optional[Datatype] = None
        self.byteData: Optional[bytes] = None
        self.byteDataLen: int = 0

    def __del__(self) -> None:
        self.byteData = None
        self.byteDataLen = 0

    def getTag(self) -> int:
        return self.tag

    def getToken(self) -> str:
        return self.token

    def getByteData(self) -> Optional[bytes]:
        return self.byteData

    def getByteDataLength(self) -> int:
        return self.byteDataLen

    def getType(self) -> Optional[Datatype]:
        return self.type

    def getValue(self) -> int:
        return self.value

    def isConstructor(self) -> bool:
        return (self.flags & CPoolRecord.is_constructor) != 0

    def isDestructor(self) -> bool:
        return (self.flags & CPoolRecord.is_destructor) != 0

    def getFlags(self) -> int:
        return self.flags

    def encode(self, encoder) -> None:
        """Encode this CPoolRecord as a <cpoolrec> element.

        C++ ref: ``CPoolRecord::encode``
        """
        from ghidra.core.marshal import (
            ATTRIB_TAG, ATTRIB_CONSTRUCTOR, ATTRIB_DESTRUCTOR,
            ATTRIB_CONTENT, ATTRIB_LENGTH,
            ELEM_CPOOLREC, ELEM_TOKEN, ELEM_VALUE, ELEM_DATA,
        )
        tag_map = {
            CPoolRecord.pointer_method: "method",
            CPoolRecord.pointer_field: "field",
            CPoolRecord.instance_of: "instanceof",
            CPoolRecord.array_length: "arraylength",
            CPoolRecord.check_cast: "checkcast",
            CPoolRecord.string_literal: "string",
            CPoolRecord.class_reference: "classref",
        }
        encoder.openElement(ELEM_CPOOLREC)
        encoder.writeString(ATTRIB_TAG, tag_map.get(self.tag, "primitive"))
        if self.isConstructor():
            encoder.writeBool(ATTRIB_CONSTRUCTOR, True)
        if self.isDestructor():
            encoder.writeBool(ATTRIB_DESTRUCTOR, True)
        if self.tag == CPoolRecord.primitive:
            encoder.openElement(ELEM_VALUE)
            encoder.writeUnsignedInteger(ATTRIB_CONTENT, self.value)
            encoder.closeElement(ELEM_VALUE)
        if self.byteData is not None:
            encoder.openElement(ELEM_DATA)
            encoder.writeSignedInteger(ATTRIB_LENGTH, self.byteDataLen)
            wrap = 0
            pieces: list[str] = []
            for i in range(self.byteDataLen):
                pieces.append(f"{self.byteData[i]:02x} ")
                wrap += 1
                if wrap > 15:
                    pieces.append("\n")
                    wrap = 0
            hex_str = "".join(pieces)
            encoder.writeString(ATTRIB_CONTENT, hex_str)
            encoder.closeElement(ELEM_DATA)
        else:
            encoder.openElement(ELEM_TOKEN)
            encoder.writeString(ATTRIB_CONTENT, self.token)
            encoder.closeElement(ELEM_TOKEN)
        self.type.encodeRef(encoder)
        encoder.closeElement(ELEM_CPOOLREC)

    def decode(self, decoder, typegrp) -> None:
        """Decode a CPoolRecord from a <cpoolrec> element.

        C++ ref: ``CPoolRecord::decode``
        """
        from ghidra.core.marshal import (
            ATTRIB_TAG, ATTRIB_CONSTRUCTOR, ATTRIB_DESTRUCTOR,
            ATTRIB_CONTENT, ATTRIB_LENGTH,
            ELEM_CPOOLREC, ELEM_TOKEN, ELEM_VALUE,
        )
        self.tag = CPoolRecord.primitive
        self.value = 0
        self.flags = 0
        self.token = ""
        self.type = None
        self.byteData = None
        self.byteDataLen = 0
        elemId = decoder.openElement(ELEM_CPOOLREC)
        while True:
            attribId = decoder.getNextAttributeId()
            if attribId == 0:
                break
            if attribId == ATTRIB_TAG.id:
                tagstring = decoder.readString()
                tag_map = {
                    "method": CPoolRecord.pointer_method,
                    "field": CPoolRecord.pointer_field,
                    "instanceof": CPoolRecord.instance_of,
                    "arraylength": CPoolRecord.array_length,
                    "checkcast": CPoolRecord.check_cast,
                    "string": CPoolRecord.string_literal,
                    "classref": CPoolRecord.class_reference,
                }
                self.tag = tag_map.get(tagstring, CPoolRecord.primitive)
            elif attribId == ATTRIB_CONSTRUCTOR.id:
                if decoder.readBool():
                    self.flags |= CPoolRecord.is_constructor
            elif attribId == ATTRIB_DESTRUCTOR.id:
                if decoder.readBool():
                    self.flags |= CPoolRecord.is_destructor
        # If primitive, first child is <value>
        if self.tag == CPoolRecord.primitive:
            subId = decoder.openElement(ELEM_VALUE)
            self.value = decoder.readUnsignedInteger(ATTRIB_CONTENT)
            decoder.closeElement(subId)
        # Next child is <token> or <data>
        subId = decoder.openElement()
        if subId == ELEM_TOKEN.id:
            self.token = decoder.readString(ATTRIB_CONTENT)
        else:
            self.byteDataLen = decoder.readSignedInteger(ATTRIB_LENGTH)
            content_str = decoder.readString(ATTRIB_CONTENT)
            parts = content_str.split()
            data = bytearray()
            for i in range(self.byteDataLen):
                data.append(int(parts[i], 16))
            self.byteData = bytes(data)
        decoder.closeElement(subId)
        if self.tag == CPoolRecord.string_literal and self.byteData is None:
            raise LowlevelError("Bad constant pool record: missing <data>")
        if self.flags != 0:
            is_con = (self.flags & CPoolRecord.is_constructor) != 0
            is_des = (self.flags & CPoolRecord.is_destructor) != 0
            self.type = typegrp.decodeTypeWithCodeFlags(decoder, is_con, is_des)
        else:
            self.type = typegrp.decodeType(decoder)
        decoder.closeElement(elemId)


class ConstantPool(ABC):
    """An interface to the pool of constant objects for byte-code languages."""

    @abstractmethod
    def createRecord(self, refs: List[int]) -> Optional[CPoolRecord]: ...

    def __del__(self) -> None:
        return None

    @abstractmethod
    def getRecord(self, refs: List[int]) -> Optional[CPoolRecord]: ...

    @abstractmethod
    def empty(self) -> bool: ...

    @abstractmethod
    def clear(self) -> None: ...

    @abstractmethod
    def encode(self, encoder) -> None: ...

    @abstractmethod
    def decode(self, decoder, typegrp) -> None: ...

    def putRecord(self, refs: List[int], tag: int, tok: str, ct: Optional[Datatype]) -> None:
        rec = self.createRecord(refs)
        rec.tag = tag
        rec.token = tok
        rec.type = ct

    def decodeRecord(self, refs: List[int], decoder, typegrp) -> Optional[CPoolRecord]:
        """Decode a CPoolRecord from the stream and store it.

        C++ ref: ``ConstantPool::decodeRecord``
        """
        rec = self.createRecord(refs)
        rec.decode(decoder, typegrp)
        return rec

    def storeRecord(self, refs: List[int], rec: CPoolRecord) -> None:
        """Store a pre-decoded CPoolRecord directly into the pool."""
        # Base implementation is a no-op; subclasses override


class ConstantPoolInternal(ConstantPool):
    """In-memory ConstantPool implementation."""

    class CheapSorter:
        def __init__(self, refs=None) -> None:
            if isinstance(refs, ConstantPoolInternal.CheapSorter):
                self.a = refs.a
                self.b = refs.b
            elif refs is None:
                self.a = 0
                self.b = 0
            else:
                self.a = refs[0]
                self.b = refs[1] if len(refs) > 1 else 0

        def __lt__(self, op2: ConstantPoolInternal.CheapSorter) -> bool:
            if self.a != op2.a:
                return self.a < op2.a
            return self.b < op2.b

        def apply(self, refs: List[int]) -> None:
            refs.append(self.a)
            refs.append(self.b)

        def encode(self, encoder) -> None:
            from ghidra.core.marshal import ELEM_REF, ATTRIB_A, ATTRIB_B

            encoder.openElement(ELEM_REF)
            encoder.writeUnsignedInteger(ATTRIB_A, self.a)
            encoder.writeUnsignedInteger(ATTRIB_B, self.b)
            encoder.closeElement(ELEM_REF)

        def decode(self, decoder) -> None:
            from ghidra.core.marshal import ELEM_REF, ATTRIB_A, ATTRIB_B

            elemId = decoder.openElement(ELEM_REF)
            self.a = decoder.readUnsignedInteger(ATTRIB_A)
            self.b = decoder.readUnsignedInteger(ATTRIB_B)
            decoder.closeElement(elemId)

    def __init__(self) -> None:
        self._pool: Dict[Tuple[int, ...], CPoolRecord] = {}

    def createRecord(self, refs: List[int]) -> Optional[CPoolRecord]:
        sorter = ConstantPoolInternal.CheapSorter(refs)
        key = (sorter.a, sorter.b)
        if key in self._pool:
            raise LowlevelError("Creating duplicate entry in constant pool: " + self._pool[key].getToken())
        rec = CPoolRecord()
        self._pool[key] = rec
        return rec

    def getRecord(self, refs: List[int]) -> Optional[CPoolRecord]:
        return self._pool.get(tuple(refs))

    def empty(self) -> bool:
        return len(self._pool) == 0

    def clear(self) -> None:
        self._pool.clear()

    def storeRecord(self, refs: List[int], rec: CPoolRecord) -> None:
        """Store a pre-decoded CPoolRecord directly into the pool."""
        self._pool[tuple(refs)] = rec

    def encode(self, encoder) -> None:
        """Encode the entire constant pool.

        C++ ref: ``ConstantPoolInternal::encode``
        """
        from ghidra.core.marshal import ELEM_CONSTANTPOOL
        encoder.openElement(ELEM_CONSTANTPOOL)
        for key in sorted(self._pool):
            rec = self._pool[key]
            ConstantPoolInternal.CheapSorter(key).encode(encoder)
            rec.encode(encoder)
        encoder.closeElement(ELEM_CONSTANTPOOL)

    def decode(self, decoder, typegrp) -> None:
        """Decode the entire constant pool.

        C++ ref: ``ConstantPoolInternal::decode``
        """
        from ghidra.core.marshal import ELEM_CONSTANTPOOL
        elemId = decoder.openElement(ELEM_CONSTANTPOOL)
        while decoder.peekElement() != 0:
            sorter = ConstantPoolInternal.CheapSorter()
            sorter.decode(decoder)
            refs: List[int] = []
            sorter.apply(refs)
            rec = self.createRecord(refs)
            rec.decode(decoder, typegrp)
        decoder.closeElement(elemId)

    def size(self) -> int:
        return len(self._pool)
