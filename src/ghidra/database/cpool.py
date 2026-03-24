"""
Corresponds to: cpool.hh / cpool.cc

Definitions to support a constant pool for deferred compilation languages (e.g. Java byte-code).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Tuple

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

    def getTag(self) -> int:
        return self.tag

    def getToken(self) -> str:
        return self.token

    def getByteData(self) -> Optional[bytes]:
        return self.byteData

    def getByteDataLength(self) -> int:
        return len(self.byteData) if self.byteData else 0

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
            encoder.writeSignedInteger(ATTRIB_LENGTH, len(self.byteData))
            hex_str = ' '.join(f'{b:02x}' for b in self.byteData)
            encoder.writeString(ATTRIB_CONTENT, hex_str)
            encoder.closeElement(ELEM_DATA)
        else:
            encoder.openElement(ELEM_TOKEN)
            encoder.writeString(ATTRIB_CONTENT, self.token)
            encoder.closeElement(ELEM_TOKEN)
        if self.type is not None and hasattr(self.type, 'encodeRef'):
            self.type.encodeRef(encoder)
        encoder.closeElement(ELEM_CPOOLREC)

    def decode(self, decoder, typegrp=None) -> None:
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
            # <data> element with byte content
            try:
                length = decoder.readSignedInteger(ATTRIB_LENGTH)
                content_str = decoder.readString(ATTRIB_CONTENT)
                parts = content_str.split()
                self.byteData = bytes(int(p, 16) for p in parts[:length])
            except Exception:
                self.byteData = b""
        decoder.closeElement(subId)
        # Decode type reference if present
        if typegrp is not None:
            try:
                if self.flags != 0:
                    is_con = (self.flags & CPoolRecord.is_constructor) != 0
                    is_des = (self.flags & CPoolRecord.is_destructor) != 0
                    if hasattr(typegrp, 'decodeTypeWithCodeFlags'):
                        self.type = typegrp.decodeTypeWithCodeFlags(decoder, is_con, is_des)
                    else:
                        self.type = typegrp.decodeType(decoder)
                else:
                    self.type = typegrp.decodeType(decoder)
            except Exception:
                pass
        decoder.closeElement(elemId)


class ConstantPool(ABC):
    """An interface to the pool of constant objects for byte-code languages."""

    @abstractmethod
    def getRecord(self, refs: List[int]) -> Optional[CPoolRecord]: ...

    @abstractmethod
    def empty(self) -> bool: ...

    @abstractmethod
    def clear(self) -> None: ...

    def putRecord(self, refs: List[int], tag: int, tok: str, ct: Optional[Datatype]) -> None:
        rec = self._createRecord(refs)
        if rec is not None:
            rec.tag = tag
            rec.token = tok
            rec.type = ct

    def decodeRecord(self, refs: List[int], decoder, typegrp) -> Optional[CPoolRecord]:
        """Decode a CPoolRecord from the stream and store it.

        C++ ref: ``ConstantPool::decodeRecord``
        """
        rec = self._createRecord(refs)
        if rec is not None:
            rec.decode(decoder, typegrp)
        return rec

    def storeRecord(self, refs: List[int], rec: CPoolRecord) -> None:
        """Store a pre-decoded CPoolRecord directly into the pool."""
        # Base implementation is a no-op; subclasses override

    @abstractmethod
    def _createRecord(self, refs: List[int]) -> Optional[CPoolRecord]: ...


class ConstantPoolInternal(ConstantPool):
    """In-memory ConstantPool implementation."""

    def __init__(self) -> None:
        self._pool: Dict[Tuple[int, ...], CPoolRecord] = {}

    def _createRecord(self, refs: List[int]) -> Optional[CPoolRecord]:
        key = tuple(refs)
        if key in self._pool:
            return self._pool[key]
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
        from ghidra.core.marshal import ELEM_CONSTANTPOOL, ELEM_REF, ATTRIB_A, ATTRIB_B
        encoder.openElement(ELEM_CONSTANTPOOL)
        for key, rec in self._pool.items():
            # Encode reference key as <ref> element
            a = key[0] if len(key) > 0 else 0
            b = key[1] if len(key) > 1 else 0
            encoder.openElement(ELEM_REF)
            encoder.writeUnsignedInteger(ATTRIB_A, a)
            encoder.writeUnsignedInteger(ATTRIB_B, b)
            encoder.closeElement(ELEM_REF)
            rec.encode(encoder)
        encoder.closeElement(ELEM_CONSTANTPOOL)

    def decode(self, decoder, typegrp=None) -> None:
        """Decode the entire constant pool.

        C++ ref: ``ConstantPoolInternal::decode``
        """
        from ghidra.core.marshal import ELEM_CONSTANTPOOL, ELEM_REF, ATTRIB_A, ATTRIB_B
        elemId = decoder.openElement(ELEM_CONSTANTPOOL)
        while decoder.peekElement() != 0:
            refId = decoder.openElement(ELEM_REF)
            a = decoder.readUnsignedInteger(ATTRIB_A)
            b = decoder.readUnsignedInteger(ATTRIB_B)
            decoder.closeElement(refId)
            refs = [a, b]
            rec = self._createRecord(refs)
            if rec is not None:
                rec.decode(decoder, typegrp)
        decoder.closeElement(elemId)

    def size(self) -> int:
        return len(self._pool)
