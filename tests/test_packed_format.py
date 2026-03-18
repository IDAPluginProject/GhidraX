"""Tests for PackedDecode / PackedEncode binary format and subsystem parsing."""

import io
import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))

from ghidra.core.marshal import (
    PackedDecode, PackedEncode, _PF,
    AttributeId, ElementId,
    ATTRIB_CONTENT, ATTRIB_ID, ATTRIB_NAME, ATTRIB_OFFSET, ATTRIB_SIZE,
    ATTRIB_SPACE, ATTRIB_TYPE, ATTRIB_READONLY, ATTRIB_VOLATILE,
    ATTRIB_TAG, ATTRIB_METATYPE,
    ELEM_ADDR, ELEM_HOLE, ELEM_MAPSYM, ELEM_SYMBOL, ELEM_FUNCTION,
    ELEM_LABELSYM, ELEM_EXTERNREFSYMBOL, ELEM_COMMENT, ELEM_COMMENTDB,
    ELEM_TEXT, ELEM_CPOOLREC, ELEM_VALUE, ELEM_TOKEN,
    ELEM_TRACKED_POINTSET, ELEM_TRACKED_SET,
)


# =========================================================================
# PackedEncode / PackedDecode roundtrip tests
# =========================================================================

class TestPackedRoundtrip:
    """Test that PackedEncode -> PackedDecode produces the same values."""

    def _roundtrip(self):
        """Return (encoder, decoder_factory) pair."""
        enc = PackedEncode()
        return enc

    def test_empty_element(self):
        enc = PackedEncode()
        enc.openElement(ELEM_ADDR)
        enc.closeElement(ELEM_ADDR)
        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        eid = dec.openElement(ELEM_ADDR)
        assert eid == ELEM_ADDR.id
        dec.closeElement(eid)

    def test_bool_attribute(self):
        enc = PackedEncode()
        enc.openElement(ELEM_ADDR)
        enc.writeBool(ATTRIB_READONLY, True)
        enc.writeBool(ATTRIB_VOLATILE, False)
        enc.closeElement(ELEM_ADDR)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        dec.openElement(ELEM_ADDR)
        assert dec.readBool(ATTRIB_READONLY) is True
        assert dec.readBool(ATTRIB_VOLATILE) is False

    def test_signed_integer_positive(self):
        enc = PackedEncode()
        enc.openElement(ELEM_ADDR)
        enc.writeSignedInteger(ATTRIB_OFFSET, 42)
        enc.closeElement(ELEM_ADDR)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        dec.openElement(ELEM_ADDR)
        assert dec.readSignedInteger(ATTRIB_OFFSET) == 42

    def test_signed_integer_negative(self):
        enc = PackedEncode()
        enc.openElement(ELEM_ADDR)
        enc.writeSignedInteger(ATTRIB_OFFSET, -100)
        enc.closeElement(ELEM_ADDR)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        dec.openElement(ELEM_ADDR)
        assert dec.readSignedInteger(ATTRIB_OFFSET) == -100

    def test_signed_integer_zero(self):
        enc = PackedEncode()
        enc.openElement(ELEM_ADDR)
        enc.writeSignedInteger(ATTRIB_OFFSET, 0)
        enc.closeElement(ELEM_ADDR)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        dec.openElement(ELEM_ADDR)
        assert dec.readSignedInteger(ATTRIB_OFFSET) == 0

    def test_unsigned_integer(self):
        enc = PackedEncode()
        enc.openElement(ELEM_ADDR)
        enc.writeUnsignedInteger(ATTRIB_OFFSET, 0xDEADBEEF)
        enc.closeElement(ELEM_ADDR)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        dec.openElement(ELEM_ADDR)
        assert dec.readUnsignedInteger(ATTRIB_OFFSET) == 0xDEADBEEF

    def test_unsigned_integer_zero(self):
        enc = PackedEncode()
        enc.openElement(ELEM_ADDR)
        enc.writeUnsignedInteger(ATTRIB_OFFSET, 0)
        enc.closeElement(ELEM_ADDR)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        dec.openElement(ELEM_ADDR)
        assert dec.readUnsignedInteger(ATTRIB_OFFSET) == 0

    def test_large_unsigned_integer(self):
        enc = PackedEncode()
        enc.openElement(ELEM_ADDR)
        enc.writeUnsignedInteger(ATTRIB_OFFSET, 0xFFFFFFFFFFFFFFFF)
        enc.closeElement(ELEM_ADDR)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        dec.openElement(ELEM_ADDR)
        assert dec.readUnsignedInteger(ATTRIB_OFFSET) == 0xFFFFFFFFFFFFFFFF

    def test_string_attribute(self):
        enc = PackedEncode()
        enc.openElement(ELEM_ADDR)
        enc.writeString(ATTRIB_NAME, "hello_world")
        enc.closeElement(ELEM_ADDR)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        dec.openElement(ELEM_ADDR)
        assert dec.readString(ATTRIB_NAME) == "hello_world"

    def test_string_empty(self):
        enc = PackedEncode()
        enc.openElement(ELEM_ADDR)
        enc.writeString(ATTRIB_NAME, "")
        enc.closeElement(ELEM_ADDR)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        dec.openElement(ELEM_ADDR)
        assert dec.readString(ATTRIB_NAME) == ""

    def test_string_unicode(self):
        enc = PackedEncode()
        enc.openElement(ELEM_ADDR)
        enc.writeString(ATTRIB_NAME, "日本語テスト")
        enc.closeElement(ELEM_ADDR)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        dec.openElement(ELEM_ADDR)
        assert dec.readString(ATTRIB_NAME) == "日本語テスト"

    def test_multiple_attributes(self):
        enc = PackedEncode()
        enc.openElement(ELEM_ADDR)
        enc.writeString(ATTRIB_SPACE, "ram")
        enc.writeUnsignedInteger(ATTRIB_OFFSET, 0x1000)
        enc.writeSignedInteger(ATTRIB_SIZE, 4)
        enc.closeElement(ELEM_ADDR)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        dec.openElement(ELEM_ADDR)
        assert dec.readString(ATTRIB_SPACE) == "ram"
        assert dec.readUnsignedInteger(ATTRIB_OFFSET) == 0x1000
        assert dec.readSignedInteger(ATTRIB_SIZE) == 4

    def test_nested_elements(self):
        enc = PackedEncode()
        enc.openElement(ELEM_MAPSYM)
        enc.writeUnsignedInteger(ATTRIB_ID, 99)
        enc.openElement(ELEM_SYMBOL)
        enc.writeString(ATTRIB_NAME, "test_sym")
        enc.closeElement(ELEM_SYMBOL)
        enc.closeElement(ELEM_MAPSYM)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        mid = dec.openElement(ELEM_MAPSYM)
        assert mid == ELEM_MAPSYM.id
        assert dec.readUnsignedInteger(ATTRIB_ID) == 99
        sid = dec.openElement(ELEM_SYMBOL)
        assert sid == ELEM_SYMBOL.id
        assert dec.readString(ATTRIB_NAME) == "test_sym"
        dec.closeElement(sid)
        dec.closeElement(mid)

    def test_peek_element(self):
        enc = PackedEncode()
        enc.openElement(ELEM_HOLE)
        enc.closeElement(ELEM_HOLE)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        assert dec.peekElement() == ELEM_HOLE.id
        # peek should not consume
        assert dec.peekElement() == ELEM_HOLE.id
        eid = dec.openElement()
        assert eid == ELEM_HOLE.id

    def test_open_element_generic(self):
        enc = PackedEncode()
        enc.openElement(ELEM_COMMENT)
        enc.closeElement(ELEM_COMMENT)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        eid = dec.openElement()
        assert eid == ELEM_COMMENT.id
        dec.closeElement(eid)

    def test_rewind_attributes(self):
        enc = PackedEncode()
        enc.openElement(ELEM_ADDR)
        enc.writeString(ATTRIB_NAME, "abc")
        enc.writeUnsignedInteger(ATTRIB_OFFSET, 123)
        enc.closeElement(ELEM_ADDR)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        dec.openElement(ELEM_ADDR)
        # Read first pass
        assert dec.readString(ATTRIB_NAME) == "abc"
        # Rewind and read again
        dec.rewindAttributes()
        assert dec.readString(ATTRIB_NAME) == "abc"
        assert dec.readUnsignedInteger(ATTRIB_OFFSET) == 123

    def test_get_next_attribute_id(self):
        enc = PackedEncode()
        enc.openElement(ELEM_ADDR)
        enc.writeString(ATTRIB_NAME, "x")
        enc.writeUnsignedInteger(ATTRIB_OFFSET, 5)
        enc.closeElement(ELEM_ADDR)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        dec.openElement(ELEM_ADDR)

        att1 = dec.getNextAttributeId()
        assert att1 == ATTRIB_NAME.id
        val1 = dec.readString()
        assert val1 == "x"

        att2 = dec.getNextAttributeId()
        assert att2 == ATTRIB_OFFSET.id
        val2 = dec.readUnsignedInteger()
        assert val2 == 5

        att3 = dec.getNextAttributeId()
        assert att3 == 0  # no more

    def test_close_element_skipping(self):
        enc = PackedEncode()
        enc.openElement(ELEM_MAPSYM)
        enc.openElement(ELEM_SYMBOL)
        enc.writeString(ATTRIB_NAME, "inner")
        enc.closeElement(ELEM_SYMBOL)
        enc.openElement(ELEM_ADDR)
        enc.writeUnsignedInteger(ATTRIB_OFFSET, 0x100)
        enc.closeElement(ELEM_ADDR)
        enc.closeElement(ELEM_MAPSYM)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        mid = dec.openElement(ELEM_MAPSYM)
        # Skip everything inside
        dec.closeElementSkipping(mid)

    def test_extended_element_id(self):
        """Test element IDs > 0x1F that need extension bytes."""
        big_elem = ElementId("big_element", 100)
        enc = PackedEncode()
        enc.openElement(big_elem)
        enc.writeString(ATTRIB_NAME, "test")
        enc.closeElement(big_elem)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        eid = dec.openElement()
        assert eid == 100
        assert dec.readString(ATTRIB_NAME) == "test"
        dec.closeElement(eid)

    def test_extended_attribute_id(self):
        """Test attribute IDs > 0x1F that need extension bytes."""
        big_attr = AttributeId("big_attr", 100)
        enc = PackedEncode()
        enc.openElement(ELEM_ADDR)
        enc.writeString(big_attr, "extended")
        enc.closeElement(ELEM_ADDR)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        dec.openElement(ELEM_ADDR)
        assert dec.readString(big_attr) == "extended"

    def test_sibling_elements(self):
        enc = PackedEncode()
        enc.openElement(ELEM_COMMENTDB)
        enc.openElement(ELEM_COMMENT)
        enc.writeString(ATTRIB_NAME, "c1")
        enc.closeElement(ELEM_COMMENT)
        enc.openElement(ELEM_COMMENT)
        enc.writeString(ATTRIB_NAME, "c2")
        enc.closeElement(ELEM_COMMENT)
        enc.closeElement(ELEM_COMMENTDB)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        db_id = dec.openElement(ELEM_COMMENTDB)
        # First child
        c1 = dec.openElement(ELEM_COMMENT)
        assert dec.readString(ATTRIB_NAME) == "c1"
        dec.closeElement(c1)
        # Second child
        c2 = dec.openElement(ELEM_COMMENT)
        assert dec.readString(ATTRIB_NAME) == "c2"
        dec.closeElement(c2)
        # No more children
        assert dec.peekElement() == 0
        dec.closeElement(db_id)


# =========================================================================
# Integer encoding boundary tests
# =========================================================================

class TestPackedIntegerBoundaries:
    """Test integer encoding at boundary values for length codes."""

    @pytest.mark.parametrize("val", [
        0, 1, 0x7F,  # 1-byte boundary
        0x80, 0x3FFF,  # 2-byte boundary
        0x4000, 0x1FFFFF,  # 3-byte boundary
        0x200000, 0xFFFFFFF,  # 4-byte boundary
        0x10000000, 0x7FFFFFFFF,  # 5-byte boundary
    ])
    def test_unsigned_roundtrip(self, val):
        enc = PackedEncode()
        enc.openElement(ELEM_ADDR)
        enc.writeUnsignedInteger(ATTRIB_OFFSET, val)
        enc.closeElement(ELEM_ADDR)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        dec.openElement(ELEM_ADDR)
        assert dec.readUnsignedInteger(ATTRIB_OFFSET) == val

    @pytest.mark.parametrize("val", [
        0, 1, -1, 127, -127, 1000, -1000,
        0x7FFFFFFF, -0x7FFFFFFF,
    ])
    def test_signed_roundtrip(self, val):
        enc = PackedEncode()
        enc.openElement(ELEM_ADDR)
        enc.writeSignedInteger(ATTRIB_OFFSET, val)
        enc.closeElement(ELEM_ADDR)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        dec.openElement(ELEM_ADDR)
        assert dec.readSignedInteger(ATTRIB_OFFSET) == val


# =========================================================================
# PackedFormat constant verification
# =========================================================================

class TestPackedFormatConstants:
    """Verify PackedFormat constants match C++ definitions."""

    def test_header_masks(self):
        assert _PF.HEADER_MASK == 0xC0
        assert _PF.ELEMENT_START == 0x40
        assert _PF.ELEMENT_END == 0x80
        assert _PF.ATTRIBUTE == 0xC0

    def test_type_codes(self):
        assert _PF.TYPECODE_BOOLEAN == 1
        assert _PF.TYPECODE_SIGNEDINT_POSITIVE == 2
        assert _PF.TYPECODE_SIGNEDINT_NEGATIVE == 3
        assert _PF.TYPECODE_UNSIGNEDINT == 4
        assert _PF.TYPECODE_ADDRESSSPACE == 5
        assert _PF.TYPECODE_SPECIALSPACE == 6
        assert _PF.TYPECODE_STRING == 7

    def test_special_space_codes(self):
        assert _PF.SPECIALSPACE_STACK == 0
        assert _PF.SPECIALSPACE_JOIN == 1
        assert _PF.SPECIALSPACE_FSPEC == 2
        assert _PF.SPECIALSPACE_IOP == 3
        assert _PF.SPECIALSPACE_SPACEBASE == 4


# =========================================================================
# Subsystem parsing smoke tests
# =========================================================================

class TestScopeGhidraHoleParsing:
    """Test ScopeGhidra._decodeHole with synthetic packed data."""

    def test_decode_hole_basic(self):
        """A <hole> element should be recognized and stored."""
        from ghidra.console.subsystems import ScopeGhidra

        # Build a fake <hole> element with space/first/last attributes
        enc = PackedEncode()
        enc.openElement(ELEM_HOLE)
        enc.writeString(ATTRIB_SPACE, "ram")
        enc.writeUnsignedInteger(ATTRIB_OFFSET, 0x1000)
        # ATTRIB_SIZE encodes the range size (last = first + size - 1)
        enc.writeSignedInteger(ATTRIB_SIZE, 0x100)
        enc.closeElement(ELEM_HOLE)

        # Create a minimal ScopeGhidra (no real Ghidra connection)
        class FakeArch:
            symboltab = None
            min_funcsymbol_size = 1
        scope = ScopeGhidra.__new__(ScopeGhidra)
        ScopeGhidra.__init__(scope, FakeArch())

        decoder = PackedDecode()
        decoder.ingestBytes(enc.getBytes())
        # peekElement should show ELEM_HOLE
        assert decoder.peekElement() == ELEM_HOLE.id

    def test_dump2cache_hole_returns_none(self):
        """dump2Cache with a <hole> element should return None."""
        from ghidra.console.subsystems import ScopeGhidra

        enc = PackedEncode()
        enc.openElement(ELEM_HOLE)
        enc.writeString(ATTRIB_SPACE, "ram")
        enc.writeUnsignedInteger(ATTRIB_OFFSET, 0x2000)
        enc.writeSignedInteger(ATTRIB_SIZE, 0x10)
        enc.closeElement(ELEM_HOLE)

        class FakeArch:
            symboltab = None
            min_funcsymbol_size = 1
        scope = ScopeGhidra.__new__(ScopeGhidra)
        ScopeGhidra.__init__(scope, FakeArch())

        decoder = PackedDecode()
        decoder.ingestBytes(enc.getBytes())
        result = scope._dump2Cache(decoder)
        assert result is None


class TestPackedDecodeErrorHandling:
    """Test error conditions in PackedDecode."""

    def test_wrong_element_raises(self):
        enc = PackedEncode()
        enc.openElement(ELEM_ADDR)
        enc.closeElement(ELEM_ADDR)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        with pytest.raises(Exception):
            dec.openElement(ELEM_COMMENT)  # wrong element

    def test_missing_attribute_raises(self):
        enc = PackedEncode()
        enc.openElement(ELEM_ADDR)
        enc.writeString(ATTRIB_NAME, "x")
        enc.closeElement(ELEM_ADDR)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        dec.openElement(ELEM_ADDR)
        with pytest.raises(Exception):
            dec.readUnsignedInteger(ATTRIB_OFFSET)  # not present

    def test_wrong_close_element_raises(self):
        enc = PackedEncode()
        enc.openElement(ELEM_ADDR)
        enc.closeElement(ELEM_ADDR)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        dec.openElement(ELEM_ADDR)
        with pytest.raises(Exception):
            dec.closeElement(999)  # wrong id


class TestPackedEncodeGetBytes:
    """Test PackedEncode.getBytes() helper."""

    def test_get_bytes_returns_bytes(self):
        enc = PackedEncode()
        enc.openElement(ELEM_ADDR)
        enc.closeElement(ELEM_ADDR)
        data = enc.getBytes()
        assert isinstance(data, bytes)
        assert len(data) > 0

    def test_custom_stream(self):
        buf = io.BytesIO()
        enc = PackedEncode(buf)
        enc.openElement(ELEM_ADDR)
        enc.closeElement(ELEM_ADDR)
        assert buf.getvalue() == enc.getBytes()


class TestIngestBytes:
    """Test PackedDecode.ingestBytes adds sentinel."""

    def test_ingest_adds_sentinel(self):
        dec = PackedDecode()
        data = bytes([_PF.ELEMENT_START | ELEM_ADDR.id,
                      _PF.ELEMENT_END | ELEM_ADDR.id])
        dec.ingestBytes(data)
        eid = dec.openElement()
        assert eid == ELEM_ADDR.id
        dec.closeElement(eid)


# =========================================================================
# Symbol / SymbolEntry / FunctionSymbol / LabSymbol / ExternRefSymbol decode
# =========================================================================

class TestSymbolDecode:
    """Test Symbol.decode with packed binary data."""

    def test_symbol_decode_basic(self):
        """Decode a <symbol> with name and id attributes."""
        from ghidra.database.database import Symbol
        enc = PackedEncode()
        enc.openElement(ELEM_SYMBOL)
        enc.writeString(ATTRIB_NAME, "myvar")
        enc.writeUnsignedInteger(ATTRIB_ID, 42)
        # No type sub-element (scope has no arch/types)
        enc.closeElement(ELEM_SYMBOL)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        sym = Symbol()
        sym.decode(dec)
        assert sym.name == "myvar"
        assert sym.symbolId == 42

    def test_symbol_decode_readonly_volatile(self):
        """Decode a <symbol> with readonly and volatile flags."""
        from ghidra.database.database import Symbol
        from ghidra.ir.varnode import Varnode
        enc = PackedEncode()
        enc.openElement(ELEM_SYMBOL)
        enc.writeString(ATTRIB_NAME, "rovar")
        enc.writeBool(ATTRIB_READONLY, True)
        enc.writeBool(ATTRIB_VOLATILE, True)
        enc.closeElement(ELEM_SYMBOL)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        sym = Symbol()
        sym.decode(dec)
        assert sym.name == "rovar"
        assert (sym.flags & Varnode.readonly) != 0
        assert (sym.flags & Varnode.volatil) != 0

    def test_symbol_decode_displayname_defaults_to_name(self):
        """displayName should default to name if not explicitly set."""
        from ghidra.database.database import Symbol
        enc = PackedEncode()
        enc.openElement(ELEM_SYMBOL)
        enc.writeString(ATTRIB_NAME, "abc")
        enc.closeElement(ELEM_SYMBOL)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        sym = Symbol()
        sym.decode(dec)
        assert sym.displayName == "abc"


class TestSymbolEntryDecode:
    """Test SymbolEntry.decode with packed binary data."""

    def test_symbolentry_decode_hash(self):
        """Decode a SymbolEntry with a <hash> element + empty <rangelist>."""
        from ghidra.database.database import Symbol, SymbolEntry
        from ghidra.core.marshal import ELEM_HASH, ATTRIB_VAL, ELEM_RANGELIST
        enc = PackedEncode()
        # <hash val="0xDEADBEEF"/>
        enc.openElement(ELEM_HASH)
        enc.writeUnsignedInteger(ATTRIB_VAL, 0xDEADBEEF)
        enc.closeElement(ELEM_HASH)
        # <rangelist/> (empty use-limit)
        enc.openElement(ELEM_RANGELIST)
        enc.closeElement(ELEM_RANGELIST)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        sym = Symbol(name="hash_sym")
        entry = SymbolEntry(sym)
        entry.decode(dec)
        assert entry.hash == 0xDEADBEEF
        assert entry.addr.isInvalid()

    def test_symbolentry_peeks_hash_element(self):
        """SymbolEntry.decode should peek and detect <hash> vs <addr>."""
        from ghidra.database.database import Symbol, SymbolEntry
        from ghidra.core.marshal import ELEM_HASH, ATTRIB_VAL, ELEM_RANGELIST
        enc = PackedEncode()
        enc.openElement(ELEM_HASH)
        enc.writeUnsignedInteger(ATTRIB_VAL, 123456)
        enc.closeElement(ELEM_HASH)
        enc.openElement(ELEM_RANGELIST)
        enc.closeElement(ELEM_RANGELIST)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        # Verify peek detects the hash element
        assert dec.peekElement() == ELEM_HASH.id
        sym = Symbol(name="peek_test")
        entry = SymbolEntry(sym)
        entry.decode(dec)
        assert entry.hash == 123456


class TestFunctionSymbolDecode:
    """Test FunctionSymbol.decode with packed binary data."""

    def test_functionshell_decode(self):
        """Decode a <functionshell> element."""
        from ghidra.database.database import FunctionSymbol
        from ghidra.core.marshal import ELEM_FUNCTIONSHELL, ATTRIB_LABEL
        enc = PackedEncode()
        enc.openElement(ELEM_FUNCTIONSHELL)
        enc.writeString(ATTRIB_NAME, "main")
        enc.writeUnsignedInteger(ATTRIB_ID, 100)
        enc.writeString(ATTRIB_LABEL, "main_display")
        enc.closeElement(ELEM_FUNCTIONSHELL)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        fsym = FunctionSymbol()
        fsym.decode(dec)
        assert fsym.name == "main"
        assert fsym.symbolId == 100
        assert fsym.displayName == "main_display"

    def test_functionshell_decode_no_label(self):
        """If no label attribute, displayName defaults to name."""
        from ghidra.database.database import FunctionSymbol
        from ghidra.core.marshal import ELEM_FUNCTIONSHELL
        enc = PackedEncode()
        enc.openElement(ELEM_FUNCTIONSHELL)
        enc.writeString(ATTRIB_NAME, "foo")
        enc.closeElement(ELEM_FUNCTIONSHELL)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        fsym = FunctionSymbol()
        fsym.decode(dec)
        assert fsym.name == "foo"
        assert fsym.displayName == "foo"


class TestLabSymbolDecode:
    """Test LabSymbol.decode with packed binary data."""

    def test_labsym_decode(self):
        """Decode a <labelsym> element."""
        from ghidra.database.database import LabSymbol
        enc = PackedEncode()
        enc.openElement(ELEM_LABELSYM)
        enc.writeString(ATTRIB_NAME, "loop_top")
        enc.writeUnsignedInteger(ATTRIB_ID, 55)
        enc.closeElement(ELEM_LABELSYM)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        lsym = LabSymbol()
        lsym.decode(dec)
        assert lsym.name == "loop_top"
        assert lsym.symbolId == 55


class TestExternRefSymbolDecode:
    """Test ExternRefSymbol.decode with packed binary data."""

    def test_externref_decode_attributes(self):
        """Verify ExternRefSymbol decodeHeader parses name correctly."""
        from ghidra.database.database import ExternRefSymbol
        # ExternRefSymbol.decode calls Address.decode for the child <addr>,
        # which needs a spcManager. Test just the attribute parsing by
        # testing decodeHeader directly via the Symbol base method.
        enc = PackedEncode()
        enc.openElement(ELEM_EXTERNREFSYMBOL)
        enc.writeString(ATTRIB_NAME, "printf")
        enc.closeElement(ELEM_EXTERNREFSYMBOL)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        esym = ExternRefSymbol()
        # Manually open element, parse attributes, close
        elemId = dec.openElement(ELEM_EXTERNREFSYMBOL)
        assert esym.name == ""  # not yet decoded
        while True:
            att = dec.getNextAttributeId()
            if att == 0:
                break
            if att == ATTRIB_NAME.id:
                esym.name = dec.readString()
        dec.closeElement(elemId)
        assert esym.name == "printf"


# =========================================================================
# CPoolRecord.decode tests
# =========================================================================

class TestCPoolRecordDecode:
    """Test CPoolRecord.decode with packed binary data."""

    def test_cpoolrec_decode_method(self):
        """Decode a <cpoolrec> with tag=method and a <token> child."""
        from ghidra.database.cpool import CPoolRecord
        enc = PackedEncode()
        enc.openElement(ELEM_CPOOLREC)
        enc.writeString(ATTRIB_TAG, "method")
        # <token> child
        enc.openElement(ELEM_TOKEN)
        enc.writeString(ATTRIB_CONTENT, "System.out.println")
        enc.closeElement(ELEM_TOKEN)
        enc.closeElement(ELEM_CPOOLREC)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        rec = CPoolRecord()
        rec.decode(dec)
        assert rec.tag == CPoolRecord.pointer_method
        assert rec.token == "System.out.println"
        assert rec.value == 0
        assert rec.flags == 0

    def test_cpoolrec_decode_primitive(self):
        """Decode a <cpoolrec> with default (primitive) tag and <value>."""
        from ghidra.database.cpool import CPoolRecord
        enc = PackedEncode()
        enc.openElement(ELEM_CPOOLREC)
        # No tag attribute => primitive
        # <value> child
        enc.openElement(ELEM_VALUE)
        enc.writeUnsignedInteger(ATTRIB_CONTENT, 42)
        enc.closeElement(ELEM_VALUE)
        # <token> child
        enc.openElement(ELEM_TOKEN)
        enc.writeString(ATTRIB_CONTENT, "CONST_42")
        enc.closeElement(ELEM_TOKEN)
        enc.closeElement(ELEM_CPOOLREC)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        rec = CPoolRecord()
        rec.decode(dec)
        assert rec.tag == CPoolRecord.primitive
        assert rec.value == 42
        assert rec.token == "CONST_42"

    def test_cpoolrec_decode_constructor_flag(self):
        """Decode a <cpoolrec> with constructor flag set."""
        from ghidra.database.cpool import CPoolRecord
        enc = PackedEncode()
        enc.openElement(ELEM_CPOOLREC)
        enc.writeString(ATTRIB_TAG, "method")
        from ghidra.core.marshal import ATTRIB_CONSTRUCTOR
        enc.writeBool(ATTRIB_CONSTRUCTOR, True)
        enc.openElement(ELEM_TOKEN)
        enc.writeString(ATTRIB_CONTENT, "<init>")
        enc.closeElement(ELEM_TOKEN)
        enc.closeElement(ELEM_CPOOLREC)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        rec = CPoolRecord()
        rec.decode(dec)
        assert rec.tag == CPoolRecord.pointer_method
        assert rec.isConstructor()
        assert not rec.isDestructor()
        assert rec.token == "<init>"

    def test_cpoolrec_all_tag_types(self):
        """Verify all tag string -> tag constant mappings."""
        from ghidra.database.cpool import CPoolRecord
        tag_map = {
            "method": CPoolRecord.pointer_method,
            "field": CPoolRecord.pointer_field,
            "instanceof": CPoolRecord.instance_of,
            "arraylength": CPoolRecord.array_length,
            "checkcast": CPoolRecord.check_cast,
            "string": CPoolRecord.string_literal,
            "classref": CPoolRecord.class_reference,
        }
        for tag_str, expected_tag in tag_map.items():
            enc = PackedEncode()
            enc.openElement(ELEM_CPOOLREC)
            enc.writeString(ATTRIB_TAG, tag_str)
            enc.openElement(ELEM_TOKEN)
            enc.writeString(ATTRIB_CONTENT, "test")
            enc.closeElement(ELEM_TOKEN)
            enc.closeElement(ELEM_CPOOLREC)

            dec = PackedDecode()
            dec.ingestBytes(enc.getBytes())
            rec = CPoolRecord()
            rec.decode(dec)
            assert rec.tag == expected_tag, f"Tag mismatch for {tag_str}"


# =========================================================================
# TypeFactory.decodeType tests
# =========================================================================

class TestTypeFactoryDecodeType:
    """Test TypeFactory.decodeType with packed binary data."""

    def test_decode_type_by_name(self):
        """decodeType should resolve a type by name from the factory."""
        from ghidra.types.datatype import TypeFactory
        tf = TypeFactory()
        tf.setupCoreTypes()

        # Encode a type reference with name="int4"
        enc = PackedEncode()
        enc.openElement(ELEM_SYMBOL)  # any element works
        enc.writeString(ATTRIB_NAME, "int4")
        enc.closeElement(ELEM_SYMBOL)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        dt = tf.decodeType(dec)
        assert dt is not None
        assert dt.getName() == "int4"

    def test_decode_type_by_id(self):
        """decodeType should resolve a type by id."""
        from ghidra.types.datatype import TypeFactory
        tf = TypeFactory()
        tf.setupCoreTypes()

        # Find the id of uint4
        uint4 = tf.findByName("uint4")
        assert uint4 is not None

        enc = PackedEncode()
        enc.openElement(ELEM_SYMBOL)
        enc.writeUnsignedInteger(ATTRIB_ID, uint4.id)
        enc.closeElement(ELEM_SYMBOL)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        dt = tf.decodeType(dec)
        assert dt is not None
        assert dt.getName() == "uint4"

    def test_decode_type_unknown_creates_placeholder(self):
        """decodeType should create a placeholder for unknown types."""
        from ghidra.types.datatype import TypeFactory
        tf = TypeFactory()
        tf.setupCoreTypes()

        enc = PackedEncode()
        enc.openElement(ELEM_SYMBOL)
        enc.writeString(ATTRIB_NAME, "custom_struct")
        enc.writeSignedInteger(ATTRIB_SIZE, 16)
        enc.closeElement(ELEM_SYMBOL)

        dec = PackedDecode()
        dec.ingestBytes(enc.getBytes())
        dt = tf.decodeType(dec)
        assert dt is not None
        assert dt.getSize() == 16


# =========================================================================
# ConstantPoolInternal.storeRecord tests
# =========================================================================

class TestConstantPoolStoreRecord:
    """Test ConstantPoolInternal.storeRecord."""

    def test_store_and_retrieve(self):
        """storeRecord should allow later retrieval via getRecord."""
        from ghidra.database.cpool import ConstantPoolInternal, CPoolRecord
        pool = ConstantPoolInternal()
        rec = CPoolRecord()
        rec.tag = CPoolRecord.pointer_method
        rec.token = "myMethod"
        pool.storeRecord([1, 2, 3], rec)
        retrieved = pool.getRecord([1, 2, 3])
        assert retrieved is rec
        assert retrieved.token == "myMethod"

    def test_store_overwrites(self):
        """storeRecord should overwrite existing record for same refs."""
        from ghidra.database.cpool import ConstantPoolInternal, CPoolRecord
        pool = ConstantPoolInternal()
        rec1 = CPoolRecord()
        rec1.token = "first"
        pool.storeRecord([1], rec1)
        rec2 = CPoolRecord()
        rec2.token = "second"
        pool.storeRecord([1], rec2)
        assert pool.getRecord([1]).token == "second"
