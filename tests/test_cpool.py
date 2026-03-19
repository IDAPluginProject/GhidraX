"""Tests for ghidra.database.cpool -- CPoolRecord + ConstantPoolInternal."""
from __future__ import annotations

from ghidra.database.cpool import CPoolRecord, ConstantPoolInternal


# ---------------------------------------------------------------------------
# CPoolRecord
# ---------------------------------------------------------------------------

class TestCPoolRecord:
    def test_defaults(self):
        r = CPoolRecord()
        assert r.getTag() == CPoolRecord.primitive
        assert r.getToken() == ""
        assert r.getValue() == 0
        assert r.getType() is None
        assert r.getByteData() is None
        assert r.getByteDataLength() == 0
        assert r.getFlags() == 0
        assert r.isConstructor() is False
        assert r.isDestructor() is False

    def test_tag_constants(self):
        assert CPoolRecord.primitive == 0
        assert CPoolRecord.string_literal == 1
        assert CPoolRecord.class_reference == 2
        assert CPoolRecord.pointer_method == 3
        assert CPoolRecord.pointer_field == 4
        assert CPoolRecord.array_length == 5
        assert CPoolRecord.instance_of == 6
        assert CPoolRecord.check_cast == 7

    def test_flag_constants(self):
        assert CPoolRecord.is_constructor == 0x1
        assert CPoolRecord.is_destructor == 0x2

    def test_constructor_flag(self):
        r = CPoolRecord()
        r.flags = CPoolRecord.is_constructor
        assert r.isConstructor() is True
        assert r.isDestructor() is False

    def test_destructor_flag(self):
        r = CPoolRecord()
        r.flags = CPoolRecord.is_destructor
        assert r.isConstructor() is False
        assert r.isDestructor() is True

    def test_byte_data(self):
        r = CPoolRecord()
        r.byteData = b"\x01\x02\x03"
        assert r.getByteData() == b"\x01\x02\x03"
        assert r.getByteDataLength() == 3

    def test_set_fields(self):
        r = CPoolRecord()
        r.tag = CPoolRecord.string_literal
        r.token = "hello"
        r.value = 42
        assert r.getTag() == CPoolRecord.string_literal
        assert r.getToken() == "hello"
        assert r.getValue() == 42


# ---------------------------------------------------------------------------
# ConstantPoolInternal
# ---------------------------------------------------------------------------

class TestConstantPoolInternal:
    def test_empty(self):
        pool = ConstantPoolInternal()
        assert pool.empty() is True
        assert pool.size() == 0
        assert pool.getRecord([1, 2]) is None

    def test_put_and_get(self):
        pool = ConstantPoolInternal()
        pool.putRecord([1, 2], CPoolRecord.string_literal, "test", None)
        assert pool.empty() is False
        assert pool.size() == 1
        rec = pool.getRecord([1, 2])
        assert rec is not None
        assert rec.getTag() == CPoolRecord.string_literal
        assert rec.getToken() == "test"

    def test_get_missing(self):
        pool = ConstantPoolInternal()
        pool.putRecord([1], CPoolRecord.primitive, "x", None)
        assert pool.getRecord([2]) is None

    def test_clear(self):
        pool = ConstantPoolInternal()
        pool.putRecord([1], CPoolRecord.primitive, "x", None)
        pool.clear()
        assert pool.empty() is True
        assert pool.size() == 0

    def test_store_record(self):
        pool = ConstantPoolInternal()
        rec = CPoolRecord()
        rec.tag = CPoolRecord.pointer_method
        rec.token = "myMethod"
        pool.storeRecord([5, 6, 7], rec)
        assert pool.getRecord([5, 6, 7]) is rec

    def test_multiple_records(self):
        pool = ConstantPoolInternal()
        pool.putRecord([1], CPoolRecord.primitive, "a", None)
        pool.putRecord([2], CPoolRecord.string_literal, "b", None)
        pool.putRecord([3], CPoolRecord.pointer_field, "c", None)
        assert pool.size() == 3
        assert pool.getRecord([1]).getToken() == "a"
        assert pool.getRecord([2]).getToken() == "b"
        assert pool.getRecord([3]).getToken() == "c"

    def test_overwrite_record(self):
        pool = ConstantPoolInternal()
        pool.putRecord([1], CPoolRecord.primitive, "old", None)
        # putRecord with same key reuses existing record
        rec = pool.getRecord([1])
        assert rec.getToken() == "old"
        # storeRecord replaces
        new_rec = CPoolRecord()
        new_rec.token = "new"
        pool.storeRecord([1], new_rec)
        assert pool.getRecord([1]).getToken() == "new"
