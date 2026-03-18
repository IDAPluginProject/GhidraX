"""
Phase 3: Unit tests for Type system classes.
Tests Datatype hierarchy, TypeFactory, CastStrategyC, MetaType utilities.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

import pytest
from ghidra.types.datatype import (
    MetaType, SubMetaType, TypeClass,
    TYPE_VOID, TYPE_UNKNOWN, TYPE_INT, TYPE_UINT, TYPE_BOOL, TYPE_FLOAT,
    TYPE_PTR, TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION, TYPE_CODE, TYPE_SPACEBASE,
    TYPE_ENUM_INT, TYPE_ENUM_UINT,
    metatype2string, string2metatype, metatype2typeclass,
    Datatype, TypeBase, TypeChar, TypeUnicode, TypeVoid, TypePointer,
    TypeArray, TypeEnum, TypeStruct, TypeUnion, TypeCode, TypeSpacebase,
    TypeField, TypeFactory,
)
from ghidra.types.cast import (
    CastStrategyC, CastStrategyJava, IntPromotionCode,
)


# =========================================================================
# MetaType / SubMetaType utilities
# =========================================================================

class TestMetaTypeUtils:
    def test_metatype2string(self):
        assert metatype2string(TYPE_VOID) == "void"
        assert metatype2string(TYPE_INT) == "int"
        assert metatype2string(TYPE_UINT) == "uint"
        assert metatype2string(TYPE_BOOL) == "bool"
        assert metatype2string(TYPE_FLOAT) == "float"
        assert metatype2string(TYPE_PTR) == "ptr"
        assert metatype2string(TYPE_ARRAY) == "array"
        assert metatype2string(TYPE_STRUCT) == "struct"
        assert metatype2string(TYPE_UNION) == "union"
        assert metatype2string(TYPE_CODE) == "code"
        assert metatype2string(TYPE_UNKNOWN) == "unknown"

    def test_string2metatype(self):
        assert string2metatype("void") == TYPE_VOID
        assert string2metatype("int") == TYPE_INT
        assert string2metatype("uint") == TYPE_UINT
        assert string2metatype("float") == TYPE_FLOAT
        assert string2metatype("ptr") == TYPE_PTR
        assert string2metatype("struct") == TYPE_STRUCT
        assert string2metatype("nonsense") == TYPE_UNKNOWN

    def test_metatype2typeclass(self):
        assert metatype2typeclass(TYPE_FLOAT) == TypeClass.TYPECLASS_FLOAT
        assert metatype2typeclass(TYPE_PTR) == TypeClass.TYPECLASS_PTR
        assert metatype2typeclass(TYPE_INT) == TypeClass.TYPECLASS_GENERAL
        assert metatype2typeclass(TYPE_UINT) == TypeClass.TYPECLASS_GENERAL
        assert metatype2typeclass(TYPE_VOID) == TypeClass.TYPECLASS_GENERAL


# =========================================================================
# TypeBase Tests
# =========================================================================

class TestTypeBase:
    def test_creation(self):
        t = TypeBase(4, TYPE_INT, "int4")
        assert t.getSize() == 4
        assert t.getMetatype() == TYPE_INT
        assert t.getName() == "int4"

    def test_clone(self):
        t = TypeBase(4, TYPE_INT, "int4")
        t.id = 42
        c = t.clone()
        assert c.getSize() == 4
        assert c.getMetatype() == TYPE_INT
        assert c.getName() == "int4"
        assert c.id == 42

    def test_submeta_auto(self):
        t = TypeBase(4, TYPE_INT)
        assert t.getSubMeta() == SubMetaType.SUB_INT_PLAIN
        t2 = TypeBase(4, TYPE_UINT)
        assert t2.getSubMeta() == SubMetaType.SUB_UINT_PLAIN
        t3 = TypeBase(4, TYPE_FLOAT)
        assert t3.getSubMeta() == SubMetaType.SUB_FLOAT

    def test_flags(self):
        t = TypeBase(4, TYPE_INT, "myint")
        assert not t.isCoreType()
        t.flags |= Datatype.coretype
        assert t.isCoreType()

    def test_compare_same(self):
        t1 = TypeBase(4, TYPE_INT, "int4")
        t2 = TypeBase(4, TYPE_INT, "int4")
        assert t1.compare(t2, 10) == 0

    def test_compare_different_size(self):
        t1 = TypeBase(4, TYPE_INT, "int4")
        t2 = TypeBase(8, TYPE_INT, "int8")
        assert t1.compare(t2, 10) == -1
        assert t2.compare(t1, 10) == 1

    def test_compare_different_meta(self):
        t1 = TypeBase(4, TYPE_INT, "int4")
        t2 = TypeBase(4, TYPE_UINT, "uint4")
        # SubMeta ordering determines result
        assert t1.compare(t2, 10) != 0

    def test_print_raw(self):
        t = TypeBase(4, TYPE_INT, "int4")
        assert t.printRaw() == "int4"

    def test_hash_name(self):
        h1 = Datatype.hashName("int4")
        h2 = Datatype.hashName("int4")
        h3 = Datatype.hashName("uint4")
        assert h1 == h2
        assert h1 != h3

    def test_display_format(self):
        t = TypeBase(4, TYPE_INT, "int4")
        assert t.getDisplayFormat() == 0
        t.setDisplayFormat(3)
        assert t.getDisplayFormat() == 3


# =========================================================================
# TypeVoid Tests
# =========================================================================

class TestTypeVoid:
    def test_creation(self):
        t = TypeVoid()
        assert t.getSize() == 0
        assert t.getMetatype() == TYPE_VOID
        assert t.getName() == "void"
        assert t.isCoreType()

    def test_clone(self):
        t = TypeVoid()
        c = t.clone()
        assert c.getName() == "void"
        assert c.getMetatype() == TYPE_VOID


# =========================================================================
# TypeChar Tests
# =========================================================================

class TestTypeChar:
    def test_creation(self):
        t = TypeChar()
        assert t.getSize() == 1
        assert t.getName() == "char"
        assert t.isASCII()
        assert t.isCharPrint()

    def test_custom_name(self):
        t = TypeChar("mychar")
        assert t.getName() == "mychar"
        assert t.isASCII()

    def test_clone(self):
        t = TypeChar()
        c = t.clone()
        assert c.getName() == "char"
        assert c.isASCII()


# =========================================================================
# TypeUnicode Tests
# =========================================================================

class TestTypeUnicode:
    def test_utf16(self):
        t = TypeUnicode("wchar", 2, TYPE_INT)
        assert t.getSize() == 2
        assert t.isUTF16()
        assert t.isCharPrint()
        assert not t.isUTF32()

    def test_utf32(self):
        t = TypeUnicode("wchar4", 4, TYPE_INT)
        assert t.getSize() == 4
        assert t.isUTF32()
        assert t.isCharPrint()

    def test_clone(self):
        t = TypeUnicode("wchar", 2)
        c = t.clone()
        assert c.isUTF16()


# =========================================================================
# TypePointer Tests
# =========================================================================

class TestTypePointer:
    def test_creation(self):
        base = TypeBase(4, TYPE_INT, "int4")
        ptr = TypePointer(8, base)
        assert ptr.getSize() == 8
        assert ptr.getMetatype() == TYPE_PTR
        assert ptr.getPtrTo() is base
        assert ptr.getWordSize() == 1

    def test_null_ptrto(self):
        ptr = TypePointer(8)
        assert ptr.getPtrTo() is None
        assert ptr.getSubMeta() == SubMetaType.SUB_PTR

    def test_ptr_to_struct(self):
        s = TypeStruct("myStruct", 16)
        ptr = TypePointer(8, s)
        assert ptr.getSubMeta() == SubMetaType.SUB_PTR_STRUCT

    def test_ptr_to_array(self):
        base = TypeBase(4, TYPE_INT, "int4")
        arr = TypeArray(10, base)
        ptr = TypePointer(8, arr)
        assert ptr.isPointerToArray()

    def test_num_depend(self):
        base = TypeBase(4, TYPE_INT, "int4")
        ptr = TypePointer(8, base)
        assert ptr.numDepend() == 1
        assert ptr.getDepend(0) is base

    def test_get_sub_type(self):
        base = TypeBase(4, TYPE_INT, "int4")
        ptr = TypePointer(8, base)
        sub, off = ptr.getSubType(0)
        assert sub is base
        assert off == 0

    def test_clone(self):
        base = TypeBase(4, TYPE_INT, "int4")
        ptr = TypePointer(8, base, 2)
        c = ptr.clone()
        assert c.getSize() == 8
        assert c.getPtrTo() is base
        assert c.getWordSize() == 2

    def test_print_raw(self):
        base = TypeBase(4, TYPE_INT, "int4")
        ptr = TypePointer(8, base)
        assert ptr.printRaw() == "int4 *"

    def test_compare(self):
        b1 = TypeBase(4, TYPE_INT, "int4")
        b2 = TypeBase(8, TYPE_INT, "int8")
        p1 = TypePointer(8, b1)
        p2 = TypePointer(8, b2)
        # Same size pointers, different pointed-to types
        r = p1.compare(p2, 2)
        # Should differ based on pointed-to type comparison
        assert r == p1.getPtrTo().compare(p2.getPtrTo(), 1)


# =========================================================================
# TypeArray Tests
# =========================================================================

class TestTypeArray:
    def test_creation(self):
        base = TypeBase(4, TYPE_INT, "int4")
        arr = TypeArray(10, base)
        assert arr.getSize() == 40
        assert arr.numElements() == 10
        assert arr.getBase() is base
        assert arr.getMetatype() == TYPE_ARRAY

    def test_get_sub_type(self):
        base = TypeBase(4, TYPE_INT, "int4")
        arr = TypeArray(10, base)
        sub, off = arr.getSubType(12)
        assert sub is base
        assert off == 0  # 12 % 4 == 0

        sub2, off2 = arr.getSubType(13)
        assert sub2 is base
        assert off2 == 1  # 13 % 4 == 1

    def test_num_depend(self):
        base = TypeBase(4, TYPE_INT, "int4")
        arr = TypeArray(5, base)
        assert arr.numDepend() == 1
        assert arr.getDepend(0) is base

    def test_clone(self):
        base = TypeBase(4, TYPE_INT, "int4")
        arr = TypeArray(5, base)
        c = arr.clone()
        assert c.numElements() == 5
        assert c.getBase() is base

    def test_print_raw(self):
        base = TypeBase(4, TYPE_INT, "int4")
        arr = TypeArray(3, base)
        assert arr.printRaw() == "int4[3]"

    def test_compare(self):
        base = TypeBase(4, TYPE_INT, "int4")
        a1 = TypeArray(5, base)
        a2 = TypeArray(10, base)
        assert a1.compare(a2, 10) == -1


# =========================================================================
# TypeEnum Tests
# =========================================================================

class TestTypeEnum:
    def test_creation(self):
        e = TypeEnum(4, TYPE_UINT, "myEnum")
        assert e.getSize() == 4
        assert e.isEnumType()
        assert e.getName() == "myEnum"

    def test_name_map(self):
        e = TypeEnum(4, TYPE_UINT, "color")
        e.setNameMap({0: "RED", 1: "GREEN", 2: "BLUE"})
        assert e.hasNamedValue(0)
        assert e.getValueName(1) == "GREEN"
        assert not e.hasNamedValue(99)

    def test_clone(self):
        e = TypeEnum(4, TYPE_UINT, "color")
        e.setNameMap({0: "RED"})
        c = e.clone()
        assert c.hasNamedValue(0)
        assert c.getValueName(0) == "RED"


# =========================================================================
# TypeStruct Tests
# =========================================================================

class TestTypeStruct:
    def test_creation(self):
        s = TypeStruct("myStruct", 16)
        assert s.getName() == "myStruct"
        assert s.getSize() == 16
        assert s.getMetatype() == TYPE_STRUCT
        assert s.numFields() == 0

    def test_set_fields(self):
        s = TypeStruct("point")
        int4 = TypeBase(4, TYPE_INT, "int4")
        fields = [
            TypeField(0, 0, "x", int4),
            TypeField(1, 4, "y", int4),
        ]
        s.setFields(fields)
        assert s.numFields() == 2
        assert s.getSize() == 8
        assert s.getField(0).name == "x"
        assert s.getField(1).name == "y"

    def test_get_sub_type(self):
        s = TypeStruct("point")
        int4 = TypeBase(4, TYPE_INT, "int4")
        s.setFields([
            TypeField(0, 0, "x", int4),
            TypeField(1, 4, "y", int4),
        ])
        sub, off = s.getSubType(5)
        assert sub is int4
        assert off == 1  # 5 - 4 (offset of y)

    def test_get_sub_type_miss(self):
        s = TypeStruct("point", 16)
        int4 = TypeBase(4, TYPE_INT, "int4")
        s.setFields([TypeField(0, 0, "x", int4)])
        sub, off = s.getSubType(8)
        assert sub is None

    def test_num_depend(self):
        s = TypeStruct("pair")
        int4 = TypeBase(4, TYPE_INT, "int4")
        s.setFields([
            TypeField(0, 0, "a", int4),
            TypeField(1, 4, "b", int4),
        ])
        assert s.numDepend() == 2
        assert s.getDepend(0) is int4

    def test_clone(self):
        s = TypeStruct("pair", 8)
        c = s.clone()
        assert c.getName() == "pair"
        assert c.getSize() == 8

    def test_print_raw(self):
        s = TypeStruct("myStruct")
        assert s.printRaw() == "struct myStruct"

    def test_compare_dependency(self):
        s1 = TypeStruct("alpha", 8)
        s2 = TypeStruct("beta", 8)
        r = s1.compareDependency(s2)
        assert r == -1  # "alpha" < "beta"


# =========================================================================
# TypeUnion Tests
# =========================================================================

class TestTypeUnion:
    def test_creation(self):
        u = TypeUnion("myUnion", 8)
        assert u.getName() == "myUnion"
        assert u.getMetatype() == TYPE_UNION
        assert u.needsResolution()

    def test_set_fields(self):
        u = TypeUnion("val")
        int4 = TypeBase(4, TYPE_INT, "int4")
        float4 = TypeBase(4, TYPE_FLOAT, "float4")
        u.setFields([
            TypeField(0, 0, "i", int4),
            TypeField(1, 0, "f", float4),
        ])
        assert u.numFields() == 2
        assert u.getSize() == 4

    def test_clone(self):
        u = TypeUnion("val", 4)
        c = u.clone()
        assert c.getName() == "val"

    def test_print_raw(self):
        u = TypeUnion("myUnion")
        assert u.printRaw() == "union myUnion"


# =========================================================================
# TypeCode / TypeSpacebase Tests
# =========================================================================

class TestTypeCode:
    def test_creation(self):
        t = TypeCode()
        assert t.getMetatype() == TYPE_CODE
        assert t.getName() == "code"

    def test_clone(self):
        t = TypeCode(4)
        c = t.clone()
        assert c.getSize() == 4


class TestTypeSpacebase:
    def test_creation(self):
        t = TypeSpacebase(8)
        assert t.getMetatype() == TYPE_SPACEBASE
        assert t.getSize() == 8


# =========================================================================
# TypeField Tests
# =========================================================================

class TestTypeField:
    def test_creation(self):
        int4 = TypeBase(4, TYPE_INT, "int4")
        f = TypeField(0, 8, "myField", int4)
        assert f.name == "myField"
        assert f.offset == 8
        assert f.type is int4

    def test_ordering(self):
        f1 = TypeField(0, 0, "a")
        f2 = TypeField(1, 4, "b")
        assert f1 < f2


# =========================================================================
# TypeFactory Tests
# =========================================================================

class TestTypeFactory:
    def test_creation(self):
        tf = TypeFactory()
        assert tf.getTypeVoid() is not None
        assert tf.getTypeVoid().getName() == "void"

    def test_setup_core_types(self):
        tf = TypeFactory()
        tf.setupCoreTypes()
        # Check all core types exist
        assert tf.findByName("void") is not None
        assert tf.findByName("bool") is not None
        assert tf.findByName("int4") is not None
        assert tf.findByName("uint4") is not None
        assert tf.findByName("float8") is not None
        assert tf.findByName("char") is not None
        assert tf.findByName("undefined") is not None

    def test_core_type_properties(self):
        tf = TypeFactory()
        tf.setupCoreTypes()
        int4 = tf.findByName("int4")
        assert int4.getSize() == 4
        assert int4.getMetatype() == TYPE_INT
        assert int4.isCoreType()

        ch = tf.findByName("char")
        assert ch.isASCII()
        assert ch.isCharPrint()

        wc = tf.findByName("wchar2")
        assert wc.isUTF16()

    def test_get_base(self):
        tf = TypeFactory()
        t = tf.getBase(4, TYPE_INT, "myint")
        assert t.getSize() == 4
        assert t.getName() == "myint"
        # Same name returns same instance
        t2 = tf.getBase(4, TYPE_INT, "myint")
        assert t2 is t

    def test_get_type_pointer(self):
        tf = TypeFactory()
        tf.setupCoreTypes()
        int4 = tf.findByName("int4")
        ptr = tf.getTypePointer(8, int4)
        assert ptr.getSize() == 8
        assert ptr.getPtrTo() is int4

    def test_get_type_array(self):
        tf = TypeFactory()
        tf.setupCoreTypes()
        int4 = tf.findByName("int4")
        arr = tf.getTypeArray(10, int4)
        assert arr.numElements() == 10
        assert arr.getSize() == 40

    def test_get_type_struct(self):
        tf = TypeFactory()
        s = tf.getTypeStruct("point")
        assert s.getName() == "point"
        assert s.isIncomplete()
        # Same name returns same instance
        s2 = tf.getTypeStruct("point")
        assert s2 is s

    def test_get_type_union(self):
        tf = TypeFactory()
        u = tf.getTypeUnion("val")
        assert u.getName() == "val"
        u2 = tf.getTypeUnion("val")
        assert u2 is u

    def test_get_type_enum(self):
        tf = TypeFactory()
        e = tf.getTypeEnum(4, TYPE_UINT, "color")
        assert e.isEnumType()
        assert e.getName() == "color"

    def test_find_by_id(self):
        tf = TypeFactory()
        t = tf.getBase(4, TYPE_INT, "x")
        found = tf.findById(t.id)
        assert found is t

    def test_clear(self):
        tf = TypeFactory()
        tf.setupCoreTypes()
        tf.clear()
        assert tf.findByName("int4") is None
        assert tf.getTypeVoid() is not None  # void is re-created

    def test_size_config(self):
        tf = TypeFactory()
        assert tf.getSizeOfInt() == 4
        assert tf.getSizeOfLong() == 8
        assert tf.getSizeOfPointer() == 8


# =========================================================================
# CastStrategyC Tests
# =========================================================================

class TestCastStrategyC:
    @pytest.fixture
    def cs(self):
        tf = TypeFactory()
        tf.setupCoreTypes()
        c = CastStrategyC()
        c.setTypeFactory(tf)
        return c, tf

    def test_set_type_factory(self, cs):
        c, tf = cs
        assert c.tlst is tf
        assert c.promoteSize == tf.getSizeOfInt()

    def test_cast_standard_same_type(self, cs):
        c, tf = cs
        int4 = tf.findByName("int4")
        assert c.castStandard(int4, int4, True, True) is None

    def test_cast_standard_different_size(self, cs):
        c, tf = cs
        int4 = tf.findByName("int4")
        int8 = tf.findByName("int8")
        result = c.castStandard(int4, int8, True, True)
        assert result is int4

    def test_cast_standard_int_uint(self, cs):
        c, tf = cs
        int4 = tf.findByName("int4")
        uint4 = tf.findByName("uint4")
        # With care_uint_int=True
        result = c.castStandard(int4, uint4, True, False)
        assert result is int4
        # With care_uint_int=False
        result2 = c.castStandard(int4, uint4, False, False)
        assert result2 is None

    def test_cast_standard_float(self, cs):
        c, tf = cs
        float4 = tf.findByName("float4")
        int4 = tf.findByName("int4")
        result = c.castStandard(float4, int4, False, False)
        assert result is float4

    def test_cast_standard_bool(self, cs):
        c, tf = cs
        b = tf.findByName("bool")
        int1 = tf.findByName("int1")
        result = c.castStandard(b, int1, False, False)
        assert result is b

    def test_cast_standard_ptr_uint(self, cs):
        c, tf = cs
        uint8 = tf.findByName("uint8")
        ptr = tf.getTypePointer(8, tf.findByName("int4"))
        result = c.castStandard(ptr, uint8, False, True)
        assert result is ptr

    def test_is_subpiece_cast(self, cs):
        c, tf = cs
        int4 = tf.findByName("int4")
        int8 = tf.findByName("int8")
        assert c.isSubpieceCast(int4, int8, 0)

    def test_is_sext_cast(self, cs):
        c, tf = cs
        int4 = tf.findByName("int4")
        int8 = tf.findByName("int8")
        assert c.isSextCast(int8, int4)

    def test_is_zext_cast(self, cs):
        c, tf = cs
        uint4 = tf.findByName("uint4")
        uint8 = tf.findByName("uint8")
        assert c.isZextCast(uint8, uint4)


# =========================================================================
# CastStrategyJava Tests
# =========================================================================

class TestCastStrategyJava:
    def test_ptr_to_ptr_no_cast(self):
        tf = TypeFactory()
        tf.setupCoreTypes()
        c = CastStrategyJava()
        c.setTypeFactory(tf)
        int4 = tf.findByName("int4")
        p1 = tf.getTypePointer(8, int4)
        uint4 = tf.findByName("uint4")
        p2 = tf.getTypePointer(8, uint4)
        # Java: ptr-to-ptr casts are suppressed
        result = c.castStandard(p1, p2, True, True)
        assert result is None


# =========================================================================
# Datatype misc
# =========================================================================

class TestDatatypeMisc:
    def test_is_primitive_whole(self):
        t = TypeBase(4, TYPE_INT, "int4")
        assert t.isPrimitiveWhole()
        s = TypeStruct("x", 8)
        assert not s.isPrimitiveWhole()
        a = TypeArray(5, t)
        assert not a.isPrimitiveWhole()

    def test_mark_complete(self):
        s = TypeStruct("x")
        s.flags |= Datatype.type_incomplete
        assert s.isIncomplete()
        s.markComplete()
        assert not s.isIncomplete()

    def test_type_order(self):
        t1 = TypeBase(4, TYPE_INT, "int4")
        assert t1.typeOrder(t1) == 0

    def test_num_depend_base(self):
        t = TypeBase(4, TYPE_INT)
        assert t.numDepend() == 0
        assert t.getDepend(0) is None

    def test_variable_length_flag(self):
        t = TypeBase(4, TYPE_INT, "int4")
        assert not t.isVariableLength()
        t.flags |= Datatype.variable_length
        assert t.isVariableLength()

    def test_opaque_string(self):
        t = TypeBase(4, TYPE_INT, "int4")
        assert not t.isOpaqueString()
        t.flags |= Datatype.opaque_string
        assert t.isOpaqueString()

    def test_get_display_name(self):
        t = TypeBase(4, TYPE_INT, "int4")
        t.displayName = "Integer"
        assert t.getDisplayName() == "Integer"

    def test_get_display_name_fallback(self):
        t = TypeBase(4, TYPE_INT, "int4")
        assert t.getDisplayName() == "int4"
