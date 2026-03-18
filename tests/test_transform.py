"""Tests for ghidra.transform.transform – Python port of transform.cc."""
from __future__ import annotations

import pytest
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

from ghidra.core.error import LowlevelError
from ghidra.transform.transform import (
    LanedRegister, LanedIterator, LaneDescription,
    TransformVar, TransformOp, TransformManager,
)


# =========================================================================
# Tests – LanedIterator
# =========================================================================

class TestLanedIterator:
    def test_empty_mask(self):
        it = LanedIterator(0)
        assert list(it) == []

    def test_single_lane(self):
        # bit 2 set => lane size 2
        assert list(LanedIterator(0b100)) == [2]

    def test_multiple_lanes(self):
        # bits 1, 2, 4 set => sizes 1, 2, 4
        assert list(LanedIterator(0b10110)) == [1, 2, 4]

    def test_contiguous(self):
        # bits 0,1,2,3 set
        assert list(LanedIterator(0b1111)) == [0, 1, 2, 3]


# =========================================================================
# Tests – LanedRegister
# =========================================================================

class TestLanedRegister:
    def test_init_default(self):
        lr = LanedRegister()
        assert lr.getWholeSize() == 0
        assert lr.getSizeBitMask() == 0

    def test_add_lane_size(self):
        lr = LanedRegister(16)
        lr.addLaneSize(4)
        lr.addLaneSize(8)
        assert lr.allowedLane(4)
        assert lr.allowedLane(8)
        assert not lr.allowedLane(2)

    def test_parse_sizes(self):
        lr = LanedRegister()
        lr.parseSizes(16, "1,2,4,8")
        assert lr.getWholeSize() == 16
        assert lr.allowedLane(1)
        assert lr.allowedLane(2)
        assert lr.allowedLane(4)
        assert lr.allowedLane(8)
        assert not lr.allowedLane(3)

    def test_parse_sizes_hex(self):
        lr = LanedRegister()
        lr.parseSizes(16, "0x2,0x4")
        assert lr.allowedLane(2)
        assert lr.allowedLane(4)

    def test_parse_sizes_bad(self):
        lr = LanedRegister()
        with pytest.raises(LowlevelError, match="Bad lane size"):
            lr.parseSizes(16, "17")

    def test_iteration(self):
        lr = LanedRegister(16)
        lr.addLaneSize(2)
        lr.addLaneSize(4)
        sizes = list(lr)
        assert sizes == [2, 4]

    def test_constructor_with_mask(self):
        lr = LanedRegister(8, 0b10100)  # sizes 2 and 4
        assert lr.allowedLane(2)
        assert lr.allowedLane(4)
        assert not lr.allowedLane(1)


# =========================================================================
# Tests – LaneDescription
# =========================================================================

class TestLaneDescription:
    def test_uniform_lanes(self):
        ld = LaneDescription(8, 2)  # 8 bytes, 2-byte lanes
        assert ld.getNumLanes() == 4
        assert ld.getWholeSize() == 8
        for i in range(4):
            assert ld.getSize(i) == 2
            assert ld.getPosition(i) == i * 2

    def test_two_lane(self):
        ld = LaneDescription(8, 3, 5)  # lo=3, hi=5
        assert ld.getNumLanes() == 2
        assert ld.getSize(0) == 3
        assert ld.getSize(1) == 5
        assert ld.getPosition(0) == 0
        assert ld.getPosition(1) == 3

    def test_copy(self):
        ld = LaneDescription(8, 2)
        ld2 = LaneDescription.fromCopy(ld)
        assert ld2.getNumLanes() == ld.getNumLanes()
        assert ld2.getWholeSize() == ld.getWholeSize()
        # Verify independence
        ld2.laneSize[0] = 999
        assert ld.laneSize[0] == 2

    def test_get_boundary(self):
        ld = LaneDescription(8, 2)  # positions: 0, 2, 4, 6
        assert ld.getBoundary(0) == 0
        assert ld.getBoundary(2) == 1
        assert ld.getBoundary(4) == 2
        assert ld.getBoundary(6) == 3
        assert ld.getBoundary(8) == 4  # past end = numLanes
        assert ld.getBoundary(1) == -1  # not on boundary
        assert ld.getBoundary(-1) == -1
        assert ld.getBoundary(9) == -1

    def test_subset_identity(self):
        ld = LaneDescription(8, 2)
        assert ld.subset(0, 8) is True
        assert ld.getNumLanes() == 4

    def test_subset_trim(self):
        ld = LaneDescription(8, 2)  # lanes at 0,2,4,6
        assert ld.subset(2, 4) is True  # keep lanes at 2,4 (indices 1,2)
        assert ld.getNumLanes() == 2
        assert ld.getWholeSize() == 4
        assert ld.getPosition(0) == 0
        assert ld.getPosition(1) == 2

    def test_subset_misaligned(self):
        ld = LaneDescription(8, 2)
        assert ld.subset(1, 4) is False  # doesn't align

    def test_restriction_valid(self):
        ld = LaneDescription(8, 2)  # 4 lanes
        ok, nLanes, skip = ld.restriction(4, 0, 2, 4)
        assert ok is True
        assert nLanes == 2
        assert skip == 1

    def test_restriction_invalid(self):
        ld = LaneDescription(8, 2)
        ok, _, _ = ld.restriction(4, 0, 1, 4)  # misaligned
        assert ok is False

    def test_extension_valid(self):
        ld = LaneDescription(8, 2)
        ok, nLanes, skip = ld.extension(2, 2, 4, 8)
        assert ok is True
        assert nLanes == 4
        assert skip == 0

    def test_extension_invalid(self):
        ld = LaneDescription(8, 2)
        ok, _, _ = ld.extension(2, 2, 1, 8)  # misaligned
        assert ok is False


# =========================================================================
# Tests – TransformVar
# =========================================================================

class TestTransformVar:
    def test_init(self):
        tv = TransformVar()
        assert tv.vn is None
        assert tv.replacement is None
        assert tv.type == 0
        assert tv.flags == 0

    def test_initialize(self):
        tv = TransformVar()
        tv.initialize(TransformVar.constant, None, 32, 4, 0xFF)
        assert tv.type == TransformVar.constant
        assert tv.byteSize == 4
        assert tv.bitSize == 32
        assert tv.val == 0xFF
        assert tv.defOp is None

    def test_types(self):
        assert TransformVar.piece == 1
        assert TransformVar.preexisting == 2
        assert TransformVar.normal_temp == 3
        assert TransformVar.piece_temp == 4
        assert TransformVar.constant == 5
        assert TransformVar.constant_iop == 6

    def test_flags(self):
        assert TransformVar.split_terminator == 1
        assert TransformVar.input_duplicate == 2


# =========================================================================
# Tests – TransformOp
# =========================================================================

class TestTransformOp:
    def test_init(self):
        top = TransformOp()
        assert top.op is None
        assert top.replacement is None
        assert top.output is None
        assert top.follow is None
        assert len(top.input) == 0

    def test_special_flags(self):
        assert TransformOp.op_replacement == 1
        assert TransformOp.op_preexisting == 2
        assert TransformOp.indirect_creation == 4
        assert TransformOp.indirect_creation_possible_out == 8

    def test_get_in_out(self):
        top = TransformOp()
        tv_out = TransformVar()
        tv_in0 = TransformVar()
        tv_in1 = TransformVar()
        top.output = tv_out
        top.input = [tv_in0, tv_in1]
        assert top.getOut() is tv_out
        assert top.getIn(0) is tv_in0
        assert top.getIn(1) is tv_in1


# =========================================================================
# Tests – TransformManager (lightweight, no Funcdata)
# =========================================================================

class TestTransformManagerLightweight:
    """Tests that don't require a real Funcdata."""

    def test_preexisting_guard_slot0(self):
        rvn = TransformVar()
        rvn.type = TransformVar.constant
        assert TransformManager.preexistingGuard(0, rvn) is True

    def test_preexisting_guard_slot1_piece(self):
        rvn = TransformVar()
        rvn.type = TransformVar.piece
        assert TransformManager.preexistingGuard(1, rvn) is False

    def test_preexisting_guard_slot1_piece_temp(self):
        rvn = TransformVar()
        rvn.type = TransformVar.piece_temp
        assert TransformManager.preexistingGuard(1, rvn) is False

    def test_preexisting_guard_slot1_other(self):
        rvn = TransformVar()
        rvn.type = TransformVar.constant
        assert TransformManager.preexistingGuard(1, rvn) is True

    def test_op_set_input(self):
        top = TransformOp()
        top.input = [None, None]
        tv = TransformVar()
        TransformManager.opSetInput(top, tv, 1)
        assert top.input[1] is tv

    def test_op_set_output(self):
        top = TransformOp()
        tv = TransformVar()
        TransformManager.opSetOutput(top, tv)
        assert top.output is tv
        assert tv.defOp is top


# =========================================================================
# Tests – LaneDescription edge cases
# =========================================================================

class TestLaneDescriptionEdge:
    def test_single_lane(self):
        ld = LaneDescription(4, 4)  # 1 lane of 4 bytes
        assert ld.getNumLanes() == 1
        assert ld.getSize(0) == 4
        assert ld.getPosition(0) == 0

    def test_many_lanes(self):
        ld = LaneDescription(16, 1)  # 16 one-byte lanes
        assert ld.getNumLanes() == 16
        for i in range(16):
            assert ld.getPosition(i) == i
            assert ld.getSize(i) == 1

    def test_boundary_at_whole_size(self):
        ld = LaneDescription(8, 4)
        assert ld.getBoundary(8) == 2

    def test_subset_to_single_lane(self):
        ld = LaneDescription(8, 2)  # 4 lanes
        assert ld.subset(4, 2) is True
        assert ld.getNumLanes() == 1
        assert ld.getWholeSize() == 2

    def test_subset_empty_result(self):
        ld = LaneDescription(8, 2)
        # subset(2, 0) should give 0 lanes
        assert ld.subset(2, 0) is True
        assert ld.getNumLanes() == 0

    def test_restriction_at_edge(self):
        ld = LaneDescription(8, 2)
        ok, nLanes, skip = ld.restriction(4, 0, 0, 8)
        assert ok is True
        assert nLanes == 4
        assert skip == 0

    def test_extension_at_edge(self):
        ld = LaneDescription(8, 2)
        ok, nLanes, skip = ld.extension(4, 0, 0, 8)
        assert ok is True
        assert nLanes == 4
        assert skip == 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
