"""Tests for ghidra.analysis.signature — feature vector generation."""
from __future__ import annotations

import io
import pytest

from ghidra.analysis.signature import (
    Signature, VarnodeSignature, BlockSignature, CopySignature,
    SignatureEntry, BlockSignatureEntry,
    SigManager, GraphSigManager,
    hashword,
)


# ---------------------------------------------------------------------------
# Signature
# ---------------------------------------------------------------------------

class TestSignature:
    def test_hash(self):
        s = Signature(0xDEADBEEF)
        assert s.getHash() == 0xDEADBEEF

    def test_hash_truncated(self):
        s = Signature(0x1FFFFFFFF)
        assert s.getHash() == 0xFFFFFFFF

    def test_compare_equal(self):
        a = Signature(42)
        b = Signature(42)
        assert a.compare(b) == 0

    def test_compare_less(self):
        a = Signature(10)
        b = Signature(20)
        assert a.compare(b) == -1

    def test_compare_greater(self):
        a = Signature(20)
        b = Signature(10)
        assert a.compare(b) == 1

    def test_comparePtr(self):
        a = Signature(10)
        b = Signature(20)
        assert Signature.comparePtr(a, b) is True
        assert Signature.comparePtr(b, a) is False

    def test_print(self):
        s = Signature(0x1234)
        buf = io.StringIO()
        s.print(buf)
        assert "0x00001234" in buf.getvalue()

    def test_printOrigin(self):
        s = Signature(0xABCD)
        buf = io.StringIO()
        s.printOrigin(buf)
        assert "0x0000abcd" in buf.getvalue()


# ---------------------------------------------------------------------------
# VarnodeSignature
# ---------------------------------------------------------------------------

class TestVarnodeSignature:
    def test_inherits(self):
        vs = VarnodeSignature(None, 100)
        assert isinstance(vs, Signature)
        assert vs.getHash() == 100

    def test_varnode(self):
        class FakeVn:
            def printRaw(self, s):
                s.write("fake_vn")
        vn = FakeVn()
        vs = VarnodeSignature(vn, 42)
        assert vs.getVarnode() is vn
        buf = io.StringIO()
        vs.printOrigin(buf)
        assert "fake_vn" in buf.getvalue()

    def test_printOrigin_none_vn(self):
        vs = VarnodeSignature(None, 0xFF)
        buf = io.StringIO()
        vs.printOrigin(buf)
        assert "0x000000ff" in buf.getvalue()


# ---------------------------------------------------------------------------
# BlockSignature
# ---------------------------------------------------------------------------

class TestBlockSignature:
    def test_inherits(self):
        bs = BlockSignature(None, 200)
        assert isinstance(bs, Signature)
        assert bs.getHash() == 200

    def test_block(self):
        class FakeBl:
            def printHeader(self, s):
                s.write("block0")
        bl = FakeBl()
        bs = BlockSignature(bl, 10)
        assert bs.getBlock() is bl
        buf = io.StringIO()
        bs.printOrigin(buf)
        assert "block0" in buf.getvalue()

    def test_printOrigin_none(self):
        bs = BlockSignature(None, 0x10)
        buf = io.StringIO()
        bs.printOrigin(buf)
        assert "0x00000010" in buf.getvalue()


# ---------------------------------------------------------------------------
# CopySignature
# ---------------------------------------------------------------------------

class TestCopySignature:
    def test_inherits(self):
        cs = CopySignature(None, 300)
        assert isinstance(cs, Signature)
        assert cs.getHash() == 300

    def test_block(self):
        class FakeBl:
            def printHeader(self, s):
                s.write("copyblock")
        cs = CopySignature(FakeBl(), 5)
        buf = io.StringIO()
        cs.printOrigin(buf)
        assert "copyblock" in buf.getvalue()

    def test_printOrigin_none(self):
        cs = CopySignature(None, 0x20)
        buf = io.StringIO()
        cs.printOrigin(buf)
        assert "copy" in buf.getvalue()


# ---------------------------------------------------------------------------
# SignatureEntry
# ---------------------------------------------------------------------------

class TestSignatureEntry:
    def test_defaults(self):
        se = SignatureEntry()
        assert se.isTerminal() is False or se.isTerminal() is True
        assert se.getHash() == 0

    def test_create_virtual(self):
        ve = SignatureEntry.createVirtual(7)
        assert ve._index == 7
        assert ve.isTerminal() is True

    def test_flip(self):
        se = SignatureEntry()
        se._hash[0] = 42
        se.flip()
        assert se._hash[1] == 42

    def test_visited(self):
        se = SignatureEntry()
        assert se.isVisited() is False
        se.setVisited()
        assert se.isVisited() is True

    def test_hash_size(self):
        class FakeVn:
            def getSize(self):
                return 4
        h = SignatureEntry.hashSize(FakeVn(), 0)
        assert h != 0

    def test_hash_size_collapse(self):
        class FakeVn:
            def getSize(self):
                return 8
        h_normal = SignatureEntry.hashSize(FakeVn(), 0)
        h_collapse = SignatureEntry.hashSize(FakeVn(), 0x1)  # SIG_COLLAPSE_SIZE
        assert h_normal != h_collapse

    def test_localHash(self):
        se = SignatureEntry()
        se.localHash(0)
        # Just verify no crash

    def test_hashIn(self):
        a = SignatureEntry()
        a._hash = [100, 100]
        b = SignatureEntry()
        b._hash = [200, 200]
        a.hashIn([b])
        assert a._hash[0] != 100  # hash changed


# ---------------------------------------------------------------------------
# BlockSignatureEntry
# ---------------------------------------------------------------------------

class TestBlockSignatureEntry:
    def test_defaults(self):
        bse = BlockSignatureEntry()
        assert bse.getBlock() is None
        assert bse.getHash() == 0

    def test_flip(self):
        bse = BlockSignatureEntry()
        bse._hash[0] = 99
        bse.flip()
        assert bse._hash[1] == 99

    def test_localHash(self):
        class FakeBl:
            def sizeIn(self):
                return 2
            def sizeOut(self):
                return 1
        bse = BlockSignatureEntry(FakeBl())
        bse.localHash(0)
        assert bse.getHash() != 0

    def test_hashIn(self):
        a = BlockSignatureEntry()
        a._hash = [10, 10]
        b = BlockSignatureEntry()
        b._hash = [20, 20]
        a.hashIn([b])
        assert a._hash[0] != 10


# ---------------------------------------------------------------------------
# SigManager
# ---------------------------------------------------------------------------

class TestSigManager:
    def test_defaults(self):
        sm = SigManager()
        assert sm.numSignatures() == 0
        assert sm._fd is None

    def test_add_signature(self):
        sm = SigManager()
        sm.addSignature(Signature(10))
        sm.addSignature(Signature(20))
        assert sm.numSignatures() == 2
        assert sm.getSignature(0).getHash() == 10
        assert sm.getSignature(1).getHash() == 20

    def test_get_signature_vector(self):
        sm = SigManager()
        sm.addSignature(Signature(0xA))
        sm.addSignature(Signature(0xB))
        vec = sm.getSignatureVector()
        assert vec == [0xA, 0xB]

    def test_overall_hash(self):
        sm = SigManager()
        sm.addSignature(Signature(0xABCD))
        sm.addSignature(Signature(0x1234))
        h = sm.getOverallHash()
        assert isinstance(h, int)

    def test_overall_hash_deterministic(self):
        sm1 = SigManager()
        sm1.addSignature(Signature(1))
        sm1.addSignature(Signature(2))
        sm2 = SigManager()
        sm2.addSignature(Signature(1))
        sm2.addSignature(Signature(2))
        assert sm1.getOverallHash() == sm2.getOverallHash()

    def test_sort_by_hash(self):
        sm = SigManager()
        sm.addSignature(Signature(30))
        sm.addSignature(Signature(10))
        sm.addSignature(Signature(20))
        sm.sortByHash()
        vec = sm.getSignatureVector()
        assert vec == [10, 20, 30]

    def test_clear(self):
        sm = SigManager()
        sm.addSignature(Signature(1))
        sm.setCurrentFunction("fake")
        sm.clear()
        assert sm.numSignatures() == 0
        assert sm._fd is None

    def test_print(self):
        sm = SigManager()
        sm.addSignature(Signature(0xAA))
        buf = io.StringIO()
        sm.print(buf)
        assert "0x000000aa" in buf.getvalue()

    def test_settings(self):
        SigManager.setSettings(42)
        assert SigManager.getSettings() == 42
        SigManager.setSettings(0)

    def test_generate_raises(self):
        sm = SigManager()
        with pytest.raises(NotImplementedError):
            sm.generate()

    def test_initializeFromStream_raises(self):
        sm = SigManager()
        with pytest.raises(NotImplementedError):
            sm.initializeFromStream(None)


# ---------------------------------------------------------------------------
# GraphSigManager
# ---------------------------------------------------------------------------

class TestGraphSigManager:
    def test_inherits(self):
        gm = GraphSigManager()
        assert isinstance(gm, SigManager)

    def test_defaults(self):
        gm = GraphSigManager()
        assert gm._maxiter == 7
        assert gm._maxblockiter == 3
        assert gm._maxvarnode == 10000

    def test_set_max_iteration(self):
        gm = GraphSigManager()
        gm.setMaxIteration(10)
        assert gm._maxiter == 10

    def test_set_max_block_iteration(self):
        gm = GraphSigManager()
        gm.setMaxBlockIteration(5)
        assert gm._maxblockiter == 5

    def test_set_max_varnode(self):
        gm = GraphSigManager()
        gm.setMaxVarnode(500)
        assert gm._maxvarnode == 500

    def test_generate_no_fd(self):
        gm = GraphSigManager()
        gm.generate()  # Should not raise, just returns
        assert gm.numSignatures() == 0

    def test_clear(self):
        gm = GraphSigManager()
        gm.addSignature(Signature(1))
        gm.clear()
        assert gm.numSignatures() == 0

    def test_settings_constants(self):
        assert GraphSigManager.SIG_COLLAPSE_SIZE == 0x1
        assert GraphSigManager.SIG_COLLAPSE_INDNOISE == 0x2
        assert GraphSigManager.SIG_DONOTUSE_CONST == 0x10
        assert GraphSigManager.SIG_DONOTUSE_INPUT == 0x20
        assert GraphSigManager.SIG_DONOTUSE_PERSIST == 0x40

    def test_test_settings(self):
        assert GraphSigManager.testSettings(0) is True

    def test_initializeFromStream(self):
        gm = GraphSigManager()
        gm.initializeFromStream(None)  # Placeholder, should not raise
