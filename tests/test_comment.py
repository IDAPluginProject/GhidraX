"""Tests for ghidra.database.comment -- Comment + CommentDatabaseInternal + CommentSorter."""
from __future__ import annotations

from ghidra.core.address import Address
from ghidra.core.space import AddrSpace
from ghidra.database.comment import Comment, CommentDatabaseInternal, CommentSorter


def _spc():
    return AddrSpace(name="ram", size=4)


def _addr(off):
    return Address(_spc(), off)


# ---------------------------------------------------------------------------
# Comment
# ---------------------------------------------------------------------------

class TestComment:
    def test_defaults(self):
        c = Comment()
        assert c.getType() == 0
        assert c.getText() == ""
        assert c.getUniq() == 0
        assert c.isEmitted() is False

    def test_construction(self):
        faddr = _addr(0x1000)
        addr = _addr(0x1004)
        c = Comment(tp=Comment.CommentType.user1, funcaddr=faddr, addr=addr, uniq=5, text="hello")
        assert c.getType() == Comment.CommentType.user1
        assert c.getFuncAddr().getOffset() == 0x1000
        assert c.getAddr().getOffset() == 0x1004
        assert c.getUniq() == 5
        assert c.getText() == "hello"

    def test_set_emitted(self):
        c = Comment()
        c.setEmitted(True)
        assert c.isEmitted() is True
        c.setEmitted(False)
        assert c.isEmitted() is False

    def test_set_text(self):
        c = Comment(text="old")
        c.setText("new")
        assert c.getText() == "new"

    def test_encode_comment_type(self):
        assert Comment.encodeCommentType("user1") == 1
        assert Comment.encodeCommentType("header") == 8
        assert Comment.encodeCommentType("warning") == 16
        assert Comment.encodeCommentType("unknown") == 0

    def test_decode_comment_type(self):
        assert Comment.decodeCommentType(1) == "user1"
        assert Comment.decodeCommentType(8) == "header"
        assert Comment.decodeCommentType(3) == "user1|user2"
        assert Comment.decodeCommentType(0) == "none"

    def test_comment_type_enum(self):
        assert Comment.CommentType.user1 == 1
        assert Comment.CommentType.user2 == 2
        assert Comment.CommentType.user3 == 4
        assert Comment.CommentType.header == 8
        assert Comment.CommentType.warning == 16
        assert Comment.CommentType.warningheader == 32


# ---------------------------------------------------------------------------
# CommentDatabaseInternal
# ---------------------------------------------------------------------------

class TestCommentDatabaseInternal:
    def test_empty(self):
        db = CommentDatabaseInternal()
        assert db.getComments(_addr(0x1000)) == []

    def test_add_and_get(self):
        db = CommentDatabaseInternal()
        faddr = _addr(0x1000)
        addr = _addr(0x1004)
        db.addComment(Comment.CommentType.user1, faddr, addr, "test comment")
        comments = db.getComments(faddr)
        assert len(comments) == 1
        assert comments[0].getText() == "test comment"
        assert comments[0].getType() == Comment.CommentType.user1

    def test_add_multiple(self):
        db = CommentDatabaseInternal()
        faddr = _addr(0x1000)
        db.addComment(1, faddr, _addr(0x1004), "a")
        db.addComment(2, faddr, _addr(0x1008), "b")
        assert len(db.getComments(faddr)) == 2

    def test_add_no_duplicate(self):
        db = CommentDatabaseInternal()
        faddr = _addr(0x1000)
        addr = _addr(0x1004)
        assert db.addCommentNoDuplicate(1, faddr, addr, "x") is True
        assert db.addCommentNoDuplicate(1, faddr, addr, "x") is False
        assert len(db.getComments(faddr)) == 1

    def test_clear(self):
        db = CommentDatabaseInternal()
        faddr = _addr(0x1000)
        db.addComment(1, faddr, _addr(0x1004), "c")
        db.clear()
        assert db.getComments(faddr) == []

    def test_clear_type(self):
        db = CommentDatabaseInternal()
        faddr = _addr(0x1000)
        db.addComment(Comment.CommentType.user1, faddr, _addr(0x1004), "a")
        db.addComment(Comment.CommentType.header, faddr, _addr(0x1008), "b")
        db.clearType(faddr, Comment.CommentType.user1)
        comments = db.getComments(faddr)
        assert len(comments) == 1
        assert comments[0].getText() == "b"

    def test_begin_comment(self):
        db = CommentDatabaseInternal()
        faddr = _addr(0x1000)
        db.addComment(1, faddr, _addr(0x1004), "iter_test")
        it = db.beginComment(faddr)
        c = next(it)
        assert c.getText() == "iter_test"

    def test_different_functions(self):
        db = CommentDatabaseInternal()
        f1 = _addr(0x1000)
        f2 = _addr(0x2000)
        db.addComment(1, f1, _addr(0x1004), "func1")
        db.addComment(1, f2, _addr(0x2004), "func2")
        assert len(db.getComments(f1)) == 1
        assert len(db.getComments(f2)) == 1
        assert db.getComments(f1)[0].getText() == "func1"
        assert db.getComments(f2)[0].getText() == "func2"


# ---------------------------------------------------------------------------
# CommentSorter
# ---------------------------------------------------------------------------

class TestCommentEncodeDecode:
    def test_comment_encode(self):
        from ghidra.core.marshal import XmlEncode
        faddr = _addr(0x1000)
        addr = _addr(0x1004)
        c = Comment(tp=Comment.CommentType.user1, funcaddr=faddr, addr=addr, text="hello world")
        enc = XmlEncode(do_format=False)
        c.encode(enc)
        xml = enc.toString()
        assert "<comment" in xml
        assert 'type="user1"' in xml
        assert "<text" in xml

    def test_comment_encode_decode_roundtrip(self):
        from ghidra.core.marshal import XmlEncode, XmlDecode
        from ghidra.core.space import AddrSpaceManager
        from xml.etree.ElementTree import fromstring as xml_fromstring
        spc = _spc()
        mgr = AddrSpaceManager()
        mgr._insertSpace(spc)
        faddr = _addr(0x1000)
        addr = _addr(0x1004)
        c = Comment(tp=Comment.CommentType.warning, funcaddr=faddr, addr=addr, text="danger")
        enc = XmlEncode(do_format=False)
        c.encode(enc)
        xml_str = enc.toString()
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        c2 = Comment()
        c2.decode(dec)
        assert c2.getType() == Comment.CommentType.warning
        assert c2.getText() == "danger"

    def test_commentdb_encode(self):
        from ghidra.core.marshal import XmlEncode
        db = CommentDatabaseInternal()
        db.addComment(1, _addr(0x1000), _addr(0x1004), "first")
        db.addComment(8, _addr(0x1000), _addr(0x1008), "header")
        enc = XmlEncode(do_format=False)
        db.encode(enc)
        xml = enc.toString()
        assert "<commentdb" in xml
        assert "<comment" in xml

    def test_commentdb_encode_decode_roundtrip(self):
        from ghidra.core.marshal import XmlEncode, XmlDecode
        from ghidra.core.space import AddrSpaceManager
        from xml.etree.ElementTree import fromstring as xml_fromstring
        spc = _spc()
        mgr = AddrSpaceManager()
        mgr._insertSpace(spc)
        db = CommentDatabaseInternal()
        db.addComment(1, _addr(0x1000), _addr(0x1004), "alpha")
        db.addComment(8, _addr(0x2000), _addr(0x2004), "beta")
        enc = XmlEncode(do_format=False)
        db.encode(enc)
        xml_str = enc.toString()
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        db2 = CommentDatabaseInternal()
        db2.decode(dec)
        # Should have loaded 2 comments (may be under different func addrs)
        total = sum(len(v) for v in db2._comments.values())
        assert total == 2


class TestCommentSorter:
    def test_empty(self):
        cs = CommentSorter()
        assert cs.hasNext() is False

    def test_setup_with_none(self):
        cs = CommentSorter()
        cs.setupFunctionList(0xFF, None, None)
        assert cs.hasNext() is False
