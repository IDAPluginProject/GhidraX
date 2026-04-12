"""
Corresponds to: comment.hh / comment.cc

A database interface for high-level language comments.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import IntEnum
from typing import Optional, List, Dict, Tuple

from ghidra.core.address import Address
from ghidra.core.error import LowlevelError


class Comment:
    """A comment attached to a specific function and code address."""

    class CommentType(IntEnum):
        user1 = 1
        user2 = 2
        user3 = 4
        header = 8
        warning = 16
        warningheader = 32

    def __init__(self, tp: int = 0, funcaddr: Optional[Address] = None,
                 addr: Optional[Address] = None, uniq: int = 0, text: str = "") -> None:
        self.type: int = tp
        self.uniq: int = uniq
        self.funcaddr: Address = Address(funcaddr) if funcaddr is not None else Address()
        self.addr: Address = Address(addr) if addr is not None else Address()
        self.text: str = text
        self.emitted: bool = False

    def setEmitted(self, val: bool) -> None:
        self.emitted = val

    def isEmitted(self) -> bool:
        return self.emitted

    def getType(self) -> int:
        return self.type

    def getFuncAddr(self) -> Address:
        return self.funcaddr

    def getAddr(self) -> Address:
        return self.addr

    def getUniq(self) -> int:
        return self.uniq

    def getText(self) -> str:
        return self.text

    def setText(self, txt: str) -> None:
        self.text = txt

    def encode(self, encoder) -> None:
        """Encode this comment as a <comment> element.

        C++ ref: ``Comment::encode``
        """
        from ghidra.core.marshal import ELEM_COMMENT, ELEM_TEXT, ATTRIB_TYPE, ATTRIB_CONTENT
        tpname = Comment.decodeCommentType(self.type)
        encoder.openElement(ELEM_COMMENT)
        encoder.writeString(ATTRIB_TYPE, tpname)
        self.funcaddr.encode(encoder)
        self.addr.encode(encoder)
        encoder.openElement(ELEM_TEXT)
        encoder.writeString(ATTRIB_CONTENT, self.text)
        encoder.closeElement(ELEM_TEXT)
        encoder.closeElement(ELEM_COMMENT)

    def decode(self, decoder) -> None:
        """Decode this comment from a <comment> element.

        C++ ref: ``Comment::decode``
        """
        from ghidra.core.marshal import ELEM_COMMENT, ATTRIB_TYPE, ATTRIB_CONTENT
        self.emitted = False
        self.type = 0
        elemId = decoder.openElement(ELEM_COMMENT)
        self.type = Comment.encodeCommentType(decoder.readString(ATTRIB_TYPE))
        self.funcaddr = Address.decode(decoder)
        self.addr = Address.decode(decoder)
        subId = decoder.peekElement()
        if subId != 0:
            decoder.openElement()
            self.text = decoder.readString(ATTRIB_CONTENT)
            decoder.closeElement(subId)
        decoder.closeElement(elemId)

    @staticmethod
    def encodeCommentType(name: str) -> int:
        if name == "user1":
            return Comment.CommentType.user1
        if name == "user2":
            return Comment.CommentType.user2
        if name == "user3":
            return Comment.CommentType.user3
        if name == "header":
            return Comment.CommentType.header
        if name == "warning":
            return Comment.CommentType.warning
        if name == "warningheader":
            return Comment.CommentType.warningheader
        raise LowlevelError("Unknown comment type: " + name)

    @staticmethod
    def decodeCommentType(val: int) -> str:
        if val == Comment.CommentType.user1:
            return "user1"
        if val == Comment.CommentType.user2:
            return "user2"
        if val == Comment.CommentType.user3:
            return "user3"
        if val == Comment.CommentType.header:
            return "header"
        if val == Comment.CommentType.warning:
            return "warning"
        if val == Comment.CommentType.warningheader:
            return "warningheader"
        raise LowlevelError("Unknown comment type")


class CommentOrder:
    """Compare comments by function address, address, then uniq."""

    def __call__(self, a: Comment, b: Comment) -> bool:
        if a.getFuncAddr() != b.getFuncAddr():
            return a.getFuncAddr() < b.getFuncAddr()
        if a.getAddr() != b.getAddr():
            return a.getAddr() < b.getAddr()
        if a.getUniq() != b.getUniq():
            return a.getUniq() < b.getUniq()
        return False


class CommentDatabase(ABC):
    """An interface to a container of comments."""

    def __init__(self) -> None:
        super().__init__()

    def __del__(self) -> None:
        return None

    @abstractmethod
    def clear(self) -> None: ...

    @abstractmethod
    def clearType(self, fad: Address, tp: int) -> None: ...

    @abstractmethod
    def addComment(self, tp: int, fad: Address, ad: Address, txt: str) -> None: ...

    @abstractmethod
    def addCommentNoDuplicate(self, tp: int, fad: Address, ad: Address, txt: str) -> bool: ...

    @abstractmethod
    def deleteComment(self, com: Comment) -> None: ...

    @abstractmethod
    def beginComment(self, fad: Address): ...

    @abstractmethod
    def endComment(self, fad: Address): ...

    @abstractmethod
    def encode(self, encoder) -> None: ...

    @abstractmethod
    def decode(self, decoder) -> None: ...

    def getComments(self, fad: Address) -> List[Comment]:
        return list(self.beginComment(fad))


class CommentDatabaseInternal(CommentDatabase):
    """In-memory implementation of CommentDatabase."""

    def __init__(self) -> None:
        super().__init__()
        self._commentset: List[Comment] = []
        self._order = CommentOrder()

    def __del__(self) -> None:
        try:
            self.clear()
        except Exception:
            pass

    def _lower_bound(self, probe: Comment) -> int:
        idx = 0
        while idx < len(self._commentset) and self._order(self._commentset[idx], probe):
            idx += 1
        return idx

    def _function_bounds(self, fad: Address) -> Tuple[int, int]:
        testcommbeg = Comment(0, fad, Address(Address.m_minimal), 0, "")
        testcommend = Comment(0, fad, Address(Address.m_maximal), 65535, "")
        return self._lower_bound(testcommbeg), self._lower_bound(testcommend)

    def clear(self) -> None:
        self._commentset.clear()

    def clearType(self, fad: Address, tp: int) -> None:
        start, end = self._function_bounds(fad)
        kept: List[Comment] = []
        for idx, comment in enumerate(self._commentset):
            if start <= idx < end and (comment.getType() & tp) != 0:
                continue
            kept.append(comment)
        self._commentset = kept

    def addComment(self, tp: int, fad: Address, ad: Address, txt: str) -> None:
        newcom = Comment(tp, fad, ad, 65535, txt)
        idx = self._lower_bound(newcom)
        newcom.uniq = 0
        if idx != 0:
            prev = self._commentset[idx - 1]
            if prev.getAddr() == ad and prev.getFuncAddr() == fad:
                newcom.uniq = prev.getUniq() + 1
        self._commentset.insert(idx, newcom)

    def addCommentNoDuplicate(self, tp: int, fad: Address, ad: Address, txt: str) -> bool:
        newcom = Comment(tp, fad, ad, 65535, txt)
        idx = self._lower_bound(newcom)
        newcom.uniq = 0
        scan = idx
        while scan != 0:
            scan -= 1
            cur = self._commentset[scan]
            if cur.getAddr() == ad and cur.getFuncAddr() == fad:
                if cur.getText() == txt:
                    return False
                if newcom.uniq == 0:
                    newcom.uniq = cur.getUniq() + 1
            else:
                break
        self._commentset.insert(idx, newcom)
        return True

    def getComments(self, fad: Address) -> List[Comment]:
        start, end = self._function_bounds(fad)
        return list(self._commentset[start:end])

    def deleteComment(self, com: Comment) -> None:
        """Delete a specific comment from the database.

        C++ ref: CommentDatabaseInternal::deleteComment
        """
        idx = self._lower_bound(com)
        if idx >= len(self._commentset):
            return
        cur = self._commentset[idx]
        if self._order(cur, com) or self._order(com, cur):
            return
        del self._commentset[idx]

    def encode(self, encoder) -> None:
        """Encode the entire comment database.

        C++ ref: ``CommentDatabaseInternal::encode``
        """
        from ghidra.core.marshal import ELEM_COMMENTDB
        encoder.openElement(ELEM_COMMENTDB)
        for comm in self._commentset:
            comm.encode(encoder)
        encoder.closeElement(ELEM_COMMENTDB)

    def decode(self, decoder) -> None:
        """Decode the entire comment database.

        C++ ref: ``CommentDatabaseInternal::decode``
        """
        from ghidra.core.marshal import ELEM_COMMENTDB
        elemId = decoder.openElement(ELEM_COMMENTDB)
        while decoder.peekElement() != 0:
            comm = Comment()
            comm.decode(decoder)
            self.addComment(comm.getType(), comm.getFuncAddr(), comm.getAddr(), comm.getText())
        decoder.closeElement(elemId)

    def beginComment(self, fad: Address):
        return iter(self.getComments(fad))

    def endComment(self, fad: Address):
        return None


class CommentSorter:
    """Sort comments into and within basic blocks for display.

    Corresponds to CommentSorter in comment.hh/cc.
    """

    header_basic = 0
    header_unplaced = 1

    class Subsort:
        def __init__(self) -> None:
            self.index = 0
            self.order = 0
            self.pos = 0

        def __lt__(self, op2: CommentSorter.Subsort) -> bool:
            if self.index == op2.index:
                if self.order == op2.order:
                    return self.pos < op2.pos
                return self.order < op2.order
            return self.index < op2.index

        def setHeader(self, headerType: int) -> None:
            self.index = -1
            self.order = headerType

        def setBlock(self, i: int, ord: int) -> None:
            self.index = i
            self.order = ord

        def copy(self) -> CommentSorter.Subsort:
            res = CommentSorter.Subsort()
            res.index = self.index
            res.order = self.order
            res.pos = self.pos
            return res

    def __init__(self) -> None:
        self._commmap: List[Tuple[CommentSorter.Subsort, Comment]] = []
        self._start_idx: int = 0
        self._stop_idx: int = 0
        self._opstop_idx: int = 0
        self.displayUnplacedComments: bool = False

    def _lower_bound(self, subsort: CommentSorter.Subsort) -> int:
        idx = 0
        while idx < len(self._commmap) and self._commmap[idx][0] < subsort:
            idx += 1
        return idx

    def _upper_bound(self, subsort: CommentSorter.Subsort) -> int:
        idx = 0
        while idx < len(self._commmap):
            if subsort < self._commmap[idx][0]:
                break
            idx += 1
        return idx

    @staticmethod
    def _all_ops(fd) -> List:
        if not hasattr(fd, "beginOpAll"):
            return []
        opiter = fd.beginOpAll()
        if opiter is None:
            return []
        return list(opiter)

    def findPosition(self, subsort: CommentSorter.Subsort, comm: Comment, fd) -> bool:
        """Figure out position of given Comment and initialize its key.

        C++ ref: CommentSorter::findPosition
        Returns True if the Comment could be positioned.
        """
        if comm.getType() == 0:
            return False
        fad = fd.getAddress()
        ctype = comm.getType()
        if (ctype & (Comment.CommentType.header | Comment.CommentType.warningheader)) != 0 and comm.getAddr() == fad:
            subsort.setHeader(CommentSorter.header_basic)
            return True

        backupOp = None
        ops = self._all_ops(fd)
        op_index = None
        for idx, op in enumerate(ops):
            if op.getAddr() >= comm.getAddr():
                op_index = idx
                break
        if op_index is not None:
            op = ops[op_index]
            block = op.getParent()
            if block is None:
                raise LowlevelError("Dead op reaching CommentSorter")
            if block.contains(comm.getAddr()):
                subsort.setBlock(block.getIndex(), op.getSeqNum().getOrder())
                return True
            if comm.getAddr() == op.getAddr():
                backupOp = op

        prev_index = len(ops) - 1 if op_index is None else op_index - 1
        if prev_index >= 0:
            op = ops[prev_index]
            block = op.getParent()
            if block is None:
                raise LowlevelError("Dead op reaching CommentSorter")
            if block.contains(comm.getAddr()):
                subsort.setBlock(block.getIndex(), 0xFFFFFFFF)
                return True
        if backupOp is not None:
            parent = backupOp.getParent()
            if parent is None:
                raise LowlevelError("Dead op reaching CommentSorter")
            subsort.setBlock(parent.getIndex(), backupOp.getSeqNum().getOrder())
            return True

        if len(ops) == 0:
            subsort.setBlock(0, 0)
            return True

        if self.displayUnplacedComments:
            subsort.setHeader(CommentSorter.header_unplaced)
            return True

        return False

    def setupFunctionList(self, tp: int, fd, db, displayUnplaced: bool = False) -> None:
        """Collect all comments for a function and sort by block position.

        C++ ref: CommentSorter::setupFunctionList
        """
        self._commmap.clear()
        self._start_idx = 0
        self._stop_idx = 0
        self._opstop_idx = 0
        self.displayUnplacedComments = displayUnplaced
        if tp == 0:
            return
        funcaddr = fd.getAddress()
        comments = db.getComments(funcaddr)
        subsort = CommentSorter.Subsort()
        subsort.pos = 0
        for comm in comments:
            if self.findPosition(subsort, comm, fd):
                comm.setEmitted(False)
                self._commmap.append((subsort.copy(), comm))
                subsort.pos += 1
        self._commmap.sort(key=lambda item: item[0])
        self._stop_idx = len(self._commmap)
        self._opstop_idx = self._stop_idx

    def setupBlockList(self, bl) -> None:
        """Prepare to walk comments from a single basic block."""
        if bl is None:
            self._start_idx = self._stop_idx = self._opstop_idx = 0
            return
        subsort = CommentSorter.Subsort()
        subsort.setBlock(bl.getIndex(), 0)
        subsort.pos = 0
        self._start_idx = self._lower_bound(subsort)
        subsort.order = 0xFFFFFFFF
        subsort.pos = 0xFFFFFFFF
        self._stop_idx = self._upper_bound(subsort)
        self._opstop_idx = self._stop_idx

    def setupOpList(self, op) -> None:
        """Establish a p-code landmark within the current set of comments."""
        if op is None:
            self._opstop_idx = self._stop_idx
            return
        subsort = CommentSorter.Subsort()
        subsort.setBlock(op.getParent().getIndex(), op.getSeqNum().getOrder())
        subsort.pos = 0xFFFFFFFF
        self._opstop_idx = self._upper_bound(subsort)

    def setupHeader(self, headerType: int) -> None:
        """Prepare to walk comments in the header."""
        subsort = CommentSorter.Subsort()
        subsort.setHeader(headerType)
        subsort.pos = 0
        self._start_idx = self._lower_bound(subsort)
        subsort.pos = 0xFFFFFFFF
        self._opstop_idx = self._upper_bound(subsort)
        self._stop_idx = self._opstop_idx

    def hasNext(self) -> bool:
        return self._start_idx < self._opstop_idx

    def getNext(self) -> Comment:
        key, comment = self._commmap[self._start_idx]
        self._start_idx += 1
        return comment
