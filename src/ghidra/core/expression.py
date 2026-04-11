"""
Corresponds to: expression.hh / expression.cc
functionalEquality, BooleanMatch, and related utilities.
"""
from __future__ import annotations
from functools import cmp_to_key
from typing import TYPE_CHECKING, List
from ghidra.core.opcodes import OpCode, get_booleanflip
from ghidra.core.address import signbit_negative, calc_mask
if TYPE_CHECKING:
    from ghidra.ir.varnode import Varnode


# =========================================================================
# PcodeOpNode
# =========================================================================

class PcodeOpNode:
    """An edge in a data-flow path or graph."""

    def __init__(self, op=None, slot: int = 0) -> None:
        self.op = op
        self.slot = slot

    def __lt__(self, other: PcodeOpNode) -> bool:
        if self.op is not other.op:
            return self.op.getSeqNum().getTime() < other.op.getSeqNum().getTime()
        if self.slot != other.slot:
            return self.slot < other.slot
        return False

    @staticmethod
    def compareByHigh(a: PcodeOpNode, b: PcodeOpNode) -> bool:
        """Compare by the HighVariable of the input Varnode."""
        ha = a.op.getIn(a.slot).getHigh()
        hb = b.op.getIn(b.slot).getHigh()
        return id(ha) < id(hb)


# =========================================================================
# TraverseNode
# =========================================================================

class TraverseNode:
    """Node for a forward traversal of a Varnode expression."""

    actionalt = 1
    indirect = 2
    indirectalt = 4
    lsb_truncated = 8
    concat_high = 0x10

    def __init__(self, vn, flags: int = 0) -> None:
        self.vn = vn
        self.flags = flags

    @staticmethod
    def isAlternatePathValid(vn, flags: int) -> bool:
        """Return True if the alternate path looks more valid than the main path."""
        if (flags & (TraverseNode.indirect | TraverseNode.indirectalt)) == TraverseNode.indirect:
            return True
        if (flags & (TraverseNode.indirect | TraverseNode.indirectalt)) == TraverseNode.indirectalt:
            return False
        if (flags & TraverseNode.actionalt) != 0:
            return True
        if vn.loneDescend() is None:
            return False
        op = vn.getDef()
        if op is None:
            return True
        while (hasattr(op, 'isIncidentalCopy') and op.isIncidentalCopy()
               and op.code() == OpCode.CPUI_COPY):
            vn = op.getIn(0)
            if vn.loneDescend() is None:
                return False
            op = vn.getDef()
            if op is None:
                return True
        return not op.isMarker()


class BooleanMatch:
    same = 1
    complementary = 2
    uncorrelated = 3

    @staticmethod
    def varnodeSame(a, b):
        if a is b: return True
        if a.isConstant() and b.isConstant():
            return a.getOffset() == b.getOffset()
        return False

    @staticmethod
    def sameOpComplement(op1, op2):
        opc = op1.code()
        if opc not in (OpCode.CPUI_INT_SLESS, OpCode.CPUI_INT_LESS):
            return False
        cs = 1 if op1.getIn(1).isConstant() else 0
        if not op1.getIn(cs).isConstant(): return False
        if not op2.getIn(1-cs).isConstant(): return False
        if not BooleanMatch.varnodeSame(op1.getIn(1-cs), op2.getIn(cs)):
            return False
        v1 = op1.getIn(cs).getOffset()
        v2 = op2.getIn(1-cs).getOffset()
        if cs != 0: v1, v2 = v2, v1
        if v1 + 1 != v2: return False
        if v2 == 0 and opc == OpCode.CPUI_INT_LESS: return False
        if opc == OpCode.CPUI_INT_SLESS:
            sz = op1.getIn(cs).getSize()
            if signbit_negative(v2, sz) and not signbit_negative(v1, sz):
                return False
        return True

    @staticmethod
    def evaluate(vn1, vn2, depth):
        if vn1 is vn2: return BooleanMatch.same
        if vn1.isWritten():
            op1 = vn1.getDef(); opc1 = op1.code()
            if opc1 == OpCode.CPUI_BOOL_NEGATE:
                r = BooleanMatch.evaluate(op1.getIn(0), vn2, depth)
                return {BooleanMatch.same: BooleanMatch.complementary,
                        BooleanMatch.complementary: BooleanMatch.same}.get(r, r)
        else:
            op1 = None; opc1 = OpCode.CPUI_MAX
        if vn2.isWritten():
            op2 = vn2.getDef(); opc2 = op2.code()
            if opc2 == OpCode.CPUI_BOOL_NEGATE:
                r = BooleanMatch.evaluate(vn1, op2.getIn(0), depth)
                return {BooleanMatch.same: BooleanMatch.complementary,
                        BooleanMatch.complementary: BooleanMatch.same}.get(r, r)
        else:
            return BooleanMatch.uncorrelated
        if op1 is None: return BooleanMatch.uncorrelated
        if not op1.isBoolOutput() or not op2.isBoolOutput():
            return BooleanMatch.uncorrelated
        bools = {OpCode.CPUI_BOOL_AND, OpCode.CPUI_BOOL_OR, OpCode.CPUI_BOOL_XOR}
        if depth != 0 and opc1 in bools and opc2 in bools:
            ok = (opc1 == opc2 or {opc1,opc2} == {OpCode.CPUI_BOOL_AND, OpCode.CPUI_BOOL_OR})
            if ok:
                p1 = BooleanMatch.evaluate(op1.getIn(0), op2.getIn(0), depth-1)
                if p1 == BooleanMatch.uncorrelated:
                    p1 = BooleanMatch.evaluate(op1.getIn(0), op2.getIn(1), depth-1)
                    if p1 == BooleanMatch.uncorrelated: return BooleanMatch.uncorrelated
                    p2 = BooleanMatch.evaluate(op1.getIn(1), op2.getIn(0), depth-1)
                else:
                    p2 = BooleanMatch.evaluate(op1.getIn(1), op2.getIn(1), depth-1)
                if p2 == BooleanMatch.uncorrelated: return BooleanMatch.uncorrelated
                if opc1 == opc2:
                    if p1 == BooleanMatch.same and p2 == BooleanMatch.same:
                        return BooleanMatch.same
                    if opc1 == OpCode.CPUI_BOOL_XOR:
                        if p1 == BooleanMatch.complementary and p2 == BooleanMatch.complementary:
                            return BooleanMatch.same
                        return BooleanMatch.complementary
                else:
                    if p1 == BooleanMatch.complementary and p2 == BooleanMatch.complementary:
                        return BooleanMatch.complementary
        else:
            if opc1 == opc2:
                ok = all(BooleanMatch.varnodeSame(op1.getIn(i), op2.getIn(i))
                         for i in range(op1.numInput()))
                if ok: return BooleanMatch.same
                if BooleanMatch.sameOpComplement(op1, op2):
                    return BooleanMatch.complementary
                return BooleanMatch.uncorrelated
            comp, reorder = get_booleanflip(opc2)
            if opc1 != comp: return BooleanMatch.uncorrelated
            s2 = 1 if reorder else 0
            if not BooleanMatch.varnodeSame(op1.getIn(0), op2.getIn(s2)):
                return BooleanMatch.uncorrelated
            if not BooleanMatch.varnodeSame(op1.getIn(1), op2.getIn(1-s2)):
                return BooleanMatch.uncorrelated
            return BooleanMatch.complementary
        return BooleanMatch.uncorrelated

    _varnodeSame = varnodeSame
    _sameOpComplement = sameOpComplement


class BooleanExpressionMatch:
    """Describes the similarity of boolean conditions between 2 CBRANCH operations."""

    maxDepth = 1

    def __init__(self) -> None:
        self.matchflip: bool = False

    def verifyCondition(self, op, iop) -> bool:
        """Perform the correlation test on two CBRANCH operations."""
        res = BooleanMatch.evaluate(op.getIn(1), iop.getIn(1), self.maxDepth)
        if res == BooleanMatch.uncorrelated:
            return False
        self.matchflip = (res == BooleanMatch.complementary)
        if hasattr(op, 'isBooleanFlip') and op.isBooleanFlip():
            self.matchflip = not self.matchflip
        if hasattr(iop, 'isBooleanFlip') and iop.isBooleanFlip():
            self.matchflip = not self.matchflip
        return True

    def getMultiSlot(self) -> int:
        """Get the MULTIEQUAL slot in the critical path."""
        return -1

    def getFlip(self) -> bool:
        """Return True if the expressions are anti-correlated."""
        return self.matchflip


# =========================================================================
# AdditiveEdge
# =========================================================================

class AdditiveEdge:
    """Class representing a term in an additive expression."""

    def __init__(self, op, slot: int, mult=None) -> None:
        self._op = op
        self._slot = slot
        self._vn = op.getIn(slot)
        self._mult = mult

    def getMultiplier(self):
        """Get the multiplier PcodeOp."""
        return self._mult

    def getOp(self):
        """Get the component PcodeOp adding in the term."""
        return self._op

    def getSlot(self) -> int:
        """Get the slot reading the term."""
        return self._slot

    def getVarnode(self):
        """Get the Varnode term."""
        return self._vn


# =========================================================================
# TermOrder
# =========================================================================

class TermOrder:
    """A class for ordering Varnode terms in an additive expression."""

    def __init__(self, root) -> None:
        self._root = root
        self._terms: List[AdditiveEdge] = []
        self._sorter: List[AdditiveEdge] = []

    def getSize(self) -> int:
        """Get the number of terms in the expression."""
        return len(self._terms)

    def collect(self) -> None:
        """Collect all the terms in the expression."""
        opstack = [self._root]
        multstack = [None]

        while opstack:
            curop = opstack.pop()
            multop = multstack.pop()
            for i in range(curop.numInput()):
                curvn = curop.getIn(i)
                if not curvn.isWritten():
                    self._terms.append(AdditiveEdge(curop, i, multop))
                    continue
                if curvn.loneDescend() is None:
                    self._terms.append(AdditiveEdge(curop, i, multop))
                    continue
                subop = curvn.getDef()
                if subop.code() != OpCode.CPUI_INT_ADD:
                    if (subop.code() == OpCode.CPUI_INT_MULT and
                            subop.getIn(1).isConstant()):
                        addop = subop.getIn(0).getDef()
                        if (addop is not None and
                                addop.code() == OpCode.CPUI_INT_ADD):
                            if addop.getOut().loneDescend() is not None:
                                opstack.append(addop)
                                multstack.append(subop)
                                continue
                    self._terms.append(AdditiveEdge(curop, i, multop))
                    continue
                opstack.append(subop)
                multstack.append(multop)

    def sortTerms(self) -> None:
        """Sort the terms using additiveCompare."""
        self._sorter = list(self._terms)
        self._sorter.sort(
            key=cmp_to_key(
                lambda op1, op2: -1 if TermOrder.additiveCompare(op1, op2)
                else (1 if TermOrder.additiveCompare(op2, op1) else 0)
            )
        )

    def getSort(self) -> List[AdditiveEdge]:
        """Get the sorted list of references."""
        return self._sorter

    @staticmethod
    def additiveCompare(op1: AdditiveEdge, op2: AdditiveEdge) -> bool:
        """Comparison operator for ordering terms in a sum."""
        return op1.getVarnode().termOrder(op2.getVarnode()) == -1


# =========================================================================
# AddExpression
# =========================================================================

class AddExpression:
    """Class for lightweight matching of two additive expressions."""

    class Term:
        """A term in the expression."""
        def __init__(self, vn=None, coeff: int = 0) -> None:
            self.vn = vn
            self.coeff = coeff

        def isEquivalent(self, op2: AddExpression.Term) -> bool:
            """Compare two terms for functional equivalence."""
            if self.coeff != op2.coeff:
                return False
            return functionalEquality(self.vn, op2.vn)

    def __init__(self) -> None:
        self.constval: int = 0
        self.numTerms: int = 0
        self.terms: List[AddExpression.Term] = [AddExpression.Term(), AddExpression.Term()]

    def add(self, vn, coeff: int) -> None:
        """Add a term to the expression."""
        if self.numTerms < 2:
            self.terms[self.numTerms] = AddExpression.Term(vn, coeff)
            self.numTerms += 1

    def gather(self, vn, coeff: int, depth: int) -> None:
        """Gather terms in the expression from a root point."""
        if vn.isConstant():
            self.constval = (self.constval + coeff * vn.getOffset()) & calc_mask(vn.getSize())
            return
        if vn.isWritten():
            op = vn.getDef()
            if op.code() == OpCode.CPUI_INT_ADD:
                if not op.getIn(1).isConstant():
                    depth -= 1
                if depth >= 0:
                    self.gather(op.getIn(0), coeff, depth)
                    self.gather(op.getIn(1), coeff, depth)
                    return
            elif op.code() == OpCode.CPUI_INT_MULT:
                if op.getIn(1).isConstant():
                    coeff = (coeff * op.getIn(1).getOffset()) & calc_mask(vn.getSize())
                    self.gather(op.getIn(0), coeff, depth)
                    return
        self.add(vn, coeff)

    def gatherTwoTermsSubtract(self, a, b) -> None:
        """Walk expression given two roots being subtracted."""
        depth = 1 if (a.isConstant() or b.isConstant()) else 0
        self.gather(a, 1, depth)
        self.gather(b, calc_mask(b.getSize()), depth)

    def gatherTwoTermsAdd(self, a, b) -> None:
        """Walk expression given two roots being added."""
        depth = 1 if (a.isConstant() or b.isConstant()) else 0
        self.gather(a, 1, depth)
        self.gather(b, 1, depth)

    def gatherTwoTermsRoot(self, root) -> None:
        """Gather up to 2 terms given root Varnode."""
        self.gather(root, 1, 1)

    def isEquivalent(self, op2: AddExpression) -> bool:
        """Determine if 2 expressions are equivalent."""
        if self.constval != op2.constval:
            return False
        if self.numTerms != op2.numTerms:
            return False
        if self.numTerms == 1:
            if self.terms[0].isEquivalent(op2.terms[0]):
                return True
        elif self.numTerms == 2:
            if (self.terms[0].isEquivalent(op2.terms[0]) and
                    self.terms[1].isEquivalent(op2.terms[1])):
                return True
            if (self.terms[0].isEquivalent(op2.terms[1]) and
                    self.terms[1].isEquivalent(op2.terms[0])):
                return True
        return False

    _add = add
    _gather = gather


# =========================================================================
# Free functions
# =========================================================================

def _functionalEqualityLevel0(vn1, vn2) -> int:
    """Basic comparison of two Varnodes.

    Returns 0 if same value, -1 if definitely different, 1 if depends on writing ops.
    """
    if vn1 is vn2:
        return 0
    if vn1.getSize() != vn2.getSize():
        return -1
    if vn1.isConstant():
        if vn2.isConstant():
            return 0 if (vn1.getOffset() == vn2.getOffset()) else -1
        return -1
    if vn1.isFree() or vn2.isFree():
        return -1
    return 1


def functionalEqualityLevel(vn1, vn2, res1: list, res2: list) -> int:
    """Try to determine if vn1 and vn2 contain the same value.

    Returns:
        -1 if they do not or can't be immediately verified
         0 if they do hold the same value
        >0 the number of contingent varnode pairs returned in res1/res2
    """
    testval = _functionalEqualityLevel0(vn1, vn2)
    if testval != 1:
        return testval
    if not vn1.isWritten() or not vn2.isWritten():
        return -1
    op1 = vn1.getDef()
    op2 = vn2.getDef()
    opc = op1.code()
    if opc != op2.code():
        return -1
    num = op1.numInput()
    if num != op2.numInput():
        return -1
    if op1.isMarker():
        return -1
    if op2.isCall():
        return -1
    if opc == OpCode.CPUI_LOAD:
        if op1.getAddr() != op2.getAddr():
            return -1
    if num >= 3:
        if opc != OpCode.CPUI_PTRADD:
            return -1
        if op1.getIn(2).getOffset() != op2.getIn(2).getOffset():
            return -1
        num = 2
    # Fill res arrays
    while len(res1) < num:
        res1.append(None)
    while len(res2) < num:
        res2.append(None)
    for i in range(num):
        res1[i] = op1.getIn(i)
        res2[i] = op2.getIn(i)

    testval = _functionalEqualityLevel0(res1[0], res2[0])
    if testval == 0:
        if num == 1:
            return 0
        testval = _functionalEqualityLevel0(res1[1], res2[1])
        if testval == 0:
            return 0
        if testval < 0:
            return -1
        res1[0] = res1[1]
        res2[0] = res2[1]
        return 1
    if num == 1:
        return testval
    testval2 = _functionalEqualityLevel0(res1[1], res2[1])
    if testval2 == 0:
        return testval
    if testval == 1 and testval2 == 1:
        unmatchsize = 2
    else:
        unmatchsize = -1

    if not (hasattr(op1, 'isCommutative') and op1.isCommutative()):
        return unmatchsize
    comm1 = _functionalEqualityLevel0(res1[0], res2[1])
    comm2 = _functionalEqualityLevel0(res1[1], res2[0])
    if comm1 == 0 and comm2 == 0:
        return 0
    if comm1 < 0 or comm2 < 0:
        return unmatchsize
    if comm1 == 0:  # AND (comm2==1)
        res1[0] = res1[1]
        return 1
    if comm2 == 0:  # AND (comm1==1)
        res2[0] = res2[1]
        return 1
    # (comm1==1) AND (comm2==1)
    if unmatchsize == 2:
        return 2
    tmpvn = res2[0]
    res2[0] = res2[1]
    res2[1] = tmpvn
    return 2


def functionalEquality(vn1, vn2) -> bool:
    """Determine if two Varnodes hold the same value."""
    buf1 = [None, None]
    buf2 = [None, None]
    return functionalEqualityLevel(vn1, vn2, buf1, buf2) == 0


def functionalDifference(vn1, vn2, depth: int) -> bool:
    """Return True if vn1 and vn2 are verifiably different values."""
    if vn1 is vn2:
        return False
    if not vn1.isWritten() or not vn2.isWritten():
        if vn1.isConstant() and vn2.isConstant():
            return vn1.getAddr() != vn2.getAddr()
        if vn1.isInput() and vn2.isInput():
            return False
        if vn1.isFree() or vn2.isFree():
            return False
        return True
    op1 = vn1.getDef()
    op2 = vn2.getDef()
    if op1.code() != op2.code():
        return True
    num = op1.numInput()
    if num != op2.numInput():
        return True
    if depth == 0:
        return True
    depth -= 1
    for i in range(num):
        if functionalDifference(op1.getIn(i), op2.getIn(i), depth):
            return True
    return False
