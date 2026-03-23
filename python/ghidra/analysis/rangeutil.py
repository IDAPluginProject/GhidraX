"""
Corresponds to: rangeutil.hh / rangeutil.cc

CircleRange class for manipulating integer value ranges.
Represents a circular range [left, right) over integers mod 2^n.
Used by jump-table recovery, guard analysis, and value set analysis.
"""

from __future__ import annotations
from typing import Optional, Tuple
from ghidra.core.address import calc_mask
from ghidra.core.opcodes import OpCode


class CircleRange:
    """A circular integer range [left, right) mod 2^n with optional step.

    The range wraps around: if left > right, the range covers
    [left, 2^n) union [0, right). An empty range has isempty=True.
    A full range has left == right and step == 1.
    """

    _arrange = "gcgbegdagggggggeggggcgbggggggggcdfgggggggegdggggbgggfggggcgbegda"

    @staticmethod
    def _encodeRangeOverlaps(op1left: int, op1right: int, op2left: int, op2right: int) -> str:
        """Encode the overlap category of two ranges as a character code."""
        val = 0x20 if (op1left <= op1right) else 0
        val |= 0x10 if (op1left <= op2left) else 0
        val |= 0x8 if (op1left <= op2right) else 0
        val |= 4 if (op1right <= op2left) else 0
        val |= 2 if (op1right <= op2right) else 0
        val |= 1 if (op2left <= op2right) else 0
        return CircleRange._arrange[val]

    @staticmethod
    def _newStride(mask: int, step: int, oldStep: int, rem: int, myleft: int, myright: int):
        """Increase the stride of a range. Returns (empty, newleft, newright)."""
        if oldStep != 1:
            oldRem = myleft % oldStep
            if oldRem != (rem % oldStep):
                return True, myleft, myright
        origOrder = (myleft < myright)
        leftRem = myleft % step
        rightRem = myright % step
        if leftRem > rem:
            myleft += rem + step - leftRem
        else:
            myleft += rem - leftRem
        if rightRem > rem:
            myright += rem + step - rightRem
        else:
            myright += rem - rightRem
        myleft &= mask
        myright &= mask
        newOrder = (myleft < myright)
        if origOrder != newOrder:
            return True, myleft, myright
        return False, myleft, myright

    @staticmethod
    def _newDomain(newMask: int, newStep: int, myleft: int, myright: int):
        """Truncate range to fit in a new domain. Returns (empty, newleft, newright)."""
        rem = myleft % newStep if newStep != 1 else 0
        if myleft > newMask:
            if myright > newMask:
                if myleft < myright:
                    return True, myleft, myright
                myleft = rem
                myright = rem
                return False, myleft, myright
            myleft = rem
        if myright > newMask:
            myright = rem
        if myleft == myright:
            myleft = rem
            myright = rem
        return False, myleft, myright

    def __init__(self, left: int = 0, right: int = 0,
                 size: int = 0, step: int = 1) -> None:
        if size == 0:
            self._left: int = 0
            self._right: int = 0
            self._mask: int = 0
            self._isempty: bool = True
            self._step: int = 1
        else:
            self._mask = calc_mask(size)
            self._step = step
            self._left = left & self._mask
            self._right = right & self._mask
            self._isempty = False
            self._normalize()

    @classmethod
    def fromSingle(cls, val: int, size: int) -> CircleRange:
        """Construct a range containing a single value."""
        r = cls.__new__(cls)
        r._mask = calc_mask(size)
        r._step = 1
        r._left = val & r._mask
        r._right = (val + 1) & r._mask
        r._isempty = False
        return r

    @classmethod
    def fromBool(cls, val: bool) -> CircleRange:
        """Construct a boolean range (0 or 1)."""
        r = cls.__new__(cls)
        r._mask = 0xFF
        r._step = 1
        r._isempty = False
        if val:
            r._left = 1
            r._right = 2
        else:
            r._left = 0
            r._right = 1
        return r

    @classmethod
    def empty(cls) -> CircleRange:
        """Construct an empty range."""
        r = cls.__new__(cls)
        r._left = 0
        r._right = 0
        r._mask = 0
        r._isempty = True
        r._step = 1
        return r

    @classmethod
    def full(cls, size: int) -> CircleRange:
        """Construct a full range covering all values for the given byte size."""
        r = cls.__new__(cls)
        r._mask = calc_mask(size)
        r._step = 1
        r._left = 0
        r._right = 0
        r._isempty = False
        return r

    def _normalize(self) -> None:
        """Normalize the representation of full sets."""
        if self._isempty:
            return
        if self._left == self._right:
            if self._step != 1:
                self._left = self._left % self._step
            else:
                self._left = 0
            self._right = self._left

    def setRange(self, left: int, right: int, size: int, step: int = 1) -> None:
        self._mask = calc_mask(size)
        self._step = step
        self._left = left & self._mask
        self._right = right & self._mask
        self._isempty = False

    def setFull(self, size: int) -> None:
        self._mask = calc_mask(size)
        self._step = 1
        self._left = 0
        self._right = 0
        self._isempty = False

    def isEmpty(self) -> bool:
        return self._isempty

    def isFull(self) -> bool:
        return not self._isempty and self._step == 1 and self._left == self._right

    def isSingle(self) -> bool:
        return not self._isempty and self._right == ((self._left + self._step) & self._mask)

    def getMin(self) -> int:
        return self._left

    def getMax(self) -> int:
        return (self._right - self._step) & self._mask

    def getEnd(self) -> int:
        return self._right

    def getMask(self) -> int:
        return self._mask

    def getStep(self) -> int:
        return self._step

    def getSize(self) -> int:
        """Get the number of elements in this range."""
        if self._isempty:
            return 0
        if self._left == self._right:
            return (self._mask + 1) // self._step
        if self._right > self._left:
            return (self._right - self._left) // self._step
        return ((self._mask + 1) - self._left + self._right) // self._step

    def getMaxInfo(self) -> int:
        """Get maximum information content of range in bits."""
        sz = self.getSize()
        if sz == 0:
            return 0
        bits = 0
        while sz > 1:
            sz >>= 1
            bits += 1
        return bits

    def __eq__(self, other) -> bool:
        if not isinstance(other, CircleRange):
            return NotImplemented
        if self._isempty and other._isempty:
            return True
        if self._isempty != other._isempty:
            return False
        return (self._left == other._left and self._right == other._right and
                self._mask == other._mask and self._step == other._step)

    def getNext(self, val: int) -> Tuple[int, bool]:
        """Advance val by step. Returns (new_val, still_in_range)."""
        val = (val + self._step) & self._mask
        return val, val != self._right

    def contains(self, val_or_range) -> bool:
        """Check if a value or range is contained in this range."""
        if isinstance(val_or_range, CircleRange):
            op2 = val_or_range
            if self._isempty:
                return op2._isempty
            if op2._isempty:
                return True
            if self._step > op2._step:
                if not op2.isSingle():
                    return False
            if self._left == self._right:
                return True
            if op2._left == op2._right:
                return False
            if self._left % self._step != op2._left % self._step:
                return False
            if self._left == op2._left and self._right == op2._right:
                return True
            overlapCode = CircleRange._encodeRangeOverlaps(self._left, self._right, op2._left, op2._right)
            if overlapCode == 'c':
                return True
            if overlapCode == 'b' and self._right == op2._right:
                return True
            return False
        else:
            if self._isempty:
                return False
            val = val_or_range & self._mask
            if self._step != 1:
                if (self._left % self._step) != (val % self._step):
                    return False
            if self._left < self._right:
                if val < self._left:
                    return False
                if self._right <= val:
                    return False
            elif self._right < self._left:
                if val < self._right:
                    return True
                if val >= self._left:
                    return True
                return False
            return True

    def intersect(self, op2: CircleRange) -> int:
        """Intersect this with another range. Returns 0 on success, 1 if result is 2 pieces, 2 if empty."""
        if self._isempty:
            return 0
        if op2._isempty:
            self._isempty = True
            return 0
        myleft = self._left
        myright = self._right
        op2left = op2._left
        op2right = op2._right
        if self._step < op2._step:
            newStep = op2._step
            rem = op2left % newStep
            empty, myleft, myright = CircleRange._newStride(self._mask, newStep, self._step, rem, myleft, myright)
            if empty:
                self._isempty = True
                return 0
        elif op2._step < self._step:
            newStep = self._step
            rem = myleft % newStep
            empty, op2left, op2right = CircleRange._newStride(op2._mask, newStep, op2._step, rem, op2left, op2right)
            if empty:
                self._isempty = True
                return 0
        else:
            newStep = self._step
        newMask = self._mask & op2._mask
        if self._mask != newMask:
            empty, myleft, myright = CircleRange._newDomain(newMask, newStep, myleft, myright)
            if empty:
                self._isempty = True
                return 0
        elif op2._mask != newMask:
            empty, op2left, op2right = CircleRange._newDomain(newMask, newStep, op2left, op2right)
            if empty:
                self._isempty = True
                return 0
        if myleft == myright:
            self._left = op2left
            self._right = op2right
            retval = 0
        elif op2left == op2right:
            self._left = myleft
            self._right = myright
            retval = 0
        else:
            overlapCode = CircleRange._encodeRangeOverlaps(myleft, myright, op2left, op2right)
            if overlapCode in ('a', 'f'):
                self._isempty = True
                retval = 0
            elif overlapCode == 'b':
                self._left = op2left
                self._right = myright
                if self._left == self._right:
                    self._isempty = True
                retval = 0
            elif overlapCode == 'c':
                self._left = op2left
                self._right = op2right
                retval = 0
            elif overlapCode == 'd':
                self._left = myleft
                self._right = myright
                retval = 0
            elif overlapCode == 'e':
                self._left = myleft
                self._right = op2right
                if self._left == self._right:
                    self._isempty = True
                retval = 0
            elif overlapCode == 'g':
                if myleft == op2right:
                    self._left = op2left
                    self._right = myright
                    if self._left == self._right:
                        self._isempty = True
                    retval = 0
                elif op2left == myright:
                    self._left = myleft
                    self._right = op2right
                    if self._left == self._right:
                        self._isempty = True
                    retval = 0
                else:
                    retval = 2
            else:
                retval = 2
        if retval != 0:
            return retval
        self._mask = newMask
        self._step = newStep
        return 0

    def circleUnion(self, op2: CircleRange) -> int:
        """Union two ranges. Returns 0 on success, 2 if cannot unify."""
        if op2._isempty:
            return 0
        if self._isempty:
            self._left = op2._left
            self._right = op2._right
            self._mask = op2._mask
            self._step = op2._step
            self._isempty = op2._isempty
            return 0
        if self._mask != op2._mask:
            return 2
        aRight = self._right
        bRight = op2._right
        newStep = self._step
        if self._step < op2._step:
            if self.isSingle():
                newStep = op2._step
                aRight = (self._left + newStep) & self._mask
            else:
                return 2
        elif op2._step < self._step:
            if op2.isSingle():
                newStep = self._step
                bRight = (op2._left + newStep) & self._mask
            else:
                return 2
        if newStep != 1:
            rem = self._left % newStep
            if rem != (op2._left % newStep):
                return 2
        else:
            rem = 0
        if self._left == aRight or op2._left == bRight:
            self._left = rem
            self._right = rem
            self._step = newStep
            return 0
        overlapCode = CircleRange._encodeRangeOverlaps(self._left, aRight, op2._left, bRight)
        if overlapCode in ('a', 'f'):
            if aRight == op2._left:
                self._right = bRight
                self._step = newStep
                return 0
            if self._left == bRight:
                self._left = op2._left
                self._right = aRight
                self._step = newStep
                return 0
            return 2
        elif overlapCode == 'b':
            self._right = bRight
            self._step = newStep
            return 0
        elif overlapCode == 'c':
            self._right = aRight
            self._step = newStep
            return 0
        elif overlapCode == 'd':
            self._left = op2._left
            self._right = bRight
            self._step = newStep
            return 0
        elif overlapCode == 'e':
            self._left = op2._left
            self._right = aRight
            self._step = newStep
            return 0
        elif overlapCode == 'g':
            self._left = rem
            self._right = rem
            self._step = newStep
            return 0
        return -1

    def invert(self) -> int:
        """Convert to complementary range. Returns 0 on success."""
        if self._isempty:
            self._left = 0
            self._right = 0
            self._isempty = False
            return 0
        if self.isFull():
            self._isempty = True
            return 0
        self._left, self._right = self._right, self._left
        return 0

    def setStride(self, newStep: int, rem: int) -> None:
        """Set a new step on this range."""
        self._step = newStep
        if not self._isempty:
            self._left = (self._left & ~(newStep - 1)) | (rem & (newStep - 1))
            self._left &= self._mask

    def setNZMask(self, nzmask: int, size: int) -> bool:
        """Set the range based on a non-zero mask."""
        self._mask = calc_mask(size)
        self._step = 1
        self._isempty = False
        if nzmask == 0:
            self._left = 0
            self._right = 1
            return True
        self._left = 0
        self._right = (nzmask + 1) & self._mask
        if self._right == 0:
            self._right = 0  # Full range
        return True

    def pullBackUnary(self, opc: int, inSize: int, outSize: int) -> bool:
        """Pull-back this range through a unary operator."""
        from ghidra.core.address import sign_extend_sized
        if self._isempty:
            return True
        if opc == OpCode.CPUI_BOOL_NEGATE:
            if self.convertToBoolean():
                pass
            else:
                self._left = self._left ^ 1
                self._right = self._left + 1
            return True
        elif opc == OpCode.CPUI_COPY:
            return True
        elif opc == OpCode.CPUI_INT_2COMP:
            val = (~self._left + 1 + self._step) & self._mask
            self._left = (~self._right + 1 + self._step) & self._mask
            self._right = val
            return True
        elif opc == OpCode.CPUI_INT_NEGATE:
            val = (~self._left + self._step) & self._mask
            self._left = (~self._right + self._step) & self._mask
            self._right = val
            return True
        elif opc == OpCode.CPUI_INT_ZEXT:
            inMask = calc_mask(inSize)
            rem = self._left % self._step
            zextrange = CircleRange.__new__(CircleRange)
            zextrange._left = rem
            zextrange._right = inMask + 1 + rem
            zextrange._mask = self._mask
            zextrange._step = self._step
            zextrange._isempty = False
            if self.intersect(zextrange) != 0:
                return False
            self._left &= inMask
            self._right &= inMask
            self._mask &= inMask
            return True
        elif opc == OpCode.CPUI_INT_SEXT:
            inMask = calc_mask(inSize)
            rem = self._left & self._step
            sextrange = CircleRange.__new__(CircleRange)
            sextrange._left = (inMask ^ (inMask >> 1)) + rem
            sextrange._right = sign_extend_sized(sextrange._left, inSize, outSize) & self._mask
            sextrange._mask = self._mask
            sextrange._step = self._step
            sextrange._isempty = False
            res = sextrange.intersect(self._makeCopy())
            if res != 0:
                return False
            if not sextrange._isempty:
                return False
            self._left &= inMask
            self._right &= inMask
            self._mask &= inMask
            return True
        return False

    def pullBackBinary(self, opc: int, val: int, slot: int,
                       inSize: int, outSize: int) -> bool:
        """Pull-back this range through a binary operator with one constant input."""
        if self._isempty:
            return True

        if opc == OpCode.CPUI_INT_EQUAL:
            bothTrueFalse = self.convertToBoolean()
            self._mask = calc_mask(inSize)
            if bothTrueFalse:
                return True
            yescomplement = (self._left == 0)
            self._left = val
            self._right = (val + 1) & self._mask
            if yescomplement:
                self.complement()
            return True
        elif opc == OpCode.CPUI_INT_NOTEQUAL:
            bothTrueFalse = self.convertToBoolean()
            self._mask = calc_mask(inSize)
            if bothTrueFalse:
                return True
            yescomplement = (self._left == 0)
            self._left = (val + 1) & self._mask
            self._right = val
            if yescomplement:
                self.complement()
            return True
        elif opc == OpCode.CPUI_INT_LESS:
            bothTrueFalse = self.convertToBoolean()
            self._mask = calc_mask(inSize)
            if bothTrueFalse:
                return True
            yescomplement = (self._left == 0)
            if slot == 0:
                if val == 0:
                    self._isempty = True
                else:
                    self._left = 0
                    self._right = val
            else:
                if val == self._mask:
                    self._isempty = True
                else:
                    self._left = (val + 1) & self._mask
                    self._right = 0
            if yescomplement:
                self.complement()
            return True
        elif opc == OpCode.CPUI_INT_LESSEQUAL:
            bothTrueFalse = self.convertToBoolean()
            self._mask = calc_mask(inSize)
            if bothTrueFalse:
                return True
            yescomplement = (self._left == 0)
            if slot == 0:
                self._left = 0
                self._right = (val + 1) & self._mask
            else:
                self._left = val
                self._right = 0
            if yescomplement:
                self.complement()
            return True
        elif opc == OpCode.CPUI_INT_SLESS:
            bothTrueFalse = self.convertToBoolean()
            self._mask = calc_mask(inSize)
            if bothTrueFalse:
                return True
            yescomplement = (self._left == 0)
            half = (self._mask >> 1) + 1
            if slot == 0:
                if val == half:
                    self._isempty = True
                else:
                    self._left = half
                    self._right = val
            else:
                if val == (self._mask >> 1):
                    self._isempty = True
                else:
                    self._left = (val + 1) & self._mask
                    self._right = half
            if yescomplement:
                self.complement()
            return True
        elif opc == OpCode.CPUI_INT_SLESSEQUAL:
            bothTrueFalse = self.convertToBoolean()
            self._mask = calc_mask(inSize)
            if bothTrueFalse:
                return True
            yescomplement = (self._left == 0)
            half = (self._mask >> 1) + 1
            if slot == 0:
                self._left = half
                self._right = (val + 1) & self._mask
            else:
                self._left = val
                self._right = half
            if yescomplement:
                self.complement()
            return True
        elif opc == OpCode.CPUI_INT_CARRY:
            bothTrueFalse = self.convertToBoolean()
            self._mask = calc_mask(inSize)
            if bothTrueFalse:
                return True
            yescomplement = (self._left == 0)
            if val == 0:
                self._isempty = True
            else:
                self._left = ((self._mask - val) + 1) & self._mask
                self._right = 0
            if yescomplement:
                self.complement()
            return True
        elif opc == OpCode.CPUI_INT_ADD:
            self._left = (self._left - val) & self._mask
            self._right = (self._right - val) & self._mask
            return True
        elif opc == OpCode.CPUI_INT_SUB:
            if slot == 0:
                self._left = (self._left + val) & self._mask
                self._right = (self._right + val) & self._mask
            else:
                self._left = (val - self._left) & self._mask
                self._right = (val - self._right) & self._mask
            return True
        elif opc == OpCode.CPUI_INT_RIGHT:
            if self._step == 1:
                rightBound = (calc_mask(inSize) >> val) + 1
                if ((self._left >= rightBound and self._right >= rightBound and self._left >= self._right)
                        or (self._left == 0 and self._right >= rightBound) or (self._left == self._right)):
                    self._left = 0
                    self._right = 0
                else:
                    if self._left > rightBound:
                        self._left = rightBound
                    if self._right > rightBound:
                        self._right = 0
                    self._left = (self._left << val) & self._mask
                    self._right = (self._right << val) & self._mask
                    if self._left == self._right:
                        self._isempty = True
                return True
            return False
        elif opc == OpCode.CPUI_INT_SRIGHT:
            if self._step == 1:
                rightb = calc_mask(inSize)
                leftb = rightb >> (val + 1)
                rightb = leftb ^ calc_mask(inSize)
                leftb += 1
                if ((self._left >= leftb and self._left <= rightb and self._right >= leftb
                        and self._right <= rightb and self._left >= self._right) or (self._left == self._right)):
                    self._left = 0
                    self._right = 0
                else:
                    if self._left > leftb and self._left < rightb:
                        self._left = leftb
                    if self._right > leftb and self._right < rightb:
                        self._right = rightb
                    self._left = (self._left << val) & self._mask
                    self._right = (self._right << val) & self._mask
                    if self._left == self._right:
                        self._isempty = True
                return True
            return False
        return False

    def translate2Op(self) -> Tuple[int, int, int, int]:
        """Translate range to a comparison op.

        Returns (restype, opc, c, cslot) where restype is:
          0 = success, 1 = full (always true), 2 = cannot represent, 3 = empty
        """
        if self._isempty:
            return (3, 0, 0, 0)
        if self._step != 1:
            return (2, 0, 0, 0)
        if self._right == ((self._left + 1) & self._mask):  # Single value
            return (0, OpCode.CPUI_INT_EQUAL, self._left, 0)
        if self._left == ((self._right + 1) & self._mask):  # All but one
            return (0, OpCode.CPUI_INT_NOTEQUAL, self._right, 0)
        if self._left == self._right:
            return (1, 0, 0, 0)  # Full range
        if self._left == 0:
            return (0, OpCode.CPUI_INT_LESS, self._right, 1)
        if self._right == 0:
            return (0, OpCode.CPUI_INT_LESS, (self._left - 1) & self._mask, 0)
        half = (self._mask >> 1) + 1
        if self._left == half:
            return (0, OpCode.CPUI_INT_SLESS, self._right, 1)
        if self._right == half:
            return (0, OpCode.CPUI_INT_SLESS, (self._left - 1) & self._mask, 0)
        return (2, 0, 0, 0)

    def pullBack(self, op, usenzmask: bool = False):
        """Pull-back through a PcodeOp. Returns (Varnode, constMarkup) or (None, None)."""
        from ghidra.core.address import mostsigbit_set
        constMarkup = None
        if op.numInput() == 1:
            res = op.getIn(0)
            if res.isConstant():
                return (None, None)
            if not self.pullBackUnary(op.code(), res.getSize(), op.getOut().getSize()):
                return (None, None)
        elif op.numInput() == 2:
            slot = 0
            res = op.getIn(slot)
            constvn = op.getIn(1 - slot)
            if res.isConstant():
                slot = 1
                constvn = res
                res = op.getIn(slot)
                if res.isConstant():
                    return (None, None)
            elif not constvn.isConstant():
                return (None, None)
            val = constvn.getOffset()
            opc = op.code()
            if not self.pullBackBinary(opc, val, slot, res.getSize(), op.getOut().getSize()):
                if usenzmask and opc == OpCode.CPUI_SUBPIECE and val == 0:
                    nzmask = res.getNZMask() if hasattr(res, 'getNZMask') else self._mask
                    msbset = mostsigbit_set(nzmask)
                    msbset = (msbset + 8) // 8
                    if op.getOut().getSize() < msbset:
                        return (None, None)
                    else:
                        self._mask = calc_mask(res.getSize())
                else:
                    return (None, None)
            if hasattr(constvn, 'getSymbolEntry') and constvn.getSymbolEntry() is not None:
                constMarkup = constvn
        else:
            return (None, None)

        if usenzmask:
            nzrange = CircleRange.__new__(CircleRange)
            nzrange._mask = 0
            nzrange._isempty = True
            nzrange._step = 1
            nzrange._left = 0
            nzrange._right = 0
            nzmask = res.getNZMask() if hasattr(res, 'getNZMask') else self._mask
            if nzrange.setNZMask(nzmask, res.getSize()):
                self.intersect(nzrange)
        return (res, constMarkup)

    def complement(self) -> None:
        """Set this to the complement of itself."""
        if self._isempty:
            self._left = 0
            self._right = 0
            self._isempty = False
            return
        if self.isFull():
            self._isempty = True
            return
        self._left, self._right = self._right, self._left

    def convertToBoolean(self) -> bool:
        """Convert range to boolean. Returns True if range contains both 0 and 1."""
        if self._isempty:
            return False
        contains_zero = self.contains(0)
        contains_one = self.contains(1)
        self._mask = 0xFF
        self._step = 1
        if contains_zero and contains_one:
            self._left = 0
            self._right = 2
            self._isempty = False
            return True
        elif contains_zero:
            self._left = 0
            self._right = 1
            self._isempty = False
        elif contains_one:
            self._left = 1
            self._right = 2
            self._isempty = False
        else:
            self._isempty = True
        return False

    def _makeCopy(self) -> CircleRange:
        """Return a copy of this range."""
        r = CircleRange.__new__(CircleRange)
        r._left = self._left
        r._right = self._right
        r._mask = self._mask
        r._step = self._step
        r._isempty = self._isempty
        return r

    def minimalContainer(self, op2: CircleRange, maxStep: int) -> bool:
        """Construct minimal range that contains both this and another range.
        Returns True if result is full (everything)."""
        if self._isempty:
            self._left = op2._left
            self._right = op2._right
            self._mask = op2._mask
            self._step = op2._step
            self._isempty = op2._isempty
            return self._left == self._right and not self._isempty
        if op2._isempty:
            return self._left == self._right
        from ghidra.core.address import leastsigbit_set, mostsigbit_set
        if self.isSingle() and op2.isSingle():
            mn = min(self.getMin(), op2.getMin())
            mx = max(self.getMin(), op2.getMin())
            diff = mx - mn
            if 0 < diff <= maxStep:
                if leastsigbit_set(diff) == mostsigbit_set(diff):
                    self._step = diff
                    self._left = mn
                    self._right = (mx + self._step) & self._mask
                    return False
        aRight = (self._right - self._step + 1) & self._mask
        bRight = (op2._right - op2._step + 1) & op2._mask
        self._step = 1
        self._mask |= op2._mask
        overlapCode = CircleRange._encodeRangeOverlaps(self._left, aRight, op2._left, bRight)
        if overlapCode == 'a':
            vacantSize1 = self._left + (self._mask - bRight) + 1
            vacantSize2 = op2._left - aRight
            if vacantSize1 < vacantSize2:
                self._left = op2._left
                self._right = aRight
            else:
                self._right = bRight
        elif overlapCode == 'f':
            vacantSize1 = op2._left + (self._mask - aRight) + 1
            vacantSize2 = self._left - bRight
            if vacantSize1 < vacantSize2:
                self._right = bRight
            else:
                self._left = op2._left
                self._right = aRight
        elif overlapCode == 'b':
            self._right = bRight
        elif overlapCode == 'c':
            self._right = aRight
        elif overlapCode == 'd':
            self._left = op2._left
            self._right = bRight
        elif overlapCode == 'e':
            self._left = op2._left
            self._right = aRight
        elif overlapCode == 'g':
            self._left = 0
            self._right = 0
        self._normalize()
        return self._left == self._right

    def widen(self, op2: CircleRange, leftIsStable: bool) -> None:
        """Widen the unstable bound to match containing range."""
        if self._isempty:
            self._left = op2._left
            self._right = op2._right
            self._mask = op2._mask
            self._step = op2._step
            self._isempty = op2._isempty
            return
        if op2._isempty:
            return
        if leftIsStable:
            lmod = self._left % self._step
            mod = op2._right % self._step
            if mod <= lmod:
                self._right = op2._right + (lmod - mod)
            else:
                self._right = op2._right - (mod - lmod)
            self._right &= self._mask
        else:
            self._left = op2._left & self._mask
        self._normalize()

    def pushForwardUnary(self, opc: int, in1: CircleRange, inSize: int, outSize: int) -> bool:
        """Push-forward through given unary operator."""
        from ghidra.core.address import sign_extend_sized
        if in1._isempty:
            self._isempty = True
            return True
        if opc in (OpCode.CPUI_CAST, OpCode.CPUI_COPY):
            self._left = in1._left
            self._right = in1._right
            self._mask = in1._mask
            self._step = in1._step
            self._isempty = in1._isempty
            return True
        elif opc == OpCode.CPUI_INT_ZEXT:
            self._isempty = False
            self._step = in1._step
            self._mask = calc_mask(outSize)
            if in1._left == in1._right:
                self._left = in1._left % self._step
                self._right = in1._mask + 1 + self._left
            else:
                self._left = in1._left
                self._right = (in1._right - in1._step) & in1._mask
                if self._right < self._left:
                    return False
                self._right += self._step
            return True
        elif opc == OpCode.CPUI_INT_SEXT:
            self._isempty = False
            self._step = in1._step
            self._mask = calc_mask(outSize)
            if in1._left == in1._right:
                rem = in1._left % self._step
                right_val = calc_mask(inSize) >> 1
                self._left = (calc_mask(outSize) ^ right_val) + rem
                self._right = right_val + 1 + rem
            else:
                self._left = sign_extend_sized(in1._left, inSize, outSize) & self._mask
                rval = sign_extend_sized((in1._right - in1._step) & in1._mask, inSize, outSize) & self._mask
                srval = rval if rval < (1 << (outSize * 8 - 1)) else rval - (1 << (outSize * 8))
                slval = self._left if self._left < (1 << (outSize * 8 - 1)) else self._left - (1 << (outSize * 8))
                if srval < slval:
                    return False
                self._right = (rval + self._step) & self._mask
            return True
        elif opc == OpCode.CPUI_INT_2COMP:
            self._isempty = False
            self._step = in1._step
            self._mask = in1._mask
            self._right = ((~in1._left + 1 + self._step) & self._mask)
            self._left = ((~in1._right + 1 + self._step) & self._mask)
            self._normalize()
            return True
        elif opc == OpCode.CPUI_INT_NEGATE:
            self._isempty = False
            self._step = in1._step
            self._mask = in1._mask
            self._left = ((~in1._right + self._step) & self._mask)
            self._right = ((~in1._left + self._step) & self._mask)
            self._normalize()
            return True
        elif opc == OpCode.CPUI_BOOL_NEGATE:
            if in1._isempty:
                self._isempty = True
                return True
            self._mask = 0xFF
            self._step = 1
            if in1.isSingle():
                val = 0 if in1._left != 0 else 1
                self._left = val
                self._right = (val + 1) & self._mask
            else:
                self._left = 0
                self._right = 2
            self._isempty = False
            return True
        return False

    def pushForwardBinary(self, opc: int, in1: CircleRange, in2: CircleRange,
                          inSize: int, outSize: int, maxStep: int) -> bool:
        """Push-forward through given binary operator."""
        from ghidra.core.address import sign_extend, count_leading_zeros
        if in1._isempty or in2._isempty:
            self._isempty = True
            return True
        if opc in (OpCode.CPUI_PTRSUB, OpCode.CPUI_INT_ADD):
            self._isempty = False
            self._mask = in1._mask | in2._mask
            if in1._left == in1._right or in2._left == in2._right:
                self._step = min(in1._step, in2._step)
                self._left = (in1._left + in2._left) % self._step
                self._right = self._left
            elif in2.isSingle():
                self._step = in1._step
                self._left = (in1._left + in2._left) & self._mask
                self._right = (in1._right + in2._left) & self._mask
            elif in1.isSingle():
                self._step = in2._step
                self._left = (in2._left + in1._left) & self._mask
                self._right = (in2._right + in1._left) & self._mask
            else:
                self._step = min(in1._step, in2._step)
                size1 = (in1._right - in1._left) if in1._left < in1._right else (in1._mask - (in1._left - in1._right) + in1._step)
                self._left = (in1._left + in2._left) & self._mask
                self._right = (in1._right - in1._step + in2._right - in2._step + self._step) & self._mask
                sizenew = (self._right - self._left) if self._left < self._right else (self._mask - (self._left - self._right) + self._step)
                if sizenew < size1:
                    self._right = self._left
                self._normalize()
            return True
        elif opc == OpCode.CPUI_INT_MULT:
            self._isempty = False
            self._mask = in1._mask | in2._mask
            if in1.isSingle():
                constVal = in1.getMin()
                self._step = in2._step
            elif in2.isSingle():
                constVal = in2.getMin()
                self._step = in1._step
            else:
                return False
            tmp = constVal & 0xFFFFFFFF
            while self._step < maxStep:
                if (tmp & 1) != 0:
                    break
                self._step <<= 1
                tmp >>= 1
            wholeSize = self._mask.bit_length()
            if in1.getMaxInfo() + in2.getMaxInfo() > wholeSize:
                self._left = (in1._left * in2._left) % self._step
                self._right = self._left
                self._normalize()
                return True
            if (constVal & (self._mask ^ (self._mask >> 1))) != 0:
                self._left = ((in1._right - in1._step) * (in2._right - in2._step)) & self._mask
                self._right = ((in1._left * in2._left) + self._step) & self._mask
            else:
                self._left = (in1._left * in2._left) & self._mask
                self._right = ((in1._right - in1._step) * (in2._right - in2._step) + self._step) & self._mask
            return True
        elif opc == OpCode.CPUI_INT_LEFT:
            if not in2.isSingle():
                return False
            self._isempty = False
            self._mask = in1._mask
            self._step = in1._step
            sa = int(in2.getMin())
            tmp = sa
            while self._step < maxStep and tmp > 0:
                self._step <<= 1
                tmp -= 1
            self._left = (in1._left << sa) & self._mask
            self._right = (in1._right << sa) & self._mask
            wholeSize = self._mask.bit_length()
            if in1.getMaxInfo() + sa > wholeSize:
                self._right = self._left
                self._normalize()
                return True
            return True
        elif opc == OpCode.CPUI_SUBPIECE:
            if not in2.isSingle():
                return False
            self._isempty = False
            sa = int(in2._left) * 8
            self._mask = calc_mask(outSize)
            self._step = in1._step if sa == 0 else 1
            rng = (in1._right - in1._left) if in1._left < in1._right else (in1._left - in1._right)
            if rng == 0 or ((rng >> sa) > self._mask):
                self._left = 0
                self._right = 0
            else:
                self._left = (in1._left >> sa) & self._mask
                self._right = (((in1._right - in1._step) >> sa) + self._step) & self._mask
                self._normalize()
            return True
        elif opc == OpCode.CPUI_INT_RIGHT:
            if not in2.isSingle():
                return False
            self._isempty = False
            sa = int(in2._left)
            self._mask = calc_mask(outSize)
            self._step = 1
            if in1._left < in1._right:
                self._left = in1._left >> sa
                self._right = ((in1._right - in1._step) >> sa) + 1
            else:
                self._left = 0
                self._right = in1._mask >> sa
            if self._left == self._right:
                self._right = (self._left + 1) & self._mask
            return True
        elif opc == OpCode.CPUI_INT_SRIGHT:
            if not in2.isSingle():
                return False
            self._isempty = False
            sa = int(in2._left)
            self._mask = calc_mask(outSize)
            self._step = 1
            bitPos = 8 * inSize - 1
            valLeft = sign_extend(in1._left, bitPos)
            valRight = sign_extend(in1._right, bitPos)
            if valLeft >= valRight:
                valRight = self._mask >> 1
                valLeft = valRight + 1
                valLeft = sign_extend(valLeft, bitPos)
            self._left = (valLeft >> sa) & self._mask
            self._right = (((valRight - in1._step) >> sa) + 1) & self._mask
            if self._left == self._right:
                self._right = (self._left + 1) & self._mask
            return True
        elif opc in (OpCode.CPUI_INT_AND, OpCode.CPUI_INT_OR, OpCode.CPUI_INT_XOR):
            if in1.isSingle() and in2.isSingle():
                self._mask = calc_mask(outSize)
                self._step = 1
                if opc == OpCode.CPUI_INT_AND:
                    val = in1._left & in2._left
                elif opc == OpCode.CPUI_INT_OR:
                    val = in1._left | in2._left
                else:
                    val = in1._left ^ in2._left
                val &= self._mask
                self._left = val
                self._right = (val + 1) & self._mask
                self._isempty = False
                return True
            self.setFull(outSize)
            return True
        elif opc in (OpCode.CPUI_INT_EQUAL, OpCode.CPUI_INT_NOTEQUAL,
                     OpCode.CPUI_INT_SLESS, OpCode.CPUI_INT_SLESSEQUAL,
                     OpCode.CPUI_INT_LESS, OpCode.CPUI_INT_LESSEQUAL,
                     OpCode.CPUI_INT_CARRY, OpCode.CPUI_INT_SCARRY, OpCode.CPUI_INT_SBORROW,
                     OpCode.CPUI_BOOL_XOR, OpCode.CPUI_BOOL_AND, OpCode.CPUI_BOOL_OR,
                     OpCode.CPUI_FLOAT_EQUAL, OpCode.CPUI_FLOAT_NOTEQUAL,
                     OpCode.CPUI_FLOAT_LESS, OpCode.CPUI_FLOAT_LESSEQUAL):
            self._isempty = False
            self._mask = 0xFF
            self._step = 1
            self._left = 0
            self._right = 2
            return True
        elif opc == OpCode.CPUI_INT_SUB:
            self._mask = calc_mask(outSize)
            self._step = max(in1._step, in2._step)
            if in1.isSingle() and in2.isSingle():
                val = (in1._left - in2._left) & self._mask
                self._left = val
                self._right = (val + self._step) & self._mask
            else:
                self.setFull(outSize)
            self._isempty = False
            return True
        return False

    def pushForwardTrinary(self, opc: int, in1: CircleRange, in2: CircleRange,
                           in3: CircleRange, inSize: int, outSize: int, maxStep: int) -> bool:
        """Push-forward through given ternary operator."""
        if opc != OpCode.CPUI_PTRADD:
            return False
        tmpRange = CircleRange()
        if not tmpRange.pushForwardBinary(OpCode.CPUI_INT_MULT, in2, in3, inSize, inSize, maxStep):
            return False
        return self.pushForwardBinary(OpCode.CPUI_INT_ADD, in1, tmpRange, inSize, outSize, maxStep)

    def printRaw(self) -> str:
        if self._isempty:
            return "(empty)"
        if self.isFull():
            return "(full)"
        return f"[0x{self._left:x},0x{self._right:x})"

    def __repr__(self) -> str:
        return f"CircleRange({self.printRaw()})"


# =========================================================================
# ValueSet and related classes
# =========================================================================

class ValueSet:
    """A range of values attached to a Varnode within a data-flow subsystem."""
    MAX_STEP = 32

    class Equation:
        """An external constraint that can be applied to a ValueSet."""
        def __init__(self, slot: int = 0, typeCode: int = 0, rng: CircleRange = None):
            self.slot = slot
            self.typeCode = typeCode
            self.range = rng if rng is not None else CircleRange()

    def __init__(self) -> None:
        self.typeCode: int = 0
        self.numParams: int = 0
        self.count: int = 0
        self.opCode = OpCode.CPUI_COPY
        self.leftIsStable: bool = True
        self.rightIsStable: bool = True
        self.vn = None
        self.range: CircleRange = CircleRange()
        self.equations: list = []
        self.partHead = None
        self.next = None

    def getCount(self) -> int:
        return self.count

    def getTypeCode(self) -> int:
        return self.typeCode

    def getVarnode(self):
        return self.vn

    def getRange(self) -> CircleRange:
        return self.range

    def isLeftStable(self) -> bool:
        return self.leftIsStable

    def isRightStable(self) -> bool:
        return self.rightIsStable

    def getLandMark(self):
        """Get any landmark range."""
        for eq in self.equations:
            if eq.slot == self.numParams:
                return eq.range
        return None

    def setVarnode(self, v, tCode: int) -> None:
        self.vn = v
        self.typeCode = tCode
        if v is not None:
            self.range.setFull(v.getSize())
            v.setValueSet(self)

    def setFull(self) -> None:
        if self.vn is not None:
            self.range.setFull(self.vn.getSize())
        self.typeCode = 0

    def addEquation(self, slot: int, typeCode: int, constraint: CircleRange) -> None:
        self.equations.append(ValueSet.Equation(slot, typeCode, constraint))

    def addLandmark(self, typeCode: int, constraint: CircleRange) -> None:
        self.addEquation(self.numParams, typeCode, constraint)

    def getNext(self):
        return self.next

    def setNext(self, n) -> None:
        self.next = n

    def getPartHead(self):
        return self.partHead

    def setPartHead(self, p) -> None:
        self.partHead = p

    def getEquations(self) -> list:
        return self.equations

    def printRaw(self) -> str:
        return f"ValueSet({self.range.printRaw()}, type={self.typeCode})"


class ValueSetRead:
    """A special form of ValueSet associated with the read point of a Varnode."""

    def __init__(self) -> None:
        self.typeCode: int = 0
        self.slot: int = 0
        self.op = None
        self.range: CircleRange = CircleRange()
        self.equationConstraint: CircleRange = CircleRange()
        self.equationTypeCode: int = 0
        self.leftIsStable: bool = True
        self.rightIsStable: bool = True

    def getTypeCode(self) -> int:
        return self.typeCode

    def getRange(self) -> CircleRange:
        return self.range

    def isLeftStable(self) -> bool:
        return self.leftIsStable

    def isRightStable(self) -> bool:
        return self.rightIsStable

    def setPcodeOp(self, o, slt: int) -> None:
        self.op = o
        self.slot = slt

    def addEquation(self, slt: int, typeCode: int, constraint: CircleRange) -> None:
        self.equationTypeCode = typeCode
        self.equationConstraint = constraint

    def compute(self) -> None:
        """Compute this value set from the underlying Varnode's ValueSet."""
        if self.op is None:
            return
        invn = self.op.getIn(self.slot) if self.slot < self.op.numInput() else None
        if invn is not None and invn.getValueSet() is not None:
            vs = invn.getValueSet()
            self.range = CircleRange(vs.range._left, vs.range._right,
                                     invn.getSize(), vs.range._step)
            self.typeCode = vs.typeCode
            self.leftIsStable = vs.leftIsStable
            self.rightIsStable = vs.rightIsStable

    def getSlot(self) -> int:
        return self.slot

    def getOp(self):
        return self.op

    def printRaw(self) -> str:
        return f"ValueSetRead({self.range.printRaw()})"


class Partition:
    """A range of nodes (within the weak topological ordering) that are iterated together."""

    def __init__(self) -> None:
        self.startNode = None
        self.stopNode = None
        self.isDirty: bool = False

    def getStartNode(self):
        return self.startNode

    def getStopNode(self):
        return self.stopNode

    def setStartNode(self, node) -> None:
        self.startNode = node

    def setStopNode(self, node) -> None:
        self.stopNode = node

    def markDirty(self) -> None:
        self.isDirty = True

    def clear(self) -> None:
        self.startNode = None
        self.stopNode = None
        self.isDirty = False

    def isDirtyFlag(self) -> bool:
        return self.isDirty


class Widener:
    """Class holding a particular widening strategy for the ValueSetSolver iteration."""

    def determineIterationReset(self, valueSet: ValueSet) -> int:
        return 0

    def checkFreeze(self, valueSet: ValueSet) -> bool:
        return False

    def doWidening(self, valueSet: ValueSet, rng: CircleRange, newRange: CircleRange) -> bool:
        return False

    def getWidenCount(self) -> int:
        return 0


class WidenerFull(Widener):
    """Class for doing normal widening.

    C++ ref: ``WidenerFull``
    """

    def __init__(self, wide: int = 2, full: int = 5) -> None:
        self._widenIteration: int = wide
        self._fullIteration: int = full

    def determineIterationReset(self, valueSet: ValueSet) -> int:
        """C++ ref: ``WidenerFull::determineIterationReset``"""
        if valueSet.count >= self._widenIteration:
            return self._widenIteration  # Reset to point just after widening
        return 0  # Delay widening

    def checkFreeze(self, valueSet: ValueSet) -> bool:
        """C++ ref: ``WidenerFull::checkFreeze``"""
        return valueSet.getRange().isFull() if hasattr(valueSet, 'getRange') and hasattr(valueSet.getRange(), 'isFull') else False

    def doWidening(self, valueSet: ValueSet, rng: CircleRange, newRange: CircleRange) -> bool:
        """C++ ref: ``WidenerFull::doWidening``"""
        if valueSet.count < self._widenIteration:
            rng.copyFrom(newRange) if hasattr(rng, 'copyFrom') else None
            return True
        elif valueSet.count == self._widenIteration:
            landmark = valueSet.getLandMark() if hasattr(valueSet, 'getLandMark') else None
            if landmark is not None:
                leftIsStable = rng.getMin() == newRange.getMin() if hasattr(rng, 'getMin') else False
                rng.copyFrom(newRange) if hasattr(rng, 'copyFrom') else None
                if hasattr(landmark, 'contains') and landmark.contains(rng):
                    rng.widen(landmark, leftIsStable)
                    return True
                else:
                    constraint = landmark.clone() if hasattr(landmark, 'clone') else None
                    if constraint is not None and hasattr(constraint, 'invert'):
                        constraint.invert()
                        if hasattr(constraint, 'contains') and constraint.contains(rng):
                            rng.widen(constraint, leftIsStable)
                            return True
        elif valueSet.count < self._fullIteration:
            rng.copyFrom(newRange) if hasattr(rng, 'copyFrom') else None
            return True
        return False  # Constrained widening failed


class WidenerNone(Widener):
    """Class for freezing value sets at a specific iteration.

    C++ ref: ``WidenerNone``
    """

    def __init__(self, freeze: int = 3) -> None:
        self._freezeIteration: int = freeze

    def determineIterationReset(self, valueSet: ValueSet) -> int:
        """C++ ref: ``WidenerNone::determineIterationReset``"""
        if valueSet.count >= self._freezeIteration:
            return self._freezeIteration
        return valueSet.count

    def checkFreeze(self, valueSet: ValueSet) -> bool:
        """C++ ref: ``WidenerNone::checkFreeze``"""
        return valueSet.count >= self._freezeIteration

    def doWidening(self, valueSet: ValueSet, rng: CircleRange, newRange: CircleRange) -> bool:
        """C++ ref: ``WidenerNone::doWidening``"""
        return False


class ValueSetSolver:
    """Class that determines a ValueSet for each Varnode in a data-flow system."""

    def __init__(self) -> None:
        self._valueNodes: list = []
        self._readNodes: dict = {}
        self._orderPartition = Partition()
        self._rootNodes: list = []
        self._depthFirstIndex: int = 0
        self._numIterations: int = 0
        self._maxIterations: int = 0

    def getNumIterations(self) -> int:
        return self._numIterations

    def establishValueSets(self, sinks: list, reads: list, stackReg=None,
                           indirectAsCopy: bool = False) -> None:
        """Build the system of ValueSets from the given sinks."""
        for vn in sinks:
            if vn is None:
                continue
            vs = ValueSet()
            vs.setVarnode(vn, 0)
            self._valueNodes.append(vs)
        for op in reads:
            if op is None:
                continue
            seq = op.getSeqNum()
            vsr = ValueSetRead()
            vsr.setPcodeOp(op, 1)
            self._readNodes[seq] = vsr

    def solve(self, maxIter: int, widener: Widener) -> None:
        """Iterate the ValueSet system until it stabilizes."""
        self._maxIterations = maxIter
        self._numIterations = 0
        # Simple fixed-point iteration
        changed = True
        while changed and self._numIterations < self._maxIterations:
            changed = False
            self._numIterations += 1
            for vs in self._valueNodes:
                vs.count += 1
                if widener.checkFreeze(vs):
                    continue
                # Would compute new range from op inputs here
        # Compute read nodes
        for seq, vsr in self._readNodes.items():
            vsr.compute()

    def getValueSetRead(self, seq):
        """Get ValueSetRead by SeqNum."""
        return self._readNodes.get(seq, ValueSetRead())

    def beginValueSets(self):
        return iter(self._valueNodes)

    def endValueSets(self):
        return None

    def beginValueSetReads(self):
        return iter(self._readNodes.items())

    def endValueSetReads(self):
        return None

    def getNumValueSets(self) -> int:
        return len(self._valueNodes)

    def getNumReads(self) -> int:
        return len(self._readNodes)

    def getValueSet(self, i: int):
        keys = list(self._valueNodes.keys())
        return self._valueNodes[keys[i]] if i < len(keys) else None

    def getReadNode(self, i: int):
        keys = list(self._readNodes.keys())
        return self._readNodes[keys[i]] if i < len(keys) else None

    def finalizeValueSets(self) -> None:
        pass

    def iterateValueSets(self) -> None:
        pass
