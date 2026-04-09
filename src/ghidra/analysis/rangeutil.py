"""
Corresponds to: rangeutil.hh / rangeutil.cc

CircleRange class for manipulating integer value ranges.
Represents a circular range [left, right) over integers mod 2^n.
Used by jump-table recovery, guard analysis, and value set analysis.
"""

from __future__ import annotations
from typing import Optional, Tuple
from ghidra.core.address import (
    bit_transitions,
    calc_mask,
    count_leading_zeros,
    leastsigbit_set,
)
from ghidra.core.opcodes import OpCode, get_opname


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
            self._left = left
            self._right = right
            self._isempty = False

    @classmethod
    def fromSingle(cls, val: int, size: int) -> CircleRange:
        """Construct a range containing a single value."""
        r = cls.__new__(cls)
        r._mask = calc_mask(size)
        r._step = 1
        r._left = val
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
        if self._left == self._right:
            if self._step != 1:
                self._left = self._left % self._step
            else:
                self._left = 0
            self._right = self._left

    def setRange(self, left: int, right_or_size: int, size: int | None = None, step: int = 1) -> None:
        if size is None:
            self._mask = calc_mask(right_or_size)
            self._step = 1
            self._left = left
            self._right = (self._left + 1) & self._mask
            self._isempty = False
            return
        self._mask = calc_mask(size)
        self._left = left
        self._right = right_or_size
        self._step = step
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
        if self._left < self._right:
            val = (self._right - self._left) // self._step
        else:
            uintb_mask = calc_mask(8)
            raw = (self._mask - (self._left - self._right) + self._step) & uintb_mask
            val = raw // self._step
            if val == 0:
                val = self._mask
                if self._step > 1:
                    val //= self._step
                    val += 1
        return val

    def getMaxInfo(self) -> int:
        """Get maximum information content of range in bits."""
        halfPoint = self._mask ^ (self._mask >> 1)
        if self.contains(halfPoint):
            return 64 - count_leading_zeros(halfPoint)
        if (halfPoint & self._left) == 0:
            sizeLeft = count_leading_zeros(self._left)
        else:
            sizeLeft = count_leading_zeros((~self._left) & self._mask)
        if (halfPoint & self._right) == 0:
            sizeRight = count_leading_zeros(self._right)
        else:
            sizeRight = count_leading_zeros((~self._right) & self._mask)
        size1 = 64 - (sizeRight if sizeRight < sizeLeft else sizeLeft)
        if size1 < 0:
            return 0
        return size1

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
            val = val_or_range
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
        """Intersect this with another range. Returns 0 on success, 2 if the result is 2 pieces."""
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
        """Convert to complementary range. Returns the original step."""
        res = self._step
        self._step = 1
        self.complement()
        return res

    def setStride(self, newStep: int, rem: int) -> None:
        """Set a new step on this range."""
        iseverything = (not self._isempty) and (self._left == self._right)
        if newStep == self._step:
            return
        uintb_mask = calc_mask(8)
        aRight = (self._right - self._step) & uintb_mask
        self._step = newStep
        if self._step == 1:
            return
        curRem = self._left % self._step
        self._left = ((self._left - curRem) + rem) & uintb_mask
        curRem = aRight % self._step
        aRight = ((aRight - curRem) + rem) & uintb_mask
        self._right = (aRight + self._step) & uintb_mask
        if (not iseverything) and (self._left == self._right):
            self._isempty = True

    def setNZMask(self, nzmask: int, size: int) -> bool:
        """Set the range based on a non-zero mask."""
        trans = bit_transitions(nzmask, size)
        if trans > 2:
            return False
        hasstep = (nzmask & 1) == 0
        if (not hasstep) and trans == 2:
            return False

        new_mask = calc_mask(size)
        self._isempty = False
        if trans == 0:
            self._mask = new_mask
            self._step = 1
            self._left = 0
            self._right = 1 if hasstep else 0
            return True

        shift = leastsigbit_set(nzmask)
        self._step = 1 << shift
        self._mask = new_mask
        self._left = 0
        self._right = (nzmask + self._step) & self._mask
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
            uintb_mask = calc_mask(8)
            zextrange = CircleRange.__new__(CircleRange)
            zextrange._left = rem
            zextrange._right = (inMask + 1 + rem) & uintb_mask
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
            sextrange._right = sign_extend_sized(sextrange._left, inSize, outSize)
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
                rightBound = ((calc_mask(inSize) >> val) + 1) & calc_mask(8)
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
                    nzmask = res.getNZMask()
                    msbset = mostsigbit_set(nzmask)
                    msbset = (msbset + 8) // 8
                    if op.getOut().getSize() < msbset:
                        return (None, None)
                    else:
                        self._mask = calc_mask(res.getSize())
                else:
                    return (None, None)
            if constvn.getSymbolEntry() is not None:
                constMarkup = constvn
        else:
            return (None, None)

        if usenzmask:
            nzrange = CircleRange()
            nzmask = res.getNZMask()
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
        if self._left == self._right:
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
        uintb_mask = calc_mask(8)
        aRight = (self._right - self._step + 1) & uintb_mask
        bRight = (op2._right - op2._step + 1) & uintb_mask
        self._step = 1
        self._mask |= op2._mask
        overlapCode = CircleRange._encodeRangeOverlaps(self._left, aRight, op2._left, bRight)
        if overlapCode == 'a':
            vacantSize1 = (self._left + ((self._mask - bRight) & uintb_mask) + 1) & uintb_mask
            vacantSize2 = (op2._left - aRight) & uintb_mask
            if vacantSize1 < vacantSize2:
                self._left = op2._left
                self._right = aRight
            else:
                self._right = bRight
        elif overlapCode == 'f':
            vacantSize1 = (op2._left + ((self._mask - aRight) & uintb_mask) + 1) & uintb_mask
            vacantSize2 = (self._left - bRight) & uintb_mask
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
                uintb_mask = calc_mask(8)
                self._left = in1._left % self._step
                self._right = (in1._mask + 1 + self._left) & uintb_mask
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
                uintb_mask = calc_mask(8)
                rem = in1._left % self._step
                right_val = calc_mask(inSize) >> 1
                self._left = ((calc_mask(outSize) ^ right_val) + rem) & uintb_mask
                self._right = (right_val + 1 + rem) & uintb_mask
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
        elif opc in (OpCode.CPUI_BOOL_NEGATE, OpCode.CPUI_FLOAT_NAN):
            self._mask = 0xFF
            self._step = 1
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
        if self._left == self._right:
            if self._step != 1:
                return f"(full,{self._step})"
            return "(full)"
        if self._right == ((self._left + 1) & self._mask):
            return f"[{self._left:x}]"
        if self._step != 1:
            return f"[{self._left:x},{self._right:x},{self._step})"
        return f"[{self._left:x},{self._right:x})"

    def __repr__(self) -> str:
        return f"CircleRange({self.printRaw()})"


def _copy_circle_range(dst: CircleRange, src: CircleRange) -> None:
    dst._left = src._left
    dst._right = src._right
    dst._mask = src._mask
    dst._step = src._step
    dst._isempty = src._isempty


def _clone_circle_range(src: CircleRange) -> CircleRange:
    rng = CircleRange()
    _copy_circle_range(rng, src)
    return rng


# =========================================================================
# ValueSet and related classes
# =========================================================================

class ValueSet:
    """A range of values attached to a Varnode within a data-flow subsystem."""
    MAX_STEP = 32

    class Equation:
        """An external constraint that can be applied to a ValueSet."""
        def __init__(self, slot: int, typeCode: int, rng: CircleRange):
            self.slot = slot
            self.typeCode = typeCode
            self.range = _clone_circle_range(rng)

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

    def doesEquationApply(self, num: int, slot: int) -> bool:
        if num < len(self.equations):
            if self.equations[num].slot == slot:
                if self.equations[num].typeCode == self.typeCode:
                    return True
        return False

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
            if eq.typeCode == self.typeCode:
                return eq.range
        return None

    def setVarnode(self, v, tCode: int) -> None:
        self.typeCode = tCode
        self.vn = v
        self.vn.setValueSet(self)
        if self.typeCode != 0:
            self.opCode = OpCode.CPUI_MAX
            self.numParams = 0
            self.range.setRange(0, self.vn.getSize())
            self.leftIsStable = True
            self.rightIsStable = True
        elif self.vn.isWritten():
            op = self.vn.getDef()
            self.opCode = op.code()
            if self.opCode == OpCode.CPUI_INDIRECT:
                self.numParams = 1
                self.opCode = OpCode.CPUI_COPY
            else:
                self.numParams = op.numInput()
            self.leftIsStable = False
            self.rightIsStable = False
        elif self.vn.isConstant():
            self.opCode = OpCode.CPUI_MAX
            self.numParams = 0
            self.range.setRange(self.vn.getOffset(), self.vn.getSize())
            self.leftIsStable = True
            self.rightIsStable = True
        else:
            self.opCode = OpCode.CPUI_MAX
            self.numParams = 0
            self.typeCode = 0
            self.range.setFull(self.vn.getSize())
            self.leftIsStable = False
            self.rightIsStable = False

    def setFull(self) -> None:
        self.range.setFull(self.vn.getSize())
        self.typeCode = 0

    def addEquation(self, slot: int, typeCode: int, constraint: CircleRange) -> None:
        pos = 0
        while pos < len(self.equations):
            if self.equations[pos].slot > slot:
                break
            pos += 1
        self.equations.insert(pos, ValueSet.Equation(slot, typeCode, constraint))

    def addLandmark(self, typeCode: int, constraint: CircleRange) -> None:
        self.addEquation(self.numParams, typeCode, constraint)

    def computeTypeCode(self) -> bool:
        relCount = 0
        lastTypeCode = 0
        op = self.vn.getDef()
        for i in range(self.numParams):
            valueSet = op.getIn(i).getValueSet()
            if valueSet.typeCode != 0:
                relCount += 1
                lastTypeCode = valueSet.typeCode
        if relCount == 0:
            self.typeCode = 0
            return False
        if self.opCode in (
            OpCode.CPUI_PTRSUB,
            OpCode.CPUI_PTRADD,
            OpCode.CPUI_INT_ADD,
            OpCode.CPUI_INT_SUB,
        ):
            if relCount == 1:
                self.typeCode = lastTypeCode
            else:
                return True
        elif self.opCode in (
            OpCode.CPUI_CAST,
            OpCode.CPUI_COPY,
            OpCode.CPUI_INDIRECT,
            OpCode.CPUI_MULTIEQUAL,
        ):
            self.typeCode = lastTypeCode
        else:
            return True
        return False

    def iterate(self, widener) -> bool:
        if not self.vn.isWritten():
            return False
        if widener.checkFreeze(self):
            return False
        if self.count == 0:
            if self.computeTypeCode():
                self.setFull()
                return True
        self.count += 1
        res = CircleRange()
        op = self.vn.getDef()
        eqPos = 0
        if self.opCode == OpCode.CPUI_MULTIEQUAL:
            pieces = 0
            for i in range(self.numParams):
                inSet = op.getIn(i).getValueSet()
                if self.doesEquationApply(eqPos, i):
                    rangeCopy = _clone_circle_range(inSet.range)
                    if 0 != rangeCopy.intersect(self.equations[eqPos].range):
                        rangeCopy = _clone_circle_range(self.equations[eqPos].range)
                    pieces = res.circleUnion(rangeCopy)
                    eqPos += 1
                else:
                    pieces = res.circleUnion(inSet.range)
                if pieces == 2:
                    if res.minimalContainer(inSet.range, ValueSet.MAX_STEP):
                        break
            if 0 != res.circleUnion(self.range):
                res.minimalContainer(self.range, ValueSet.MAX_STEP)
            if not self.range.isEmpty() and not res.isEmpty():
                self.leftIsStable = self.range.getMin() == res.getMin()
                self.rightIsStable = self.range.getEnd() == res.getEnd()
        elif self.numParams == 1:
            inSet1 = op.getIn(0).getValueSet()
            if self.doesEquationApply(eqPos, 0):
                rangeCopy = _clone_circle_range(inSet1.range)
                if 0 != rangeCopy.intersect(self.equations[eqPos].range):
                    rangeCopy = _clone_circle_range(self.equations[eqPos].range)
                if not res.pushForwardUnary(self.opCode, rangeCopy, inSet1.vn.getSize(), self.vn.getSize()):
                    self.setFull()
                    return True
                eqPos += 1
            elif not res.pushForwardUnary(self.opCode, inSet1.range, inSet1.vn.getSize(), self.vn.getSize()):
                self.setFull()
                return True
            self.leftIsStable = inSet1.leftIsStable
            self.rightIsStable = inSet1.rightIsStable
        elif self.numParams == 2:
            inSet1 = op.getIn(0).getValueSet()
            inSet2 = op.getIn(1).getValueSet()
            if len(self.equations) == 0:
                if not res.pushForwardBinary(
                    self.opCode, inSet1.range, inSet2.range, inSet1.vn.getSize(), self.vn.getSize(), ValueSet.MAX_STEP
                ):
                    self.setFull()
                    return True
            else:
                range1 = _clone_circle_range(inSet1.range)
                range2 = _clone_circle_range(inSet2.range)
                if self.doesEquationApply(eqPos, 0):
                    if 0 != range1.intersect(self.equations[eqPos].range):
                        range1 = _clone_circle_range(self.equations[eqPos].range)
                    eqPos += 1
                if self.doesEquationApply(eqPos, 1):
                    if 0 != range2.intersect(self.equations[eqPos].range):
                        range2 = _clone_circle_range(self.equations[eqPos].range)
                if not res.pushForwardBinary(
                    self.opCode, range1, range2, inSet1.vn.getSize(), self.vn.getSize(), ValueSet.MAX_STEP
                ):
                    self.setFull()
                    return True
            self.leftIsStable = inSet1.leftIsStable and inSet2.leftIsStable
            self.rightIsStable = inSet1.rightIsStable and inSet2.rightIsStable
        elif self.numParams == 3:
            inSet1 = op.getIn(0).getValueSet()
            inSet2 = op.getIn(1).getValueSet()
            inSet3 = op.getIn(2).getValueSet()
            range1 = _clone_circle_range(inSet1.range)
            range2 = _clone_circle_range(inSet2.range)
            if self.doesEquationApply(eqPos, 0):
                if 0 != range1.intersect(self.equations[eqPos].range):
                    range1 = _clone_circle_range(self.equations[eqPos].range)
                eqPos += 1
            if self.doesEquationApply(eqPos, 1):
                if 0 != range2.intersect(self.equations[eqPos].range):
                    range2 = _clone_circle_range(self.equations[eqPos].range)
            if not res.pushForwardTrinary(
                self.opCode, range1, range2, inSet3.range, inSet1.vn.getSize(), self.vn.getSize(), ValueSet.MAX_STEP
            ):
                self.setFull()
                return True
            self.leftIsStable = inSet1.leftIsStable and inSet2.leftIsStable
            self.rightIsStable = inSet1.rightIsStable and inSet2.rightIsStable
        else:
            return False

        if res == self.range:
            return False
        if self.partHead is not None:
            if not widener.doWidening(self, self.range, res):
                self.setFull()
        else:
            _copy_circle_range(self.range, res)
        return True

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
        if self.vn is None:
            text = "root"
        else:
            text = self.vn.printRaw()
        if self.typeCode == 0:
            text += " absolute"
        else:
            text += " stackptr"
        if self.opCode == OpCode.CPUI_MAX:
            if self.vn is not None and self.vn.isConstant():
                text += " const"
            else:
                text += " input"
        else:
            text += f" {get_opname(self.opCode)}"
        return f"{text} {self.range.printRaw()}"


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
        self.typeCode = 0
        self.op = o
        self.slot = slt
        self.equationTypeCode = -1

    def addEquation(self, slt: int, typeCode: int, constraint: CircleRange) -> None:
        if self.slot == slt:
            self.equationTypeCode = typeCode
            _copy_circle_range(self.equationConstraint, constraint)

    def compute(self) -> None:
        """Compute this value set from the underlying Varnode's ValueSet."""
        invn = self.op.getIn(self.slot)
        valueSet = invn.getValueSet()
        self.typeCode = valueSet.getTypeCode()
        _copy_circle_range(self.range, valueSet.getRange())
        self.leftIsStable = valueSet.isLeftStable()
        self.rightIsStable = valueSet.isRightStable()
        if self.typeCode == self.equationTypeCode:
            if 0 != self.range.intersect(self.equationConstraint):
                _copy_circle_range(self.range, self.equationConstraint)

    def getSlot(self) -> int:
        return self.slot

    def getOp(self):
        return self.op

    def printRaw(self) -> str:
        if self.typeCode == 0:
            typeText = "absolute"
        else:
            typeText = "stackptr"
        return f"Read: {get_opname(self.op.code())}({self.op.getSeqNum()}) {typeText} {self.range.printRaw()}"


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

    def __del__(self) -> None:
        pass

    def determineIterationReset(self, valueSet: ValueSet) -> int:
        raise NotImplementedError

    def checkFreeze(self, valueSet: ValueSet) -> bool:
        raise NotImplementedError

    def doWidening(self, valueSet: ValueSet, rng: CircleRange, newRange: CircleRange) -> bool:
        raise NotImplementedError

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
        return valueSet.getRange().isFull()

    def doWidening(self, valueSet: ValueSet, rng: CircleRange, newRange: CircleRange) -> bool:
        """C++ ref: ``WidenerFull::doWidening``"""
        if valueSet.count < self._widenIteration:
            _copy_circle_range(rng, newRange)
            return True
        elif valueSet.count == self._widenIteration:
            landmark = valueSet.getLandMark()
            if landmark is not None:
                leftIsStable = rng.getMin() == newRange.getMin()
                _copy_circle_range(rng, newRange)
                if landmark.contains(rng):
                    rng.widen(landmark, leftIsStable)
                    return True
                else:
                    constraint = _clone_circle_range(landmark)
                    constraint.invert()
                    if constraint.contains(rng):
                        rng.widen(constraint, leftIsStable)
                        return True
        elif valueSet.count < self._fullIteration:
            _copy_circle_range(rng, newRange)
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
        if valueSet.getRange().isFull():
            return True
        return valueSet.count >= self._freezeIteration

    def doWidening(self, valueSet: ValueSet, rng: CircleRange, newRange: CircleRange) -> bool:
        """C++ ref: ``WidenerNone::doWidening``"""
        _copy_circle_range(rng, newRange)
        return True


class ValueSetSolver:
    """Class that determines a ValueSet for each Varnode in a data-flow system."""

    class ValueSetEdge:
        def __init__(self, node: ValueSet, roots: list[ValueSet]) -> None:
            self._rootEdges = None
            self._rootPos = 0
            self._vn = node.getVarnode()
            if self._vn is None:
                self._rootEdges = roots
                self._descendIter = None
            else:
                self._descendIter = iter(self._vn.beginDescend())

        def getNext(self):
            if self._vn is None:
                if self._rootPos < len(self._rootEdges):
                    res = self._rootEdges[self._rootPos]
                    self._rootPos += 1
                    return res
                return None
            for op in self._descendIter:
                outVn = op.getOut()
                if outVn is not None and outVn.isMark():
                    return outVn.getValueSet()
            return None

    def __init__(self) -> None:
        self._valueNodes: list = []
        self._readNodes: dict = {}
        self._orderPartition = Partition()
        self._recordStorage: list[Partition] = []
        self._rootNodes: list = []
        self._nodeStack: list[ValueSet] = []
        self._depthFirstIndex: int = 0
        self._numIterations: int = 0
        self._maxIterations: int = 0

    def getNumIterations(self) -> int:
        return self._numIterations

    def newValueSet(self, vn, tCode: int) -> None:
        self._valueNodes.append(ValueSet())
        self._valueNodes[-1].setVarnode(vn, tCode)

    @staticmethod
    def partitionPrepend(head_or_vertex, part: Partition) -> None:
        if isinstance(head_or_vertex, Partition):
            head_or_vertex.stopNode.next = part.startNode
            part.startNode = head_or_vertex.startNode
            if part.stopNode is None:
                part.stopNode = head_or_vertex.stopNode
            return

        vertex = head_or_vertex
        vertex.next = part.startNode
        part.startNode = vertex
        if part.stopNode is None:
            part.stopNode = vertex

    def partitionSurround(self, part: Partition) -> None:
        stored = Partition()
        stored.startNode = part.startNode
        stored.stopNode = part.stopNode
        stored.isDirty = part.isDirty
        self._recordStorage.append(stored)
        part.startNode.partHead = self._recordStorage[-1]

    def component(self, vertex: ValueSet, part: Partition) -> None:
        edgeIterator = ValueSetSolver.ValueSetEdge(vertex, self._rootNodes)
        succ = edgeIterator.getNext()
        while succ is not None:
            if succ.count == 0:
                self.visit(succ, part)
            succ = edgeIterator.getNext()
        self.partitionPrepend(vertex, part)
        self.partitionSurround(part)

    def visit(self, vertex: ValueSet, part: Partition) -> int:
        self._nodeStack.append(vertex)
        self._depthFirstIndex += 1
        vertex.count = self._depthFirstIndex
        head = self._depthFirstIndex
        loop = False
        edgeIterator = ValueSetSolver.ValueSetEdge(vertex, self._rootNodes)
        succ = edgeIterator.getNext()
        while succ is not None:
            if succ.count == 0:
                minVal = self.visit(succ, part)
            else:
                minVal = succ.count
            if minVal <= head:
                head = minVal
                loop = True
            succ = edgeIterator.getNext()
        if head == vertex.count:
            vertex.count = 0x7FFFFFFF
            element = self._nodeStack.pop()
            if loop:
                while element != vertex:
                    element.count = 0
                    element = self._nodeStack.pop()
                compPart = Partition()
                self.component(vertex, compPart)
                self.partitionPrepend(compPart, part)
            else:
                self.partitionPrepend(vertex, part)
        return head

    def establishTopologicalOrder(self) -> None:
        for valueSet in self._valueNodes:
            valueSet.count = 0
            valueSet.next = None
            valueSet.partHead = None
        rootNode = ValueSet()
        rootNode.vn = None
        self._depthFirstIndex = 0
        self.visit(rootNode, self._orderPartition)
        if self._orderPartition.startNode is not None:
            self._orderPartition.startNode = self._orderPartition.startNode.next

    def generateTrueEquation(self, vn, op, slot: int, typeCode: int, rng: CircleRange) -> None:
        if vn is not None:
            vn.getValueSet().addEquation(slot, typeCode, rng)
        else:
            self._readNodes[op.getSeqNum()].addEquation(slot, typeCode, rng)

    def generateFalseEquation(self, vn, op, slot: int, typeCode: int, rng: CircleRange) -> None:
        falseRange = _clone_circle_range(rng)
        falseRange.invert()
        if vn is not None:
            vn.getValueSet().addEquation(slot, typeCode, falseRange)
        else:
            self._readNodes[op.getSeqNum()].addEquation(slot, typeCode, falseRange)

    def applyConstraints(self, vn, typeCode: int, rng: CircleRange, cbranch) -> None:
        splitPoint = cbranch.getParent()
        if cbranch.isBooleanFlip():
            trueBlock = splitPoint.getFalseOut()
            falseBlock = splitPoint.getTrueOut()
        else:
            trueBlock = splitPoint.getTrueOut()
            falseBlock = splitPoint.getFalseOut()

        trueIsRestricted = trueBlock.restrictedByConditional(splitPoint)
        falseIsRestricted = falseBlock.restrictedByConditional(splitPoint)

        if vn.isWritten():
            valueSet = vn.getValueSet()
            if valueSet.opCode == OpCode.CPUI_MULTIEQUAL:
                valueSet.addLandmark(typeCode, rng)

        for op in vn.beginDescend():
            outVn = None
            if not op.isMark():
                outVn = op.getOut()
                if outVn is None:
                    continue
                if not outVn.isMark():
                    continue
            curBlock = op.getParent()
            slot = op.getSlot(vn)
            if op.code() == OpCode.CPUI_MULTIEQUAL:
                if curBlock == trueBlock:
                    if trueIsRestricted or trueBlock.getIn(slot) == splitPoint:
                        self.generateTrueEquation(outVn, op, slot, typeCode, rng)
                    continue
                if curBlock == falseBlock:
                    if falseIsRestricted or falseBlock.getIn(slot) == splitPoint:
                        self.generateFalseEquation(outVn, op, slot, typeCode, rng)
                    continue
                curBlock = curBlock.getIn(slot)
            while True:
                if curBlock == trueBlock:
                    if trueIsRestricted:
                        self.generateTrueEquation(outVn, op, slot, typeCode, rng)
                    break
                if curBlock == falseBlock:
                    if falseIsRestricted:
                        self.generateFalseEquation(outVn, op, slot, typeCode, rng)
                    break
                if curBlock == splitPoint or curBlock is None:
                    break
                curBlock = curBlock.getImmedDom()

    def constraintsFromPath(self, typeCode: int, lift: CircleRange, startVn, endVn, cbranch) -> None:
        while startVn != endVn:
            startVn, constVn = lift.pullBack(startVn.getDef(), False)
            if startVn is None:
                return
        while True:
            self.applyConstraints(endVn, typeCode, lift, cbranch)
            if not endVn.isWritten():
                break
            op = endVn.getDef()
            if op.isCall() or op.isMarker():
                break
            endVn, constVn = lift.pullBack(op, False)
            if endVn is None:
                break
            if not endVn.isMark():
                break

    def constraintsFromCBranch(self, cbranch) -> None:
        vn = cbranch.getIn(1)
        while not vn.isMark():
            if not vn.isWritten():
                break
            op = vn.getDef()
            if op.isCall() or op.isMarker():
                break
            num = op.numInput()
            if num == 0 or num > 2:
                break
            vn = op.getIn(0)
            if num == 2:
                if vn.isConstant():
                    vn = op.getIn(1)
                elif not op.getIn(1).isConstant():
                    self.generateRelativeConstraint(op, cbranch)
                    return
        if vn.isMark():
            lift = CircleRange.fromBool(True)
            startVn = cbranch.getIn(1)
            self.constraintsFromPath(0, lift, startVn, vn, cbranch)

    def generateConstraints(self, worklist: list, reads: list) -> None:
        blockList = []
        for vn in worklist:
            op = vn.getDef()
            if op is None:
                continue
            bl = op.getParent()
            if op.code() == OpCode.CPUI_MULTIEQUAL:
                for i in range(bl.sizeIn()):
                    curBl = bl.getIn(i)
                    while curBl is not None:
                        if curBl.isMark():
                            break
                        curBl.setMark()
                        blockList.append(curBl)
                        curBl = curBl.getImmedDom()
            else:
                while bl is not None:
                    if bl.isMark():
                        break
                    bl.setMark()
                    blockList.append(bl)
                    bl = bl.getImmedDom()

        for op in reads:
            bl = op.getParent()
            while bl is not None:
                if bl.isMark():
                    break
                bl.setMark()
                blockList.append(bl)
                bl = bl.getImmedDom()

        for bl in blockList:
            bl.clearMark()

        finalList = []
        for bl in blockList:
            for i in range(bl.sizeIn()):
                splitPoint = bl.getIn(i)
                if splitPoint.isMark():
                    continue
                if splitPoint.sizeOut() != 2:
                    continue
                lastOp = splitPoint.lastOp()
                if lastOp is not None and lastOp.code() == OpCode.CPUI_CBRANCH:
                    splitPoint.setMark()
                    finalList.append(splitPoint)
                    self.constraintsFromCBranch(lastOp)

        for bl in finalList:
            bl.clearMark()

    def checkRelativeConstant(self, vn):
        value = 0
        while True:
            if vn.isMark():
                valueSet = vn.getValueSet()
                if valueSet.typeCode != 0:
                    return True, valueSet.typeCode, value
            if not vn.isWritten():
                return False, 0, 0
            op = vn.getDef()
            opc = op.code()
            if opc == OpCode.CPUI_COPY or opc == OpCode.CPUI_INDIRECT:
                vn = op.getIn(0)
            elif opc == OpCode.CPUI_INT_ADD or opc == OpCode.CPUI_PTRSUB:
                constVn = op.getIn(1)
                if not constVn.isConstant():
                    return False, 0, 0
                value = (value + constVn.getOffset()) & calc_mask(constVn.getSize())
                vn = op.getIn(0)
            else:
                return False, 0, 0

    def generateRelativeConstraint(self, compOp, cbranch) -> None:
        opc = compOp.code()
        if opc == OpCode.CPUI_INT_LESS:
            opc = OpCode.CPUI_INT_SLESS
        elif opc == OpCode.CPUI_INT_LESSEQUAL:
            opc = OpCode.CPUI_INT_SLESSEQUAL
        elif (
            opc != OpCode.CPUI_INT_SLESS
            and opc != OpCode.CPUI_INT_SLESSEQUAL
            and opc != OpCode.CPUI_INT_EQUAL
            and opc != OpCode.CPUI_INT_NOTEQUAL
        ):
            return

        inVn0 = compOp.getIn(0)
        inVn1 = compOp.getIn(1)
        lift = CircleRange.fromBool(True)
        matched, typeCode, value = self.checkRelativeConstant(inVn0)
        if matched:
            vn = inVn1
            if not lift.pullBackBinary(opc, value, 1, vn.getSize(), 1):
                return
        else:
            matched, typeCode, value = self.checkRelativeConstant(inVn1)
            if not matched:
                return
            vn = inVn0
            if not lift.pullBackBinary(opc, value, 0, vn.getSize(), 1):
                return

        endVn = vn
        while not endVn.isMark():
            if not endVn.isWritten():
                return
            op = endVn.getDef()
            opc = op.code()
            if opc == OpCode.CPUI_COPY or opc == OpCode.CPUI_PTRSUB:
                endVn = op.getIn(0)
            elif opc == OpCode.CPUI_INT_ADD:
                if not op.getIn(1).isConstant():
                    return
                endVn = op.getIn(0)
            else:
                return
        self.constraintsFromPath(typeCode, lift, vn, endVn, cbranch)

    def establishValueSets(self, sinks: list, reads: list, stackReg=None,
                           indirectAsCopy: bool = False) -> None:
        """Build the system of ValueSets from the given sinks."""
        worklist = []
        workPos = 0
        if stackReg is not None:
            self.newValueSet(stackReg, 1)
            stackReg.setMark()
            worklist.append(stackReg)
            workPos += 1
            self._rootNodes.append(stackReg.getValueSet())

        for vn in sinks:
            self.newValueSet(vn, 0)
            vn.setMark()
            worklist.append(vn)

        while workPos < len(worklist):
            vn = worklist[workPos]
            workPos += 1
            if not vn.isWritten():
                if vn.isConstant():
                    if vn.isSpacebase() or vn.loneDescend().numInput() == 1:
                        self._rootNodes.append(vn.getValueSet())
                else:
                    self._rootNodes.append(vn.getValueSet())
                continue

            op = vn.getDef()
            opcode = op.code()
            if opcode == OpCode.CPUI_INDIRECT:
                if indirectAsCopy or op.isIndirectStore():
                    inVn = op.getIn(0)
                    if not inVn.isMark():
                        self.newValueSet(inVn, 0)
                        inVn.setMark()
                        worklist.append(inVn)
                else:
                    vn.getValueSet().setFull()
                    self._rootNodes.append(vn.getValueSet())
            elif opcode in (
                OpCode.CPUI_CALL,
                OpCode.CPUI_CALLIND,
                OpCode.CPUI_CALLOTHER,
                OpCode.CPUI_LOAD,
                OpCode.CPUI_NEW,
                OpCode.CPUI_SEGMENTOP,
                OpCode.CPUI_CPOOLREF,
                OpCode.CPUI_FLOAT_ADD,
                OpCode.CPUI_FLOAT_DIV,
                OpCode.CPUI_FLOAT_MULT,
                OpCode.CPUI_FLOAT_SUB,
                OpCode.CPUI_FLOAT_NEG,
                OpCode.CPUI_FLOAT_ABS,
                OpCode.CPUI_FLOAT_SQRT,
                OpCode.CPUI_FLOAT_INT2FLOAT,
                OpCode.CPUI_FLOAT_FLOAT2FLOAT,
                OpCode.CPUI_FLOAT_TRUNC,
                OpCode.CPUI_FLOAT_CEIL,
                OpCode.CPUI_FLOAT_FLOOR,
                OpCode.CPUI_FLOAT_ROUND,
            ):
                vn.getValueSet().setFull()
                self._rootNodes.append(vn.getValueSet())
            else:
                for i in range(op.numInput()):
                    inVn = op.getIn(i)
                    if inVn.isMark() or inVn.isAnnotation():
                        continue
                    self.newValueSet(inVn, 0)
                    inVn.setMark()
                    worklist.append(inVn)

        for op in reads:
            for slot in range(op.numInput()):
                vn = op.getIn(slot)
                if vn.isMark():
                    seq = op.getSeqNum()
                    if seq not in self._readNodes:
                        self._readNodes[seq] = ValueSetRead()
                    self._readNodes[seq].setPcodeOp(op, slot)
                    op.setMark()
                    break

        self.generateConstraints(worklist, reads)
        for op in reads:
            op.clearMark()

        self.establishTopologicalOrder()
        for vn in worklist:
            vn.clearMark()

    def solve(self, maxIter: int, widener: Widener) -> None:
        """Iterate the ValueSet system until it stabilizes."""
        self._maxIterations = maxIter
        self._numIterations = 0
        for valueSet in self._valueNodes:
            valueSet.count = 0

        componentStack = []
        curComponent = None
        curSet = self._orderPartition.startNode

        while curSet is not None:
            self._numIterations += 1
            if self._numIterations > self._maxIterations:
                break
            if curSet.partHead is not None and curSet.partHead != curComponent:
                componentStack.append(curSet.partHead)
                curComponent = curSet.partHead
                curComponent.isDirty = False
                curComponent.startNode.count = widener.determineIterationReset(curComponent.startNode)
            if curComponent is not None:
                if curSet.iterate(widener):
                    curComponent.isDirty = True
                if curComponent.stopNode != curSet:
                    curSet = curSet.next
                else:
                    while True:
                        if curComponent.isDirty:
                            curComponent.isDirty = False
                            curSet = curComponent.startNode
                            if len(componentStack) > 1:
                                componentStack[-2].isDirty = True
                            break

                        componentStack.pop()
                        if len(componentStack) == 0:
                            curComponent = None
                            curSet = curSet.next
                            break
                        curComponent = componentStack[-1]
                        if curComponent.stopNode != curSet:
                            curSet = curSet.next
                            break
            else:
                curSet.iterate(widener)
                curSet = curSet.next

        for vsr in self._readNodes.values():
            vsr.compute()

    def getValueSetRead(self, seq):
        """Get ValueSetRead by SeqNum."""
        return self._readNodes[seq]

    def beginValueSets(self):
        return iter(self._valueNodes)

    def endValueSets(self):
        return None

    def beginValueSetReads(self):
        return iter(sorted(self._readNodes.items(), key=lambda item: item[0]))

    def endValueSetReads(self):
        return None

    def dumpValueSets(self, s) -> None:
        for valueNode in self._valueNodes:
            s.write(valueNode.printRaw())
            s.write("\n")
        for _, readNode in self.beginValueSetReads():
            s.write(readNode.printRaw())
            s.write("\n")

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
