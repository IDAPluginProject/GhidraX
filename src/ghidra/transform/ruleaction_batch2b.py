"""
Remaining rules batch 2b: Division optimization rules + misc.
These rules handle complex division/modulo patterns using multiply-high tricks.
"""
from __future__ import annotations
from ghidra.transform.action import Rule
from ghidra.core.opcodes import OpCode
from ghidra.core.address import calc_mask, mostsigbit_set


class RuleDivOpt(Rule):
    """Collapse multiply-high division pattern: (x * c) >> n => x / d."""
    def __init__(self, g): super().__init__(g, 0, "divopt")
    def clone(self, gl):
        return RuleDivOpt(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_INT_RIGHT, OpCode.CPUI_INT_SRIGHT]
    def applyOp(self, op, data):
        if not op.getIn(1).isConstant(): return 0
        n = int(op.getIn(1).getOffset())
        invn = op.getIn(0)
        if not invn.isWritten(): return 0
        # Look for SUBPIECE(MULT(ZEXT/SEXT(x), const))
        subop = invn.getDef()
        if subop.code() == OpCode.CPUI_SUBPIECE:
            multvn = subop.getIn(0)
            if not multvn.isWritten(): return 0
            multop = multvn.getDef()
            if multop.code() != OpCode.CPUI_INT_MULT: return 0
            if not multop.getIn(1).isConstant(): return 0
            c = int(subop.getIn(1).getOffset())
            n += c * 8
            extvn = multop.getIn(0)
            if not extvn.isWritten(): return 0
            extop = extvn.getDef()
            if extop.code() not in (OpCode.CPUI_INT_ZEXT, OpCode.CPUI_INT_SEXT): return 0
            x = extop.getIn(0)
            if x.isFree(): return 0
            xsize = x.getSize() * 8
            multconst = multop.getIn(1).getOffset()
            from ghidra.core.int128 import calcDivisor
            divisor = calcDivisor(n, multconst, xsize)
            if divisor == 0: return 0
            outsize = op.getOut().getSize()
            if extop.code() == OpCode.CPUI_INT_ZEXT:
                data.opSetInput(op, x, 0)
                data.opSetInput(op, data.newConstant(outsize, divisor), 1)
                data.opSetOpcode(op, OpCode.CPUI_INT_DIV)
            else:
                data.opSetInput(op, x, 0)
                data.opSetInput(op, data.newConstant(outsize, divisor), 1)
                data.opSetOpcode(op, OpCode.CPUI_INT_SDIV)
            return 1
        return 0


class RuleDivTermAdd(Rule):
    """Simplify division term: sub(ext(x)*c, n) + x => sub(ext(x)*(c+2^n), n)."""
    def __init__(self, g): super().__init__(g, 0, "divtermadd")
    def clone(self, gl):
        return RuleDivTermAdd(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_INT_RIGHT, OpCode.CPUI_INT_SRIGHT]
    def applyOp(self, op, data):
        # Pattern: (sub(ext(x)*c) >> n) + x => sub(ext(x)*(c+2^n)) >> n
        # This collapses the extra add into the multiply constant
        if not op.getIn(1).isConstant():
            return 0
        n = int(op.getIn(1).getOffset())
        if n > 127:
            return 0
        invn = op.getIn(0)
        if not invn.isWritten():
            return 0
        subop = invn.getDef()
        if subop.code() != OpCode.CPUI_SUBPIECE:
            return 0
        multvn = subop.getIn(0)
        if not multvn.isWritten():
            return 0
        multop = multvn.getDef()
        if multop.code() != OpCode.CPUI_INT_MULT:
            return 0
        if not multop.getIn(1).isConstant():
            return 0
        # Check for extension
        extvn = multop.getIn(0)
        if not extvn.isWritten():
            return 0
        extop = extvn.getDef()
        if extop.code() not in (OpCode.CPUI_INT_ZEXT, OpCode.CPUI_INT_SEXT):
            return 0
        # Would need 128-bit constant arithmetic to complete the transform
        return 0


class RuleDivTermAdd2(Rule):
    """Simplify division term addition (variant 2).

    Simplify: `(sub(zext(x)*c, n) + x*-1) >> 1 + sub(zext(x)*c, n)`
    into a single optimized division form.
    """
    def __init__(self, g): super().__init__(g, 0, "divtermadd2")
    def clone(self, gl):
        return RuleDivTermAdd2(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_INT_RIGHT]
    def applyOp(self, op, data):
        if not op.getIn(1).isConstant():
            return 0
        if op.getIn(1).getOffset() != 1:
            return 0
        if not op.getIn(0).isWritten():
            return 0
        subop = op.getIn(0).getDef()
        if subop.code() != OpCode.CPUI_INT_ADD:
            return 0
        x = None
        compvn = None
        for i in range(2):
            compvn = subop.getIn(i)
            if compvn.isWritten():
                compop = compvn.getDef()
                if compop.code() == OpCode.CPUI_INT_MULT:
                    invn = compop.getIn(1)
                    if invn.isConstant():
                        if invn.getOffset() == calc_mask(invn.getSize()):
                            x = subop.getIn(1 - i)
                            break
        else:
            return 0
        if x is None:
            return 0
        z = compvn.getDef().getIn(0)
        if not z.isWritten():
            return 0
        subpieceop = z.getDef()
        if subpieceop.code() != OpCode.CPUI_SUBPIECE:
            return 0
        n = int(subpieceop.getIn(1).getOffset()) * 8
        if n != 8 * (subpieceop.getIn(0).getSize() - z.getSize()):
            return 0
        multvn = subpieceop.getIn(0)
        if not multvn.isWritten():
            return 0
        multop = multvn.getDef()
        if multop.code() != OpCode.CPUI_INT_MULT:
            return 0
        # Get extended constant - Python handles big ints natively
        multConstVn = multop.getIn(1)
        ok, multConstPair = multConstVn.isConstantExtended()
        if not ok:
            return 0
        multConst = multConstPair[0] | (multConstPair[1] << 64)
        zextvn = multop.getIn(0)
        if not zextvn.isWritten():
            return 0
        zextop = zextvn.getDef()
        if zextop.code() != OpCode.CPUI_INT_ZEXT:
            return 0
        if zextop.getIn(0) is not x:
            return 0

        for addop in list(op.getOut().getDescendants()):
            if addop.code() != OpCode.CPUI_INT_ADD:
                continue
            if addop.getIn(0) is not z and addop.getIn(1) is not z:
                continue
            # Calculate 2^n and add to multConst
            pow2n = 1 << n
            newMultConst = multConst + pow2n
            # Truncate to the extended size
            extSize = zextvn.getSize()
            extBits = extSize * 8
            extMask = (1 << extBits) - 1
            newMultConst &= extMask

            newmultop = data.newOp(2, op.getAddr())
            data.opSetOpcode(newmultop, OpCode.CPUI_INT_MULT)
            newmultvn = data.newUniqueOut(extSize, newmultop)
            data.opSetInput(newmultop, zextvn, 0)
            # Create the new constant - may need extended form
            if extSize <= 8:
                newConstVn = data.newConstant(extSize, newMultConst)
            else:
                lo = newMultConst & 0xFFFFFFFFFFFFFFFF
                hi = (newMultConst >> 64) & 0xFFFFFFFFFFFFFFFF
                if hasattr(data, 'newExtendedConstant'):
                    newConstVn = data.newExtendedConstant(extSize, [lo, hi], op)
                else:
                    newConstVn = data.newConstant(extSize, lo)
            data.opSetInput(newmultop, newConstVn, 1)
            data.opInsertBefore(newmultop, op)

            newshiftop = data.newOp(2, op.getAddr())
            data.opSetOpcode(newshiftop, OpCode.CPUI_INT_RIGHT)
            newshiftvn = data.newUniqueOut(extSize, newshiftop)
            data.opSetInput(newshiftop, newmultvn, 0)
            data.opSetInput(newshiftop, data.newConstant(4, n + 1), 1)
            data.opInsertBefore(newshiftop, op)

            data.opSetOpcode(addop, OpCode.CPUI_SUBPIECE)
            data.opSetInput(addop, newshiftvn, 0)
            data.opSetInput(addop, data.newConstant(4, 0), 1)
            return 1
        return 0


class RuleDivChain(Rule):
    """Collapse (x / c1) / c2 => x / (c1*c2)."""
    def __init__(self, g): super().__init__(g, 0, "divchain")
    def clone(self, gl):
        return RuleDivChain(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_INT_DIV, OpCode.CPUI_INT_SDIV]
    def applyOp(self, op, data):
        opc2 = op.code()
        c2 = op.getIn(1)
        if not c2.isConstant(): return 0
        vn = op.getIn(0)
        if not vn.isWritten(): return 0
        divop = vn.getDef()
        opc1 = divop.code()
        if opc1 != opc2 and not (opc2 == OpCode.CPUI_INT_DIV and opc1 == OpCode.CPUI_INT_RIGHT):
            return 0
        c1 = divop.getIn(1)
        if not c1.isConstant(): return 0
        if not vn.loneDescend(): return 0
        if opc1 == opc2:
            val1 = c1.getOffset()
        else:
            val1 = 1 << int(c1.getOffset())
        base = divop.getIn(0)
        if base.isFree(): return 0
        sz = vn.getSize()
        val2 = c2.getOffset()
        resval = (val1 * val2) & calc_mask(sz)
        if resval == 0: return 0
        data.opSetInput(op, base, 0)
        data.opSetInput(op, data.newConstant(sz, resval), 1)
        return 1


class RuleSignDiv2(Rule):
    """Convert (V + -1*(V s>> 31)) s>> 1 => V s/ 2."""
    def __init__(self, g): super().__init__(g, 0, "signdiv2")
    def clone(self, gl):
        return RuleSignDiv2(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_INT_SRIGHT]
    def applyOp(self, op, data):
        if not op.getIn(1).isConstant(): return 0
        if op.getIn(1).getOffset() != 1: return 0
        addout = op.getIn(0)
        if not addout.isWritten(): return 0
        addop = addout.getDef()
        if addop.code() != OpCode.CPUI_INT_ADD: return 0
        a = None
        for i in range(2):
            multout = addop.getIn(i)
            if not multout.isWritten(): continue
            multop = multout.getDef()
            if multop.code() != OpCode.CPUI_INT_MULT: continue
            if not multop.getIn(1).isConstant(): continue
            if multop.getIn(1).getOffset() != calc_mask(multop.getIn(1).getSize()): continue
            shiftout = multop.getIn(0)
            if not shiftout.isWritten(): continue
            shiftop = shiftout.getDef()
            if shiftop.code() != OpCode.CPUI_INT_SRIGHT: continue
            if not shiftop.getIn(1).isConstant(): continue
            n = int(shiftop.getIn(1).getOffset())
            a = shiftop.getIn(0)
            if a is not addop.getIn(1 - i): continue
            if n != 8 * a.getSize() - 1: continue
            if a.isFree(): continue
            break
        else:
            return 0
        if a is None: return 0
        data.opSetInput(op, a, 0)
        data.opSetInput(op, data.newConstant(a.getSize(), 2), 1)
        data.opSetOpcode(op, OpCode.CPUI_INT_SDIV)
        return 1


class RuleSignForm2(Rule):
    """Simplify sign extraction: sub(sext(V)*W, c) s>> (sz*8-1) => V s>> (sz*8-1)."""
    def __init__(self, g): super().__init__(g, 0, "signform2")
    def clone(self, gl):
        return RuleSignForm2(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_INT_SRIGHT]
    def applyOp(self, op, data):
        constvn = op.getIn(1)
        if not constvn.isConstant(): return 0
        invn = op.getIn(0)
        sizeout = invn.getSize()
        if int(constvn.getOffset()) != sizeout * 8 - 1: return 0
        if not invn.isWritten(): return 0
        subop = invn.getDef()
        if subop.code() != OpCode.CPUI_SUBPIECE: return 0
        c = int(subop.getIn(1).getOffset())
        multout = subop.getIn(0)
        multsize = multout.getSize()
        if c + sizeout != multsize: return 0  # Must extract high part
        if not multout.isWritten(): return 0
        multop = multout.getDef()
        if multop.code() != OpCode.CPUI_INT_MULT: return 0
        # Search for INT_SEXT input
        for slot in range(2):
            vn = multop.getIn(slot)
            if not vn.isWritten(): continue
            sextop = vn.getDef()
            if sextop.code() == OpCode.CPUI_INT_SEXT:
                a = sextop.getIn(0)
                if a.isFree() or a.getSize() != sizeout: continue
                data.opSetInput(op, a, 0)
                return 1
        return 0


class RuleSignMod2Opt(Rule):
    """Detect signed mod 2 pattern: (x + -(x s>> 31)) & 1 used in x + sign_correction => x s% 2."""
    def __init__(self, g): super().__init__(g, 0, "signmod2opt")
    def clone(self, gl):
        return RuleSignMod2Opt(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_INT_AND]
    def applyOp(self, op, data):
        constvn = op.getIn(1)
        if not constvn.isConstant() or constvn.getOffset() != 1:
            return 0
        addout = op.getIn(0)
        if not addout.isWritten():
            return 0
        addop = addout.getDef()
        if addop.code() != OpCode.CPUI_INT_ADD:
            return 0
        # Look for INT_MULT by -1 on one input
        multSlotFound = -1
        multop = None
        for multSlot in range(2):
            vn = addop.getIn(multSlot)
            if not vn.isWritten():
                continue
            multop = vn.getDef()
            if multop.code() != OpCode.CPUI_INT_MULT:
                continue
            mc = multop.getIn(1)
            if not mc.isConstant():
                continue
            if mc.getOffset() != calc_mask(mc.getSize()):
                continue
            multSlotFound = multSlot
            break
        if multSlotFound < 0 or multop is None:
            return 0
        base = RuleSignMod2nOpt.checkSignExtraction(multop.getIn(0))
        if base is None:
            return 0
        otherBase = addop.getIn(1 - multSlotFound)
        trunc = False
        if base is not otherBase:
            if not base.isWritten() or not otherBase.isWritten():
                return 0
            subOp = base.getDef()
            if subOp.code() != OpCode.CPUI_SUBPIECE:
                return 0
            truncAmt = int(subOp.getIn(1).getOffset())
            if truncAmt + base.getSize() != subOp.getIn(0).getSize():
                return 0
            base = subOp.getIn(0)
            subOp2 = otherBase.getDef()
            if subOp2.code() != OpCode.CPUI_SUBPIECE:
                return 0
            if int(subOp2.getIn(1).getOffset()) != 0:
                return 0
            otherBase = subOp2.getIn(0)
            if otherBase is not base:
                return 0
            trunc = True
        if base.isFree():
            return 0
        andOut = op.getOut()
        if trunc:
            extOp = andOut.loneDescend()
            if extOp is None or extOp.code() != OpCode.CPUI_INT_ZEXT:
                return 0
            andOut = extOp.getOut()
        for rootOp in list(andOut.getDescendants()):
            if rootOp.code() != OpCode.CPUI_INT_ADD:
                continue
            slot = rootOp.getSlot(andOut)
            ob = RuleSignMod2nOpt.checkSignExtraction(rootOp.getIn(1 - slot))
            if ob is not base:
                continue
            data.opSetOpcode(rootOp, OpCode.CPUI_INT_SREM)
            data.opSetInput(rootOp, base, 0)
            data.opSetInput(rootOp, data.newConstant(base.getSize(), 2), 1)
            return 1
        return 0


class RuleSignMod2nOpt(Rule):
    """Convert INT_SREM forms: (V + (sign >> (64-n)) & (2^n-1)) - (sign >> (64-n)) => V s% 2^n."""
    def __init__(self, g): super().__init__(g, 0, "signmod2nopt")
    def clone(self, gl):
        return RuleSignMod2nOpt(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_INT_RIGHT]

    @staticmethod
    def checkSignExtraction(outVn):
        """Verify outVn is a sign extraction of the form V s>> 63. Returns V or None."""
        if not outVn.isWritten():
            return None
        signOp = outVn.getDef()
        if signOp.code() != OpCode.CPUI_INT_SRIGHT:
            return None
        constVn = signOp.getIn(1)
        if not constVn.isConstant():
            return None
        val = int(constVn.getOffset())
        resVn = signOp.getIn(0)
        insize = resVn.getSize()
        if val != insize * 8 - 1:
            return None
        return resVn

    def applyOp(self, op, data):
        if not op.getIn(1).isConstant():
            return 0
        shiftAmt = int(op.getIn(1).getOffset())
        a = RuleSignMod2nOpt.checkSignExtraction(op.getIn(0))
        if a is None or a.isFree():
            return 0
        correctVn = op.getOut()
        n = a.getSize() * 8 - shiftAmt
        mask = (1 << n) - 1
        for multop in list(correctVn.getDescendants()):
            if multop.code() != OpCode.CPUI_INT_MULT:
                continue
            negone = multop.getIn(1)
            if not negone.isConstant():
                continue
            if negone.getOffset() != calc_mask(correctVn.getSize()):
                continue
            baseOp = multop.getOut().loneDescend()
            if baseOp is None:
                continue
            if baseOp.code() != OpCode.CPUI_INT_ADD:
                continue
            slot = 1 - baseOp.getSlot(multop.getOut())
            andOut = baseOp.getIn(slot)
            if not andOut.isWritten():
                continue
            andOp = andOut.getDef()
            truncSize = -1
            if andOp.code() == OpCode.CPUI_INT_ZEXT:
                andOut = andOp.getIn(0)
                if not andOut.isWritten():
                    continue
                andOp = andOut.getDef()
                if andOp.code() != OpCode.CPUI_INT_AND:
                    continue
                truncSize = andOut.getSize()
            elif andOp.code() != OpCode.CPUI_INT_AND:
                continue
            constVn = andOp.getIn(1)
            if not constVn.isConstant():
                continue
            if constVn.getOffset() != mask:
                continue
            addOut2 = andOp.getIn(0)
            if not addOut2.isWritten():
                continue
            addOp = addOut2.getDef()
            if addOp.code() != OpCode.CPUI_INT_ADD:
                continue
            aSlotFound = -1
            for aSlot in range(2):
                vn = addOp.getIn(aSlot)
                if truncSize >= 0:
                    if not vn.isWritten():
                        continue
                    subOp = vn.getDef()
                    if subOp.code() != OpCode.CPUI_SUBPIECE:
                        continue
                    if int(subOp.getIn(1).getOffset()) != 0:
                        continue
                    vn = subOp.getIn(0)
                if a is vn:
                    aSlotFound = aSlot
                    break
            if aSlotFound < 0:
                continue
            extVn = addOp.getIn(1 - aSlotFound)
            if not extVn.isWritten():
                continue
            shiftOp = extVn.getDef()
            if shiftOp.code() != OpCode.CPUI_INT_RIGHT:
                continue
            constVn2 = shiftOp.getIn(1)
            if not constVn2.isConstant():
                continue
            shiftval = int(constVn2.getOffset())
            if truncSize >= 0:
                shiftval += (a.getSize() - truncSize) * 8
            if shiftval != shiftAmt:
                continue
            extVn2 = RuleSignMod2nOpt.checkSignExtraction(shiftOp.getIn(0))
            if extVn2 is None:
                continue
            if truncSize >= 0:
                if not extVn2.isWritten():
                    continue
                subOp2 = extVn2.getDef()
                if subOp2.code() != OpCode.CPUI_SUBPIECE:
                    continue
                if int(subOp2.getIn(1).getOffset()) != truncSize:
                    continue
                extVn2 = subOp2.getIn(0)
            if a is not extVn2:
                continue
            data.opSetOpcode(baseOp, OpCode.CPUI_INT_SREM)
            data.opSetInput(baseOp, a, 0)
            data.opSetInput(baseOp, data.newConstant(a.getSize(), mask + 1), 1)
            return 1
        return 0


class RuleSignMod2nOpt2(Rule):
    """Optimize signed modulo by power of 2 (variant 2).

    Detect pattern: x + (-(x & mask) * -1) where mask = ~(2^n-1) and
    convert the root INT_ADD to INT_SREM.
    """
    def __init__(self, g): super().__init__(g, 0, "signmod2nopt2")
    def clone(self, gl):
        return RuleSignMod2nOpt2(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_INT_MULT]

    @staticmethod
    def checkSignExtForm(op):
        """Verify a form of V - (V s>> 0x3f). Returns the Varnode V or None."""
        for slot in range(2):
            minusVn = op.getIn(slot)
            if not minusVn.isWritten():
                continue
            multOp = minusVn.getDef()
            if multOp.code() != OpCode.CPUI_INT_MULT:
                continue
            constVn = multOp.getIn(1)
            if not constVn.isConstant():
                continue
            if constVn.getOffset() != calc_mask(constVn.getSize()):
                continue
            base = op.getIn(1 - slot)
            signExt = multOp.getIn(0)
            if not signExt.isWritten():
                continue
            shiftOp = signExt.getDef()
            if shiftOp.code() != OpCode.CPUI_INT_SRIGHT:
                continue
            if shiftOp.getIn(0) is not base:
                continue
            constVn2 = shiftOp.getIn(1)
            if not constVn2.isConstant():
                continue
            if int(constVn2.getOffset()) != 8 * base.getSize() - 1:
                continue
            return base
        return None

    @staticmethod
    def checkMultiequalForm(op, npow):
        """Verify an if block like V = (V s< 0) ? V + 2^n-1 : V. Returns V or None."""
        if op.numInput() != 2:
            return None
        npow_minus1 = npow - 1
        base = None
        slot = -1
        for s in range(2):
            addOut = op.getIn(s)
            if not addOut.isWritten():
                continue
            addOp = addOut.getDef()
            if addOp.code() != OpCode.CPUI_INT_ADD:
                continue
            constVn = addOp.getIn(1)
            if not constVn.isConstant():
                continue
            if constVn.getOffset() != npow_minus1:
                continue
            base = addOp.getIn(0)
            otherBase = op.getIn(1 - s)
            if otherBase is base:
                slot = s
                break
        if slot < 0:
            return None
        bl = op.getParent()
        innerSlot = 0
        inner = bl.getIn(innerSlot)
        if inner.sizeOut() != 1 or inner.sizeIn() != 1:
            innerSlot = 1
            inner = bl.getIn(innerSlot)
            if inner.sizeOut() != 1 or inner.sizeIn() != 1:
                return None
        decision = inner.getIn(0)
        if bl.getIn(1 - innerSlot) is not decision:
            return None
        cbranch = decision.lastOp() if hasattr(decision, 'lastOp') else None
        if cbranch is None or cbranch.code() != OpCode.CPUI_CBRANCH:
            return None
        boolVn = cbranch.getIn(1)
        if not boolVn.isWritten():
            return None
        lessOp = boolVn.getDef()
        if lessOp.code() != OpCode.CPUI_INT_SLESS:
            return None
        if not lessOp.getIn(1).isConstant():
            return None
        if lessOp.getIn(1).getOffset() != 0:
            return None
        isBoolFlip = cbranch.isBooleanFlip() if hasattr(cbranch, 'isBooleanFlip') else False
        negBlock = decision.getFalseOut() if not isBoolFlip else decision.getFalseOut()
        if hasattr(decision, 'getTrueOut'):
            negBlock = decision.getTrueOut() if not isBoolFlip else decision.getFalseOut()
        negSlot = innerSlot if negBlock is inner else (1 - innerSlot)
        if negSlot != slot:
            return None
        return base

    def applyOp(self, op, data):
        constVn = op.getIn(1)
        if not constVn.isConstant():
            return 0
        mask = calc_mask(constVn.getSize())
        if constVn.getOffset() != mask:
            return 0  # Must be INT_MULT by -1
        andOut = op.getIn(0)
        if not andOut.isWritten():
            return 0
        andOp = andOut.getDef()
        if andOp.code() != OpCode.CPUI_INT_AND:
            return 0
        constVn2 = andOp.getIn(1)
        if not constVn2.isConstant():
            return 0
        npow = (~constVn2.getOffset() + 1) & mask
        if npow == 0 or (npow & (npow - 1)) != 0:
            return 0  # npow must be a power of 2
        if npow == 1:
            return 0
        adjVn = andOp.getIn(0)
        if not adjVn.isWritten():
            return 0
        adjOp = adjVn.getDef()
        if adjOp.code() == OpCode.CPUI_INT_ADD:
            if npow != 2:
                return 0
            base = RuleSignMod2nOpt2.checkSignExtForm(adjOp)
        elif adjOp.code() == OpCode.CPUI_MULTIEQUAL:
            base = RuleSignMod2nOpt2.checkMultiequalForm(adjOp, npow)
        else:
            return 0
        if base is None:
            return 0
        if base.isFree():
            return 0
        multOut = op.getOut()
        for rootOp in list(multOut.getDescendants()):
            if rootOp.code() != OpCode.CPUI_INT_ADD:
                continue
            rootSlot = rootOp.getSlot(multOut)
            if rootOp.getIn(1 - rootSlot) is not base:
                continue
            if rootSlot == 0:
                data.opSetInput(rootOp, base, 0)
            data.opSetInput(rootOp, data.newConstant(base.getSize(), npow), 1)
            data.opSetOpcode(rootOp, OpCode.CPUI_INT_SREM)
            return 1
        return 0


class RuleAddUnsigned(Rule):
    """Convert INT_ADD of large unsigned constant to INT_SUB: x + 0xFFFF... => x - small."""
    def __init__(self, g): super().__init__(g, 0, "addunsigned")
    def clone(self, gl):
        return RuleAddUnsigned(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_INT_ADD]
    def applyOp(self, op, data):
        constvn = op.getIn(1)
        if not constvn.isConstant(): return 0
        val = constvn.getOffset()
        mask = calc_mask(constvn.getSize())
        sa = constvn.getSize() * 6  # 1/4 less than full bitsize
        quarter = (mask >> sa) << sa
        if (val & quarter) != quarter: return 0  # Top quarter bits must be 1s
        negval = (-val) & mask
        data.opSetOpcode(op, OpCode.CPUI_INT_SUB)
        data.opSetInput(op, data.newConstant(constvn.getSize(), negval), 1)
        return 1


class RuleSubRight(Rule):
    """Simplify SUBPIECE that extracts high bytes of an extended value: sub(zext(x),c) => 0 when c >= sizeof(x)."""
    def __init__(self, g): super().__init__(g, 0, "subright")
    def clone(self, gl):
        return RuleSubRight(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_SUBPIECE]
    def applyOp(self, op, data):
        invn = op.getIn(0)
        if not invn.isWritten(): return 0
        c = int(op.getIn(1).getOffset())
        defop = invn.getDef()
        if defop.code() == OpCode.CPUI_INT_ZEXT:
            origsize = defop.getIn(0).getSize()
            if c >= origsize:
                # Extracting above the zero-extended part => result is 0
                outsize = op.getOut().getSize()
                data.opSetOpcode(op, OpCode.CPUI_COPY)
                data.opSetInput(op, data.newConstant(outsize, 0), 0)
                data.opRemoveInput(op, 1)
                return 1
        return 0


class RuleExtensionPush(Rule):
    """Push ZEXT/SEXT through arithmetic when all descendants are PTRADD or INT_ADD->PTRADD."""
    def __init__(self, g): super().__init__(g, 0, "extensionpush")
    def clone(self, gl):
        return RuleExtensionPush(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_INT_ZEXT, OpCode.CPUI_INT_SEXT]
    def applyOp(self, op, data):
        invn = op.getIn(0)
        if invn.isConstant() or invn.isAddrForce() or invn.isAddrTied():
            return 0
        outvn = op.getOut()
        if outvn.isTypeLock() or outvn.isNameLock():
            return 0
        addcount = 0
        ptrcount = 0
        for desc in outvn.getDescendants():
            opc = desc.code()
            if opc == OpCode.CPUI_PTRADD:
                ptrcount += 1
            elif opc == OpCode.CPUI_INT_ADD:
                subdesc = desc.getOut().loneDescend()
                if subdesc is None or subdesc.code() != OpCode.CPUI_PTRADD:
                    return 0
                addcount += 1
            else:
                return 0
        if addcount + ptrcount <= 1:
            return 0
        if addcount > 0:
            if op.getIn(0).loneDescend() is not None:
                return 0
        from ghidra.transform.ruleaction_batch2c import RulePushPtr
        RulePushPtr.duplicateNeed(op, data)
        return 1


class RuleThreeWayCompare(Rule):
    """Simplify expressions involving three-way comparisons.

    A three-way comparison is: zext(V < W) + zext(V <= W) - 1
    giving -1, 0, or 1 depending on whether V < W, V == W, or V > W.
    This rule simplifies secondary comparisons of the three-way result.
    """
    def __init__(self, g): super().__init__(g, 0, "threewaycompare")
    def clone(self, gl):
        return RuleThreeWayCompare(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_INT_SLESS, OpCode.CPUI_INT_SLESSEQUAL,
                                  OpCode.CPUI_INT_EQUAL, OpCode.CPUI_INT_NOTEQUAL]

    @staticmethod
    def testCompareEquivalence(lessop, lessequalop):
        """Check that lessop is LESS and lessequalop is LESSEQUAL on same operands.
        Returns 0 if matched, 1 if swapped, -1 if no match."""
        twoLessThan = False
        opc = lessop.code()
        if opc == OpCode.CPUI_INT_LESS:
            if lessequalop.code() == OpCode.CPUI_INT_LESSEQUAL:
                twoLessThan = False
            elif lessequalop.code() == OpCode.CPUI_INT_LESS:
                twoLessThan = True
            else:
                return -1
        elif opc == OpCode.CPUI_INT_SLESS:
            if lessequalop.code() == OpCode.CPUI_INT_SLESSEQUAL:
                twoLessThan = False
            elif lessequalop.code() == OpCode.CPUI_INT_SLESS:
                twoLessThan = True
            else:
                return -1
        elif opc == OpCode.CPUI_FLOAT_LESS:
            if lessequalop.code() == OpCode.CPUI_FLOAT_LESSEQUAL:
                twoLessThan = False
            else:
                return -1
        else:
            return -1
        a1 = lessop.getIn(0)
        a2 = lessequalop.getIn(0)
        b1 = lessop.getIn(1)
        b2 = lessequalop.getIn(1)
        res = 0
        if a1 is not a2:
            if not a1.isConstant() or not a2.isConstant():
                return -1
            if a1.getOffset() != a2.getOffset() and twoLessThan:
                if a2.getOffset() + 1 == a1.getOffset():
                    twoLessThan = False
                elif a1.getOffset() + 1 == a2.getOffset():
                    twoLessThan = False
                    res = 1
                else:
                    return -1
        if b1 is not b2:
            if not b1.isConstant() or not b2.isConstant():
                return -1
            if b1.getOffset() != b2.getOffset() and twoLessThan:
                if b1.getOffset() + 1 == b2.getOffset():
                    twoLessThan = False
                elif b2.getOffset() + 1 == b1.getOffset():
                    twoLessThan = False
                    res = 1
            else:
                return -1
        if twoLessThan:
            return -1
        return res

    @staticmethod
    def detectThreeWay(op):
        """Detect a three-way calculation from an INT_ADD root.
        Returns (lessop, isPartial) or (None, False)."""
        isPartial = False
        vn2 = op.getIn(1)
        if vn2.isConstant():
            # Form 1: (z + z) - 1
            mask = calc_mask(vn2.getSize())
            if mask != vn2.getOffset():
                return (None, False)
            vn1 = op.getIn(0)
            if not vn1.isWritten():
                return (None, False)
            addop = vn1.getDef()
            if addop.code() != OpCode.CPUI_INT_ADD:
                return (None, False)
            tmpvn = addop.getIn(0)
            if not tmpvn.isWritten():
                return (None, False)
            zext1 = tmpvn.getDef()
            if zext1.code() != OpCode.CPUI_INT_ZEXT:
                return (None, False)
            tmpvn = addop.getIn(1)
            if not tmpvn.isWritten():
                return (None, False)
            zext2 = tmpvn.getDef()
            if zext2.code() != OpCode.CPUI_INT_ZEXT:
                return (None, False)
        elif vn2.isWritten():
            tmpop = vn2.getDef()
            if tmpop.code() == OpCode.CPUI_INT_ZEXT:
                # Form 2: (z - 1) + z
                zext2 = tmpop
                vn1 = op.getIn(0)
                if not vn1.isWritten():
                    return (None, False)
                addop = vn1.getDef()
                if addop.code() != OpCode.CPUI_INT_ADD:
                    # Partial form: (z + z)
                    zext1 = addop
                    if zext1.code() != OpCode.CPUI_INT_ZEXT:
                        return (None, False)
                    isPartial = True
                else:
                    tmpvn = addop.getIn(1)
                    if not tmpvn.isConstant():
                        return (None, False)
                    mask = calc_mask(tmpvn.getSize())
                    if mask != tmpvn.getOffset():
                        return (None, False)
                    tmpvn = addop.getIn(0)
                    if not tmpvn.isWritten():
                        return (None, False)
                    zext1 = tmpvn.getDef()
                    if zext1.code() != OpCode.CPUI_INT_ZEXT:
                        return (None, False)
            elif tmpop.code() == OpCode.CPUI_INT_ADD:
                # Form 3: z + (z - 1)
                addop = tmpop
                vn1 = op.getIn(0)
                if not vn1.isWritten():
                    return (None, False)
                zext1 = vn1.getDef()
                if zext1.code() != OpCode.CPUI_INT_ZEXT:
                    return (None, False)
                tmpvn = addop.getIn(1)
                if not tmpvn.isConstant():
                    return (None, False)
                mask = calc_mask(tmpvn.getSize())
                if mask != tmpvn.getOffset():
                    return (None, False)
                tmpvn = addop.getIn(0)
                if not tmpvn.isWritten():
                    return (None, False)
                zext2 = tmpvn.getDef()
                if zext2.code() != OpCode.CPUI_INT_ZEXT:
                    return (None, False)
            else:
                return (None, False)
        else:
            return (None, False)

        vn1 = zext1.getIn(0)
        if not vn1.isWritten():
            return (None, False)
        vn2 = zext2.getIn(0)
        if not vn2.isWritten():
            return (None, False)
        lessop = vn1.getDef()
        lessequalop = vn2.getDef()
        opc = lessop.code()
        if opc not in (OpCode.CPUI_INT_LESS, OpCode.CPUI_INT_SLESS, OpCode.CPUI_FLOAT_LESS):
            lessop, lessequalop = lessequalop, lessop
        form = RuleThreeWayCompare.testCompareEquivalence(lessop, lessequalop)
        if form < 0:
            return (None, False)
        if form == 1:
            lessop, lessequalop = lessequalop, lessop
        return (lessop, isPartial)

    def applyOp(self, op, data):
        constSlot = 0
        tmpvn = op.getIn(constSlot)
        if not tmpvn.isConstant():
            constSlot = 1
            tmpvn = op.getIn(constSlot)
            if not tmpvn.isConstant():
                return 0
        val = tmpvn.getOffset()
        if val <= 2:
            form = int(val) + 1
        elif val == calc_mask(tmpvn.getSize()):
            form = 0
        else:
            return 0

        tmpvn = op.getIn(1 - constSlot)
        if not tmpvn.isWritten():
            return 0
        if tmpvn.getDef().code() != OpCode.CPUI_INT_ADD:
            return 0
        lessop, isPartial = RuleThreeWayCompare.detectThreeWay(tmpvn.getDef())
        if lessop is None:
            return 0
        if isPartial:
            if form == 0:
                return 0
            form -= 1

        form <<= 1
        if constSlot == 1:
            form += 1
        lessform = lessop.code()
        form <<= 2
        opc = op.code()
        if opc == OpCode.CPUI_INT_SLESSEQUAL:
            form += 1
        elif opc == OpCode.CPUI_INT_EQUAL:
            form += 2
        elif opc == OpCode.CPUI_INT_NOTEQUAL:
            form += 3

        bvn = lessop.getIn(0)
        avn = lessop.getIn(1)
        if not avn.isConstant() and avn.isFree():
            return 0
        if not bvn.isConstant() and bvn.isFree():
            return 0

        if form in (1, 21):
            # always true
            data.opSetOpcode(op, OpCode.CPUI_INT_EQUAL)
            data.opSetInput(op, data.newConstant(1, 0), 0)
            data.opSetInput(op, data.newConstant(1, 0), 1)
        elif form in (4, 16):
            # always false
            data.opSetOpcode(op, OpCode.CPUI_INT_NOTEQUAL)
            data.opSetInput(op, data.newConstant(1, 0), 0)
            data.opSetInput(op, data.newConstant(1, 0), 1)
        elif form in (2, 5, 6, 12):
            # a < b
            data.opSetOpcode(op, lessform)
            data.opSetInput(op, avn, 0)
            data.opSetInput(op, bvn, 1)
        elif form in (13, 19, 20, 23):
            # a <= b
            data.opSetOpcode(op, OpCode(int(lessform) + 1))
            data.opSetInput(op, avn, 0)
            data.opSetInput(op, bvn, 1)
        elif form in (8, 17, 18, 22):
            # a > b (swap)
            data.opSetOpcode(op, lessform)
            data.opSetInput(op, bvn, 0)
            data.opSetInput(op, avn, 1)
        elif form in (0, 3, 7, 9):
            # a >= b (swap + lessequal)
            data.opSetOpcode(op, OpCode(int(lessform) + 1))
            data.opSetInput(op, bvn, 0)
            data.opSetInput(op, avn, 1)
        elif form in (10, 14):
            # a == b
            if lessform == OpCode.CPUI_FLOAT_LESS:
                lessform = OpCode.CPUI_FLOAT_EQUAL
            else:
                lessform = OpCode.CPUI_INT_EQUAL
            data.opSetOpcode(op, lessform)
            data.opSetInput(op, avn, 0)
            data.opSetInput(op, bvn, 1)
        elif form in (11, 15):
            # a != b
            if lessform == OpCode.CPUI_FLOAT_LESS:
                lessform = OpCode.CPUI_FLOAT_NOTEQUAL
            else:
                lessform = OpCode.CPUI_INT_NOTEQUAL
            data.opSetOpcode(op, lessform)
            data.opSetInput(op, avn, 0)
            data.opSetInput(op, bvn, 1)
        else:
            return 0
        return 1


class RuleRangeMeld(Rule):
    """Merge adjacent range checks (BOOL_AND/BOOL_OR of comparisons on the same variable).

    Try to union or intersect the ranges to produce a more concise expression.
    """
    def __init__(self, g): super().__init__(g, 0, "rangemeld")
    def clone(self, gl):
        return RuleRangeMeld(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_BOOL_AND, OpCode.CPUI_BOOL_OR]
    def applyOp(self, op, data):
        from ghidra.analysis.rangeutil import CircleRange
        from ghidra.core.expression import functionalEquality
        vn1 = op.getIn(0)
        if not vn1.isWritten():
            return 0
        vn2 = op.getIn(1)
        if not vn2.isWritten():
            return 0
        sub1 = vn1.getDef()
        if not (hasattr(sub1, 'isBoolOutput') and sub1.isBoolOutput()):
            return 0
        sub2 = vn2.getDef()
        if not (hasattr(sub2, 'isBoolOutput') and sub2.isBoolOutput()):
            return 0

        range1 = CircleRange(0, 0, 1, 1)  # Full boolean range
        range1._left = 1
        range1._right = 2
        range1._mask = 0xFF
        range1._isempty = False
        markup = [None]
        A1, constMarkup1 = range1.pullBack(sub1, False)
        if A1 is None:
            return 0
        if constMarkup1 is not None:
            markup[0] = constMarkup1

        range2 = CircleRange(0, 0, 1, 1)
        range2._left = 1
        range2._right = 2
        range2._mask = 0xFF
        range2._isempty = False
        A2, constMarkup2 = range2.pullBack(sub2, False)
        if A2 is None:
            return 0
        if constMarkup2 is not None:
            markup[0] = constMarkup2

        if sub1.code() == OpCode.CPUI_BOOL_NEGATE:
            if not A1.isWritten():
                return 0
            A1, cm = range1.pullBack(A1.getDef(), False)
            if A1 is None:
                return 0
            if cm is not None:
                markup[0] = cm
        if sub2.code() == OpCode.CPUI_BOOL_NEGATE:
            if not A2.isWritten():
                return 0
            A2, cm = range2.pullBack(A2.getDef(), False)
            if A2 is None:
                return 0
            if cm is not None:
                markup[0] = cm

        if not functionalEquality(A1, A2):
            if A2.getSize() == A1.getSize():
                return 0
            if A1.getSize() < A2.getSize() and A2.isWritten():
                A2, cm = range2.pullBack(A2.getDef(), False)
                if cm is not None:
                    markup[0] = cm
            elif A1.isWritten():
                A1, cm = range1.pullBack(A1.getDef(), False)
                if cm is not None:
                    markup[0] = cm
            if A1 is None or A2 is None:
                return 0
            if A1 is not A2:
                return 0
        if not A1.isHeritageKnown():
            return 0

        if op.code() == OpCode.CPUI_BOOL_AND:
            restype = range1.intersect(range2)
        else:
            restype = range1.circleUnion(range2)

        if restype == 0:
            restype2, opc, resc, resslot = range1.translate2Op()
            if restype2 == 0:
                newConst = data.newConstant(A1.getSize(), resc)
                if markup[0] is not None:
                    if hasattr(newConst, 'copySymbolIfValid'):
                        newConst.copySymbolIfValid(markup[0])
                data.opSetOpcode(op, opc)
                data.opSetInput(op, A1, 1 - resslot)
                data.opSetInput(op, newConst, resslot)
                return 1

        if restype == 2:
            return 0
        if restype == 1:
            # Full range => always true
            data.opSetOpcode(op, OpCode.CPUI_COPY)
            data.opRemoveInput(op, 1)
            data.opSetInput(op, data.newConstant(1, 1), 0)
        elif restype == 3:
            # Empty => always false
            data.opSetOpcode(op, OpCode.CPUI_COPY)
            data.opRemoveInput(op, 1)
            data.opSetInput(op, data.newConstant(1, 0), 0)
        return 1


class RuleSwitchSingle(Rule):
    """Convert switch with single case to direct BRANCH."""
    def __init__(self, g): super().__init__(g, 0, "switchsingle")
    def clone(self, gl):
        return RuleSwitchSingle(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_BRANCHIND]
    def applyOp(self, op, data):
        bl = op.getParent()
        if bl is None or bl.sizeOut() != 1:
            return 0
        # Single-target BRANCHIND => convert to BRANCH
        data.opSetOpcode(op, OpCode.CPUI_BRANCH)
        return 1


class RuleSegment(Rule):
    """Convert SEGMENTOP to equivalent address calculation."""
    def __init__(self, g): super().__init__(g, 0, "segment")
    def clone(self, gl):
        return RuleSegment(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_SEGMENTOP]
    def applyOp(self, op, data):
        # SEGMENTOP(space, base, offset) => base + offset in most flat models
        if op.numInput() < 3: return 0
        basevn = op.getIn(1)
        offvn = op.getIn(2)
        if basevn.isConstant() and basevn.getOffset() == 0:
            # Trivial segment: just use the offset
            data.opSetOpcode(op, OpCode.CPUI_COPY)
            data.opSetInput(op, offvn, 0)
            while op.numInput() > 1:
                data.opRemoveInput(op, op.numInput() - 1)
            return 1
        return 0


class RuleTransformCpool(Rule):
    """Transform constant pool references into direct values when possible."""
    def __init__(self, g): super().__init__(g, 0, "transformcpool")
    def clone(self, gl):
        return RuleTransformCpool(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_CPOOLREF]
    def applyOp(self, op, data):
        glb = data.getArch()
        if glb is None: return 0
        cpool = getattr(glb, 'cpool', None)
        if cpool is None: return 0
        # Would query constant pool to resolve the reference
        return 0  # Needs cpool.getRecord()


class RulePiecePathology(Rule):
    """Fix PIECE where high part is sign/zero extension of low part."""
    def __init__(self, g): super().__init__(g, 0, "piecepathology")
    def clone(self, gl):
        return RulePiecePathology(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_PIECE]
    def applyOp(self, op, data):
        hivn = op.getIn(0)  # High part
        lovn = op.getIn(1)  # Low part
        # Check if high part is all zeros (zero extension of low)
        if hivn.isConstant() and hivn.getOffset() == 0:
            data.opSetOpcode(op, OpCode.CPUI_INT_ZEXT)
            data.opSetInput(op, lovn, 0)
            data.opRemoveInput(op, 1)
            return 1
        return 0


class RulePieceStructure(Rule):
    """Detect PIECE ops that form structure fields and convert to structured access."""
    def __init__(self, g): super().__init__(g, 0, "piecestructure")
    def clone(self, gl):
        return RulePieceStructure(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_PIECE]
    def applyOp(self, op, data):
        # Would detect when PIECE inputs come from adjacent fields of the same structure
        # and convert to a direct structure access
        outvn = op.getOut()
        if outvn is None: return 0
        # Need to check if output has a structured type
        dt = outvn.getType() if hasattr(outvn, 'getType') and outvn.getType() is not None else None
        if dt is None: return 0
        from ghidra.types.datatype import TYPE_STRUCT
        if dt.getMetatype() == TYPE_STRUCT:
            # Would check if inputs match adjacent fields
            pass
        return 0
