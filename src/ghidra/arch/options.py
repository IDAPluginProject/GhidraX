"""
Corresponds to: options.hh / options.cc

Classes for processing architecture configuration options.
ArchOption base class + OptionDatabase dispatcher + all concrete option classes.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Optional, Dict

from ghidra.core.error import LowlevelError, ParseError, RecovError
from ghidra.core.marshal import ElementId

if TYPE_CHECKING:
    from ghidra.arch.architecture import Architecture


class ArchOption(ABC):
    """Base class for options that affect Architecture configuration."""

    def __init__(self) -> None:
        self.name: str = ""

    def getName(self) -> str:
        return self.name

    @abstractmethod
    def apply(self, glb, p1: str = "", p2: str = "", p3: str = "") -> str:
        raise NotImplementedError

    @staticmethod
    def onOrOff(p: str) -> bool:
        if len(p) == 0:
            return True
        if p == "on":
            return True
        if p == "off":
            return False
        raise ParseError("Must specify toggle value, on/off")


class OptionDatabase:
    """Dispatcher for ArchOption commands."""

    def __init__(self, glb) -> None:
        self._glb = glb
        self._optionmap: Dict[int, ArchOption] = {}
        self._registerDefaults()

    def _registerDefaults(self) -> None:
        for cls in _ALL_OPTIONS:
            self.registerOption(cls())

    def registerOption(self, option: ArchOption) -> None:
        option_id = ElementId.find(option.getName(), 0)
        self._optionmap[option_id] = option

    def __del__(self) -> None:
        if hasattr(self, "_optionmap"):
            self._optionmap.clear()

    def set(self, nameId: int, p1: str = "", p2: str = "", p3: str = "") -> str:
        opt = self._optionmap.get(nameId)
        if opt is None:
            raise ParseError("Unknown option")
        return opt.apply(self._glb, p1, p2, p3)

    def decodeOne(self, decoder) -> None:
        from ghidra.core.marshal import (
            ATTRIB_CONTENT,
            ELEM_PARAM1,
            ELEM_PARAM2,
            ELEM_PARAM3,
        )

        p1 = ""
        p2 = ""
        p3 = ""

        elemId = decoder.openElement()
        subId = decoder.openElement()
        if subId == ELEM_PARAM1.id:
            p1 = decoder.readString(ATTRIB_CONTENT)
            decoder.closeElement(subId)
            subId = decoder.openElement()
            if subId == ELEM_PARAM2.id:
                p2 = decoder.readString(ATTRIB_CONTENT)
                decoder.closeElement(subId)
                subId = decoder.openElement()
                if subId == ELEM_PARAM3.id:
                    p3 = decoder.readString(ATTRIB_CONTENT)
                    decoder.closeElement(subId)
        elif subId == 0:
            p1 = decoder.readString(ATTRIB_CONTENT)

        decoder.closeElement(elemId)
        self.set(elemId, p1, p2, p3)

    def decode(self, decoder) -> None:
        from ghidra.core.marshal import ELEM_OPTIONSLIST

        elemId = decoder.openElement(ELEM_OPTIONSLIST)
        while decoder.peekElement() != 0:
            self.decodeOne(decoder)
        decoder.closeElement(elemId)


# ================================================================
# Concrete option classes
# ================================================================

class OptionExtraPop(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "extrapop"

    def apply(self, glb, p1="", p2="", p3=""):
        from ghidra.fspec.fspec import ProtoModel

        expop = -300
        if p1 == "unknown":
            expop = ProtoModel.extrapop_unknown
        else:
            try:
                expop = int(p1, 0)
            except ValueError:
                pass
        if expop == -300:
            raise ParseError("Bad extrapop adjustment parameter")
        if len(p2) != 0:
            fd = glb.symboltab.getGlobalScope().queryFunction(p2)
            if fd is None:
                raise RecovError("Unknown function name: " + p2)
            fd.getFuncProto().setExtraPop(expop)
            return "ExtraPop set for function " + p2
        glb.defaultfp.setExtraPop(expop)
        if glb.evalfp_current is not None:
            glb.evalfp_current.setExtraPop(expop)
        if glb.evalfp_called is not None:
            glb.evalfp_called.setExtraPop(expop)
        return "Global extrapop set"


class OptionDefaultPrototype(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "defaultprototype"

    def apply(self, glb, p1="", p2="", p3=""):
        model = glb.getModel(p1)
        if model is None:
            raise LowlevelError("Unknown prototype model :" + p1)
        glb.setDefaultModel(model)
        return "Set default prototype to " + p1


class OptionInferConstPtr(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "inferconstptr"

    def apply(self, glb, p1="", p2="", p3=""):
        val = ArchOption.onOrOff(p1)
        if val:
            glb.infer_pointers = True
            return "Constant pointers are now inferred"
        glb.infer_pointers = False
        return "Constant pointers must now be set explicitly"


class OptionForLoops(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "analyzeforloops"

    def apply(self, glb, p1="", p2="", p3=""):
        glb.analyze_for_loops = ArchOption.onOrOff(p1)
        return "Recovery of for-loops is " + p1


class OptionNullPrinting(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "nullprinting"

    def apply(self, glb, p1="", p2="", p3=""):
        val = ArchOption.onOrOff(p1)
        if glb.print_.getName() != "c-language":
            return "Only c-language accepts the null printing option"
        glb.print_.setNULLPrinting(val)
        prop = "on" if val else "off"
        return "Null printing turned " + prop


class OptionInPlaceOps(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "inplaceops"

    def apply(self, glb, p1="", p2="", p3=""):
        val = ArchOption.onOrOff(p1)
        if glb.print_.getName() != "c-language":
            return "Can only set inplace operators for C language"
        glb.print_.setInplaceOps(val)
        prop = "on" if val else "off"
        return "Inplace operators turned " + prop


class OptionConventionPrinting(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "conventionprinting"

    def apply(self, glb, p1="", p2="", p3=""):
        val = ArchOption.onOrOff(p1)
        if glb.print_.getName() != "c-language":
            return "Can only set convention printing for C language"
        glb.print_.setConvention(val)
        prop = "on" if val else "off"
        return "Convention printing turned " + prop


class OptionNoCastPrinting(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "nocastprinting"

    def apply(self, glb, p1="", p2="", p3=""):
        val = ArchOption.onOrOff(p1)
        if glb.print_.getName() != "c-language":
            return "Can only set no cast printing for C language"
        glb.print_.setNoCastPrinting(val)
        prop = "on" if val else "off"
        return "No cast printing turned " + prop


class OptionHideExtensions(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "hideextensions"

    def apply(self, glb, p1="", p2="", p3=""):
        val = ArchOption.onOrOff(p1)
        if glb.print_.getName() != "c-language":
            return "Can only toggle extension hiding for C language"
        glb.print_.setHideImpliedExts(val)
        prop = "on" if val else "off"
        return "Implied extension hiding turned " + prop


class OptionMaxLineWidth(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "maxlinewidth"

    def apply(self, glb, p1="", p2="", p3=""):
        try:
            val = int(p1, 0)
        except ValueError:
            val = -1
        if val == -1:
            raise ParseError("Must specify integer linewidth")
        glb.print_.setMaxLineSize(val)
        return "Maximum line width set to " + p1


class OptionIndentIncrement(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "indentincrement"

    def apply(self, glb, p1="", p2="", p3=""):
        try:
            val = int(p1, 0)
        except ValueError:
            val = -1
        if val == -1:
            raise ParseError("Must specify integer increment")
        glb.print_.setIndentIncrement(val)
        return "Characters per indent level set to " + p1


class OptionCommentIndent(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "commentindent"

    def apply(self, glb, p1="", p2="", p3=""):
        try:
            val = int(p1, 0)
        except ValueError:
            val = -1
        if val == -1:
            raise ParseError("Must specify integer comment indent")
        glb.print_.setLineCommentIndent(val)
        return "Comment indent set to " + p1


class OptionCommentStyle(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "commentstyle"

    def apply(self, glb, p1="", p2="", p3=""):
        glb.print_.setCommentStyle(p1)
        return "Comment style set to " + p1


class OptionCommentHeader(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "commentheader"

    def apply(self, glb, p1="", p2="", p3=""):
        from ghidra.database.comment import Comment

        toggle = ArchOption.onOrOff(p2)
        flags = glb.print_.getHeaderComment()
        val = Comment.encodeCommentType(p1)
        if toggle:
            flags |= val
        else:
            flags &= ~val
        glb.print_.setHeaderComment(flags)
        prop = "on" if toggle else "off"
        return "Header comment type " + p1 + " turned " + prop


class OptionCommentInstruction(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "commentinstruction"

    def apply(self, glb, p1="", p2="", p3=""):
        from ghidra.database.comment import Comment

        toggle = ArchOption.onOrOff(p2)
        flags = glb.print_.getInstructionComment()
        val = Comment.encodeCommentType(p1)
        if toggle:
            flags |= val
        else:
            flags &= ~val
        glb.print_.setInstructionComment(flags)
        prop = "on" if toggle else "off"
        return "Instruction comment type " + p1 + " turned " + prop


class OptionIntegerFormat(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "integerformat"

    def apply(self, glb, p1="", p2="", p3=""):
        glb.print_.setIntegerFormat(p1)
        return "Integer format set to " + p1


class OptionSetAction(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "setaction"

    def apply(self, glb, p1="", p2="", p3=""):
        if len(p1) == 0:
            raise ParseError("Must specify preexisting action")
        if len(p2) != 0:
            glb.allacts.cloneGroup(p1, p2)
            glb.allacts.setCurrent(p2)
            return "Created " + p2 + " by cloning " + p1 + " and made it current"
        glb.allacts.setCurrent(p1)
        return "Set current action to " + p1


class OptionCurrentAction(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "currentaction"

    def apply(self, glb, p1="", p2="", p3=""):
        if len(p1) == 0 or len(p2) == 0:
            raise ParseError("Must specify subaction, on/off")
        res = "Toggled "
        if len(p3) != 0:
            glb.allacts.setCurrent(p1)
            val = ArchOption.onOrOff(p3)
            glb.allacts.toggleAction(p1, p2, val)
            res += p2 + " in action " + p1
        else:
            val = ArchOption.onOrOff(p2)
            cur_name = glb.allacts.getCurrentName()
            glb.allacts.toggleAction(cur_name, p1, val)
            res += p1 + " in action " + cur_name
        return res


class OptionToggleRule(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "togglerule"

    def apply(self, glb, p1="", p2="", p3=""):
        if len(p1) == 0:
            raise ParseError("Must specify rule path")
        if len(p2) == 0:
            raise ParseError("Must specify on/off")
        val = ArchOption.onOrOff(p2)
        root = glb.allacts.getCurrent()
        if root is None:
            raise LowlevelError("Missing current action")
        if not val:
            res = "Successfully disabled" if root.disableRule(p1) else "Failed to disable"
        else:
            res = "Successfully enabled" if root.enableRule(p1) else "Failed to enable"
        return res + " rule"


class OptionAliasBlock(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "aliasblock"

    def apply(self, glb, p1="", p2="", p3=""):
        if len(p1) == 0:
            raise ParseError("Must specify alias block level")
        old_val = glb.alias_block_level
        if p1 == "none":
            glb.alias_block_level = 0
        elif p1 == "struct":
            glb.alias_block_level = 1
        elif p1 == "array":
            glb.alias_block_level = 2
        elif p1 == "all":
            glb.alias_block_level = 3
        else:
            raise ParseError("Unknown alias block level: " + p1)
        if old_val == glb.alias_block_level:
            return "Alias block level unchanged"
        return "Alias block level set to " + p1


class OptionMaxInstruction(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "maxinstruction"

    def apply(self, glb, p1="", p2="", p3=""):
        if len(p1) == 0:
            raise ParseError("Must specify number of instructions")
        try:
            new_max = int(p1, 0)
        except ValueError:
            new_max = -1
        if new_max < 0:
            raise ParseError("Bad maxinstruction parameter")
        glb.max_instructions = new_max
        return "Maximum instructions per function set"


class OptionNamespaceStrategy(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "namespacestrategy"

    def apply(self, glb, p1="", p2="", p3=""):
        from ghidra.output.printlanguage import PrintLanguage
        if p1 == "minimal":
            strategy = PrintLanguage.MINIMAL_NAMESPACES
        elif p1 == "all":
            strategy = PrintLanguage.ALL_NAMESPACES
        elif p1 == "none":
            strategy = PrintLanguage.NO_NAMESPACES
        else:
            raise ParseError("Must specify a valid strategy")
        glb.print_.setNamespaceStrategy(strategy)
        return "Namespace strategy set"


class OptionJumpTableMax(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "jumptablemax"

    def apply(self, glb, p1="", p2="", p3=""):
        try:
            val = int(p1, 0)
        except ValueError:
            val = 0
        if val == 0:
            raise ParseError("Must specify integer maximum")
        glb.max_jumptable_size = val
        return "Maximum jumptable size set to " + p1


class OptionProtoEval(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "protoeval"

    def apply(self, glb, p1="", p2="", p3=""):
        if len(p1) == 0:
            raise ParseError("Must specify prototype model")
        if p1 == "default":
            model = glb.defaultfp
        else:
            model = glb.getModel(p1)
            if model is None:
                raise ParseError("Unknown prototype model: " + p1)
        glb.evalfp_current = model
        return "Set current evaluation to " + p1


class OptionSetLanguage(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "setlanguage"

    def apply(self, glb, p1="", p2="", p3=""):
        glb.setPrintLanguage(p1)
        return "Decompiler produces " + p1


class OptionSplitDatatypes(ArchOption):
    option_struct = 1
    option_array = 2
    option_pointer = 4

    def __init__(self):
        super().__init__()
        self.name = "splitdatatype"

    @staticmethod
    def getOptionBit(val: str) -> int:
        if len(val) == 0:
            return 0
        if val == "struct":
            return OptionSplitDatatypes.option_struct
        if val == "array":
            return OptionSplitDatatypes.option_array
        if val == "pointer":
            return OptionSplitDatatypes.option_pointer
        raise LowlevelError("Unknown data-type split option: " + val)

    def apply(self, glb, p1="", p2="", p3=""):
        old_config = glb.split_datatype_config
        glb.split_datatype_config = OptionSplitDatatypes.getOptionBit(p1)
        glb.split_datatype_config |= OptionSplitDatatypes.getOptionBit(p2)
        glb.split_datatype_config |= OptionSplitDatatypes.getOptionBit(p3)
        current_name = glb.allacts.getCurrentName()
        if (glb.split_datatype_config & (self.option_struct | self.option_array)) == 0:
            glb.allacts.toggleAction(current_name, "splitcopy", False)
            glb.allacts.toggleAction(current_name, "splitpointer", False)
        else:
            pointers = (glb.split_datatype_config & self.option_pointer) != 0
            glb.allacts.toggleAction(current_name, "splitcopy", True)
            glb.allacts.toggleAction(current_name, "splitpointer", pointers)
        if old_config == glb.split_datatype_config:
            return "Split data-type configuration unchanged"
        return "Split data-type configuration set"


class OptionNanIgnore(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "nanignore"

    def apply(self, glb, p1="", p2="", p3=""):
        old_ignore_all = glb.nan_ignore_all
        old_ignore_compare = glb.nan_ignore_compare
        if p1 == "none":
            glb.nan_ignore_all = False
            glb.nan_ignore_compare = False
        elif p1 == "compare":
            glb.nan_ignore_all = False
            glb.nan_ignore_compare = True
        elif p1 == "all":
            glb.nan_ignore_all = True
            glb.nan_ignore_compare = True
        else:
            raise LowlevelError("Unknown nanignore option: " + p1)
        root = glb.allacts.getCurrent()
        if not glb.nan_ignore_all and not glb.nan_ignore_compare:
            root.disableRule("ignorenan")
        else:
            root.enableRule("ignorenan")
        if old_ignore_all == glb.nan_ignore_all and old_ignore_compare == glb.nan_ignore_compare:
            return "NaN ignore configuration unchanged"
        return "Nan ignore configuration set to: " + p1


class OptionWarning(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "warning"

    def apply(self, glb, p1="", p2="", p3=""):
        if len(p1) == 0:
            raise ParseError("No action/rule specified")
        val = True if len(p2) == 0 else ArchOption.onOrOff(p2)
        res = glb.allacts.getCurrent().setWarning(val, p1)
        if not res:
            raise RecovError("Bad action/rule specifier: " + p1)
        prop = "on" if val else "off"
        return "Warnings for " + p1 + " turned " + prop


class OptionReadOnly(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "readonly"

    def apply(self, glb, p1="", p2="", p3=""):
        if len(p1) == 0:
            raise ParseError('Read-only option must be set "on" or "off"')
        glb.readonlypropagate = ArchOption.onOrOff(p1)
        if glb.readonlypropagate:
            return "Read-only memory locations now propagate as constants"
        return "Read-only memory locations now do not propagate"


class OptionInline(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "inline"

    def apply(self, glb, p1="", p2="", p3=""):
        infd = glb.symboltab.getGlobalScope().queryFunction(p1)
        if infd is None:
            raise RecovError("Unknown function name: " + p1)
        val = True if len(p2) == 0 else (p2 == "true")
        infd.getFuncProto().setInline(val)
        prop = "true" if val else "false"
        return "Inline property for function " + p1 + " = " + prop


class OptionNoReturn(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "noreturn"

    def apply(self, glb, p1="", p2="", p3=""):
        infd = glb.symboltab.getGlobalScope().queryFunction(p1)
        if infd is None:
            raise RecovError("Unknown function name: " + p1)
        val = True if len(p2) == 0 else (p2 == "true")
        infd.getFuncProto().setNoReturn(val)
        prop = "true" if val else "false"
        return "No return property for function " + p1 + " = " + prop


class OptionIgnoreUnimplemented(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "ignoreunimplemented"

    def apply(self, glb, p1="", p2="", p3=""):
        from ghidra.analysis.flow import FlowInfo

        val = ArchOption.onOrOff(p1)
        if val:
            glb.flowoptions |= FlowInfo.ignore_unimplemented
            return "Unimplemented instructions are now ignored (treated as nop)"
        glb.flowoptions &= ~FlowInfo.ignore_unimplemented
        return "Unimplemented instructions now generate warnings"


class OptionErrorUnimplemented(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "errorunimplemented"

    def apply(self, glb, p1="", p2="", p3=""):
        from ghidra.analysis.flow import FlowInfo

        val = ArchOption.onOrOff(p1)
        if val:
            glb.flowoptions |= FlowInfo.error_unimplemented
            return "Unimplemented instructions are now a fatal error"
        glb.flowoptions &= ~FlowInfo.error_unimplemented
        return "Unimplemented instructions now NOT a fatal error"


class OptionErrorReinterpreted(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "errorreinterpreted"

    def apply(self, glb, p1="", p2="", p3=""):
        from ghidra.analysis.flow import FlowInfo

        val = ArchOption.onOrOff(p1)
        if val:
            glb.flowoptions |= FlowInfo.error_reinterpreted
            return "Instruction reinterpretation is now a fatal error"
        glb.flowoptions &= ~FlowInfo.error_reinterpreted
        return "Instruction reinterpretation is now NOT a fatal error"


class OptionErrorTooManyInstructions(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "errortoomanyinstructions"

    def apply(self, glb, p1="", p2="", p3=""):
        from ghidra.analysis.flow import FlowInfo

        val = ArchOption.onOrOff(p1)
        if val:
            glb.flowoptions |= FlowInfo.error_toomanyinstructions
            return "Too many instructions are now a fatal error"
        glb.flowoptions &= ~FlowInfo.error_toomanyinstructions
        return "Too many instructions are now NOT a fatal error"


class OptionAllowContextSet(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "allowcontextset"

    def apply(self, glb, p1="", p2="", p3=""):
        val = ArchOption.onOrOff(p1)
        prop = "on" if val else "off"
        glb.translate.allowContextSet(val)
        return "Toggled allowcontextset to " + prop


class OptionJumpLoad(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "jumpload"

    def apply(self, glb, p1="", p2="", p3=""):
        from ghidra.analysis.flow import FlowInfo

        val = ArchOption.onOrOff(p1)
        if val:
            glb.flowoptions |= FlowInfo.record_jumploads
            return "Jumptable analysis will record loads required to calculate jump address"
        glb.flowoptions &= ~FlowInfo.record_jumploads
        return "Jumptable analysis will NOT record loads"


class OptionBraceFormat(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "braceformat"

    def apply(self, glb, p1="", p2="", p3=""):
        from ghidra.output.prettyprint import Emit
        if glb.print_.getName() != "c-language":
            return "Can only set brace formatting for C language"
        if p2 == "same":
            style = Emit.same_line
        elif p2 == "next":
            style = Emit.next_line
        elif p2 == "skip":
            style = Emit.skip_line
        else:
            raise ParseError("Unknown brace style: " + p2)
        if p1 == "function":
            glb.print_.setBraceFormatFunction(style)
        elif p1 == "ifelse":
            glb.print_.setBraceFormatIfElse(style)
        elif p1 == "loop":
            glb.print_.setBraceFormatLoop(style)
        elif p1 == "switch":
            glb.print_.setBraceFormatSwitch(style)
        else:
            raise ParseError("Unknown brace format category: " + p1)
        return "Brace formatting for " + p1 + " set to " + p2


class OptionStructAlign(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "structalign"

    def apply(self, glb, p1="", p2="", p3=""):
        try:
            val = int(p1)
        except ValueError:
            raise LowlevelError(f"Bad structalign value: {p1}")
        if hasattr(glb, 'types') and glb.types is not None:
            glb.types.setStructAlign(val) if hasattr(glb.types, 'setStructAlign') else None
        return f"Struct alignment set to {val}"


# Registry of all option classes
_ALL_OPTIONS = [
    OptionExtraPop, OptionReadOnly, OptionIgnoreUnimplemented,
    OptionErrorUnimplemented, OptionErrorReinterpreted, OptionErrorTooManyInstructions,
    OptionDefaultPrototype, OptionInferConstPtr, OptionForLoops, OptionInline,
    OptionNoReturn, OptionProtoEval, OptionWarning, OptionNullPrinting,
    OptionInPlaceOps, OptionConventionPrinting, OptionNoCastPrinting,
    OptionMaxLineWidth, OptionIndentIncrement, OptionCommentIndent,
    OptionCommentStyle, OptionCommentHeader, OptionCommentInstruction,
    OptionIntegerFormat, OptionBraceFormat, OptionCurrentAction,
    OptionAllowContextSet, OptionSetAction, OptionSetLanguage,
    OptionJumpTableMax, OptionJumpLoad, OptionToggleRule, OptionAliasBlock,
    OptionMaxInstruction, OptionNamespaceStrategy, OptionSplitDatatypes,
    OptionNanIgnore,
]
