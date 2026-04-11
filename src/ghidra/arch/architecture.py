"""
Corresponds to: architecture.hh / architecture.cc

Architecture and associated classes that help manage a single processor
architecture and load image.
"""

from __future__ import annotations

import math
from typing import Optional, List, Dict, TYPE_CHECKING

from ghidra.core.address import Address, Range, RangeList, RangeProperties, calc_mask
from ghidra.core.error import LowlevelError, ParseError
from ghidra.core.space import (
    AddrSpace, AddrSpaceManager, OtherSpace, SpacebaseSpace,
    IPTR_PROCESSOR, IPTR_SPACEBASE, IPTR_INTERNAL,
)
from ghidra.core.translate import Translate
from ghidra.core.pcoderaw import VarnodeData
from ghidra.core.opbehavior import OpBehavior
from ghidra.core.globalcontext import ContextDatabase, ContextInternal
from ghidra.types.datatype import TypeFactory
from ghidra.types.cast import CastStrategyC
from ghidra.database.database import Database, ScopeInternal
from ghidra.database.comment import Comment, CommentDatabase, CommentDatabaseInternal
from ghidra.database.stringmanage import StringManager, StringManagerUnicode
from ghidra.database.cpool import ConstantPool, ConstantPoolInternal
from ghidra.fspec.fspec import ProtoModel, FuncProto, UnknownProtoModel
from ghidra.ir.typeop import TypeOp, registerTypeOps
from ghidra.output.printlanguage import PrintLanguage, PrintLanguageCapability
from ghidra.output.printc import PrintC
from ghidra.output.prettyprint import EmitMarkup
from ghidra.transform.action import ActionDatabase
from ghidra.arch.loadimage import LoadImage, LoadImageFunc
from ghidra.arch.userop import UserOpManage
from ghidra.arch.override import Override, ELEM_FLOW, ATTRIB_TYPE
from ghidra.arch.inject import PcodeInjectLibrary

if TYPE_CHECKING:
    from ghidra.analysis.funcdata import Funcdata


ELEM_FLOWOVERRIDELIST = 140


# =========================================================================
# Statistics
# =========================================================================

class Statistics:
    """Collect simple cast statistics across processed functions."""

    def __init__(self) -> None:
        self.numfunc: int = 0
        self.numvar: int = 0
        self.coversum: int = 0
        self.coversumsq: int = 0
        self.lastcastcount: int = 0
        self.castcount: int = 0
        self.castcountsq: int = 0

    def __del__(self) -> None:
        pass

    def process_cast(self, data: Funcdata) -> None:
        perfunc = self.castcount - self.lastcastcount
        self.lastcastcount = self.castcount
        self.castcountsq += perfunc * perfunc

    def countCast(self) -> None:
        self.castcount += 1

    def process(self, fd: Funcdata) -> None:
        self.numfunc += 1
        self.process_cast(fd)

    def printResults(self, s) -> None:
        s.write(f"Number of functions: {self.numfunc}\n")

        if self.numfunc == 0:
            average = math.inf if self.castcount != 0 else math.nan
            variance = math.inf if self.castcountsq != 0 else math.nan
        else:
            average = float(self.castcount) / float(self.numfunc)
            variance = float(self.castcountsq) / float(self.numfunc)
        variance -= average * average
        stddev = math.sqrt(variance) if variance >= 0.0 else math.nan

        s.write(f"Total functions = {self.numfunc}\n")
        s.write(f"Total casts = {self.castcount}\n")
        s.write(f"Average casts per function = {format(average, 'g')}\n")
        s.write(f"        Standard deviation = {format(stddev, 'g')}\n")


# =========================================================================
# ArchitectureCapability
# =========================================================================

class ArchitectureCapability:
    """Abstract extension point for building Architecture objects.

    Each extension implements buildArchitecture() as the formal entry point
    for the bootstrapping process.
    """

    _thelist: List[ArchitectureCapability] = []
    majorversion: int = 6
    minorversion: int = 1

    def __init__(self) -> None:
        self.name: str = ""

    def getName(self) -> str:
        return self.name

    def initialize(self) -> None:
        """Register this capability."""
        ArchitectureCapability._thelist.append(self)

    def buildArchitecture(self, filename: str, target: str, estream=None) -> Architecture:
        raise NotImplementedError

    def isFileMatch(self, filename: str) -> bool:
        raise NotImplementedError

    def isXmlMatch(self, doc) -> bool:
        raise NotImplementedError

    @staticmethod
    def findCapabilityByFile(filename: str) -> Optional[ArchitectureCapability]:
        for capa in ArchitectureCapability._thelist:
            if capa.isFileMatch(filename):
                return capa
        return None

    @staticmethod
    def findCapabilityByDoc(doc) -> Optional[ArchitectureCapability]:
        for capa in ArchitectureCapability._thelist:
            if capa.isXmlMatch(doc):
                return capa
        return None

    @staticmethod
    def getCapability(name: str) -> Optional[ArchitectureCapability]:
        for capa in ArchitectureCapability._thelist:
            if capa.getName() == name:
                return capa
        return None

    @staticmethod
    def sortCapabilities() -> None:
        """Make sure the raw architecture comes last."""
        lst = ArchitectureCapability._thelist
        for i, capa in enumerate(lst):
            if capa.getName() == "raw":
                lst.append(lst.pop(i))
                break

    @staticmethod
    def getMajorVersion() -> int:
        return ArchitectureCapability.majorversion

    @staticmethod
    def getMinorVersion() -> int:
        return ArchitectureCapability.minorversion


# =========================================================================
# Architecture
# =========================================================================

class Architecture(AddrSpaceManager):
    """Manager for all the major decompiler subsystems.

    An instantiation is tailored to a specific LoadImage, processor,
    and compiler spec. This class is the owner of the LoadImage, Translate,
    symbols (Database), PrintLanguage, etc.
    """

    def __init__(self) -> None:
        super().__init__()
        from ghidra.arch.options import OptionDatabase

        self.archid: str = ""

        # Configuration data — resetDefaultsInternal sets these
        self.trim_recurse_max: int = 0
        self.max_implied_ref: int = 0
        self.max_term_duplication: int = 0
        self.max_basetype_size: int = 0
        self.min_funcsymbol_size: int = 1
        self.max_jumptable_size: int = 0
        self.aggressive_ext_trim: bool = False
        self.readonlypropagate: bool = False
        self.infer_pointers: bool = True
        self.analyze_for_loops: bool = True
        self.nan_ignore_all: bool = False
        self.nan_ignore_compare: bool = True
        self.inferPtrSpaces: List[AddrSpace] = []
        self.funcptr_align: int = 0
        self.flowoptions: int = 0x10  # FlowInfo::error_toomanyinstructions
        self.max_instructions: int = 100000
        self.alias_block_level: int = 2
        self.split_datatype_config: int = 0x7  # struct|array|pointer
        self.extra_pool_rules: list = []

        self.resetDefaultsInternal()

        self.min_funcsymbol_size = 1
        self.aggressive_ext_trim = False
        self.funcptr_align = 0

        # Major subsystems
        self.symboltab: Optional[Database] = None
        self.context: Optional[ContextDatabase] = None
        self.protoModels: Dict[str, ProtoModel] = {}
        self.defaultfp: Optional[ProtoModel] = None
        self.defaultReturnAddr: VarnodeData = VarnodeData()
        self.evalfp_current: Optional[ProtoModel] = None
        self.evalfp_called: Optional[ProtoModel] = None
        self.types: Optional[TypeFactory] = None
        self.translate: Optional[Translate] = None
        self.loader: Optional[LoadImage] = None
        self.pcodeinjectlib: Optional[PcodeInjectLibrary] = None
        self.nohighptr: RangeList = RangeList()
        self.commentdb: Optional[CommentDatabase] = None
        self.stringManager: Optional[StringManager] = None
        self.cpool: Optional[ConstantPool] = None
        self.print_: Optional[PrintLanguage] = None
        self.printlist: List[PrintLanguage] = []
        self.options = OptionDatabase(self)
        self.inst: List[Optional[TypeOp]] = []
        self.userops: UserOpManage = UserOpManage()
        self.splitrecords: list = []
        self.lanerecords: list = []
        self.allacts: ActionDatabase = ActionDatabase()
        self.loadersymbols_parsed: bool = False
        self.stats: Statistics = Statistics()
        self._debugstream = None
        self.override: Optional[Override] = None
        self.extra_pop: int = 0

        # Build default print language
        pc = PrintLanguageCapability.getDefault().buildLanguage(self)
        self.printlist.append(pc)
        self.print_ = pc

    def __del__(self) -> None:
        inst = self.__dict__.get("inst")
        if inst is not None:
            inst.clear()

        extra_pool_rules = self.__dict__.get("extra_pool_rules")
        if extra_pool_rules is not None:
            extra_pool_rules.clear()

        proto_models = self.__dict__.get("protoModels")
        if proto_models is not None:
            proto_models.clear()

        printlist = self.__dict__.get("printlist")
        if printlist is not None:
            printlist.clear()

        for name in (
            "symboltab",
            "print_",
            "options",
            "stats",
            "defaultfp",
            "evalfp_current",
            "evalfp_called",
            "types",
            "translate",
            "loader",
            "pcodeinjectlib",
            "commentdb",
            "stringManager",
            "cpool",
            "context",
        ):
            if name in self.__dict__:
                setattr(self, name, None)

    # --- Initialization ---

    def init(self, store) -> None:
        """Load the image and configure architecture.

        Follows the C++ Architecture::init() ordering exactly.
        """
        self.buildLoader(store)
        self.resolveArchitecture()
        self.buildSpecFile(store)

        self.buildContext(store)
        self.buildTypegrp(store)
        self.buildCommentDB(store)
        self.buildStringManager(store)
        self.buildConstantPool(store)
        self.buildDatabase(store)

        self.restoreFromSpec(store)
        self.buildCoreTypes(store)
        self.print_.initializeFromArchitecture()
        self.symboltab.adjustCaches()
        self.buildSymbols(store)
        self.postSpecFile()

        self.buildInstructions(store)
        self.fillinReadOnlyFromLoader()

    def resetDefaultsInternal(self) -> None:
        """Reset default values for options specific to Architecture."""
        self.trim_recurse_max = 5
        self.max_implied_ref = 2
        self.max_term_duplication = 2
        self.max_basetype_size = 10
        self.flowoptions = 0x10  # FlowInfo::error_toomanyinstructions
        self.max_instructions = 100000
        self.infer_pointers = True
        self.analyze_for_loops = True
        self.readonlypropagate = False
        self.nan_ignore_all = False
        self.nan_ignore_compare = True
        self.alias_block_level = 2
        self.split_datatype_config = 0x7  # struct|array|pointer
        self.max_jumptable_size = 1024

    def resetDefaults(self) -> None:
        """Reset options that can be modified by the OptionDatabase."""
        self.resetDefaultsInternal()
        self.allacts.resetDefaults()
        for pl in self.printlist:
            pl.resetDefaults()

    # --- Prototype management ---

    def getModel(self, nm: str) -> Optional[ProtoModel]:
        """Get a specific PrototypeModel by name. Returns None if not found."""
        return self.protoModels.get(nm)

    def hasModel(self, nm: str) -> bool:
        """Does this Architecture have a specific PrototypeModel."""
        return nm in self.protoModels

    def createUnknownModel(self, modelName: str) -> Optional[ProtoModel]:
        """Create a model for an unrecognized name.

        Clones behavior from the default model.
        """
        model = UnknownProtoModel(modelName, self.defaultfp)
        self.protoModels[modelName] = model
        if modelName == "unknown":
            model.setPrintInDecl(False)
        return model

    def setDefaultModel(self, model: ProtoModel) -> None:
        """Set the default PrototypeModel."""
        if self.defaultfp is not None:
            self.defaultfp.setPrintInDecl(True)
        model.setPrintInDecl(False)
        self.defaultfp = model

    def addModel(self, model: ProtoModel) -> None:
        self.protoModels[model.getName()] = model

    def createModelAlias(self, aliasName: str, parentName: str) -> None:
        """Clone the named ProtoModel, attaching it to another name."""
        parent = self.protoModels.get(parentName)
        if parent is None:
            raise LowlevelError("Requesting non-existent prototype model: " + parentName)
        if parent.isMerged():
            raise LowlevelError("Cannot make alias of merged model: " + parentName)
        if parent.getAliasParent() is not None:
            raise LowlevelError("Cannot make alias of an alias: " + parentName)
        if aliasName in self.protoModels:
            raise LowlevelError("Duplicate ProtoModel name: " + aliasName)
        self.protoModels[aliasName] = parent.cloneWithName(aliasName)

    # --- Language selection ---

    def setPrintLanguage(self, nm: str) -> None:
        """Select one of the supported output languages."""
        for pl in self.printlist:
            if pl.getName() == nm:
                self.print_ = pl
                pl.adjustTypeOperators()
                return
        capability = PrintLanguageCapability.findCapability(nm)
        if capability is None:
            raise LowlevelError("Unknown print language: " + nm)
        printMarkup = self.print_.emitsMarkup()
        t = self.print_.getOutputStream()
        pl = capability.buildLanguage(self)
        pl.setOutputStream(t)
        pl.initializeFromArchitecture()
        if printMarkup:
            pl.setMarkup(True)
        self.printlist.append(pl)
        self.print_ = pl
        pl.adjustTypeOperators()

    def getPrintLanguage(self) -> Optional[PrintLanguage]:
        return self.print_

    # --- Core methods ---

    def clearAnalysis(self, fd: Funcdata) -> None:
        """Throw out the syntax tree and derived information about a single function."""
        fd.clear()
        self.commentdb.clearType(
            fd.getAddress(),
            Comment.CommentType.warning | Comment.CommentType.warningheader,
        )

    def readLoaderSymbols(self, delim: str) -> None:
        """Read any symbols from loader into database."""
        if self.loadersymbols_parsed:
            return
        self.loader.openSymbols()
        self.loadersymbols_parsed = True
        record = LoadImageFunc()
        while self.loader.getNextSymbol(record):
            basename: List[str] = []
            scope = self.symboltab.findCreateScopeFromSymbolName(
                record.name, delim, basename, None
            )
            scope.addFunction(record.address, basename[0])
        self.loader.closeSymbols()

    def collectBehaviors(self, behave: List[Optional[OpBehavior]]) -> None:
        """For all registered p-code opcodes, return the corresponding OpBehavior."""
        behave[:] = [None] * len(self.inst)
        for i, op in enumerate(self.inst):
            if op is None:
                continue
            behave[i] = op.getBehavior()

    def getSegmentOp(self, spc: AddrSpace):
        """Retrieve the segment op for the given space if any."""
        idx = spc.getIndex()
        if idx >= self.userops.numSegmentOps():
            return None
        segdef = self.userops.getSegmentOp(idx)
        if segdef is None:
            return None
        if segdef.getResolve().space is not None:
            return segdef
        return None

    def setPrototype(self, pieces) -> None:
        """Establish details of the prototype for a given function symbol."""
        basename: List[str] = []
        scope = self.symboltab.resolveScopeFromSymbolName(pieces.name, "::", basename, None)
        if scope is None:
            raise ParseError("Unknown namespace: " + pieces.name)
        fd = scope.queryFunction(basename[0])
        if fd is None:
            raise ParseError("Unknown function name: " + pieces.name)
        fd.getFuncProto().setPieces(pieces)

    def globalify(self) -> None:
        """Set all IPTR_PROCESSOR and IPTR_SPACEBASE spaces to be global."""
        scope = self.symboltab.getGlobalScope()
        nm = self.numSpaces()
        for i in range(nm):
            spc = self.getSpace(i)
            if spc is None:
                continue
            tp = spc.getType()
            if tp != IPTR_PROCESSOR and tp != IPTR_SPACEBASE:
                continue
            self.symboltab.addRange(scope, spc, 0, spc.getHighest())

    def addToGlobalScope(self, props: RangeProperties) -> None:
        """Add a memory range parsed from a <global> tag to the global scope."""
        scope = self.symboltab.getGlobalScope()
        rng = Range.from_properties(props, self)
        spc = rng.getSpace()
        self.inferPtrSpaces.append(spc)
        self.symboltab.addRange(scope, spc, rng.getFirst(), rng.getLast())
        if spc.isOverlayBase():
            num = self.numSpaces()
            for i in range(num):
                ospc = self.getSpace(i)
                if ospc is None or not ospc.isOverlay():
                    continue
                if ospc.getContain() is not spc:
                    continue
                self.symboltab.addRange(scope, ospc, rng.getFirst(), rng.getLast())

    def addOtherSpace(self) -> None:
        """Add OTHER space and all of its overlays to the symboltab."""
        scope = self.symboltab.getGlobalScope()
        otherSpace = self.getSpaceByName(OtherSpace.NAME)
        self.symboltab.addRange(scope, otherSpace, 0, otherSpace.getHighest())
        if otherSpace.isOverlayBase():
            num = self.numSpaces()
            for i in range(num):
                ospc = self.getSpace(i)
                if not ospc.isOverlay():
                    continue
                if ospc.getContain() is not otherSpace:
                    continue
                self.symboltab.addRange(scope, ospc, 0, otherSpace.getHighest())

    def highPtrPossible(self, loc: Address, size: int) -> bool:
        """Are pointers possible to the given location?"""
        if loc.getSpace().getType() == IPTR_INTERNAL:
            return False
        return not self.nohighptr.inRange(loc, size)

    def getSpaceBySpacebase(self, loc: Address, size: int) -> Optional[AddrSpace]:
        """Get space associated with a spacebase register."""
        sz = self.numSpaces()
        for i in range(sz):
            spc = self.getSpace(i)
            if spc is None:
                continue
            numbase = spc.numSpacebase()
            for j in range(numbase):
                point = spc.getSpacebase(j)
                if point.size != size:
                    continue
                if point.space is not loc.getSpace():
                    continue
                if point.offset != loc.getOffset():
                    continue
                return spc
        raise LowlevelError("Unable to find entry for spacebase register")

    def getLanedRegister(self, loc: Address, size: int):
        """Get LanedRegister associated with storage. Binary search in lanerecords."""
        lo, hi = 0, len(self.lanerecords) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            sz = self.lanerecords[mid].getWholeSize()
            if sz < size:
                lo = mid + 1
            elif size < sz:
                hi = mid - 1
            else:
                return self.lanerecords[mid]
        return None

    def getMinimumLanedRegisterSize(self) -> int:
        """Get the minimum size of a laned register in bytes."""
        if not self.lanerecords:
            return -1
        return self.lanerecords[0].getWholeSize()

    def getStackSpace(self) -> Optional[AddrSpace]:
        """Get the stack address space, if it exists."""
        sz = self.numSpaces()
        for i in range(sz):
            spc = self.getSpace(i)
            if spc is not None and spc.getType() == IPTR_SPACEBASE:
                return spc
        return None

    def nameFunction(self, addr: Address) -> str:
        """Pick a default name for a function."""
        return "func_" + addr.printRaw()

    def addSpacebase(self, basespace: AddrSpace, nm: str, ptrdata: VarnodeData,
                     truncSize: int = 0, isreversejustified: bool = False,
                     stackGrowth: bool = True, isFormal: bool = False) -> None:
        """Create a new address space associated with a pointer register."""
        ind = self.numSpaces()
        spc = SpacebaseSpace(
            self,
            self.translate,
            nm,
            ind,
            truncSize,
            basespace,
            ptrdata.space.getDelay() + 1,
            isFormal,
        )
        if isreversejustified:
            self.setReverseJustified(spc)
        self.insertSpace(spc)
        self.addSpacebasePointer(spc, ptrdata, truncSize, stackGrowth)

    def addNoHighPtr(self, rng: Range) -> None:
        """Add a new region where pointers do not exist."""
        self.nohighptr.insertRange(rng.getSpace(), rng.getFirst(), rng.getLast())

    def getDescription(self) -> str:
        """Get a string describing this architecture."""
        return self.archid

    def printMessage(self, message: str) -> None:
        """Print an error message to console."""
        raise NotImplementedError("Architecture.printMessage() must be implemented by subclasses")

    def decodeFlowOverride(self, decoder) -> None:
        """Decode flow overrides from a stream."""
        elemId = decoder.openElement(ELEM_FLOWOVERRIDELIST)
        while True:
            subId = decoder.openElement()
            if subId != ELEM_FLOW:
                break
            flowType = decoder.readString(ATTRIB_TYPE)
            funcaddr = Address.decode(decoder)
            overaddr = Address.decode(decoder)
            fd = self.symboltab.getGlobalScope().queryFunction(funcaddr)
            if fd is not None:
                fd.getOverride().insertFlowOverride(
                    overaddr, Override.stringToType(flowType)
                )
            decoder.closeElement(subId)
        decoder.closeElement(elemId)

    def encode(self, encoder) -> None:
        """Encode this architecture to a stream."""
        from ghidra.core.marshal import ATTRIB_LOADERSYMBOLS, ELEM_SAVE_STATE

        encoder.openElement(ELEM_SAVE_STATE)
        encoder.writeBool(ATTRIB_LOADERSYMBOLS, self.loadersymbols_parsed)
        self.types.encode(encoder)
        self.symboltab.encode(encoder)
        self.context.encode(encoder)
        self.commentdb.encode(encoder)
        self.stringManager.encode(encoder)
        if not self.cpool.empty():
            self.cpool.encode(encoder)
        encoder.closeElement(ELEM_SAVE_STATE)

    def restoreXml(self, store) -> None:
        """Restore the Architecture state from XML documents."""
        from ghidra.core.marshal import (
            ATTRIB_LOADERSYMBOLS,
            ELEM_COMMENTDB,
            ELEM_CONSTANTPOOL,
            ELEM_CONTEXT_POINTS,
            ELEM_DB,
            ELEM_INJECTDEBUG,
            ELEM_OPTIONSLIST,
            ELEM_SAVE_STATE,
            ELEM_STRINGMANAGE,
            ELEM_TYPEGRP,
            XmlDecode,
        )

        el = store.getTag(ELEM_SAVE_STATE.getName())
        if el is None:
            raise LowlevelError("Could not find save_state tag")

        decoder = XmlDecode(self, el)
        elemId = decoder.openElement(ELEM_SAVE_STATE)
        self.loadersymbols_parsed = False
        while True:
            attribId = decoder.getNextAttributeId()
            if attribId == 0:
                break
            if attribId == ATTRIB_LOADERSYMBOLS.id:
                self.loadersymbols_parsed = decoder.readBool()

        while True:
            subId = decoder.peekElement()
            if subId == 0:
                break
            if subId == ELEM_TYPEGRP.id:
                self.types.decode(decoder)
            elif subId == ELEM_DB.id:
                self.symboltab.decode(decoder)
            elif subId == ELEM_CONTEXT_POINTS.id:
                self.context.decode(decoder)
            elif subId == ELEM_COMMENTDB.id:
                self.commentdb.decode(decoder)
            elif subId == ELEM_STRINGMANAGE.id:
                self.stringManager.decode(decoder)
            elif subId == ELEM_CONSTANTPOOL.id:
                self.cpool.decode(decoder, self.types)
            elif subId == ELEM_OPTIONSLIST.id:
                self.options.decode(decoder)
            elif subId == ELEM_FLOWOVERRIDELIST:
                self.decodeFlowOverride(decoder)
            elif subId == ELEM_INJECTDEBUG.id:
                self.pcodeinjectlib.decodeDebug(decoder)
            else:
                raise LowlevelError("XML error restoring architecture")
        decoder.closeElement(elemId)

    def decompileFunction(self, fd) -> str:
        """Run the full decompilation pipeline on a Funcdata and return C output."""
        import io
        if hasattr(fd, 'setArch'):
            fd.setArch(self)
        act = self.allacts.getCurrent()
        if act is not None:
            act.reset(fd)
            act.apply(fd)
        if self.print_ is not None:
            buf = io.StringIO()
            emit = EmitMarkup(buf)
            self.print_.setEmitter(emit)
            self.print_.docFunction(fd)
            return buf.getvalue()
        return ""

    # --- Protected factory routines ---

    def buildLoader(self, store) -> None:
        """Build the LoadImage object and load the executable image."""
        raise NotImplementedError("Architecture.buildLoader is pure virtual in C++")

    def buildTranslator(self, store):
        """Build the Translator object."""
        raise NotImplementedError("Architecture.buildTranslator is pure virtual in C++")

    def buildPcodeInjectLibrary(self):
        """Build the injection library."""
        raise NotImplementedError("Architecture.buildPcodeInjectLibrary is pure virtual in C++")

    def buildTypegrp(self, store) -> None:
        """Build the data-type factory and prepopulate with core types."""
        raise NotImplementedError("Architecture.buildTypegrp is pure virtual in C++")

    def buildCoreTypes(self, store) -> None:
        """Add core primitive data-types."""
        raise NotImplementedError("Architecture.buildCoreTypes is pure virtual in C++")

    def buildCommentDB(self, store) -> None:
        """Build the comment database."""
        raise NotImplementedError("Architecture.buildCommentDB is pure virtual in C++")

    def buildStringManager(self, store) -> None:
        """Build container for decoded strings."""
        raise NotImplementedError("Architecture.buildStringManager is pure virtual in C++")

    def buildConstantPool(self, store) -> None:
        """Build the constant pool."""
        raise NotImplementedError("Architecture.buildConstantPool is pure virtual in C++")

    def buildDatabase(self, store):
        """Build the database and global scope."""
        self.symboltab = Database(self, True)
        globscope = ScopeInternal(0, "", self)
        self.symboltab.attachScope(globscope, None)
        return globscope

    def buildInstructions(self, store) -> None:
        """Register the p-code operations."""
        self.inst = registerTypeOps(self.types, self.translate)

    def buildAction(self, store) -> None:
        """Build the Action framework with the universal decompilation pipeline."""
        self.parseExtraRules(store)
        self.allacts.universalAction(self)
        self.allacts.resetDefaults()

    def buildContext(self, store) -> None:
        """Build the Context database."""
        raise NotImplementedError("Architecture.buildContext is pure virtual in C++")

    def buildSymbols(self, store) -> None:
        """Build any symbols from spec files."""
        raise NotImplementedError("Architecture.buildSymbols is pure virtual in C++")

    def buildSpecFile(self, store) -> None:
        """Load any relevant specification files."""
        raise NotImplementedError("Architecture.buildSpecFile is pure virtual in C++")

    def modifySpaces(self, trans) -> None:
        """Modify address spaces as required by this Architecture."""
        raise NotImplementedError("Architecture.modifySpaces is pure virtual in C++")

    def postSpecFile(self) -> None:
        """Let components initialize after Translate is built."""
        self.cacheAddrSpaceProperties()

    def resolveArchitecture(self) -> None:
        """Figure out the processor and compiler of the target executable."""
        raise NotImplementedError("Architecture.resolveArchitecture is pure virtual in C++")

    def restoreFromSpec(self, store) -> None:
        """Fully initialize the Translate object."""
        from ctypes import sizeof, c_void_p
        from sys import byteorder
        from ghidra.core.space import AddrSpace, IPTR_FSPEC, IPTR_IOP, JoinSpace

        newtrans = self.buildTranslator(store)
        newtrans.initialize(store)
        self.translate = newtrans
        self.modifySpaces(newtrans)
        self.copySpaces(newtrans)
        host_big_end = byteorder == "big"
        self.insertSpace(
            AddrSpace(
                self,
                self.translate,
                IPTR_FSPEC,
                "fspec",
                host_big_end,
                sizeof(c_void_p),
                1,
                self.numSpaces(),
                0,
                1,
                1,
            )
        )
        self.insertSpace(
            AddrSpace(
                self,
                self.translate,
                IPTR_IOP,
                "iop",
                host_big_end,
                sizeof(c_void_p),
                1,
                self.numSpaces(),
                0,
                1,
                1,
            )
        )
        self.insertSpace(JoinSpace(self, self.translate, self.numSpaces()))
        self.userops.initialize(self)
        if self.translate.getAlignment() <= 8:
            self.min_funcsymbol_size = self.translate.getAlignment()
        self.pcodeinjectlib = self.buildPcodeInjectLibrary()
        self.parseProcessorConfig(store)
        newtrans.setDefaultFloatFormats()
        self.parseCompilerConfig(store)
        self.buildAction(store)

    def fillinReadOnlyFromLoader(self) -> None:
        """Load info about read-only sections."""
        from ghidra.ir.varnode import Varnode

        rangelist = RangeList()
        self.loader.getReadonly(rangelist)
        for rng in rangelist:
            self.symboltab.setPropertyRange(Varnode.readonly, rng)

    def initializeSegments(self) -> None:
        """Set up segment resolvers."""
        sz = self.userops.numSegmentOps()
        for i in range(sz):
            sop = self.userops.getSegmentOp(i)
            if sop is None:
                continue
            rsolv = SegmentedResolver(self, sop.getSpace(), sop)
            self.insertResolver(sop.getSpace(), rsolv)

    def cacheAddrSpaceProperties(self) -> None:
        """Calculate frequently used space properties and cache them."""
        copyList = list(self.inferPtrSpaces)
        dcs = self.getDefaultCodeSpace()
        dds = self.getDefaultDataSpace()
        copyList.append(dcs)
        copyList.append(dds)
        self.inferPtrSpaces.clear()
        copyList.sort(key=lambda s: s.getIndex())
        lastSpace = None
        for spc in copyList:
            if spc is lastSpace:
                continue
            lastSpace = spc
            if spc.getDelay() == 0:
                continue
            if spc.getType() == IPTR_SPACEBASE:
                continue
            if spc.isOtherSpace():
                continue
            if spc.isOverlay():
                continue
            self.inferPtrSpaces.append(spc)
        defPos = -1
        for i, spc in enumerate(self.inferPtrSpaces):
            if spc is dds:
                defPos = i
            segOp = self.getSegmentOp(spc)
            if segOp is not None:
                val = segOp.getInnerSize()
                self.markNearPointers(spc, val)
        if defPos > 0:
            self.inferPtrSpaces[0], self.inferPtrSpaces[defPos] = \
                self.inferPtrSpaces[defPos], self.inferPtrSpaces[0]

    # --- Decode/parse configuration methods ---

    def parseProcessorConfig(self, store) -> None:
        """Apply processor specific configuration."""
        from ghidra.core.marshal import (
            ATTRIB_SPACE,
            ELEM_ADDRESS_SHIFT_AMOUNT,
            ELEM_CONTEXT_DATA,
            ELEM_DATA_SPACE,
            ELEM_DEFAULT_MEMORY_BLOCKS,
            ELEM_DEFAULT_SYMBOLS,
            ELEM_INCIDENTALCOPY,
            ELEM_INFERPTRBOUNDS,
            ELEM_JUMPASSIST,
            ELEM_PROCESSOR_SPEC,
            ELEM_PROGRAMCOUNTER,
            ELEM_PROPERTIES,
            ELEM_REGISTER_DATA,
            ELEM_SEGMENTED_ADDRESS,
            ELEM_SEGMENTOP,
            ELEM_VOLATILE,
            XmlDecode,
        )

        el = store.getTag("processor_spec")
        if el is None:
            raise LowlevelError("No processor configuration tag found")
        decoder = XmlDecode(self, el)
        elemId = decoder.openElement(ELEM_PROCESSOR_SPEC)
        while True:
            subId = decoder.peekElement()
            if subId == 0:
                break
            if subId == ELEM_PROGRAMCOUNTER.id:
                decoder.openElement()
                decoder.closeElementSkipping(subId)
            elif subId == ELEM_VOLATILE.id:
                self.decodeVolatile(decoder)
            elif subId == ELEM_INCIDENTALCOPY.id:
                self.decodeIncidentalCopy(decoder)
            elif subId == ELEM_CONTEXT_DATA.id:
                self.context.decodeFromSpec(decoder)
            elif subId == ELEM_JUMPASSIST.id:
                self.userops.decodeJumpAssist(decoder, self)
            elif subId == ELEM_SEGMENTOP.id:
                self.userops.decodeSegmentOp(decoder, self)
            elif subId == ELEM_REGISTER_DATA.id:
                self.decodeRegisterData(decoder)
            elif subId == ELEM_DATA_SPACE.id:
                subElemId = decoder.openElement()
                spc = decoder.readSpace(ATTRIB_SPACE)
                decoder.closeElement(subElemId)
                self.setDefaultDataSpace(spc.getIndex())
            elif subId == ELEM_INFERPTRBOUNDS.id:
                self.decodeInferPtrBounds(decoder)
            elif subId == ELEM_SEGMENTED_ADDRESS.id:
                decoder.openElement()
                decoder.closeElementSkipping(subId)
            elif subId == ELEM_DEFAULT_SYMBOLS.id:
                decoder.openElement()
                store.registerTag(decoder._currentElement())
                decoder.closeElementSkipping(subId)
            elif subId == ELEM_DEFAULT_MEMORY_BLOCKS.id:
                decoder.openElement()
                decoder.closeElementSkipping(subId)
            elif subId == ELEM_ADDRESS_SHIFT_AMOUNT.id:
                decoder.openElement()
                decoder.closeElementSkipping(subId)
            elif subId == ELEM_PROPERTIES.id:
                decoder.openElement()
                decoder.closeElementSkipping(subId)
            else:
                raise LowlevelError("Unknown element in <processor_spec>")
        decoder.closeElement(elemId)

    def parseCompilerConfig(self, store) -> None:
        """Apply compiler specific configuration."""
        from ghidra.analysis.prefersplit import PreferSplitManager
        from ghidra.arch.inject import InjectPayload
        from ghidra.arch.override import ELEM_DEADCODEDELAY
        from ghidra.core.marshal import (
            ATTRIB_NAME,
            ATTRIB_PARENT,
            ELEM_AGGRESSIVETRIM,
            ELEM_CALLOTHERFIXUP,
            ELEM_CALLFIXUP,
            ELEM_COMPILER_SPEC,
            ELEM_CONTEXT_DATA,
            ELEM_DATA_ORGANIZATION,
            ELEM_DEFAULT_PROTO,
            ELEM_ENUM,
            ELEM_EVAL_CALLED_PROTOTYPE,
            ELEM_EVAL_CURRENT_PROTOTYPE,
            ELEM_FUNCPTR,
            ELEM_GLOBAL,
            ELEM_INFERPTRBOUNDS,
            ELEM_MODELALIAS,
            ELEM_NOHIGHPTR,
            ELEM_PREFERSPLIT,
            ELEM_PROTOTYPE,
            ELEM_READONLY,
            ELEM_RESOLVEPROTOTYPE,
            ELEM_RETURNADDRESS,
            ELEM_SEGMENTOP,
            ELEM_SPACEBASE,
            ELEM_SPECEXTENSIONS,
            ELEM_STACKPOINTER,
            XmlDecode,
        )

        globalRanges = []
        el = store.getTag("compiler_spec")
        if el is None:
            raise LowlevelError("No compiler configuration tag found")
        decoder = XmlDecode(self, el)
        elemId = decoder.openElement(ELEM_COMPILER_SPEC)
        while True:
            subId = decoder.peekElement()
            if subId == 0:
                break
            if subId == ELEM_DEFAULT_PROTO.id:
                self.decodeDefaultProto(decoder)
            elif subId == ELEM_PROTOTYPE.id:
                self.decodeProto(decoder)
            elif subId == ELEM_STACKPOINTER.id:
                self.decodeStackPointer(decoder)
            elif subId == ELEM_RETURNADDRESS.id:
                self.decodeReturnAddress(decoder)
            elif subId == ELEM_SPACEBASE.id:
                self.decodeSpacebase(decoder)
            elif subId == ELEM_NOHIGHPTR.id:
                self.decodeNoHighPtr(decoder)
            elif subId == ELEM_PREFERSPLIT.id:
                self.decodePreferSplit(decoder)
            elif subId == ELEM_AGGRESSIVETRIM.id:
                self.decodeAggressiveTrim(decoder)
            elif subId == ELEM_DATA_ORGANIZATION.id:
                self.types.decodeDataOrganization(decoder)
            elif subId == ELEM_ENUM.id:
                self.types.parseEnumConfig(decoder)
            elif subId == ELEM_GLOBAL.id:
                self.decodeGlobal(decoder, globalRanges)
            elif subId == ELEM_SEGMENTOP.id:
                self.userops.decodeSegmentOp(decoder, self)
            elif subId == ELEM_READONLY.id:
                self.decodeReadOnly(decoder)
            elif subId == ELEM_CONTEXT_DATA.id:
                self.context.decodeFromSpec(decoder)
            elif subId == ELEM_RESOLVEPROTOTYPE.id:
                self.decodeProto(decoder)
            elif subId == ELEM_EVAL_CALLED_PROTOTYPE.id:
                self.decodeProtoEval(decoder)
            elif subId == ELEM_EVAL_CURRENT_PROTOTYPE.id:
                self.decodeProtoEval(decoder)
            elif subId == ELEM_CALLFIXUP.id:
                self.pcodeinjectlib.decodeInject(self.archid + " : compiler spec", "", InjectPayload.CALLFIXUP_TYPE, decoder)
            elif subId == ELEM_CALLOTHERFIXUP.id:
                self.userops.decodeCallOtherFixup(decoder, self)
            elif subId == ELEM_FUNCPTR.id:
                self.decodeFuncPtrAlign(decoder)
            elif subId == ELEM_DEADCODEDELAY:
                self.decodeDeadcodeDelay(decoder)
            elif subId == ELEM_INFERPTRBOUNDS.id:
                self.decodeInferPtrBounds(decoder)
            elif subId == ELEM_MODELALIAS.id:
                subElemId = decoder.openElement()
                aliasName = decoder.readString(ATTRIB_NAME)
                parentName = decoder.readString(ATTRIB_PARENT)
                decoder.closeElement(subElemId)
                self.createModelAlias(aliasName, parentName)
        decoder.closeElement(elemId)

        el = store.getTag("specextensions")
        if el is not None:
            decoderExt = XmlDecode(self, el)
            elemId = decoderExt.openElement(ELEM_SPECEXTENSIONS)
            while True:
                subId = decoderExt.peekElement()
                if subId == 0:
                    break
                if subId == ELEM_PROTOTYPE.id:
                    self.decodeProto(decoderExt)
                elif subId == ELEM_CALLFIXUP.id:
                    self.pcodeinjectlib.decodeInject(self.archid + " : compiler spec", "", InjectPayload.CALLFIXUP_TYPE, decoder)
                elif subId == ELEM_CALLOTHERFIXUP.id:
                    self.userops.decodeCallOtherFixup(decoder, self)
                elif subId == ELEM_GLOBAL.id:
                    self.decodeGlobal(decoder, globalRanges)
            decoderExt.closeElement(elemId)

        for rangeProp in globalRanges:
            self.addToGlobalScope(rangeProp)

        self.addOtherSpace()

        if self.defaultfp is None:
            if len(self.protoModels) > 0:
                firstName = min(self.protoModels)
                self.setDefaultModel(self.protoModels[firstName])
            else:
                raise LowlevelError("No default prototype specified")

        if "__thiscall" not in self.protoModels:
            self.createModelAlias("__thiscall", self.defaultfp.getName())

        self.initializeSegments()
        PreferSplitManager.initialize(self.splitrecords)
        self.types.setupSizes()

    def parseExtraRules(self, store) -> None:
        """Apply any Rule tags."""
        from ghidra.core.marshal import ELEM_EXPERIMENTAL_RULES, XmlDecode

        expertag = store.getTag("experimental_rules")
        if expertag is not None:
            decoder = XmlDecode(self, expertag)
            elemId = decoder.openElement(ELEM_EXPERIMENTAL_RULES)
            while decoder.peekElement() != 0:
                self.decodeDynamicRule(decoder)
            decoder.closeElement(elemId)

    def decodeDynamicRule(self, decoder) -> None:
        """Recover information out of a <rule> element and build the new Rule object.

        C++ ref: Architecture::decodeDynamicRule (architecture.cc lines 705-734)
        """
        from ghidra.core.marshal import ELEM_RULE, ATTRIB_NAME, ATTRIB_GROUP, ATTRIB_ENABLE
        elemId = decoder.openElement(ELEM_RULE)
        rulename = ""
        groupname = ""
        enabled = False
        while True:
            attribId = decoder.getNextAttributeId()
            if attribId == 0:
                break
            if attribId == ATTRIB_NAME:
                rulename = decoder.readString()
            elif attribId == ATTRIB_GROUP:
                groupname = decoder.readString()
            elif attribId == ATTRIB_ENABLE:
                enabled = decoder.readBool()
            else:
                raise LowlevelError("Dynamic rule tag contains illegal attribute")
        if not rulename:
            raise LowlevelError("Dynamic rule has no name")
        if not groupname:
            raise LowlevelError("Dynamic rule has no group")
        if not enabled:
            return
        try:
            from ghidra.transform.rulecompile import RuleGeneric
        except ImportError as exc:
            raise LowlevelError("Dynamic rules have not been enabled for this decompiler") from exc
        content = decoder._currentElement().getContent()
        dynrule = RuleGeneric.build(rulename, groupname, content)
        self.extra_pool_rules.append(dynrule)
        decoder.closeElement(elemId)

    def decodeProto(self, decoder) -> Optional[ProtoModel]:
        """Parse a prototype model from a stream.

        C++ ref: ``Architecture::decodeProto``
        """
        elemId = decoder.peekElement()
        from ghidra.fspec.fspec import ProtoModelMerged
        from ghidra.core.marshal import ELEM_PROTOTYPE, ELEM_RESOLVEPROTOTYPE
        if elemId == ELEM_PROTOTYPE.id:
            res = ProtoModel(glb=self)
        elif elemId == ELEM_RESOLVEPROTOTYPE.id:
            res = ProtoModelMerged(self)
        else:
            raise LowlevelError("Expecting <prototype> or <resolveprototype> tag")
        res.decode(decoder)
        nm = res.getName()
        other = self.getModel(nm)
        if other is not None:
            raise LowlevelError("Duplicate ProtoModel name: " + nm)
        self.protoModels[nm] = res
        return res

    def decodeProtoEval(self, decoder) -> None:
        """Apply prototype evaluation configuration.

        C++ ref: ``Architecture::decodeProtoEval``
        """
        from ghidra.core.marshal import ATTRIB_NAME, ELEM_EVAL_CALLED_PROTOTYPE
        elemId = decoder.openElement()
        modelName = decoder.readString(ATTRIB_NAME)
        res = self.getModel(modelName)
        if res is None:
            raise LowlevelError("Unknown prototype model name: " + modelName)
        if elemId == ELEM_EVAL_CALLED_PROTOTYPE.id:
            if self.evalfp_called is not None:
                raise LowlevelError("Duplicate <eval_called_prototype> tag")
            self.evalfp_called = res
        else:
            if self.evalfp_current is not None:
                raise LowlevelError("Duplicate <eval_current_prototype> tag")
            self.evalfp_current = res
        decoder.closeElement(elemId)

    def decodeDefaultProto(self, decoder) -> None:
        """Apply default prototype model configuration.

        C++ ref: ``Architecture::decodeDefaultProto``
        """
        from ghidra.core.marshal import ELEM_DEFAULT_PROTO

        elemId = decoder.openElement(ELEM_DEFAULT_PROTO)
        while decoder.peekElement() != 0:
            if self.defaultfp is not None:
                raise LowlevelError("More than one default prototype model")
            model = self.decodeProto(decoder)
            self.setDefaultModel(model)
        decoder.closeElement(elemId)

    def decodeGlobal(self, decoder, rangeProps: list) -> None:
        """Parse information about global ranges.

        C++ ref: ``Architecture::decodeGlobal``
        """
        from ghidra.core.marshal import ELEM_GLOBAL

        elemId = decoder.openElement(ELEM_GLOBAL)
        while decoder.peekElement() != 0:
            rp = RangeProperties()
            rp.decode(decoder)
            rangeProps.append(rp)
        decoder.closeElement(elemId)

    def addNoHighPtrRange(self, decoder) -> None:
        """Apply memory alias configuration from decoder."""
        pass

    def decodeReadOnly(self, decoder) -> None:
        """Apply read-only region configuration.

        C++ ref: ``Architecture::decodeReadOnly``
        """
        from ghidra.core.marshal import ELEM_READONLY

        elemId = decoder.openElement(ELEM_READONLY)
        while decoder.peekElement() != 0:
            rng = Range()
            rng.decode(decoder)
            self.symboltab.setPropertyRange(0x1, rng)  # Varnode::readonly
        decoder.closeElement(elemId)

    def decodeVolatile(self, decoder) -> None:
        """Apply volatile region configuration.

        C++ ref: ``Architecture::decodeVolatile``
        """
        from ghidra.core.marshal import ELEM_VOLATILE

        elemId = decoder.openElement(ELEM_VOLATILE)
        self.userops.decodeVolatile(decoder, self)
        while decoder.peekElement() != 0:
            rng = Range()
            rng.decode(decoder)
            self.symboltab.setPropertyRange(0x4, rng)  # Varnode::volatil
        decoder.closeElement(elemId)

    def decodeReturnAddress(self, decoder) -> None:
        """Apply return address configuration.

        C++ ref: ``Architecture::decodeReturnAddress``
        """
        from ghidra.core.marshal import ELEM_RETURNADDRESS

        elemId = decoder.openElement(ELEM_RETURNADDRESS)
        subId = decoder.peekElement()
        if subId != 0:
            if self.defaultReturnAddr.space is not None:
                raise LowlevelError("Multiple <returnaddress> tags in .cspec")
            self.defaultReturnAddr.decode(decoder)
        decoder.closeElement(elemId)

    def decodeIncidentalCopy(self, decoder) -> None:
        """Apply incidental copy configuration.

        C++ ref: ``Architecture::decodeIncidentalCopy``
        """
        from ghidra.core.marshal import ELEM_INCIDENTALCOPY

        elemId = decoder.openElement(ELEM_INCIDENTALCOPY)
        while decoder.peekElement() != 0:
            vdata = VarnodeData()
            vdata.decode(decoder)
            rng = Range(vdata.space, vdata.offset, vdata.offset + vdata.size - 1)
            self.symboltab.setPropertyRange(0x100, rng)  # Varnode::incidental_copy
        decoder.closeElement(elemId)

    def decodeRegisterData(self, decoder) -> None:
        """Read specific register properties.

        C++ ref: ``Architecture::decodeRegisterData``
        """
        from ghidra.core.marshal import (
            ATTRIB_VECTOR_LANE_SIZES,
            ATTRIB_VOLATILE,
            ELEM_REGISTER,
            ELEM_REGISTER_DATA,
        )
        from ghidra.transform.transform import LanedRegister

        maskList = []
        elemId = decoder.openElement(ELEM_REGISTER_DATA)
        while decoder.peekElement() != 0:
            subId = decoder.openElement(ELEM_REGISTER)
            isVolatile = False
            laneSizes = ""
            while True:
                attribId = decoder.getNextAttributeId()
                if attribId == 0:
                    break
                if attribId == ATTRIB_VECTOR_LANE_SIZES:
                    laneSizes = decoder.readString()
                elif attribId == ATTRIB_VOLATILE:
                    isVolatile = decoder.readBool()
            if laneSizes or isVolatile:
                decoder.rewindAttributes()
                storage = VarnodeData()
                storage.space = None
                storage.decodeFromAttributes(decoder)
                if laneSizes:
                    lanedRegister = LanedRegister()
                    lanedRegister.parseSizes(storage.size, laneSizes)
                    sizeIndex = lanedRegister.getWholeSize()
                    while len(maskList) <= sizeIndex:
                        maskList.append(0)
                    maskList[sizeIndex] |= lanedRegister.getSizeBitMask()
                if isVolatile:
                    rng = Range(storage.space, storage.offset, storage.offset + storage.size - 1)
                    self.symboltab.setPropertyRange(0x4, rng)  # Varnode::volatil
            decoder.closeElement(subId)
        decoder.closeElement(elemId)
        self.lanerecords.clear()
        for i in range(len(maskList)):
            if maskList[i] == 0:
                continue
            self.lanerecords.append(LanedRegister(i, maskList[i]))

    def decodeStackPointer(self, decoder) -> None:
        """Apply stack pointer configuration.

        C++ ref: ``Architecture::decodeStackPointer``
        """
        from ghidra.core.marshal import (
            ATTRIB_GROWTH,
            ATTRIB_REGISTER,
            ATTRIB_REVERSEJUSTIFY,
            ATTRIB_SPACE,
            ELEM_STACKPOINTER,
        )

        elemId = decoder.openElement(ELEM_STACKPOINTER)
        registerName = ""
        stackGrowth = True  # Default: negative direction
        isreversejustify = False
        basespace = None
        while True:
            attribId = decoder.getNextAttributeId()
            if attribId == 0:
                break
            if attribId == ATTRIB_REVERSEJUSTIFY:
                isreversejustify = decoder.readBool()
            elif attribId == ATTRIB_GROWTH:
                stackGrowth = decoder.readString() == "negative"
            elif attribId == ATTRIB_SPACE:
                basespace = decoder.readSpace()
            elif attribId == ATTRIB_REGISTER:
                registerName = decoder.readString()
        if basespace is None:
            raise LowlevelError(ELEM_STACKPOINTER.getName() + ' element missing "space" attribute')
        point = self.translate.getRegister(registerName)
        decoder.closeElement(elemId)
        truncSize = point.size
        if basespace.isTruncated() and point.size > basespace.getAddrSize():
            truncSize = basespace.getAddrSize()
        self.addSpacebase(basespace, "stack", point, truncSize, isreversejustify, stackGrowth, True)

    def decodeDeadcodeDelay(self, decoder) -> None:
        """Apply dead-code delay configuration.

        C++ ref: ``Architecture::decodeDeadcodeDelay``
        """
        from ghidra.arch.override import ELEM_DEADCODEDELAY
        from ghidra.core.marshal import ATTRIB_DELAY, ATTRIB_SPACE

        elemId = decoder.openElement(ELEM_DEADCODEDELAY)
        spc = decoder.readSpace(ATTRIB_SPACE)
        delay = decoder.readSignedInteger(ATTRIB_DELAY)
        if delay >= 0:
            self.setDeadcodeDelay(spc, delay)
        else:
            raise LowlevelError("Bad <deadcodedelay> tag")
        decoder.closeElement(elemId)

    def decodeInferPtrBounds(self, decoder) -> None:
        """Apply pointer inference bounds.

        C++ ref: ``Architecture::decodeInferPtrBounds``
        """
        from ghidra.core.marshal import ELEM_INFERPTRBOUNDS

        elemId = decoder.openElement(ELEM_INFERPTRBOUNDS)
        while decoder.peekElement() != 0:
            rng = Range()
            rng.decode(decoder)
            self.setInferPtrBounds(rng)
        decoder.closeElement(elemId)

    def decodeFuncPtrAlign(self, decoder) -> None:
        """Apply function pointer alignment configuration.

        C++ ref: ``Architecture::decodeFuncPtrAlign``
        """
        from ghidra.core.marshal import ATTRIB_ALIGN, ELEM_FUNCPTR

        elemId = decoder.openElement(ELEM_FUNCPTR)
        align = decoder.readSignedInteger(ATTRIB_ALIGN)
        decoder.closeElement(elemId)
        if align == 0:
            self.funcptr_align = 0
            return
        bits = 0
        while (align & 1) == 0:
            bits += 1
            align >>= 1
        self.funcptr_align = bits

    def decodeSpacebase(self, decoder) -> None:
        """Create an additional indexed space.

        C++ ref: ``Architecture::decodeSpacebase``
        """
        from ghidra.core.marshal import ATTRIB_NAME, ATTRIB_REGISTER, ATTRIB_SPACE, ELEM_SPACEBASE

        elemId = decoder.openElement(ELEM_SPACEBASE)
        nameString = decoder.readString(ATTRIB_NAME)
        registerName = decoder.readString(ATTRIB_REGISTER)
        basespace = decoder.readSpace(ATTRIB_SPACE)
        decoder.closeElement(elemId)
        point = self.translate.getRegister(registerName)
        self.addSpacebase(basespace, nameString, point, point.size, False, False, False)

    def decodeNoHighPtr(self, decoder) -> None:
        """Apply memory alias configuration.

        C++ ref: ``Architecture::decodeNoHighPtr``
        """
        from ghidra.core.marshal import ELEM_NOHIGHPTR

        elemId = decoder.openElement(ELEM_NOHIGHPTR)
        while decoder.peekElement() != 0:
            rng = Range()
            rng.decode(decoder)
            self.addNoHighPtr(rng)
        decoder.closeElement(elemId)

    def decodePreferSplit(self, decoder) -> None:
        """Designate registers to be split.

        C++ ref: ``Architecture::decodePreferSplit``
        """
        from ghidra.analysis.prefersplit import PreferSplitRecord
        from ghidra.core.marshal import ATTRIB_STYLE, ELEM_PREFERSPLIT

        elemId = decoder.openElement(ELEM_PREFERSPLIT)
        style = decoder.readString(ATTRIB_STYLE)
        if style != "inhalf":
            raise LowlevelError("Unknown prefersplit style: " + style)
        while decoder.peekElement() != 0:
            record_storage = VarnodeData()
            record_storage.decode(decoder)
            rec = PreferSplitRecord()
            rec.storage = Address(record_storage.space, record_storage.offset)
            rec.totalSize = record_storage.size
            rec.splitSize = record_storage.size // 2
            self.splitrecords.append(rec)
        decoder.closeElement(elemId)

    def decodeAggressiveTrim(self, decoder) -> None:
        """Designate how to trim extension p-code ops.

        C++ ref: ``Architecture::decodeAggressiveTrim``
        """
        from ghidra.core.marshal import ATTRIB_SIGNEXT, ELEM_AGGRESSIVETRIM

        elemId = decoder.openElement(ELEM_AGGRESSIVETRIM)
        while True:
            attribId = decoder.getNextAttributeId()
            if attribId == 0:
                break
            if attribId == ATTRIB_SIGNEXT:
                self.aggressive_ext_trim = decoder.readBool()
        decoder.closeElement(elemId)

    def decode(self, decoder) -> None:
        """Decode architecture configuration from a stream."""
        pass

    def buildUserOps(self) -> None:
        """Initialize user-defined p-code operations."""
        self.userops.initialize(self)

    def buildInject(self) -> None:
        """Build the p-code injection library."""
        self.pcodeinjectlib = PcodeInjectLibrary()

    def buildOptions(self) -> None:
        """Build the option database."""
        try:
            from ghidra.arch.options import OptionDatabase
            self.options = OptionDatabase(self)
        except ImportError:
            pass

    # --- Convenience accessors ---

    def getTypes(self):
        """Get the type factory."""
        return self.types

    def getSymbolDatabase(self):
        return self.symboltab

    def address(self, spc_name: str, offset: int):
        """Construct an Address from space name and offset."""
        spc = self.getSpaceByName(spc_name)
        if spc is None:
            raise RuntimeError("Unknown space: " + spc_name)
        from ghidra.core.address import Address
        return Address(spc, offset)

    def nan(self) -> bool:
        """Return True if NaN operations should be ignored."""
        return self.nan_ignore_all

    def pool(self):
        """Get the constant pool (cpool) database."""
        return self.cpool

    def setDebugStream(self, s) -> None:
        """Establish the debug console stream."""
        self._debugstream = s

    def printDebug(self, message: str) -> None:
        """Print message to the debug stream."""
        self._debugstream.write(message + '\n')

    def __repr__(self) -> str:
        return f"Architecture({self.archid!r})"


# =========================================================================
# SegmentedResolver
# =========================================================================

class SegmentedResolver:
    """A resolver for segmented architectures.

    Tries to recover segment info for near pointers by looking up
    tracked registers in context.
    """

    def __init__(self, glb: Architecture, spc: AddrSpace, segop) -> None:
        self.glb = glb
        self.spc = spc
        self.segop = segop

    def resolve(self, val: int, sz: int, point: Address) -> tuple:
        """Resolve a segmented address.

        Returns (Address, fullEncoding) or (invalid Address, 0).
        """
        innersz = self.segop.getInnerSize()
        if 0 <= sz <= innersz:
            resolve_vn = self.segop.getResolve()
            if resolve_vn.space is not None:
                base = self.glb.context.getTrackedValue(resolve_vn, point)
                fullEncoding = (base << (8 * innersz)) + (val & calc_mask(innersz))
                seginput = [base, val]
                val = self.segop.execute(seginput)
                return Address(self.spc, AddrSpace.addressToByte(val, self.spc.getWordSize())), fullEncoding
        else:
            fullEncoding = val
            outersz = self.segop.getBaseSize()
            base = (val >> (8 * innersz)) & calc_mask(outersz)
            inner = val & calc_mask(innersz)
            seginput = [base, inner]
            val = self.segop.execute(seginput)
            return Address(self.spc, AddrSpace.addressToByte(val, self.spc.getWordSize())), fullEncoding
        return Address(), 0
