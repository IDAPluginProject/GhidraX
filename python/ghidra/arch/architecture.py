"""
Corresponds to: architecture.hh / architecture.cc

Architecture and associated classes that help manage a single processor
architecture and load image.
"""

from __future__ import annotations

from typing import Optional, List, Dict, TYPE_CHECKING

from ghidra.core.address import Address, Range, RangeList, RangeProperties, calc_mask
from ghidra.core.error import LowlevelError
from ghidra.core.space import (
    AddrSpace, AddrSpaceManager,
    IPTR_PROCESSOR, IPTR_SPACEBASE, IPTR_INTERNAL,
)
from ghidra.core.translate import Translate
from ghidra.core.pcoderaw import VarnodeData
from ghidra.core.opbehavior import OpBehavior
from ghidra.core.globalcontext import ContextDatabase, ContextInternal
from ghidra.types.datatype import TypeFactory
from ghidra.types.cast import CastStrategyC
from ghidra.database.database import Database, ScopeInternal
from ghidra.database.comment import CommentDatabase, CommentDatabaseInternal
from ghidra.database.stringmanage import StringManager, StringManagerUnicode
from ghidra.database.cpool import ConstantPool, ConstantPoolInternal
from ghidra.fspec.fspec import ProtoModel, FuncProto
from ghidra.ir.typeop import TypeOp, registerTypeOps
from ghidra.output.printlanguage import PrintLanguage
from ghidra.output.printc import PrintC
from ghidra.output.prettyprint import EmitMarkup
from ghidra.transform.action import ActionDatabase
from ghidra.arch.loadimage import LoadImage
from ghidra.arch.userop import UserOpManage
from ghidra.arch.override import Override
from ghidra.arch.inject import PcodeInjectLibrary

if TYPE_CHECKING:
    from ghidra.analysis.funcdata import Funcdata


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
        self.options = None  # OptionDatabase
        self.inst: List[Optional[TypeOp]] = []
        self.userops: UserOpManage = UserOpManage()
        self.splitrecords: list = []
        self.lanerecords: list = []
        self.allacts: ActionDatabase = ActionDatabase()
        self.loadersymbols_parsed: bool = False
        self.override: Optional[Override] = None
        self.extra_pop: int = 0

        # Build default print language
        pc = PrintC(self, "c-language")
        self.printlist.append(pc)
        self.print_ = pc

    # --- Initialization ---

    def init(self, store=None) -> None:
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
        if self.print_ is not None:
            self.print_.initializeFromArchitecture()
        if self.symboltab is not None:
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
        if self.defaultfp is None:
            return None
        model = ProtoModel(modelName, self.defaultfp)
        self.protoModels[modelName] = model
        if modelName == "unknown":
            if hasattr(model, 'setPrintInDecl'):
                model.setPrintInDecl(False)
        return model

    def setDefaultModel(self, model: ProtoModel) -> None:
        """Set the default PrototypeModel."""
        if self.defaultfp is not None:
            if hasattr(self.defaultfp, 'setPrintInDecl'):
                self.defaultfp.setPrintInDecl(True)
        if hasattr(model, 'setPrintInDecl'):
            model.setPrintInDecl(False)
        self.defaultfp = model

    def addModel(self, model: ProtoModel) -> None:
        self.protoModels[model.getName()] = model

    def createModelAlias(self, aliasName: str, parentName: str) -> None:
        """Clone the named ProtoModel, attaching it to another name."""
        parent = self.protoModels.get(parentName)
        if parent is None:
            raise LowlevelError("Requesting non-existent prototype model: " + parentName)
        if hasattr(parent, 'isMerged') and parent.isMerged():
            raise LowlevelError("Cannot make alias of merged model: " + parentName)
        if hasattr(parent, 'getAliasParent') and parent.getAliasParent() is not None:
            raise LowlevelError("Cannot make alias of an alias: " + parentName)
        if aliasName in self.protoModels:
            raise LowlevelError("Duplicate ProtoModel name: " + aliasName)
        self.protoModels[aliasName] = ProtoModel(aliasName, parent)

    # --- Language selection ---

    def setPrintLanguage(self, nm: str) -> None:
        """Select one of the supported output languages."""
        for pl in self.printlist:
            if pl.getName() == nm:
                self.print_ = pl
                if hasattr(pl, 'adjustTypeOperators'):
                    pl.adjustTypeOperators()
                return
        # Create new PrintC
        pc = PrintC(self, nm)
        if self.print_ is not None:
            if hasattr(self.print_, 'emitsMarkup'):
                printMarkup = self.print_.emitsMarkup()
            else:
                printMarkup = False
            if hasattr(self.print_, 'getOutputStream'):
                t = self.print_.getOutputStream()
                if t is not None and hasattr(pc, 'setOutputStream'):
                    pc.setOutputStream(t)
        else:
            printMarkup = False
        emit = EmitMarkup()
        pc.setEmitter(emit)
        if self.types is not None:
            cs = CastStrategyC()
            cs.setTypeFactory(self.types)
            pc.setCastStrategy(cs)
        if hasattr(pc, 'initializeFromArchitecture'):
            pc.initializeFromArchitecture()
        if printMarkup and hasattr(pc, 'setMarkup'):
            pc.setMarkup(True)
        self.printlist.append(pc)
        self.print_ = pc
        if hasattr(pc, 'adjustTypeOperators'):
            pc.adjustTypeOperators()

    def getPrintLanguage(self) -> Optional[PrintLanguage]:
        return self.print_

    # --- Core methods ---

    def clearAnalysis(self, fd: Funcdata) -> None:
        """Throw out the syntax tree and derived information about a single function."""
        if hasattr(fd, 'clear'):
            fd.clear()
        if self.commentdb is not None and hasattr(self.commentdb, 'clearType'):
            self.commentdb.clearType(fd.getAddress(), 0x6)  # warning|warningheader

    def readLoaderSymbols(self, delim: str = "") -> None:
        """Read any symbols from loader into database."""
        if self.loadersymbols_parsed:
            return
        self.loadersymbols_parsed = True
        if self.loader is not None and hasattr(self.loader, 'openSymbols'):
            self.loader.openSymbols()
            if hasattr(self.loader, 'getNextSymbol'):
                while True:
                    record = self.loader.getNextSymbol()
                    if record is None:
                        break
                    # Would resolve scope and add function
            if hasattr(self.loader, 'closeSymbols'):
                self.loader.closeSymbols()

    def collectBehaviors(self) -> List[Optional[OpBehavior]]:
        """For all registered p-code opcodes, return the corresponding OpBehavior."""
        behave: List[Optional[OpBehavior]] = [None] * len(self.inst)
        for i, op in enumerate(self.inst):
            if op is not None:
                behave[i] = op.getBehavior()
        return behave

    def getSegmentOp(self, spc: AddrSpace):
        """Retrieve the segment op for the given space if any."""
        idx = spc.getIndex()
        if idx >= self.userops.numSegmentOps():
            return None
        segdef = self.userops.getSegmentOp(idx)
        if segdef is None:
            return None
        if hasattr(segdef, 'getResolve') and segdef.getResolve().space is not None:
            return segdef
        return None

    def setPrototype(self, pieces) -> None:
        """Establish details of the prototype for a given function symbol."""
        if self.symboltab is None:
            return
        basename = getattr(pieces, 'name', '')
        scope = self.symboltab.getGlobalScope()
        if scope is None:
            return
        fd = scope.queryFunction(basename)
        if fd is not None and hasattr(fd, 'getFuncProto'):
            fd.getFuncProto().setPieces(pieces)

    def globalify(self) -> None:
        """Set all IPTR_PROCESSOR and IPTR_SPACEBASE spaces to be global."""
        if self.symboltab is None:
            return
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
        if self.symboltab is None:
            return
        scope = self.symboltab.getGlobalScope()
        rng = Range.from_properties(props, self)
        spc = rng.getSpace()
        self.inferPtrSpaces.append(spc)
        self.symboltab.addRange(scope, spc, rng.getFirst(), rng.getLast())
        if hasattr(spc, 'isOverlayBase') and spc.isOverlayBase():
            num = self.numSpaces()
            for i in range(num):
                ospc = self.getSpace(i)
                if ospc is None or not hasattr(ospc, 'isOverlay') or not ospc.isOverlay():
                    continue
                if hasattr(ospc, 'getContain') and ospc.getContain() is not spc:
                    continue
                self.symboltab.addRange(scope, ospc, rng.getFirst(), rng.getLast())

    def addOtherSpace(self) -> None:
        """Add OTHER space and all of its overlays to the symboltab."""
        if self.symboltab is None:
            return
        scope = self.symboltab.getGlobalScope()
        otherSpace = self.getSpaceByName("OTHER")
        if otherSpace is None:
            return
        self.symboltab.addRange(scope, otherSpace, 0, otherSpace.getHighest())
        if hasattr(otherSpace, 'isOverlayBase') and otherSpace.isOverlayBase():
            num = self.numSpaces()
            for i in range(num):
                ospc = self.getSpace(i)
                if ospc is None or not hasattr(ospc, 'isOverlay') or not ospc.isOverlay():
                    continue
                if hasattr(ospc, 'getContain') and ospc.getContain() is not otherSpace:
                    continue
                self.symboltab.addRange(scope, ospc, 0, otherSpace.getHighest())

    def highPtrPossible(self, loc: Address, size: int) -> bool:
        """Are pointers possible to the given location?"""
        if loc.getSpace() is not None and loc.getSpace().getType() == IPTR_INTERNAL:
            return False
        return not self.nohighptr.inRange(loc, size)

    def getSpaceBySpacebase(self, loc: Address, size: int) -> Optional[AddrSpace]:
        """Get space associated with a spacebase register."""
        sz = self.numSpaces()
        for i in range(sz):
            spc = self.getSpace(i)
            if spc is None:
                continue
            if not hasattr(spc, 'numSpacebase'):
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
        pass  # Requires SpacebaseSpace which is architecture-specific

    def addNoHighPtr(self, rng: Range) -> None:
        """Add a new region where pointers do not exist."""
        self.nohighptr.insertRange(rng.getSpace(), rng.getFirst(), rng.getLast())

    def getDescription(self) -> str:
        """Get a string describing this architecture."""
        return self.archid

    def printMessage(self, message: str) -> None:
        """Print an error message to console."""
        print(f"[Architecture] {message}")

    def decodeFlowOverride(self, decoder) -> None:
        """Decode flow overrides from a stream."""
        pass

    def encode(self, encoder) -> None:
        """Encode this architecture to a stream."""
        pass

    def restoreXml(self, store) -> None:
        """Restore the Architecture state from XML documents."""
        pass

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

    def buildLoader(self, store=None) -> None:
        """Build the LoadImage object and load the executable image."""
        pass

    def buildTranslator(self, store=None):
        """Build the Translator object."""
        return self.translate

    def buildPcodeInjectLibrary(self):
        """Build the injection library."""
        return PcodeInjectLibrary()

    def buildTypegrp(self, store=None) -> None:
        """Build the data-type factory and prepopulate with core types."""
        self.types = TypeFactory()
        self.types.setupCoreTypes()

    def buildCoreTypes(self, store=None) -> None:
        """Add core primitive data-types."""
        if self.types is not None:
            self.types.setupCoreTypes()

    def buildCommentDB(self, store=None) -> None:
        """Build the comment database."""
        self.commentdb = CommentDatabaseInternal()

    def buildStringManager(self, store=None) -> None:
        """Build container for decoded strings."""
        self.stringManager = StringManagerUnicode(self, 256)

    def buildConstantPool(self, store=None) -> None:
        """Build the constant pool."""
        self.cpool = ConstantPoolInternal()

    def buildDatabase(self, store=None):
        """Build the database and global scope."""
        self.symboltab = Database(self)
        globscope = ScopeInternal(0, "", self)
        self.symboltab.attachScope(globscope, None)
        return globscope

    def buildInstructions(self, store=None) -> None:
        """Register the p-code operations."""
        self.inst = registerTypeOps(self.types, self.translate)

    def buildAction(self, store=None) -> None:
        """Build the Action framework with the universal decompilation pipeline."""
        self.parseExtraRules(store)
        from ghidra.transform.universal import universalAction
        universalAction(self.allacts, self)
        self.allacts.resetDefaults()

    def buildContext(self, store=None) -> None:
        """Build the Context database."""
        self.context = ContextInternal()

    def buildSymbols(self, store=None) -> None:
        """Build any symbols from spec files."""
        pass

    def buildSpecFile(self, store=None) -> None:
        """Load any relevant specification files."""
        pass

    def modifySpaces(self, trans=None) -> None:
        """Modify address spaces as required by this Architecture."""
        pass

    def postSpecFile(self) -> None:
        """Let components initialize after Translate is built."""
        self.cacheAddrSpaceProperties()

    def resolveArchitecture(self) -> None:
        """Figure out the processor and compiler of the target executable."""
        pass

    def restoreFromSpec(self, store=None) -> None:
        """Fully initialize the Translate object."""
        newtrans = self.buildTranslator(store)
        if newtrans is not None:
            if hasattr(newtrans, 'initialize'):
                newtrans.initialize(store)
            self.translate = newtrans
            self.modifySpaces(newtrans)
            self.copySpaces(newtrans)
        self.userops.initialize(self)
        if self.translate is not None and hasattr(self.translate, 'getAlignment'):
            align = self.translate.getAlignment()
            if align <= 8:
                self.min_funcsymbol_size = align
        self.pcodeinjectlib = self.buildPcodeInjectLibrary()
        self.parseProcessorConfig(store)
        if self.translate is not None and hasattr(self.translate, 'setDefaultFloatFormats'):
            self.translate.setDefaultFloatFormats()
        self.parseCompilerConfig(store)
        self.buildAction(store)

    def fillinReadOnlyFromLoader(self) -> None:
        """Load info about read-only sections."""
        if self.loader is None:
            return
        if not hasattr(self.loader, 'getReadonly'):
            return
        rangelist = RangeList()
        self.loader.getReadonly(rangelist)
        for rng in rangelist:
            if self.symboltab is not None:
                self.symboltab.setPropertyRange(0x1, rng)  # Varnode::readonly

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
        if dcs is not None:
            copyList.append(dcs)
        if dds is not None:
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
            if hasattr(spc, 'isOtherSpace') and spc.isOtherSpace():
                continue
            if hasattr(spc, 'isOverlay') and spc.isOverlay():
                continue
            self.inferPtrSpaces.append(spc)
        defPos = -1
        for i, spc in enumerate(self.inferPtrSpaces):
            if spc is dds:
                defPos = i
            segOp = self.getSegmentOp(spc)
            if segOp is not None and hasattr(segOp, 'getInnerSize'):
                val = segOp.getInnerSize()
                self.markNearPointers(spc, val)
        if defPos > 0:
            self.inferPtrSpaces[0], self.inferPtrSpaces[defPos] = \
                self.inferPtrSpaces[defPos], self.inferPtrSpaces[0]

    # --- Decode/parse configuration methods ---

    def parseProcessorConfig(self, store=None) -> None:
        """Apply processor specific configuration."""
        pass

    def parseCompilerConfig(self, store=None) -> None:
        """Apply compiler specific configuration."""
        pass

    def parseExtraRules(self, store=None) -> None:
        """Apply any Rule tags."""
        pass

    def decodeDynamicRule(self, decoder) -> None:
        """Apply details of a dynamic Rule object."""
        pass

    def decodeProto(self, decoder) -> Optional[ProtoModel]:
        """Parse a proto-type model from a stream."""
        return None

    def decodeProtoEval(self, decoder) -> None:
        """Apply prototype evaluation configuration."""
        pass

    def decodeDefaultProto(self, decoder) -> None:
        """Apply default prototype model configuration."""
        pass

    def decodeGlobal(self, decoder, rangeProps: list = None) -> None:
        """Parse information about global ranges."""
        pass

    def addNoHighPtrRange(self, decoder) -> None:
        """Apply memory alias configuration from decoder."""
        pass

    def decodeReadOnly(self, decoder) -> None:
        """Apply read-only region configuration."""
        pass

    def decodeVolatile(self, decoder) -> None:
        """Apply volatile region configuration."""
        pass

    def decodeReturnAddress(self, decoder) -> None:
        """Apply return address configuration."""
        pass

    def decodeIncidentalCopy(self, decoder) -> None:
        """Apply incidental copy configuration."""
        pass

    def decodeRegisterData(self, decoder) -> None:
        """Read specific register properties."""
        pass

    def decodeStackPointer(self, decoder) -> None:
        """Apply stack pointer configuration."""
        pass

    def decodeDeadcodeDelay(self, decoder) -> None:
        """Apply dead-code delay configuration."""
        pass

    def decodeInferPtrBounds(self, decoder) -> None:
        """Apply pointer inference bounds."""
        pass

    def decodeFuncPtrAlign(self, decoder) -> None:
        """Apply function pointer alignment configuration."""
        pass

    def decodeSpacebase(self, decoder) -> None:
        """Create an additional indexed space."""
        pass

    def decodeNoHighPtr(self, decoder) -> None:
        """Apply memory alias configuration."""
        pass

    def decodePreferSplit(self, decoder) -> None:
        """Designate registers to be split."""
        pass

    def decodeAggressiveTrim(self, decoder) -> None:
        """Designate how to trim extension p-code ops."""
        pass

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
                return Address(self.spc, val), fullEncoding
        else:
            fullEncoding = val
            outersz = self.segop.getBaseSize()
            base = (val >> (8 * innersz)) & calc_mask(outersz)
            inner = val & calc_mask(innersz)
            seginput = [base, inner]
            val = self.segop.execute(seginput)
            return Address(self.spc, val), fullEncoding
        return Address(), 0
