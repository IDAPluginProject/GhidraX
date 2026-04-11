"""
Corresponds to: sleigh_arch.hh / sleigh_arch.cc

Architecture objects that use a Translate object derived from Sleigh.
Provides CompilerTag, LanguageDescription, and SleighArchitecture.
"""

from __future__ import annotations

import os
import io
import xml.etree.ElementTree as ET
from typing import Optional, List, TYPE_CHECKING

from ghidra.core.error import LowlevelError
from ghidra.core.marshal import AttributeId, ElementId
from ghidra.arch.architecture import Architecture, ArchitectureCapability
from ghidra.core.translate import TruncationTag

if TYPE_CHECKING:
    pass


ATTRIB_DEPRECATED = AttributeId("deprecated", 136)
ATTRIB_ENDIAN = AttributeId("endian", 137)
ATTRIB_PROCESSOR = AttributeId("processor", 138)
ATTRIB_PROCESSORSPEC = AttributeId("processorspec", 139)
ATTRIB_SLAFILE = AttributeId("slafile", 140)
ATTRIB_SPEC = AttributeId("spec", 141)
ATTRIB_TARGET = AttributeId("target", 142)
ATTRIB_VARIANT = AttributeId("variant", 143)
ATTRIB_VERSION = AttributeId("version", 144)

ELEM_COMPILER = ElementId("compiler", 232)
ELEM_DESCRIPTION = ElementId("description", 233)
ELEM_LANGUAGE = ElementId("language", 234)
ELEM_LANGUAGE_DEFINITIONS = ElementId("language_definitions", 235)


# =========================================================================
# CompilerTag
# =========================================================================

class CompilerTag:
    """Contents of a <compiler> tag in a .ldefs file.

    Describes a compiler specification file as referenced by the Sleigh
    language subsystem.
    """

    def __init__(self) -> None:
        self.name: str = ""
        self.spec: str = ""
        self.id: str = ""

    def decode(self, el: ET.Element) -> None:
        """Restore the record from an XML element or Decoder."""
        from ghidra.core.marshal import ATTRIB_ID, ATTRIB_NAME

        if hasattr(el, "tag"):
            self.name = el.get("name", "")
            self.spec = el.get("spec", "")
            self.id = el.get("id", "")
            return

        elem_id = el.openElement(ELEM_COMPILER)
        self.name = el.readString(ATTRIB_NAME)
        self.spec = el.readString(ATTRIB_SPEC)
        self.id = el.readString(ATTRIB_ID)
        el.closeElement(elem_id)

    def getName(self) -> str:
        return self.name

    def getSpec(self) -> str:
        return self.spec

    def getId(self) -> str:
        return self.id

    def __repr__(self) -> str:
        return f"CompilerTag(id={self.id!r}, spec={self.spec!r})"


# =========================================================================
# LanguageDescription
# =========================================================================

class LanguageDescription:
    """Contents of a <language> tag in a .ldefs file.

    Contains meta-data describing a single processor and the set of files
    used to analyze it.
    """

    def __init__(self) -> None:
        self.processor: str = ""
        self.isbigendian: bool = False
        self.size: int = 0
        self.variant: str = ""
        self.version: str = ""
        self.slafile: str = ""
        self.processorspec: str = ""
        self.id: str = ""
        self.description: str = ""
        self.deprecated: bool = False
        self.compilers: List[CompilerTag] = []
        self.truncations: List[TruncationTag] = []

    def decode(self, el: ET.Element) -> None:
        """Parse this description from an XML <language> element or Decoder."""
        from ghidra.core.marshal import (
            ATTRIB_CONTENT,
            ATTRIB_ID,
            ATTRIB_SIZE,
            ATTRIB_SPACE,
            ELEM_TRUNCATE_SPACE,
        )

        if hasattr(el, "tag"):
            self.processor = el.get("processor", "")
            self.isbigendian = (el.get("endian", "") == "big")
            self.size = int(el.get("size", "0"))
            self.variant = el.get("variant", "")
            self.version = el.get("version", "")
            self.slafile = el.get("slafile", "")
            self.processorspec = el.get("processorspec", "")
            self.id = el.get("id", "")
            self.deprecated = el.get("deprecated", "false").lower() == "true"

            for child in el:
                tag = child.tag
                if tag == ELEM_DESCRIPTION.name:
                    self.description = child.get("content", child.text or "")
                elif tag == ELEM_COMPILER.name:
                    ct = CompilerTag()
                    ct.decode(child)
                    self.compilers.append(ct)
                elif tag == ELEM_TRUNCATE_SPACE.name:
                    trunc = TruncationTag()
                    trunc.spaceName = child.get("space", "")
                    trunc.size = int(child.get("size", "0"))
                    self.truncations.append(trunc)
            return

        decoder = el
        elem_id = decoder.openElement(ELEM_LANGUAGE)
        self.processor = decoder.readString(ATTRIB_PROCESSOR)
        self.isbigendian = (decoder.readString(ATTRIB_ENDIAN) == "big")
        self.size = decoder.readSignedInteger(ATTRIB_SIZE)
        self.variant = decoder.readString(ATTRIB_VARIANT)
        self.version = decoder.readString(ATTRIB_VERSION)
        self.slafile = decoder.readString(ATTRIB_SLAFILE)
        self.processorspec = decoder.readString(ATTRIB_PROCESSORSPEC)
        self.id = decoder.readString(ATTRIB_ID)
        self.deprecated = False
        while True:
            attrib_id = decoder.getNextAttributeId()
            if attrib_id == 0:
                break
            if attrib_id == ATTRIB_DEPRECATED.id:
                self.deprecated = decoder.readBool()

        while True:
            sub_id = decoder.peekElement()
            if sub_id == 0:
                break
            if sub_id == ELEM_DESCRIPTION.id:
                opened = decoder.openElement()
                self.description = decoder.readString(ATTRIB_CONTENT)
                decoder.closeElement(opened)
            elif sub_id == ELEM_COMPILER.id:
                compiler = CompilerTag()
                compiler.decode(decoder)
                self.compilers.append(compiler)
            elif sub_id == ELEM_TRUNCATE_SPACE.id:
                opened = decoder.openElement()
                trunc = TruncationTag()
                trunc.spaceName = decoder.readString(ATTRIB_SPACE)
                trunc.size = decoder.readUnsignedInteger(ATTRIB_SIZE)
                self.truncations.append(trunc)
                decoder.closeElement(opened)
            else:
                opened = decoder.openElement()
                decoder.closeElementSkipping(opened)
        decoder.closeElement(elem_id)

    def getProcessor(self) -> str:
        return self.processor

    def isBigEndian(self) -> bool:
        return self.isbigendian

    def getSize(self) -> int:
        return self.size

    def getVariant(self) -> str:
        return self.variant

    def getVersion(self) -> str:
        return self.version

    def getSlaFile(self) -> str:
        return self.slafile

    def getProcessorSpec(self) -> str:
        return self.processorspec

    def getId(self) -> str:
        return self.id

    def getDescription(self) -> str:
        return self.description

    def isDeprecated(self) -> bool:
        return self.deprecated

    def getCompiler(self, nm: str | int) -> CompilerTag:
        """Get compiler specification of the given name.

        If no exact match, returns 'default' compiler or first compiler.
        """
        if isinstance(nm, int):
            return self.compilers[nm]

        default_idx = -1
        for i, ct in enumerate(self.compilers):
            if ct.getId() == nm:
                return ct
            if ct.getId() == "default":
                default_idx = i
        if default_idx != -1:
            return self.compilers[default_idx]
        return self.compilers[0]

    def numCompilers(self) -> int:
        return len(self.compilers)

    def getCompilerByIndex(self, i: int) -> CompilerTag:
        return self.getCompiler(i)

    def numTruncations(self) -> int:
        return len(self.truncations)

    def getTruncation(self, i: int) -> TruncationTag:
        return self.truncations[i]

    def __repr__(self) -> str:
        return f"LanguageDescription(id={self.id!r}, processor={self.processor!r})"


# =========================================================================
# FileManage (minimal port for spec file discovery)
# =========================================================================

class FileManage:
    """Minimal port of filemanage.hh for finding specification files."""

    def __init__(self) -> None:
        self._paths: List[str] = []

    def addDir2Path(self, d: str) -> None:
        """Add a directory to the search path."""
        if d and d not in self._paths:
            self._paths.append(d)

    def findFile(self, filename: str) -> Optional[str]:
        """Search for a file within known directories.

        Returns the full path if found, None otherwise.
        """
        for d in self._paths:
            candidate = os.path.join(d, filename)
            if os.path.isfile(candidate):
                return candidate
        return None

    def matchList(self, ext: str, recursive: bool = True) -> List[str]:
        """Find all files matching the given extension within search paths."""
        results: List[str] = []
        for d in self._paths:
            if not os.path.isdir(d):
                continue
            if recursive:
                for root, _dirs, files in os.walk(d):
                    for f in files:
                        if f.endswith(ext):
                            results.append(os.path.join(root, f))
            else:
                for f in os.listdir(d):
                    if f.endswith(ext):
                        results.append(os.path.join(d, f))
        return results

    @staticmethod
    def scanDirectoryRecursive(target_name: str, root: str, maxdepth: int = 3) -> List[str]:
        """Find directories matching target_name under root, up to maxdepth levels."""
        results: List[str] = []
        if maxdepth < 0:
            return results
        if not os.path.isdir(root):
            return results
        try:
            for entry in os.listdir(root):
                full = os.path.join(root, entry)
                if os.path.isdir(full):
                    if entry == target_name:
                        results.append(full)
                    if maxdepth > 0:
                        results.extend(FileManage.scanDirectoryRecursive(
                            target_name, full, maxdepth - 1
                        ))
        except PermissionError:
            pass
        return results

    @staticmethod
    def directoryList(path: str) -> List[str]:
        """List immediate subdirectories of the given path."""
        results: List[str] = []
        if not os.path.isdir(path):
            return results
        try:
            for entry in os.listdir(path):
                full = os.path.join(path, entry)
                if os.path.isdir(full):
                    results.append(full)
        except PermissionError:
            pass
        return results


# =========================================================================
# SleighArchitecture
# =========================================================================

class SleighArchitecture(Architecture):
    """An Architecture that uses the decompiler's native SLEIGH translation engine.

    Knows how to natively read in:
      - a compiled SLEIGH specification (.sla)
      - a processor specification file (.pspec)
      - a compiler specification file (.cspec)

    Generally a language id (e.g. x86:LE:64:default) is provided, then this
    object is able to automatically load configuration and construct the
    Translate object.
    """

    # Class-level state (mirrors C++ static members)
    _translators: dict[int, object] = {}
    _descriptions: List[LanguageDescription] = []
    specpaths: FileManage = FileManage()

    def __init__(self, fname: str, targ: str, estream) -> None:
        super().__init__()
        self.filename: str = fname
        self.target: str = targ
        self.errorstream = estream
        self._languageindex: int = -1
        self._translators = SleighArchitecture._translators

    # --- Accessors ---

    def getFilename(self) -> str:
        return self.filename

    def getTarget(self) -> str:
        return self.target

    def getDescription(self) -> str:
        return SleighArchitecture._descriptions[self._languageindex].getDescription()

    def printMessage(self, message: str) -> None:
        self.errorstream.write(message + "\n")

    def __del__(self) -> None:
        self.translate = None
        super().__del__()

    # --- Build overrides ---

    def isTranslateReused(self) -> bool:
        return self._languageindex in SleighArchitecture._translators

    def buildTranslator(self, store):
        from ghidra.sleigh.sleigh import Sleigh

        translator = SleighArchitecture._translators.get(self._languageindex)
        if translator is not None:
            translator.reset(self.loader, self.context)
            return translator

        translator = Sleigh(self.loader, self.context)
        SleighArchitecture._translators[self._languageindex] = translator
        return translator

    def buildPcodeInjectLibrary(self):
        from ghidra.arch.inject_sleigh import PcodeInjectLibrarySleigh

        return PcodeInjectLibrarySleigh(self)

    def buildTypegrp(self, store) -> None:
        from ghidra.types.datatype import TypeFactory
        self.types = TypeFactory(self)

    def buildCoreTypes(self, store) -> None:
        el = store.getTag("coretypes")
        if el is not None:
            from ghidra.core.marshal import XmlDecode

            decoder = XmlDecode(self, el)
            self.types.decodeCoreTypes(decoder)
            return

        from ghidra.types.datatype import (
            TYPE_VOID, TYPE_BOOL, TYPE_UINT, TYPE_INT, TYPE_FLOAT,
            TYPE_UNKNOWN, TYPE_CODE,
        )
        self.types.setCoreType("void", 1, TYPE_VOID, False)
        self.types.setCoreType("bool", 1, TYPE_BOOL, False)
        self.types.setCoreType("uint1", 1, TYPE_UINT, False)
        self.types.setCoreType("uint2", 2, TYPE_UINT, False)
        self.types.setCoreType("uint4", 4, TYPE_UINT, False)
        self.types.setCoreType("uint8", 8, TYPE_UINT, False)
        self.types.setCoreType("int1", 1, TYPE_INT, False)
        self.types.setCoreType("int2", 2, TYPE_INT, False)
        self.types.setCoreType("int4", 4, TYPE_INT, False)
        self.types.setCoreType("int8", 8, TYPE_INT, False)
        self.types.setCoreType("float4", 4, TYPE_FLOAT, False)
        self.types.setCoreType("float8", 8, TYPE_FLOAT, False)
        self.types.setCoreType("float10", 10, TYPE_FLOAT, False)
        self.types.setCoreType("float16", 16, TYPE_FLOAT, False)
        self.types.setCoreType("xunknown1", 1, TYPE_UNKNOWN, False)
        self.types.setCoreType("xunknown2", 2, TYPE_UNKNOWN, False)
        self.types.setCoreType("xunknown4", 4, TYPE_UNKNOWN, False)
        self.types.setCoreType("xunknown8", 8, TYPE_UNKNOWN, False)
        self.types.setCoreType("code", 1, TYPE_CODE, False)
        self.types.setCoreType("char", 1, TYPE_INT, True)
        self.types.setCoreType("wchar2", 2, TYPE_INT, True)
        self.types.setCoreType("wchar4", 4, TYPE_INT, True)
        self.types.cacheCoreTypes()

    def buildCommentDB(self, store) -> None:
        from ghidra.database.comment import CommentDatabaseInternal
        self.commentdb = CommentDatabaseInternal()

    def buildStringManager(self, store) -> None:
        from ghidra.database.stringmanage import StringManagerUnicode
        self.stringManager = StringManagerUnicode(self, 2048)

    def buildConstantPool(self, store) -> None:
        from ghidra.database.cpool import ConstantPoolInternal
        self.cpool = ConstantPoolInternal()

    def buildContext(self, store) -> None:
        from ghidra.core.globalcontext import ContextInternal
        self.context = ContextInternal()

    def buildSymbols(self, store) -> None:
        from ghidra.core.address import Address, Range
        from ghidra.core.marshal import (
            ATTRIB_ADDRESS,
            ATTRIB_NAME,
            ATTRIB_SIZE,
            ATTRIB_VOLATILE,
            ELEM_DEFAULT_SYMBOLS,
            ELEM_SYMBOL,
            XmlDecode,
        )
        from ghidra.ir.varnode import Varnode
        from ghidra.types.datatype import TYPE_UNKNOWN

        symtag = store.getTag(ELEM_DEFAULT_SYMBOLS.getName())
        if symtag is None:
            return
        decoder = XmlDecode(self, symtag)
        el = decoder.openElement(ELEM_DEFAULT_SYMBOLS)
        lastAddr = Address()
        lastSize = -1
        while decoder.peekElement() != 0:
            subel = decoder.openElement(ELEM_SYMBOL)
            addr = Address()
            name = ""
            size = 0
            volatileState = -1
            while True:
                attribId = decoder.getNextAttributeId()
                if attribId == 0:
                    break
                if attribId == ATTRIB_NAME:
                    name = decoder.readString()
                elif attribId == ATTRIB_ADDRESS:
                    addrString = decoder.readString()
                    if addrString == "next" and lastSize != -1:
                        addr = lastAddr + lastSize
                    else:
                        addr = self.parseAddressSimple(addrString)
                elif attribId == ATTRIB_VOLATILE:
                    volatileState = 1 if decoder.readBool() else 0
                elif attribId == ATTRIB_SIZE:
                    size = decoder.readSignedInteger()
            decoder.closeElement(subel)
            if len(name) == 0:
                raise LowlevelError("Missing name attribute in <symbol> element")
            if addr.isInvalid():
                raise LowlevelError("Missing address attribute in <symbol> element")
            if size == 0:
                size = addr.getSpace().getWordSize()
            if volatileState >= 0:
                range_ = Range(addr.getSpace(), addr.getOffset(), addr.getOffset() + (size - 1))
                if volatileState == 0:
                    self.symboltab.clearPropertyRange(Varnode.volatil, range_)
                else:
                    self.symboltab.setPropertyRange(Varnode.volatil, range_)
            ct = self.types.getBase(size, TYPE_UNKNOWN)
            usepoint = Address()
            self.symboltab.getGlobalScope().addSymbol(name, ct, addr, usepoint)
            lastAddr = addr
            lastSize = size
        decoder.closeElement(el)

    def resolveArchitecture(self) -> None:
        """Find the best matching language description for the target."""
        if not self.archid:
            if not self.target or self.target == "default":
                self.archid = self.loader.getArchType()
            else:
                self.archid = self.target

        if self.archid.startswith("binary-"):
            self.archid = self.archid[7:]
        elif self.archid.startswith("default-"):
            self.archid = self.archid[8:]

        self.archid = SleighArchitecture.normalizeArchitecture(self.archid)
        baseid = self.archid[:self.archid.rfind(':')]

        self._languageindex = -1
        for i, desc in enumerate(SleighArchitecture._descriptions):
            if desc.getId() == baseid:
                self._languageindex = i
                if desc.isDeprecated():
                    self.printMessage("WARNING: Language " + baseid + " is deprecated")
                break

        if self._languageindex == -1:
            raise LowlevelError("No sleigh specification for " + baseid)

    def buildSpecFile(self, store) -> None:
        """Given a specific language, make sure relevant spec files are loaded."""
        from ghidra.arch.pcodecompile import SleighError

        language = SleighArchitecture._descriptions[self._languageindex]
        language_reuse = self.isTranslateReused()
        compiler = self.archid[self.archid.rfind(':') + 1:]
        compilertag = language.getCompiler(compiler)

        processorfile = SleighArchitecture.specpaths.findFile(language.getProcessorSpec()) or ""
        compilerfile = SleighArchitecture.specpaths.findFile(compilertag.getSpec()) or ""
        slafile = ""
        if not language_reuse:
            slafile = SleighArchitecture.specpaths.findFile(language.getSlaFile()) or ""
            if len(slafile) == 0:
                raise SleighError("Could not find .sla file for " + self.archid)

        from ghidra.core.error import DecoderError

        try:
            doc = store.openDocument(processorfile)
            store.registerTag(doc.getRoot())
        except DecoderError as err:
            raise SleighError(
                "XML error parsing processor specification: "
                + processorfile
                + "\n "
                + err.explain
            ) from err
        except LowlevelError as err:
            raise SleighError(
                "Error reading processor specification: "
                + processorfile
                + "\n "
                + err.explain
            ) from err

        try:
            doc = store.openDocument(compilerfile)
            store.registerTag(doc.getRoot())
        except DecoderError as err:
            raise SleighError(
                "XML error parsing compiler specification: "
                + compilerfile
                + "\n "
                + err.explain
            ) from err
        except LowlevelError as err:
            raise SleighError(
                "Error reading compiler specification: "
                + compilerfile
                + "\n "
                + err.explain
            ) from err

        if not language_reuse:
            try:
                doc = store.parseDocument("<sleigh>" + slafile + "</sleigh>")
                store.registerTag(doc.getRoot())
            except LowlevelError as err:
                raise SleighError(
                    "Error reading SLEIGH file: "
                    + slafile
                    + "\n "
                    + err.explain
                ) from err

    def modifySpaces(self, trans) -> None:
        """Apply address space truncations required by this processor."""
        language = SleighArchitecture._descriptions[self._languageindex]
        for i in range(language.numTruncations()):
            trans.truncateSpace(language.getTruncation(i))

    def encodeHeader(self, encoder) -> None:
        """Encode basic attributes of the active executable."""
        from ghidra.core.marshal import ATTRIB_NAME

        encoder.writeString(ATTRIB_NAME, self.filename)
        encoder.writeString(ATTRIB_TARGET, self.target)

    def restoreXmlHeader(self, el) -> None:
        """Restore from basic attributes of an executable."""
        self.filename = el.getAttributeValue("name")
        self.target = el.getAttributeValue("target")

    # --- Static normalization helpers ---

    @staticmethod
    def normalizeProcessor(nm: str) -> str:
        """Try to recover a language id processor field."""
        if "386" in nm:
            return "x86"
        return nm

    @staticmethod
    def normalizeEndian(nm: str) -> str:
        """Try to recover a language id endianness field."""
        if "big" in nm:
            return "BE"
        if "little" in nm:
            return "LE"
        return nm

    @staticmethod
    def normalizeSize(nm: str) -> str:
        """Try to recover a language id size field."""
        res = nm.replace("bit", "").replace("-", "")
        return res

    @staticmethod
    def normalizeArchitecture(nm: str) -> str:
        """Try to normalize a target string into a valid language id.

        Expected format: processor:endian:size:variant[:compiler]
        """
        parts = nm.split(':')
        if len(parts) == 4:
            processor, endian, size, variant = parts
            compiler = "default"
        elif len(parts) == 5:
            processor, endian, size, variant, compiler = parts
        else:
            raise LowlevelError(
                "Architecture string does not look like sleigh id: " + nm)

        processor = SleighArchitecture.normalizeProcessor(processor)
        endian = SleighArchitecture.normalizeEndian(endian)
        size = SleighArchitecture.normalizeSize(size)
        return f"{processor}:{endian}:{size}:{variant}:{compiler}"

    # --- Static spec file management ---

    @staticmethod
    def scanForSleighDirectories(rootpath: str) -> None:
        """Scan directories for SLEIGH specification files.

        Assumes a standard Ghidra/Processors/*/data/languages layout.
        """
        languagesubdirs: List[str] = []

        ghidradirs = FileManage.scanDirectoryRecursive("Ghidra", rootpath, 2)
        procdirs: List[str] = []
        for gd in ghidradirs:
            procdirs.extend(FileManage.scanDirectoryRecursive("Processors", gd, 1))
            procdirs.extend(FileManage.scanDirectoryRecursive("contrib", gd, 1))

        if procdirs:
            procdirs2: List[str] = []
            for pd in procdirs:
                procdirs2.extend(FileManage.directoryList(pd))
            datadirs: List[str] = []
            for pd2 in procdirs2:
                datadirs.extend(FileManage.scanDirectoryRecursive("data", pd2, 1))
            languagedirs: List[str] = []
            for dd in datadirs:
                languagedirs.extend(FileManage.scanDirectoryRecursive("languages", dd, 1))
            for ld in languagedirs:
                languagesubdirs.append(ld)
            for ld in languagedirs:
                languagesubdirs.extend(FileManage.directoryList(ld))

        if not languagesubdirs:
            languagesubdirs.append(rootpath)

        for d in languagesubdirs:
            SleighArchitecture.specpaths.addDir2Path(d)

    @staticmethod
    def loadLanguageDescription(specfile: str, errs: Optional[io.StringIO] = None) -> None:
        """Read a SLEIGH .ldefs file.

        Any <language> tags are added to the LanguageDescription array.
        """
        try:
            stream = open(specfile, "rb")
        except OSError:
            return
        try:
            with stream:
                tree = ET.parse(stream)
        except ET.ParseError:
            if errs is not None:
                errs.write(f"WARNING: Unable to parse sleigh specfile: {specfile}")
            return

        root = tree.getroot()
        for child in root:
            if child.tag == "language":
                desc = LanguageDescription()
                desc.decode(child)
                SleighArchitecture._descriptions.append(desc)

    @staticmethod
    def collectSpecFiles(errs: Optional[io.StringIO] = None) -> None:
        """Parse all .ldefs files in the spec paths."""
        if SleighArchitecture._descriptions:
            return
        ldefs_files = SleighArchitecture.specpaths.matchList(".ldefs", recursive=True)
        for f in ldefs_files:
            SleighArchitecture.loadLanguageDescription(f, errs)

    @staticmethod
    def getDescriptions() -> List[LanguageDescription]:
        """Get list of all known language descriptions."""
        errs = io.StringIO()
        SleighArchitecture.collectSpecFiles(errs)
        msg = errs.getvalue()
        if msg:
            raise LowlevelError(msg)
        return SleighArchitecture._descriptions

    @staticmethod
    def shutdown() -> None:
        """Free global resources."""
        pass

    def __repr__(self) -> str:
        return f"SleighArchitecture(file={self.filename!r}, target={self.target!r})"


# =========================================================================
# SleighArchitectureCapability
# =========================================================================

class SleighArchitectureCapability(ArchitectureCapability):
    """Capability for building SleighArchitecture objects."""

    def __init__(self) -> None:
        super().__init__()
        self.name = "sleigh"

    def buildArchitecture(self, filename: str, target: str, estream=None):
        return SleighArchitecture(filename, target, estream)

    def isFileMatch(self, filename: str) -> bool:
        return True

    def isXmlMatch(self, doc) -> bool:
        return False
