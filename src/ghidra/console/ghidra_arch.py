"""
Corresponds to: ghidra_arch.hh / ghidra_arch.cc

ArchitectureGhidra — an Architecture subclass that communicates with a Ghidra
client over the binary protocol for all data queries (bytes, symbols, types,
comments, registers, p-code injection, etc.).
"""

from __future__ import annotations

import io
from typing import BinaryIO, Optional, List, TYPE_CHECKING

from ghidra.arch.architecture import Architecture
from ghidra.core.address import Address
from ghidra.arch.loadimage import DataUnavailError

from ghidra.console.protocol import (
    JavaError,
    read_to_any_burst, read_string_stream,
    read_string_stream_decoder, read_all,
    read_bool_stream, read_all_response, read_bytes_response,
    read_to_response, read_response_end,
    write_string_stream,
    send_query_open, send_query_close,
    BURST_BYTE_OPEN, BURST_BYTE_CLOSE,
)

if TYPE_CHECKING:
    from ghidra.arch.inject import InjectContext
    from ghidra.types.datatype import Datatype
    from ghidra.core.space import AddrSpace
    from ghidra.core.marshal import Encoder, Decoder
    from ghidra.core.pcoderaw import VarnodeData


class ArchitectureGhidra(Architecture):
    """Architecture implementation backed by a Ghidra client.

    All build*() methods create Ghidra-backed subsystem objects.
    All get*() methods issue queries to the Ghidra client over stdin/stdout.

    C++ ref: ``ghidra_arch.hh / ghidra_arch.cc``
    """

    def __init__(self, pspec: str, cspec: str, tspec: str, corespec: str,
                 sin: BinaryIO, sout: BinaryIO) -> None:
        super().__init__()
        self._sin: BinaryIO = sin
        self._sout: BinaryIO = sout
        self._warnings: str = ""
        self._pspecxml: str = pspec
        self._cspecxml: str = cspec
        self._tspecxml: str = tspec
        self._corespecxml: str = corespec
        self._sendsyntaxtree: bool = True
        self._sendCcode: bool = True
        self._sendParamMeasures: bool = False

        if self.print_ is not None:
            self.print_.setMarkup(True)
            self.print_.setOutputStream(sout)
            # Output goes to sout — we'll wire this after init

    # ------------------------------------------------------------------
    # Warnings
    # ------------------------------------------------------------------

    def getWarnings(self) -> str:
        return self._warnings

    def clearWarnings(self) -> None:
        self._warnings = ""

    def printMessage(self, message: str) -> None:
        self._warnings += "\n" + message

    # ------------------------------------------------------------------
    # Send/receive toggles
    # ------------------------------------------------------------------

    def setSendSyntaxTree(self, val: bool) -> None:
        self._sendsyntaxtree = val

    def getSendSyntaxTree(self) -> bool:
        return self._sendsyntaxtree

    def setSendCCode(self, val: bool) -> None:
        self._sendCcode = val

    def getSendCCode(self) -> bool:
        return self._sendCcode

    def setSendParamMeasures(self, val: bool) -> None:
        self._sendParamMeasures = val

    def getSendParamMeasures(self) -> bool:
        return self._sendParamMeasures

    # ------------------------------------------------------------------
    # build*() overrides — create Ghidra-backed subsystems
    # ------------------------------------------------------------------

    def buildLoader(self, store) -> None:
        from ghidra.console.subsystems import LoadImageGhidra
        self.loader = LoadImageGhidra(self)

    def buildTranslator(self, store):
        from ghidra.console.subsystems import GhidraTranslate
        return GhidraTranslate(self)

    def buildSpecFile(self, store) -> None:
        """Parse the spec XML strings passed from Ghidra.

        C++ ref: ``ArchitectureGhidra::buildSpecFile``
        """
        for xml_str in (
            self._pspecxml,
            self._cspecxml,
            self._tspecxml,
            self._corespecxml,
        ):
            doc = store.parseDocument(xml_str)
            store.registerTag(doc.getRoot())

        self._pspecxml = ""
        self._cspecxml = ""
        self._tspecxml = ""
        self._corespecxml = ""

    def buildContext(self, store) -> None:
        from ghidra.console.subsystems import ContextGhidra
        self.context = ContextGhidra(self)

    def buildTypegrp(self, store) -> None:
        from ghidra.console.subsystems import TypeFactoryGhidra
        self.types = TypeFactoryGhidra(self)

    def buildCommentDB(self, store) -> None:
        from ghidra.console.subsystems import CommentDatabaseGhidra
        self.commentdb = CommentDatabaseGhidra(self)

    def buildStringManager(self, store) -> None:
        from ghidra.console.subsystems import GhidraStringManager
        self.stringManager = GhidraStringManager(self, 2048)

    def buildConstantPool(self, store) -> None:
        from ghidra.console.subsystems import ConstantPoolGhidra
        self.cpool = ConstantPoolGhidra(self)

    def buildDatabase(self, store):
        from ghidra.console.subsystems import ScopeGhidra
        from ghidra.database.database import Database
        self.symboltab = Database(self, False)
        globalscope = ScopeGhidra(self)
        self.symboltab.attachScope(globalscope, None)
        return globalscope

    def buildCoreTypes(self, store) -> None:
        """Build core data types (from Ghidra's coretypes spec or defaults).

        C++ ref: ``ArchitectureGhidra::buildCoreTypes``
        """
        from ghidra.types.datatype import (
            TYPE_VOID, TYPE_BOOL, TYPE_UINT, TYPE_INT, TYPE_FLOAT,
            TYPE_UNKNOWN, TYPE_CODE,
        )

        el = store.getTag("coretypes")
        if el is not None:
            from ghidra.core.marshal import XmlDecode

            decoder = XmlDecode(self, el)
            self.types.decodeCoreTypes(decoder)
        else:
            self.types.setCoreType("void", 1, TYPE_VOID, False)
            self.types.setCoreType("bool", 1, TYPE_BOOL, False)
            self.types.setCoreType("byte", 1, TYPE_UINT, False)
            self.types.setCoreType("word", 2, TYPE_UINT, False)
            self.types.setCoreType("dword", 4, TYPE_UINT, False)
            self.types.setCoreType("qword", 8, TYPE_UINT, False)
            self.types.setCoreType("char", 1, TYPE_INT, True)
            self.types.setCoreType("sbyte", 1, TYPE_INT, False)
            self.types.setCoreType("sword", 2, TYPE_INT, False)
            self.types.setCoreType("sdword", 4, TYPE_INT, False)
            self.types.setCoreType("sqword", 8, TYPE_INT, False)
            self.types.setCoreType("float", 4, TYPE_FLOAT, False)
            self.types.setCoreType("float8", 8, TYPE_FLOAT, False)
            self.types.setCoreType("float10", 10, TYPE_FLOAT, False)
            self.types.setCoreType("float16", 16, TYPE_FLOAT, False)
            self.types.setCoreType("undefined", 1, TYPE_UNKNOWN, False)
            self.types.setCoreType("undefined2", 2, TYPE_UNKNOWN, False)
            self.types.setCoreType("undefined4", 4, TYPE_UNKNOWN, False)
            self.types.setCoreType("undefined8", 8, TYPE_UNKNOWN, False)
            self.types.setCoreType("code", 1, TYPE_CODE, False)
            self.types.setCoreType("wchar", 2, TYPE_INT, True)
            self.types.cacheCoreTypes()

    def buildSymbols(self, store) -> None:
        from ghidra.core.address import Range
        from ghidra.core.error import LowlevelError
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

        symtag = store.getTag(ELEM_DEFAULT_SYMBOLS.getName())
        if symtag is None:
            return
        decoder = XmlDecode(self, symtag)
        el = decoder.openElement(ELEM_DEFAULT_SYMBOLS)
        lastAddr = Address()
        lastSize = -1
        while decoder.peekElement() != 0:
            subel = decoder.openElement(ELEM_SYMBOL)
            addrString = ""
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
                elif attribId == ATTRIB_VOLATILE:
                    volatileState = 1 if decoder.readBool() else 0
                elif attribId == ATTRIB_SIZE:
                    size = decoder.readSignedInteger()
            decoder.closeElement(subel)
            if len(name) == 0:
                raise LowlevelError("Missing name attribute in <symbol> element")
            if len(addrString) == 0:
                raise LowlevelError("Missing address attribute in <symbol> element")
            if volatileState < 0:
                continue
            if addrString == "next" and lastSize != -1:
                addr = lastAddr + lastSize
            else:
                addr = self.parseAddressSimple(addrString)
            if size == 0:
                size = addr.getSpace().getWordSize()
            range_ = Range(addr.getSpace(), addr.getOffset(), addr.getOffset() + (size - 1))
            if volatileState == 0:
                self.symboltab.clearPropertyRange(Varnode.volatil, range_)
            else:
                self.symboltab.setPropertyRange(Varnode.volatil, range_)
            lastAddr = addr
            lastSize = size
        decoder.closeElement(el)

    def resolveArchitecture(self) -> None:
        self.archid = "ghidra"

    def modifySpaces(self, trans) -> None:
        return None

    def postSpecFile(self) -> None:
        super().postSpecFile()
        scope = self.symboltab.getGlobalScope()
        scope.lockDefaultProperties()

    def buildPcodeInjectLibrary(self):
        from ghidra.console.subsystems import PcodeInjectLibraryGhidra
        return PcodeInjectLibraryGhidra(self)

    # ------------------------------------------------------------------
    # Query methods — decompiler → Ghidra client
    # ------------------------------------------------------------------

    def _query_packed_response(self, xml: str) -> Optional[bytes]:
        send_query_open(self._sout)
        write_string_stream(self._sout, xml)
        send_query_close(self._sout)
        self._sout.flush()
        return read_all_response(self._sin)

    def _ingest_packed_response(self, response: Optional[bytes], decoder: Decoder) -> bool:
        if response is None:
            return False
        ingest_bytes = getattr(decoder, "ingestBytes", None)
        if ingest_bytes is not None:
            ingest_bytes(response)
        else:
            decoder.ingestStream(response)
        return True

    def getRegister(self, regname: str, decoder: Decoder) -> bool:
        """Ask Ghidra for register info by name.

        C++ ref: ``ArchitectureGhidra::getRegister``
        """
        response = self._query_packed_response(
            f"<command_getregister name=\"{_xml_escape(regname)}\"/>"
        )
        return self._ingest_packed_response(response, decoder)

    def getRegisterName(self, vndata: VarnodeData) -> str:
        """Ask Ghidra for register name by storage location.

        C++ ref: ``ArchitectureGhidra::getRegisterName``
        """
        space_name = vndata.space.getName()
        addr = Address(vndata.space, vndata.offset)
        send_query_open(self._sout)
        xml = (f'<command_getregistername>'
               f'{_encode_addr(addr, vndata.size)}'
               f'</command_getregistername>')
        write_string_stream(self._sout, xml)
        send_query_close(self._sout)
        self._sout.flush()

        read_to_response(self._sin)
        name = read_string_stream(self._sin)
        read_response_end(self._sin)
        return name

    def getTrackedRegisters(self, addr: Address, decoder: Decoder) -> bool:
        """Get tracked register values at addr.

        C++ ref: ``ArchitectureGhidra::getTrackedRegisters``
        """
        response = self._query_packed_response(
            f'<command_gettrackedregisters>{_encode_addr(addr)}</command_gettrackedregisters>'
        )
        return self._ingest_packed_response(response, decoder)

    def getUserOpName(self, index: int) -> str:
        """Get user-defined p-code op name.

        C++ ref: ``ArchitectureGhidra::getUserOpName``
        """
        send_query_open(self._sout)
        xml = f'<command_getuseropname index="{index}"/>'
        write_string_stream(self._sout, xml)
        send_query_close(self._sout)
        self._sout.flush()

        read_to_response(self._sin)
        name = read_string_stream(self._sin)
        read_response_end(self._sin)
        return name

    def getPcode(self, addr: Address, decoder: Decoder) -> bool:
        """Get p-code for instruction at addr.

        C++ ref: ``ArchitectureGhidra::getPcode``
        """
        response = self._query_packed_response(
            f'<command_getpcode>{_encode_addr(addr)}</command_getpcode>'
        )
        return self._ingest_packed_response(response, decoder)

    def getMappedSymbolsXML(self, addr: Address, decoder: Decoder) -> bool:
        """Get mapped symbols at addr.

        C++ ref: ``ArchitectureGhidra::getMappedSymbolsXML``
        """
        response = self._query_packed_response(
            f'<command_getmappedsymbols>{_encode_addr(addr)}</command_getmappedsymbols>'
        )
        return self._ingest_packed_response(response, decoder)

    def getExternalRef(self, addr: Address, decoder: Decoder) -> bool:
        """Get external function reference at addr.

        C++ ref: ``ArchitectureGhidra::getExternalRef``
        """
        response = self._query_packed_response(
            f'<command_getexternalref>{_encode_addr(addr)}</command_getexternalref>'
        )
        return self._ingest_packed_response(response, decoder)

    def getNamespacePath(self, ns_id: int, decoder: Decoder) -> bool:
        """Get namespace path from root to the given id.

        C++ ref: ``ArchitectureGhidra::getNamespacePath``
        """
        response = self._query_packed_response(
            f'<command_getnamespacepath id="0x{ns_id:x}"/>'
        )
        return self._ingest_packed_response(response, decoder)

    def isNameUsed(self, nm: str, startId: int, stopId: int) -> bool:
        """Check if a name is used along the namespace path.

        C++ ref: ``ArchitectureGhidra::isNameUsed``
        """
        send_query_open(self._sout)
        xml = (f'<command_isnameused name="{_xml_escape(nm)}" '
               f'first="0x{startId:x}" last="0x{stopId:x}"/>')
        write_string_stream(self._sout, xml)
        send_query_close(self._sout)
        self._sout.flush()

        read_to_response(self._sin)
        result = read_bool_stream(self._sin)
        read_response_end(self._sin)
        return result

    def getCodeLabel(self, addr: Address) -> str:
        """Get a code label at addr.

        C++ ref: ``ArchitectureGhidra::getCodeLabel``
        """
        send_query_open(self._sout)
        xml = f'<command_getcodelabel>{_encode_addr(addr)}</command_getcodelabel>'
        write_string_stream(self._sout, xml)
        send_query_close(self._sout)
        self._sout.flush()

        read_to_response(self._sin)
        label = read_string_stream(self._sin)
        read_response_end(self._sin)
        return label

    def getDataType(self, name: str, id_: int, decoder: Decoder) -> bool:
        """Get data type description.

        C++ ref: ``ArchitectureGhidra::getDataType``
        """
        response = self._query_packed_response(
            f'<command_getdatatype name="{_xml_escape(name)}" id="{id_}"/>'
        )
        return self._ingest_packed_response(response, decoder)

    def getComments(self, funcaddr: Address, flags: int, decoder: Decoder) -> bool:
        """Get comments for a function.

        C++ ref: ``ArchitectureGhidra::getComments``
        """
        response = self._query_packed_response(
            f'<command_getcomments type="{flags}">{_encode_addr(funcaddr)}</command_getcomments>'
        )
        return self._ingest_packed_response(response, decoder)

    def getBytes(self, size: int, addr: Address) -> Optional[bytes]:
        """Get bytes from the load image.

        C++ ref: ``ArchitectureGhidra::getBytes``
        """
        send_query_open(self._sout)
        xml = (f'<command_getbytes>'
               f'{_encode_addr(addr, size)}'
               f'</command_getbytes>')
        write_string_stream(self._sout, xml)
        send_query_close(self._sout)
        self._sout.flush()

        result = read_bytes_response(self._sin, size)
        if result is None:
            raise DataUnavailError(
                f"GHIDRA has no data in the loadimage at {addr}")
        return result

    def getStringData(self, addr: Address, charType, maxBytes: int) -> Optional[tuple[bytes, bool]]:
        """Get string data at addr.

        C++ ref: ``ArchitectureGhidra::getStringData``
        """
        ct_name = charType.getName()
        ct_id = charType.getUnsizedId()
        send_query_open(self._sout)
        xml = (f'<command_getstringdata maxsize="{maxBytes}" '
               f'type="{_xml_escape(ct_name)}" id="{ct_id}">'
               f'{_encode_addr(addr)}'
               f'</command_getstringdata>')
        write_string_stream(self._sout, xml)
        send_query_close(self._sout)
        self._sout.flush()

        read_to_response(self._sin)
        burst = read_to_any_burst(self._sin)
        if burst == BURST_BYTE_OPEN:
            # Read size header (2 bytes encoded) + truncation flag
            c1 = self._sin.read(1)[0]
            c2 = self._sin.read(1)[0]
            data_size = (c1 - 0x20) ^ ((c2 - 0x20) << 6)
            is_trunc = (self._sin.read(1)[0] != 0)
            dblbuf = self._sin.read(data_size * 2)
            result = bytearray(data_size)
            for i in range(data_size):
                hi = dblbuf[i * 2] - ord('A')
                lo = dblbuf[i * 2 + 1] - ord('A')
                result[i] = (hi << 4) | lo
            end_burst = read_to_any_burst(self._sin)
            if end_burst != BURST_BYTE_CLOSE:
                raise JavaError("alignment", "Expecting byte alignment end")
            burst2 = read_to_any_burst(self._sin)
            if (burst2 & 1) != 1:
                raise JavaError("alignment", "Expecting end of query response")
            return (bytes(result), is_trunc)
        if (burst & 1) == 1:
            return None
        raise JavaError("alignment", "Expecting end of query response")

    def getStringDataRaw(self, addr: Address, charType, maxBytes: int) -> Optional[tuple[bytes, bool]]:
        return self.getStringData(addr, charType, maxBytes)

    @staticmethod
    def segvHandler(sig: int) -> None:
        raise SystemExit(1)

    @staticmethod
    def readToAnyBurst(sin: BinaryIO) -> int:
        return read_to_any_burst(sin)

    @staticmethod
    def readBoolStream(sin: BinaryIO) -> bool:
        return read_bool_stream(sin)

    @staticmethod
    def readStringStream(sin: BinaryIO, decoder: Optional[Decoder] = None) -> str | bool:
        if decoder is None:
            return read_string_stream(sin)
        return read_string_stream_decoder(sin, decoder)

    @staticmethod
    def writeStringStream(sout: BinaryIO, msg: str) -> None:
        write_string_stream(sout, msg)

    @staticmethod
    def readToResponse(sin: BinaryIO) -> None:
        read_to_response(sin)

    @staticmethod
    def readResponseEnd(sin: BinaryIO) -> None:
        read_response_end(sin)

    @staticmethod
    def readAll(sin: BinaryIO, decoder: Decoder) -> bool:
        return read_all(sin, decoder)

    @staticmethod
    def passJavaException(sout: BinaryIO, tp: str, msg: str) -> None:
        from ghidra.console.protocol import pass_java_exception

        pass_java_exception(sout, tp, msg)

    def getPcodeInject(self, name: str, inject_type: int, con: InjectContext, decoder: Decoder) -> bool:
        """Get p-code injection.

        C++ ref: ``ArchitectureGhidra::getPcodeInject``
        """
        from ghidra.core.marshal import XmlEncode

        if inject_type == 1:  # CALLFIXUP_TYPE
            tag = "command_getcallfixup"
        elif inject_type == 2:  # CALLOTHERFIXUP_TYPE
            tag = "command_getcallotherfixup"
        elif inject_type == 3:  # CALLMECHANISM_TYPE
            tag = "command_getcallmech"
        else:  # EXECUTABLEPCODE_TYPE
            tag = "command_getpcodeexecutable"

        stream = io.StringIO()
        encoder = XmlEncode(stream, do_format=False)
        con.encode(encoder)
        response = self._query_packed_response(
            f'<{tag} name="{_xml_escape(name)}">{stream.getvalue()}</{tag}>'
        )
        return self._ingest_packed_response(response, decoder)

    def getCPoolRef(self, refs: List[int], decoder: Decoder) -> bool:
        """Get constant pool reference.

        C++ ref: ``ArchitectureGhidra::getCPoolRef``
        """
        inner = "".join(f'<value content="0x{r:x}"/>' for r in refs)
        response = self._query_packed_response(
            f'<command_getcpoolref size="{len(refs)}">{inner}</command_getcpoolref>'
        )
        return self._ingest_packed_response(response, decoder)

    # ------------------------------------------------------------------
    # Static utility
    # ------------------------------------------------------------------

    @staticmethod
    def isDynamicSymbolName(nm: str) -> bool:
        """Check if name is of form FUN_.. or DAT_..

        C++ ref: ``ArchitectureGhidra::isDynamicSymbolName``
        """
        if len(nm) < 8:
            return False
        if nm[3] != '_':
            return False
        if nm[:3] not in ("FUN", "DAT"):
            return False
        for c in nm[-4:]:
            if c not in "0123456789abcdef":
                return False
        return True


# ---------------------------------------------------------------------------
# XML encoding helpers
# ---------------------------------------------------------------------------

def _xml_escape(s: str) -> str:
    """Escape a string for use in XML attributes."""
    return (s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;"))


def _encode_addr(addr: Address, size: int = 0) -> str:
    """Encode an Address as a minimal <addr> XML tag."""
    space = addr.getSpace()
    space_name = space.getName() if space is not None else "ram"
    offset = addr.getOffset()
    if size > 0:
        return f'<addr space="{_xml_escape(space_name)}" offset="0x{offset:x}" size="{size}"/>'
    return f'<addr space="{_xml_escape(space_name)}" offset="0x{offset:x}"/>'
