"""
Corresponds to: ghidra_arch.hh / ghidra_arch.cc

ArchitectureGhidra — an Architecture subclass that communicates with a Ghidra
client over the binary protocol for all data queries (bytes, symbols, types,
comments, registers, p-code injection, etc.).
"""

from __future__ import annotations

from typing import BinaryIO, Optional, List, TYPE_CHECKING

from ghidra.arch.architecture import Architecture
from ghidra.core.address import Address
from ghidra.arch.loadimage import DataUnavailError

from ghidra.console.protocol import (
    JavaError,
    read_to_any_burst, read_string_stream,
    read_bool_stream, read_all_response, read_bytes_response,
    read_to_response, read_response_end,
    write_string_stream,
    send_query_open, send_query_close,
    BURST_BYTE_OPEN, BURST_BYTE_CLOSE,
)

if TYPE_CHECKING:
    from ghidra.types.datatype import Datatype
    from ghidra.core.space import AddrSpace
    from ghidra.core.marshal import Encoder, Decoder


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

    def buildLoader(self, store=None) -> None:
        from ghidra.console.subsystems import LoadImageGhidra
        self.loader = LoadImageGhidra(self)

    def buildSpecFile(self, store=None) -> None:
        """Parse the spec XML strings passed from Ghidra.

        C++ ref: ``ArchitectureGhidra::buildSpecFile``
        """
        if store is None:
            return
        # In C++, the four XML strings (pspec, cspec, tspec, corespec) are
        # parsed into Document objects and registered with the DocumentStorage.
        # We replicate this by parsing them and registering root elements.
        import xml.etree.ElementTree as ET

        for xml_str, tag_hint in [
            (self._pspecxml, "processor_spec"),
            (self._cspecxml, "compiler_spec"),
            (self._tspecxml, "sleigh"),
            (self._corespecxml, "coretypes"),
        ]:
            if xml_str:
                try:
                    root = ET.fromstring(xml_str)
                    if store is not None and hasattr(store, 'registerTag'):
                        store.registerTag(root)
                except ET.ParseError:
                    pass

        self._pspecxml = ""
        self._cspecxml = ""
        self._tspecxml = ""
        self._corespecxml = ""

    def buildContext(self, store=None) -> None:
        from ghidra.console.subsystems import ContextGhidra
        self.context = ContextGhidra(self)

    def buildTypegrp(self, store=None) -> None:
        from ghidra.console.subsystems import TypeFactoryGhidra
        self.types = TypeFactoryGhidra(self)

    def buildCommentDB(self, store=None) -> None:
        from ghidra.console.subsystems import CommentDatabaseGhidra
        self.commentdb = CommentDatabaseGhidra(self)

    def buildStringManager(self, store=None) -> None:
        from ghidra.console.subsystems import GhidraStringManager
        self.stringManager = GhidraStringManager(self, 2048)

    def buildConstantPool(self, store=None) -> None:
        from ghidra.console.subsystems import ConstantPoolGhidra
        self.cpool = ConstantPoolGhidra(self)

    def buildDatabase(self, store=None) -> None:
        from ghidra.console.subsystems import ScopeGhidra
        from ghidra.database.database import Database
        self.symboltab = Database(self, False)
        globalscope = ScopeGhidra(self)
        self.symboltab.attachScope(globalscope, None)

    def buildCoreTypes(self, store=None) -> None:
        """Build core data types (from Ghidra's coretypes spec or defaults).

        C++ ref: ``ArchitectureGhidra::buildCoreTypes``
        """
        if self.types is None:
            return
        # Try to use coretypes from the spec if available
        # Fall back to standard core types
        self.types.setupCoreTypes()

    def resolveArchitecture(self) -> None:
        self.archid = "ghidra"

    def postSpecFile(self) -> None:
        super().postSpecFile()
        if self.symboltab is not None:
            scope = self.symboltab.getGlobalScope()
            if hasattr(scope, 'lockDefaultProperties'):
                scope.lockDefaultProperties()

    def buildPcodeInjectLibrary(self):
        from ghidra.console.subsystems import PcodeInjectLibraryGhidra
        return PcodeInjectLibraryGhidra(self)

    # ------------------------------------------------------------------
    # Query methods — decompiler → Ghidra client
    # ------------------------------------------------------------------

    def getRegisterXml(self, regname: str) -> Optional[bytes]:
        """Ask Ghidra for register info by name.

        C++ ref: ``ArchitectureGhidra::getRegister``
        """
        send_query_open(self._sout)
        write_string_stream(self._sout, f"<command_getregister name=\"{_xml_escape(regname)}\"/>")
        send_query_close(self._sout)
        self._sout.flush()
        return read_all_response(self._sin)

    def getRegisterName(self, space, offset: int, size: int) -> str:
        """Ask Ghidra for register name by storage location.

        C++ ref: ``ArchitectureGhidra::getRegisterName``
        """
        space_name = getattr(space, 'name', str(space))
        send_query_open(self._sout)
        xml = (f'<command_getregistername>'
               f'<addr space="{_xml_escape(space_name)}" '
               f'offset="0x{offset:x}" size="{size}"/>'
               f'</command_getregistername>')
        write_string_stream(self._sout, xml)
        send_query_close(self._sout)
        self._sout.flush()

        read_to_response(self._sin)
        name = read_string_stream(self._sin)
        read_response_end(self._sin)
        return name

    def getTrackedRegistersXml(self, addr: Address) -> Optional[bytes]:
        """Get tracked register values at addr.

        C++ ref: ``ArchitectureGhidra::getTrackedRegisters``
        """
        send_query_open(self._sout)
        xml = (f'<command_gettrackedregisters>'
               f'{_encode_addr(addr)}'
               f'</command_gettrackedregisters>')
        write_string_stream(self._sout, xml)
        send_query_close(self._sout)
        self._sout.flush()
        return read_all_response(self._sin)

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

    def getPcodeXml(self, addr: Address) -> Optional[bytes]:
        """Get p-code for instruction at addr.

        C++ ref: ``ArchitectureGhidra::getPcode``
        """
        send_query_open(self._sout)
        xml = f'<command_getpcode>{_encode_addr(addr)}</command_getpcode>'
        write_string_stream(self._sout, xml)
        send_query_close(self._sout)
        self._sout.flush()
        return read_all_response(self._sin)

    def getMappedSymbolsXml(self, addr: Address) -> Optional[bytes]:
        """Get mapped symbols at addr.

        C++ ref: ``ArchitectureGhidra::getMappedSymbolsXML``
        """
        send_query_open(self._sout)
        xml = (f'<command_getmappedsymbols>'
               f'{_encode_addr(addr)}'
               f'</command_getmappedsymbols>')
        write_string_stream(self._sout, xml)
        send_query_close(self._sout)
        self._sout.flush()
        return read_all_response(self._sin)

    def getExternalRefXml(self, addr: Address) -> Optional[bytes]:
        """Get external function reference at addr.

        C++ ref: ``ArchitectureGhidra::getExternalRef``
        """
        send_query_open(self._sout)
        xml = (f'<command_getexternalref>'
               f'{_encode_addr(addr)}'
               f'</command_getexternalref>')
        write_string_stream(self._sout, xml)
        send_query_close(self._sout)
        self._sout.flush()
        return read_all_response(self._sin)

    def getNamespacePathXml(self, ns_id: int) -> Optional[bytes]:
        """Get namespace path from root to the given id.

        C++ ref: ``ArchitectureGhidra::getNamespacePath``
        """
        send_query_open(self._sout)
        xml = f'<command_getnamespacepath id="0x{ns_id:x}"/>'
        write_string_stream(self._sout, xml)
        send_query_close(self._sout)
        self._sout.flush()
        return read_all_response(self._sin)

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

    def getDataTypeXml(self, name: str, id_: int) -> Optional[bytes]:
        """Get data type description.

        C++ ref: ``ArchitectureGhidra::getDataType``
        """
        send_query_open(self._sout)
        xml = f'<command_getdatatype name="{_xml_escape(name)}" id="{id_}"/>'
        write_string_stream(self._sout, xml)
        send_query_close(self._sout)
        self._sout.flush()
        return read_all_response(self._sin)

    def getCommentsXml(self, funcaddr: Address, flags: int) -> Optional[bytes]:
        """Get comments for a function.

        C++ ref: ``ArchitectureGhidra::getComments``
        """
        send_query_open(self._sout)
        xml = (f'<command_getcomments type="{flags}">'
               f'{_encode_addr(funcaddr)}'
               f'</command_getcomments>')
        write_string_stream(self._sout, xml)
        send_query_close(self._sout)
        self._sout.flush()
        return read_all_response(self._sin)

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

    def getStringDataRaw(self, addr: Address, charType, maxBytes: int) -> Optional[tuple[bytes, bool]]:
        """Get string data at addr.

        C++ ref: ``ArchitectureGhidra::getStringData``
        """
        ct_name = charType.getName() if hasattr(charType, 'getName') else "char"
        ct_id = charType.getUnsizedId() if hasattr(charType, 'getUnsizedId') else 0
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
            # burst2 should be query-response-close
            return (bytes(result), is_trunc)
        if (burst & 1) == 1:
            return None
        raise JavaError("alignment", "Expecting end of query response")

    def getPcodeInjectXml(self, name: str, inject_type: int, context_xml: str) -> Optional[bytes]:
        """Get p-code injection.

        C++ ref: ``ArchitectureGhidra::getPcodeInject``
        """
        if inject_type == 1:  # CALLFIXUP_TYPE
            tag = "command_getcallfixup"
        elif inject_type == 2:  # CALLOTHERFIXUP_TYPE
            tag = "command_getcallotherfixup"
        elif inject_type == 3:  # CALLMECHANISM_TYPE
            tag = "command_getcallmech"
        else:  # EXECUTABLEPCODE_TYPE
            tag = "command_getpcodeexecutable"

        send_query_open(self._sout)
        xml = f'<{tag} name="{_xml_escape(name)}">{context_xml}</{tag}>'
        write_string_stream(self._sout, xml)
        send_query_close(self._sout)
        self._sout.flush()
        return read_all_response(self._sin)

    def getCPoolRefXml(self, refs: List[int]) -> Optional[bytes]:
        """Get constant pool reference.

        C++ ref: ``ArchitectureGhidra::getCPoolRef``
        """
        send_query_open(self._sout)
        inner = "".join(f'<value content="0x{r:x}"/>' for r in refs)
        xml = f'<command_getcpoolref size="{len(refs)}">{inner}</command_getcpoolref>'
        write_string_stream(self._sout, xml)
        send_query_close(self._sout)
        self._sout.flush()
        return read_all_response(self._sin)

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
