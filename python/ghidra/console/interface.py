"""
Generic command-line interface framework.
Corresponds to interface.hh / interface.cc.

Provides IfaceStatus, IfaceCommand, IfaceCapability and basic commands
(quit, history, echo, openfile, closefile).
"""
from __future__ import annotations

import sys
from abc import ABC, abstractmethod
from bisect import bisect_left, bisect_right
from typing import Dict, List, Optional, TextIO

from ghidra.core.capability import CapabilityPoint


# ── Exceptions ────────────────────────────────────────────────────────────

class IfaceError(Exception):
    """An exception specific to the command-line interface."""
    pass


class IfaceParseError(IfaceError):
    """Parsing error in a command line."""
    pass


class IfaceExecutionError(IfaceError):
    """Error during execution of a command."""
    pass


# ── Data / Command base classes ───────────────────────────────────────────

class IfaceData:
    """Data specialized for a particular command module."""
    pass


class IfaceCommand(ABC):
    """A command that can be executed from the command line."""

    def __init__(self) -> None:
        self._com: List[str] = []

    @abstractmethod
    def setData(self, root: IfaceStatus, data: Optional[IfaceData]) -> None: ...

    @abstractmethod
    def execute(self, args: str) -> None: ...

    @abstractmethod
    def getModule(self) -> str: ...

    @abstractmethod
    def createData(self) -> Optional[IfaceData]: ...

    def addWord(self, word: str) -> None:
        self._com.append(word)

    def removeWord(self) -> None:
        if self._com:
            self._com.pop()

    def getCommandWord(self, i: int) -> str:
        return self._com[i]

    def addWords(self, wordlist: List[str]) -> None:
        self._com.extend(wordlist)

    def numWords(self) -> int:
        return len(self._com)

    def commandString(self) -> str:
        return IfaceStatus.wordsToString(self._com)

    def compare(self, op2: IfaceCommand) -> int:
        for a, b in zip(self._com, op2._com):
            if a < b:
                return -1
            if a > b:
                return 1
        la, lb = len(self._com), len(op2._com)
        if la < lb:
            return -1
        if la > lb:
            return 1
        return 0


class IfaceCommandDummy(IfaceCommand):
    """A dummy command used during parsing."""

    def setData(self, root: IfaceStatus, data: Optional[IfaceData]) -> None:
        pass

    def execute(self, args: str) -> None:
        pass

    def getModule(self) -> str:
        return "dummy"

    def createData(self) -> Optional[IfaceData]:
        return None


def _compare_ifacecommand(a: IfaceCommand, b: IfaceCommand) -> bool:
    return a.compare(b) < 0


# ── IfaceCapability ───────────────────────────────────────────────────────

class IfaceCapability(CapabilityPoint):
    """Groups of console commands discovered by the loader."""

    _thelist: List[IfaceCapability] = []

    def __init__(self, name: str = "") -> None:
        super().__init__()
        self.name: str = name

    def getName(self) -> str:
        return self.name

    def initialize(self) -> None:
        IfaceCapability._thelist.append(self)

    @abstractmethod
    def registerCommands(self, status: IfaceStatus) -> None: ...

    @staticmethod
    def registerAllCommands(status: IfaceStatus) -> None:
        for cap in IfaceCapability._thelist:
            cap.registerCommands(status)


# ── IfaceStatus ───────────────────────────────────────────────────────────

class _CmdKey:
    """Wrapper for bisect-based binary search on sorted command lists."""
    __slots__ = ('cmd',)

    def __init__(self, cmd: IfaceCommand) -> None:
        self.cmd = cmd

    def __lt__(self, other: _CmdKey) -> bool:
        return self.cmd.compare(other.cmd) < 0


class IfaceStatus(ABC):
    """A generic console mode interface and command executor."""

    def __init__(self, prompt: str, optr: TextIO = sys.stdout,
                 maxhistory: int = 10) -> None:
        self.optr: TextIO = optr
        self.fileoptr: TextIO = optr
        self.done: bool = False
        self._prompt: str = prompt
        self._maxhistory: int = maxhistory
        self._curhistory: int = 0
        self._history: List[str] = []
        self._sorted: bool = False
        self._errorisdone: bool = False
        self.inerror: bool = False
        self._comlist: List[IfaceCommand] = []
        self._datamap: Dict[str, Optional[IfaceData]] = {}
        self._promptstack: List[str] = []
        self._flagstack: List[int] = []

    @abstractmethod
    def readLine(self) -> str:
        """Read the next command line."""
        ...

    @abstractmethod
    def isStreamFinished(self) -> bool:
        """Return True if the current stream is finished."""
        ...

    def setErrorIsDone(self, val: bool) -> None:
        self._errorisdone = val

    def pushScript(self, filename_or_stream, newprompt: str) -> None:
        self._promptstack.append(self._prompt)
        flags = 1 if self._errorisdone else 0
        self._flagstack.append(flags)
        self._errorisdone = True
        self._prompt = newprompt

    def popScript(self) -> None:
        if self._promptstack:
            self._prompt = self._promptstack.pop()
            flags = self._flagstack.pop()
            self._errorisdone = (flags & 1) != 0
            self.inerror = False

    def reset(self) -> None:
        while self._promptstack:
            self.popScript()
        self._errorisdone = False
        self.done = False

    def getNumInputStreamSize(self) -> int:
        return len(self._promptstack)

    def writePrompt(self) -> None:
        self.optr.write(self._prompt)

    def getPrompt(self) -> str:
        return self._prompt

    def registerCom(self, fptr: IfaceCommand, *names: str) -> None:
        for nm in names:
            fptr.addWord(nm)
        self._comlist.append(fptr)
        self._sorted = False

        module = fptr.getModule()
        if module not in self._datamap:
            data = fptr.createData()
            self._datamap[module] = data
        else:
            data = self._datamap[module]
        fptr.setData(self, data)

    def getData(self, nm: str) -> Optional[IfaceData]:
        return self._datamap.get(nm)

    def _saveHistory(self, line: str) -> None:
        if len(self._history) < self._maxhistory:
            self._history.append(line)
        else:
            self._history[self._curhistory] = line
        self._curhistory += 1
        if self._curhistory >= self._maxhistory:
            self._curhistory = 0

    def getHistory(self, i: int) -> str:
        if i >= len(self._history):
            return ""
        idx = self._curhistory - 1 - i
        if idx < 0:
            idx += self._maxhistory
        return self._history[idx]

    def getHistorySize(self) -> int:
        return len(self._history)

    def isInError(self) -> bool:
        return self.inerror

    def evaluateError(self) -> None:
        if self._errorisdone:
            self.optr.write("Aborting process\n")
            self.inerror = True
            self.done = True
            return
        if self.getNumInputStreamSize() != 0:
            self.optr.write(f"Aborting {self._prompt}\n")
            self.inerror = True
            return
        self.inerror = False

    def _ensureSorted(self) -> None:
        if not self._sorted:
            self._comlist.sort(key=lambda c: _CmdKey(c))
            self._sorted = True

    def _restrictCom(self, commands: List[IfaceCommand],
                     first: int, last: int,
                     words: List[str]) -> tuple[int, int]:
        """Restrict the range of commands matching the given word list."""
        dummy = IfaceCommandDummy()
        dummy.addWords(words)
        dk = _CmdKey(dummy)
        keys = [_CmdKey(c) for c in commands[first:last]]
        new_first = first + bisect_left(keys, dk)

        dummy.removeWord()
        last_word = words[-1]
        incremented = last_word[:-1] + chr(ord(last_word[-1]) + 1)
        dummy.addWord(incremented)
        dk2 = _CmdKey(dummy)
        new_last = first + bisect_right(keys, dk2)
        return new_first, new_last

    def runCommand(self) -> bool:
        self._ensureSorted()
        line = self.readLine()
        if not line.strip():
            return False
        self._saveHistory(line)
        tokens = line.split()
        first, last = 0, len(self._comlist)
        expand: List[str] = []

        for i, tok in enumerate(tokens):
            expand.append(tok)
            if first >= last:
                self.optr.write("ERROR: Invalid command\n")
                return False
            first, last = self._restrictCom(self._comlist, first, last, expand)
            if first >= last:
                self.optr.write("ERROR: Invalid command\n")
                return False
            if last - first == 1:
                # Unique match — auto-complete remaining words
                cmd = self._comlist[first]
                remaining = " ".join(tokens[i + 1:])
                cmd.execute(remaining)
                return True

        if first >= last:
            self.optr.write("ERROR: Invalid command\n")
            return False
        if last - first == 1:
            cmd = self._comlist[first]
            cmd.execute("")
            return True
        if last - first > 1:
            cmd = self._comlist[first]
            if cmd.numWords() == len(expand):
                cmd.execute("")
                return True
            self.optr.write("ERROR: Incomplete command\n")
            return False
        return False

    @staticmethod
    def wordsToString(words: List[str]) -> str:
        return " ".join(words)


# ── Base commands ─────────────────────────────────────────────────────────

class IfaceBaseCommand(IfaceCommand):
    """Root class for basic commands (module='base')."""

    def __init__(self) -> None:
        super().__init__()
        self.status: Optional[IfaceStatus] = None

    def setData(self, root: IfaceStatus, data: Optional[IfaceData]) -> None:
        self.status = root

    def getModule(self) -> str:
        return "base"

    def createData(self) -> Optional[IfaceData]:
        return None


class IfcQuit(IfaceBaseCommand):
    def execute(self, args: str) -> None:
        if args.strip():
            raise IfaceParseError("Too many parameters to quit")
        if self.status is not None:
            self.status.done = True


class IfcHistory(IfaceBaseCommand):
    def execute(self, args: str) -> None:
        if self.status is None:
            return
        parts = args.split()
        num = int(parts[0]) if parts else 10
        if len(parts) > 1:
            raise IfaceParseError("Too many parameters to history")
        num = min(num, self.status.getHistorySize())
        for i in range(num - 1, -1, -1):
            line = self.status.getHistory(i)
            self.status.optr.write(line + "\n")


class IfcOpenfile(IfaceBaseCommand):
    def execute(self, args: str) -> None:
        if self.status is None:
            return
        if self.status.optr is not self.status.fileoptr:
            raise IfaceExecutionError("Output file already opened")
        filename = args.strip()
        if not filename:
            raise IfaceParseError("No filename specified")
        try:
            self.status.fileoptr = open(filename, 'w')
        except OSError:
            self.status.fileoptr = self.status.optr
            raise IfaceExecutionError(f"Unable to open file: {filename}")


class IfcOpenfileAppend(IfaceBaseCommand):
    def execute(self, args: str) -> None:
        if self.status is None:
            return
        if self.status.optr is not self.status.fileoptr:
            raise IfaceExecutionError("Output file already opened")
        filename = args.strip()
        if not filename:
            raise IfaceParseError("No filename specified")
        try:
            self.status.fileoptr = open(filename, 'a')
        except OSError:
            self.status.fileoptr = self.status.optr
            raise IfaceExecutionError(f"Unable to open file: {filename}")


class IfcClosefile(IfaceBaseCommand):
    def execute(self, args: str) -> None:
        if self.status is None:
            return
        if self.status.optr is self.status.fileoptr:
            raise IfaceExecutionError("No file open")
        self.status.fileoptr.close()
        self.status.fileoptr = self.status.optr


class IfcEcho(IfaceBaseCommand):
    def execute(self, args: str) -> None:
        if self.status is None:
            return
        self.status.fileoptr.write(args + "\n")
