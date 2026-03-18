"""
Terminal-based command-line interface.
Corresponds to ifaceterm.hh / ifaceterm.cc.

Provides IfaceTerm — a concrete IfaceStatus that reads from an input stream
(or stdin with readline support).
"""
from __future__ import annotations

import sys
from typing import List, TextIO

from ghidra.console.interface import IfaceStatus


class IfaceTerm(IfaceStatus):
    """Implement the command-line interface on top of a specific input stream.

    Additional input streams can be stacked by invoking scripts.
    When reading from a real terminal (stdin), Python's built-in readline
    support is used for line editing and history.
    """

    def __init__(self, prompt: str, istream: TextIO = sys.stdin,
                 ostream: TextIO = sys.stdout) -> None:
        super().__init__(prompt, ostream)
        self._sptr: TextIO = istream
        self._inputstack: List[TextIO] = []
        self._is_terminal: bool = hasattr(istream, 'isatty') and istream.isatty()

        if self._is_terminal:
            try:
                import readline  # noqa: F401 — enable line editing on stdin
            except ImportError:
                pass

    def readLine(self) -> str:
        """Read the next command line from the current input stream."""
        if self._is_terminal and self._sptr is sys.stdin:
            try:
                return input(self.getPrompt())
            except EOFError:
                return ""
        else:
            line = self._sptr.readline()
            if not line:
                return ""
            return line.rstrip('\n\r')

    def pushScript(self, filename_or_stream, newprompt: str) -> None:
        """Push a new input stream (or open a file) onto the script stack."""
        if isinstance(filename_or_stream, str):
            try:
                new_stream = open(filename_or_stream, 'r', encoding='utf-8')
            except OSError as exc:
                from ghidra.console.interface import IfaceParseError
                raise IfaceParseError(f"Unable to open script file: {filename_or_stream}") from exc
        else:
            new_stream = filename_or_stream

        self._inputstack.append(self._sptr)
        self._sptr = new_stream
        super().pushScript(filename_or_stream, newprompt)

    def popScript(self) -> None:
        """Pop the current script stream and return to the previous one."""
        if self._inputstack:
            if self._sptr is not sys.stdin:
                try:
                    self._sptr.close()
                except Exception:
                    pass
            self._sptr = self._inputstack.pop()
        super().popScript()

    def isStreamFinished(self) -> bool:
        """Return True if the current stream is finished."""
        if self.done or self.inerror:
            return True
        if hasattr(self._sptr, 'closed') and self._sptr.closed:
            return True
        # For non-terminal file-like objects, peek to detect EOF
        if not self._is_terminal and hasattr(self._sptr, 'read'):
            pos = self._sptr.tell()
            ch = self._sptr.read(1)
            if not ch:
                return True
            self._sptr.seek(pos)
        return False

    def mainloop(self) -> None:
        """Run the main command loop until done or stream is exhausted."""
        while not self.isStreamFinished():
            try:
                success = self.runCommand()
                if not success and self.isStreamFinished():
                    break
            except KeyboardInterrupt:
                self.optr.write("\n")
                break
            except Exception as exc:
                self.optr.write(f"ERROR: {exc}\n")
                self.evaluateError()
                if self.inerror and self.getNumInputStreamSize() > 0:
                    self.popScript()
