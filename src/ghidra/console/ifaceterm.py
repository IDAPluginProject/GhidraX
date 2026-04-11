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
        self._eofstack: List[bool] = []
        self._is_terminal: bool = hasattr(istream, 'isatty') and istream.isatty()
        self._stream_eof = False

        if self._is_terminal:
            try:
                import readline  # noqa: F401 — enable line editing on stdin
            except ImportError:
                pass

    def __del__(self) -> None:
        while self._inputstack:
            self._close_stream(self._sptr)
            self._sptr = self._inputstack.pop()
            self._stream_eof = self._eofstack.pop()

    @staticmethod
    def _close_stream(stream: TextIO) -> None:
        if stream is sys.stdin:
            return
        try:
            stream.close()
        except Exception:
            pass

    def _read_char(self) -> str:
        if self._is_terminal and self._sptr is sys.stdin:
            try:
                import msvcrt

                value = msvcrt.getwch()
                if value in ("\x00", "\xe0"):
                    return value + msvcrt.getwch()
                return value
            except ImportError:
                pass

        value = self._sptr.read(1)
        if value == "":
            self._stream_eof = True
            return "\n"
        return value

    def doCompletion(self, line: str, cursor: int) -> tuple[str, int]:
        """Expand the current command line in the same manner as native IfaceTerm."""

        def _maxmatch(op1: str, op2: str) -> tuple[str, bool]:
            prefix: List[str] = []
            for a, b in zip(op1, op2):
                if a == b:
                    prefix.append(a)
                else:
                    return "".join(prefix), False
            return "".join(prefix), True

        self._ensureSorted()
        tokens = line.split()
        expand: List[str] = []
        first = 0
        last = len(self._comlist)
        stream_index = 0
        pos = 0
        res = True

        while True:
            if first == last:
                match = 0
                break

            if first == last - 1:
                command = self._comlist[first]
                if stream_index >= len(tokens):
                    while pos < command.numWords():
                        expand.append(command.getCommandWord(pos))
                        pos += 1
                if command.numWords() == pos:
                    match = 1
                    break

            if not res:
                match = (last - first) if stream_index < len(tokens) else (first - last)
                break

            if stream_index >= len(tokens):
                match = (first - last) if not expand else (last - first)
                break

            expand.append(tokens[stream_index])
            stream_index += 1
            first, last = self._restrictCom(self._comlist, first, last, expand)
            if first == last:
                match = 0
                break

            first_word = self._comlist[first].getCommandWord(pos)
            last_word = self._comlist[last - 1].getCommandWord(pos)
            expand[-1], res = _maxmatch(first_word, last_word)
            pos += 1

        if match == 0:
            self.optr.write("\nInvalid command\n")
            return line, cursor

        completed = self.wordsToString(expand)
        oldsize = len(line)
        if match < 0:
            match = -match
        else:
            completed += " "

        if stream_index < len(tokens):
            completed += tokens[stream_index]
            for token in tokens[stream_index + 1:]:
                completed += f" {token}"

        if oldsize < len(completed):
            return completed, len(completed)

        if match > 1:
            self.optr.write("\n")
            for command in self._comlist[first:last]:
                self.optr.write(f"{command.commandString()}\n")
        else:
            self.optr.write("\nCommand is complete\n")

        return completed, len(completed)

    def readLine(self) -> str:
        """Read the next command line from the current input stream."""
        line = ""
        cursor = 0
        hist = 0
        saveline = ""
        self._stream_eof = False

        while True:
            onecharecho = False
            lastlen = len(line)
            val = self._read_char()

            if val == "\x01":
                cursor = 0
            elif val == "\x02":
                if cursor > 0:
                    cursor -= 1
            elif val == "\x03":
                line = ""
                cursor = 0
                val = "\n"
                onecharecho = True
            elif val == "\x04":
                if cursor < len(line):
                    line = line[:cursor] + line[cursor + 1:]
            elif val == "\x05":
                cursor = len(line)
            elif val == "\x06":
                if cursor < len(line):
                    cursor += 1
            elif val == "\x07":
                pass
            elif val == "\t":
                line, cursor = self.doCompletion(line, cursor)
            elif val in ("\n", "\r"):
                cursor = len(line)
                val = "\n"
                onecharecho = True
            elif val == "\x0b":
                line = line[:cursor]
            elif val == "\x0c":
                pass
            elif val == "\x0e":
                if hist > 0:
                    hist -= 1
                    if hist > 0:
                        line = self.getHistory(hist - 1)
                    else:
                        line = saveline
                    cursor = len(line)
            elif val == "\x10":
                if hist < self.getHistorySize():
                    hist += 1
                    if hist == 1:
                        saveline = line
                    line = self.getHistory(hist - 1)
                    cursor = len(line)
            elif val == "\x12":
                pass
            elif val == "\x15":
                line = line[cursor:]
                cursor = 0
            elif val == "\x1b":
                esc1 = self._read_char()
                esc2 = self._read_char()
                if (esc1, esc2) in (("O", "D"), ("[", "D")):
                    if cursor > 0:
                        cursor -= 1
                elif (esc1, esc2) in (("O", "C"), ("[", "C")):
                    if cursor < len(line):
                        cursor += 1
            elif len(val) == 2 and val[0] in ("\x00", "\xe0"):
                if val[1] == "K" and cursor > 0:
                    cursor -= 1
                elif val[1] == "M" and cursor < len(line):
                    cursor += 1
            elif val in ("\x08", "\x7f"):
                if cursor != 0:
                    cursor -= 1
                    line = line[:cursor] + line[cursor + 1:]
            else:
                line = line[:cursor] + val + line[cursor:]
                cursor += len(val)
                if cursor == len(line):
                    onecharecho = True

            if onecharecho:
                self.optr.write(val)
            else:
                self.optr.write("\r")
                self.writePrompt()
                self.optr.write(line)
                if len(line) < lastlen:
                    self.optr.write(" " * (lastlen - len(line)))
                rewind = max(lastlen, len(line)) - cursor
                if rewind > 0:
                    self.optr.write("\b" * rewind)

            if val == "\n":
                return line

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
        self._eofstack.append(self._stream_eof)
        self._sptr = new_stream
        self._stream_eof = False
        super().pushScript(new_stream, newprompt)

    def popScript(self) -> None:
        """Pop the current script stream and return to the previous one."""
        if self._inputstack:
            self._close_stream(self._sptr)
            self._sptr = self._inputstack.pop()
            self._stream_eof = self._eofstack.pop()
        super().popScript()

    def isStreamFinished(self) -> bool:
        """Return True if the current stream is finished."""
        if self.done or self.inerror:
            return True
        return self._stream_eof

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
