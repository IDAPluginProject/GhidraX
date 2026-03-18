"""Tests for ghidra.console.ifaceterm — Python port of ifaceterm.cc."""
from __future__ import annotations

import io
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

from ghidra.console.ifaceterm import IfaceTerm
from ghidra.console.interface import (
    IfaceBaseCommand, IfaceParseError, IfcQuit, IfcEcho,
)


class _CountCmd(IfaceBaseCommand):
    count = 0

    def execute(self, args: str) -> None:
        _CountCmd.count += 1

    def getModule(self) -> str:
        return "test"


class TestIfaceTermBasics:
    def test_construct_from_stringio(self):
        inp = io.StringIO("quit\n")
        out = io.StringIO()
        t = IfaceTerm("> ", inp, out)
        assert t.done is False
        assert t.inerror is False

    def test_readline_from_stringio(self):
        inp = io.StringIO("hello world\n")
        out = io.StringIO()
        t = IfaceTerm("> ", inp, out)
        line = t.readLine()
        assert line == "hello world"

    def test_readline_eof(self):
        inp = io.StringIO("")
        out = io.StringIO()
        t = IfaceTerm("> ", inp, out)
        line = t.readLine()
        assert line == ""

    def test_is_stream_finished_initially_false(self):
        inp = io.StringIO("something\n")
        out = io.StringIO()
        t = IfaceTerm("> ", inp, out)
        assert t.isStreamFinished() is False

    def test_is_stream_finished_when_done(self):
        inp = io.StringIO("")
        out = io.StringIO()
        t = IfaceTerm("> ", inp, out)
        t.done = True
        assert t.isStreamFinished() is True

    def test_is_stream_finished_when_error(self):
        inp = io.StringIO("")
        out = io.StringIO()
        t = IfaceTerm("> ", inp, out)
        t.inerror = True
        assert t.isStreamFinished() is True


class TestRunCommands:
    def test_run_quit(self):
        inp = io.StringIO("quit\n")
        out = io.StringIO()
        t = IfaceTerm("> ", inp, out)
        t.registerCom(IfcQuit(), "quit")
        t.runCommand()
        assert t.done is True

    def test_run_echo(self):
        inp = io.StringIO("echo hello world\n")
        out = io.StringIO()
        t = IfaceTerm("> ", inp, out)
        t.registerCom(IfcEcho(), "echo")
        t.runCommand()
        assert "hello world" in out.getvalue()

    def test_run_multiple_commands(self):
        _CountCmd.count = 0
        inp = io.StringIO("count\ncount\ncount\n")
        out = io.StringIO()
        t = IfaceTerm("> ", inp, out)
        t.registerCom(_CountCmd(), "count")
        t.runCommand()
        t.runCommand()
        t.runCommand()
        assert _CountCmd.count == 3


class TestScriptStack:
    def test_push_script_stream(self):
        main_in = io.StringIO("")
        out = io.StringIO()
        t = IfaceTerm("> ", main_in, out)

        script = io.StringIO("echo from script\n")
        t.registerCom(IfcEcho(), "echo")
        t.pushScript(script, "script> ")
        assert t.getPrompt() == "script> "
        assert t.getNumInputStreamSize() == 1

        line = t.readLine()
        assert line == "echo from script"

    def test_push_script_file(self, tmp_path):
        script_file = tmp_path / "test_script.txt"
        script_file.write_text("echo scripted\n")

        main_in = io.StringIO("")
        out = io.StringIO()
        t = IfaceTerm("> ", main_in, out)
        t.registerCom(IfcEcho(), "echo")
        t.pushScript(str(script_file), "script> ")

        line = t.readLine()
        assert line == "echo scripted"

    def test_push_script_nonexistent_file(self):
        main_in = io.StringIO("")
        out = io.StringIO()
        t = IfaceTerm("> ", main_in, out)
        with pytest.raises(IfaceParseError):
            t.pushScript("/nonexistent/file/xyz.txt", "script> ")

    def test_pop_script(self):
        main_in = io.StringIO("echo main\n")
        out = io.StringIO()
        t = IfaceTerm("> ", main_in, out)

        script = io.StringIO("echo script\n")
        t.pushScript(script, "script> ")
        t.popScript()
        assert t.getPrompt() == "> "
        assert t.getNumInputStreamSize() == 0

        line = t.readLine()
        assert line == "echo main"


class TestMainloop:
    def test_mainloop_runs_to_quit(self):
        inp = io.StringIO("quit\n")
        out = io.StringIO()
        t = IfaceTerm("> ", inp, out)
        t.registerCom(IfcQuit(), "quit")
        t.mainloop()
        assert t.done is True

    def test_mainloop_processes_multiple(self):
        _CountCmd.count = 0
        inp = io.StringIO("count\ncount\nquit\n")
        out = io.StringIO()
        t = IfaceTerm("> ", inp, out)
        t.registerCom(_CountCmd(), "count")
        t.registerCom(IfcQuit(), "quit")
        t.mainloop()
        assert _CountCmd.count == 2
        assert t.done is True

    def test_mainloop_handles_empty_stream(self):
        inp = io.StringIO("")
        out = io.StringIO()
        t = IfaceTerm("> ", inp, out)
        t.mainloop()  # Should not hang


class TestNonTerminalFlag:
    def test_stringio_not_terminal(self):
        inp = io.StringIO("")
        out = io.StringIO()
        t = IfaceTerm("> ", inp, out)
        assert t._is_terminal is False


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
