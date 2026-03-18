"""Tests for ghidra.console.interface — Python port of interface.cc."""
from __future__ import annotations

import io
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

from ghidra.console.interface import (
    IfaceError, IfaceParseError, IfaceExecutionError,
    IfaceData, IfaceCommand, IfaceCommandDummy, IfaceCapability,
    IfaceStatus, IfaceBaseCommand,
    IfcQuit, IfcHistory, IfcOpenfile, IfcOpenfileAppend, IfcClosefile, IfcEcho,
    _CmdKey,
)


# ── Concrete IfaceStatus for testing ──────────────────────────────────────

class _TestStatus(IfaceStatus):
    """Minimal concrete IfaceStatus feeding lines from a list."""

    def __init__(self, lines=None, prompt="> ", optr=None):
        out = optr or io.StringIO()
        super().__init__(prompt, out)
        self._lines = list(lines or [])
        self._pos = 0

    def readLine(self) -> str:
        if self._pos < len(self._lines):
            line = self._lines[self._pos]
            self._pos += 1
            return line
        return ""

    def isStreamFinished(self) -> bool:
        return self._pos >= len(self._lines)


# ── Simple test command ───────────────────────────────────────────────────

class _TestCmd(IfaceBaseCommand):
    """A test command that records its execution."""
    executed: list = []

    def execute(self, args: str) -> None:
        _TestCmd.executed.append(args)

    def getModule(self) -> str:
        return "test"


# ── Exception tests ──────────────────────────────────────────────────────

class TestExceptions:
    def test_iface_error(self):
        with pytest.raises(IfaceError):
            raise IfaceError("test")

    def test_parse_error_is_iface_error(self):
        assert issubclass(IfaceParseError, IfaceError)

    def test_execution_error_is_iface_error(self):
        assert issubclass(IfaceExecutionError, IfaceError)


# ── IfaceCommand tests ───────────────────────────────────────────────────

class TestIfaceCommand:
    def test_add_word(self):
        cmd = IfaceCommandDummy()
        cmd.addWord("hello")
        assert cmd.numWords() == 1
        assert cmd.getCommandWord(0) == "hello"

    def test_add_words(self):
        cmd = IfaceCommandDummy()
        cmd.addWords(["a", "b", "c"])
        assert cmd.numWords() == 3

    def test_remove_word(self):
        cmd = IfaceCommandDummy()
        cmd.addWords(["a", "b"])
        cmd.removeWord()
        assert cmd.numWords() == 1

    def test_command_string(self):
        cmd = IfaceCommandDummy()
        cmd.addWords(["load", "file"])
        assert cmd.commandString() == "load file"

    def test_compare_equal(self):
        a = IfaceCommandDummy()
        a.addWords(["load", "file"])
        b = IfaceCommandDummy()
        b.addWords(["load", "file"])
        assert a.compare(b) == 0

    def test_compare_less(self):
        a = IfaceCommandDummy()
        a.addWord("aaa")
        b = IfaceCommandDummy()
        b.addWord("bbb")
        assert a.compare(b) < 0

    def test_compare_greater(self):
        a = IfaceCommandDummy()
        a.addWord("zzz")
        b = IfaceCommandDummy()
        b.addWord("aaa")
        assert a.compare(b) > 0

    def test_compare_prefix(self):
        a = IfaceCommandDummy()
        a.addWord("load")
        b = IfaceCommandDummy()
        b.addWords(["load", "file"])
        assert a.compare(b) < 0


# ── IfaceData tests ──────────────────────────────────────────────────────

class TestIfaceData:
    def test_create(self):
        d = IfaceData()
        assert d is not None


# ── IfaceStatus tests ────────────────────────────────────────────────────

class TestIfaceStatus:
    def test_construction(self):
        s = _TestStatus(prompt="test> ")
        assert s.getPrompt() == "test> "
        assert s.done is False
        assert s.inerror is False

    def test_history(self):
        s = _TestStatus()
        s._saveHistory("line1")
        s._saveHistory("line2")
        assert s.getHistorySize() == 2
        assert s.getHistory(0) == "line2"
        assert s.getHistory(1) == "line1"

    def test_history_circular(self):
        s = _TestStatus()
        s._maxhistory = 3
        for i in range(5):
            s._saveHistory(f"line{i}")
        assert s.getHistorySize() == 3
        assert s.getHistory(0) == "line4"

    def test_history_out_of_range(self):
        s = _TestStatus()
        assert s.getHistory(100) == ""

    def test_push_pop_script(self):
        s = _TestStatus(prompt="base> ")
        s.pushScript("dummy", "script> ")
        assert s.getPrompt() == "script> "
        assert s.getNumInputStreamSize() == 1
        s.popScript()
        assert s.getPrompt() == "base> "
        assert s.getNumInputStreamSize() == 0

    def test_reset(self):
        s = _TestStatus(prompt="base> ")
        s.pushScript("d1", "s1> ")
        s.pushScript("d2", "s2> ")
        s.done = True
        s.reset()
        assert s.getPrompt() == "base> "
        assert s.done is False

    def test_write_prompt(self):
        out = io.StringIO()
        s = _TestStatus(prompt=">>> ", optr=out)
        s.writePrompt()
        assert out.getvalue() == ">>> "

    def test_register_com(self):
        s = _TestStatus()
        cmd = _TestCmd()
        s.registerCom(cmd, "test", "run")
        assert cmd.numWords() == 2
        assert s.getData("test") is None  # _TestCmd.createData returns None

    def test_words_to_string(self):
        assert IfaceStatus.wordsToString(["a", "b", "c"]) == "a b c"

    def test_error_is_done(self):
        s = _TestStatus()
        s.setErrorIsDone(True)
        out = s.optr
        s.evaluateError()
        assert s.done is True
        assert s.inerror is True

    def test_evaluate_error_with_scripts(self):
        s = _TestStatus(prompt="base> ")
        s.pushScript("d", "script> ")
        # pushScript sets errorisdone=True, so evaluateError aborts
        s.evaluateError()
        assert s.inerror is True
        assert s.done is True  # errorisdone causes full abort

    def test_evaluate_error_with_scripts_no_abort(self):
        s = _TestStatus(prompt="base> ")
        s.pushScript("d", "script> ")
        s._errorisdone = False  # Override the default script behavior
        s.evaluateError()
        assert s.inerror is True
        assert s.done is False

    def test_evaluate_error_no_scripts(self):
        s = _TestStatus()
        s.evaluateError()
        assert s.inerror is False


class TestRunCommand:
    def test_run_simple_command(self):
        _TestCmd.executed = []
        s = _TestStatus(lines=["test run"])
        cmd = _TestCmd()
        s.registerCom(cmd, "test", "run")
        result = s.runCommand()
        assert result is True
        assert len(_TestCmd.executed) == 1

    def test_run_empty_line(self):
        s = _TestStatus(lines=[""])
        result = s.runCommand()
        assert result is False

    def test_run_invalid_command(self):
        s = _TestStatus(lines=["nonexistent"])
        cmd = _TestCmd()
        s.registerCom(cmd, "test", "run")
        result = s.runCommand()
        assert result is False


# ── Built-in command tests ────────────────────────────────────────────────

class TestIfcQuit:
    def test_quit_sets_done(self):
        s = _TestStatus(lines=["quit"])
        cmd = IfcQuit()
        s.registerCom(cmd, "quit")
        s.runCommand()
        assert s.done is True

    def test_quit_with_args_raises(self):
        cmd = IfcQuit()
        cmd.status = _TestStatus()
        with pytest.raises(IfaceParseError):
            cmd.execute("extra")


class TestIfcHistory:
    def test_history_output(self):
        out = io.StringIO()
        s = _TestStatus(lines=["first", "second", "history"], optr=out)
        hist_cmd = IfcHistory()
        s.registerCom(hist_cmd, "history")
        # Run two dummy commands first to build history
        s._saveHistory("first")
        s._saveHistory("second")
        hist_cmd.execute("")
        output = out.getvalue()
        assert "first" in output
        assert "second" in output


class TestIfcEcho:
    def test_echo_output(self):
        out = io.StringIO()
        s = _TestStatus(optr=out)
        cmd = IfcEcho()
        cmd.status = s
        cmd.execute("hello world")
        assert "hello world" in out.getvalue()


class TestIfcOpenClosefile:
    def test_open_no_filename(self):
        cmd = IfcOpenfile()
        cmd.status = _TestStatus()
        with pytest.raises(IfaceParseError):
            cmd.execute("")

    def test_close_no_file(self):
        cmd = IfcClosefile()
        cmd.status = _TestStatus()
        with pytest.raises(IfaceExecutionError):
            cmd.execute("")

    def test_open_and_close(self, tmp_path):
        f = tmp_path / "test_output.txt"
        s = _TestStatus()
        open_cmd = IfcOpenfile()
        open_cmd.status = s
        open_cmd.execute(str(f))
        assert s.optr is not s.fileoptr
        close_cmd = IfcClosefile()
        close_cmd.status = s
        close_cmd.execute("")
        assert s.optr is s.fileoptr

    def test_open_append(self, tmp_path):
        f = tmp_path / "append.txt"
        f.write_text("existing\n")
        s = _TestStatus()
        cmd = IfcOpenfileAppend()
        cmd.status = s
        cmd.execute(str(f))
        s.fileoptr.write("appended\n")
        s.fileoptr.close()
        s.fileoptr = s.optr
        content = f.read_text()
        assert "existing" in content
        assert "appended" in content

    def test_double_open_raises(self, tmp_path):
        f1 = tmp_path / "f1.txt"
        f2 = tmp_path / "f2.txt"
        s = _TestStatus()
        cmd = IfcOpenfile()
        cmd.status = s
        cmd.execute(str(f1))
        cmd2 = IfcOpenfile()
        cmd2.status = s
        with pytest.raises(IfaceExecutionError):
            cmd2.execute(str(f2))
        s.fileoptr.close()
        s.fileoptr = s.optr


# ── IfaceCapability tests ────────────────────────────────────────────────

class _TestCapability(IfaceCapability):
    registered = False

    def registerCommands(self, status: IfaceStatus) -> None:
        _TestCapability.registered = True


class TestIfaceCapability:
    def test_name(self):
        cap = _TestCapability("test_cap")
        assert cap.getName() == "test_cap"

    def test_initialize_and_register(self):
        _TestCapability.registered = False
        cap = _TestCapability("test_cap")
        cap.initialize()
        s = _TestStatus()
        IfaceCapability.registerAllCommands(s)
        assert _TestCapability.registered is True


# ── CmdKey sorting tests ─────────────────────────────────────────────────

class TestCmdKey:
    def test_ordering(self):
        a = IfaceCommandDummy()
        a.addWord("aaa")
        b = IfaceCommandDummy()
        b.addWord("zzz")
        assert _CmdKey(a) < _CmdKey(b)
        assert not (_CmdKey(b) < _CmdKey(a))


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
