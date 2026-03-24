"""
Corresponds to: ghidra_process.cc main()

Main entry point for the Python Ghidra decompiler process.
Reads commands from stdin, dispatches them, and writes results to stdout
using the Ghidra binary protocol.

Usage:
    python -m ghidra.console.consolemain

Or as a drop-in replacement for the Ghidra native decompiler binary.
"""

from __future__ import annotations

import os
import sys


def main() -> None:
    """Main loop — read and dispatch commands until termination.

    C++ ref: ``ghidra_process.cc::main``
    """
    # On Windows, force stdin/stdout to binary mode
    if sys.platform == "win32":
        import msvcrt
        msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)

    sin = sys.stdin.buffer
    sout = sys.stdout.buffer

    # Build the command dispatch map
    from ghidra.console.ghidra_process import build_command_map, read_command
    commandmap = build_command_map(sin, sout)

    status = 0
    while status == 0:
        try:
            status = read_command(sin, sout, commandmap)
        except SystemExit:
            break
        except Exception as e:
            # If something goes very wrong, try to recover
            sys.stderr.write(f"Fatal error in command loop: {e}\n")
            import traceback
            traceback.print_exc(file=sys.stderr)
            break


if __name__ == "__main__":
    main()
