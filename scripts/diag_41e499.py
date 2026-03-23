"""Debug why 0x41e499 RETURN diff is not expected."""
import sys
sys.path.insert(0, 'python')
sys.path.insert(0, '.')
from tests.test_cpexe_comparison import load_pe, run_heritage_comparison
from ghidra.sleigh.decompiler_native import DecompilerNative
from ghidra.sleigh.bridge_validator import (
    _snapshot_from_cpp_dict, _snapshot_from_python_fd,
    _compare_snapshots, _is_expected_varnode_diff, NVarnode, NOp
)
from ghidra.core.opcodes import OpCode

pe = load_pe('bin/cp.exe')
dn = DecompilerNative()
dn.add_spec_path('specs')
dn.initialize()

# Simulate the exact comparison
cpp_op = NOp(
    opcode=OpCode.CPUI_RETURN.value,
    addr=0x41e4d4,
    seq_order=0,
    output=None,
    inputs=[NVarnode("const", 0x1, 4)]
)
py_op = NOp(
    opcode=OpCode.CPUI_RETURN.value,
    addr=0x41e4d4,
    seq_order=0,
    output=None,
    inputs=[
        NVarnode("const", 0x17a, 4),
        NVarnode("register", 0x0, 4),
        NVarnode("register", 0x8, 4),
    ]
)

print(f"cpp_op.opcode={cpp_op.opcode} py_op.opcode={py_op.opcode}")
print(f"OpCode.CPUI_RETURN.value={OpCode.CPUI_RETURN.value}")
print(f"opcode match: {cpp_op.opcode == py_op.opcode == OpCode.CPUI_RETURN.value}")
print(f"cpp inputs: {len(cpp_op.inputs)} py inputs: {len(py_op.inputs)}")
print(f"cpp[0].space={cpp_op.inputs[0].space} py[0].space={py_op.inputs[0].space}")
print(f"cpp[0].size={cpp_op.inputs[0].size} py[0].size={py_op.inputs[0].size}")
print(f"all register: {all(i.space == 'register' for i in py_op.inputs[1:])}")

result = _is_expected_varnode_diff(cpp_op, py_op)
print(f"\n_is_expected_varnode_diff result: {result}")

# Also check matches
print(f"matches: {cpp_op.matches(py_op, strict=False)}")
