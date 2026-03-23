"""
Real binary decompilation comparison: bin/cp.exe

Compares C++ (DecompilerNative) vs Python (DecompilerPython) output at each
pipeline stage (flow → heritage → full → C code) for every function in cp.exe.

Usage:
    pytest tests/test_cpexe_comparison.py -v --timeout=300
    pytest tests/test_cpexe_comparison.py -k "flow" -v --timeout=300
    pytest tests/test_cpexe_comparison.py -k "0x401080" -v --timeout=300
"""
import os
import sys
import struct
import pytest
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
BIN_PATH = os.path.join(os.path.dirname(__file__), '..', 'bin', 'cp.exe')
SPEC_DIR = os.path.join(os.path.dirname(__file__), '..', 'specs')
SLA_PATH = os.path.join(SPEC_DIR, 'x86.sla')
TARGET = 'x86:LE:32:default'

# ---------------------------------------------------------------------------
# PE loader helper
# ---------------------------------------------------------------------------

@dataclass
class PeInfo:
    """Minimal parsed PE info for decompilation testing."""
    image_base: int
    entry_rva: int
    image: bytes  # Virtual-memory-mapped image (offset 0 = VA 0)
    text_va: int
    text_size: int
    functions: List[int]  # Sorted list of function entry VAs


def load_pe(path: str) -> PeInfo:
    """Load a PE file and map sections into a flat virtual memory image.
    
    Also scans for CALL targets in .text to discover function entry points.
    """
    with open(path, 'rb') as f:
        raw = f.read()

    # Parse DOS header
    assert raw[:2] == b'MZ', "Not a valid PE file"
    pe_offset = struct.unpack_from('<I', raw, 0x3C)[0]
    
    # Parse PE signature + COFF header
    assert raw[pe_offset:pe_offset+4] == b'PE\x00\x00'
    coff_offset = pe_offset + 4
    machine = struct.unpack_from('<H', raw, coff_offset)[0]
    num_sections = struct.unpack_from('<H', raw, coff_offset + 2)[0]
    optional_hdr_size = struct.unpack_from('<H', raw, coff_offset + 16)[0]
    
    # Parse Optional header
    opt_offset = coff_offset + 20
    magic = struct.unpack_from('<H', raw, opt_offset)[0]
    assert magic == 0x10b, f"Expected PE32, got magic=0x{magic:x}"
    
    entry_rva = struct.unpack_from('<I', raw, opt_offset + 16)[0]
    image_base = struct.unpack_from('<I', raw, opt_offset + 28)[0]
    
    # Parse section headers
    section_offset = opt_offset + optional_hdr_size
    sections = []
    for i in range(num_sections):
        s_off = section_offset + i * 40
        name = raw[s_off:s_off+8].rstrip(b'\x00').decode('ascii', errors='replace')
        virt_size = struct.unpack_from('<I', raw, s_off + 8)[0]
        virt_addr = struct.unpack_from('<I', raw, s_off + 12)[0]
        raw_size = struct.unpack_from('<I', raw, s_off + 16)[0]
        raw_ptr = struct.unpack_from('<I', raw, s_off + 20)[0]
        sections.append({
            'name': name, 'virt_addr': virt_addr, 'virt_size': virt_size,
            'raw_ptr': raw_ptr, 'raw_size': raw_size,
        })
    
    # Build virtual memory image
    max_va = max(s['virt_addr'] + s['virt_size'] for s in sections)
    img = bytearray(max_va)
    
    # Map PE header up to first section
    first_section_va = min(s['virt_addr'] for s in sections)
    hdr_copy = min(len(raw), first_section_va)
    img[:hdr_copy] = raw[:hdr_copy]
    
    # Map sections
    for s in sections:
        if s['raw_size'] > 0 and s['raw_ptr'] < len(raw):
            end = min(s['raw_ptr'] + s['raw_size'], len(raw))
            data = raw[s['raw_ptr']:end]
            img[s['virt_addr']:s['virt_addr']+len(data)] = data
    
    # Find .text section
    text_sec = None
    for s in sections:
        if '.text' in s['name']:
            text_sec = s
            break
    assert text_sec is not None, "No .text section found"
    
    text_va = text_sec['virt_addr']
    text_size = text_sec['virt_size']
    text_data = img[text_va:text_va + text_size]
    
    # Scan for CALL targets (E8 rel32)
    funcs: Set[int] = set()
    funcs.add(image_base + entry_rva)
    
    for i in range(len(text_data) - 5):
        if text_data[i] == 0xE8:  # CALL rel32
            rel = struct.unpack_from('<i', text_data, i + 1)[0]
            target_va = image_base + text_va + i + 5 + rel
            # Only accept targets within .text
            if (image_base + text_va <= target_va < 
                    image_base + text_va + text_size):
                funcs.add(target_va)
    
    return PeInfo(
        image_base=image_base,
        entry_rva=entry_rva,
        image=bytes(img),
        text_va=text_va,
        text_size=text_size,
        functions=sorted(funcs),
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def pe_info():
    """Load cp.exe once per module."""
    if not os.path.isfile(BIN_PATH):
        pytest.skip(f"Binary not found: {BIN_PATH}")
    return load_pe(BIN_PATH)


@pytest.fixture(scope="module")
def cpp_engine():
    """Create and initialize C++ decompiler engine."""
    try:
        from ghidra.sleigh.decompiler_native import DecompilerNative
    except ImportError:
        pytest.skip("decompiler_native.pyd not available")
    dn = DecompilerNative()
    dn.add_spec_path(SPEC_DIR)
    dn.initialize()
    return dn


@pytest.fixture(scope="module")
def py_engine():
    """Create and initialize Python decompiler engine."""
    from ghidra.sleigh.decompiler_python import DecompilerPython
    dp = DecompilerPython()
    dp.add_spec_path(SPEC_DIR)
    dp.initialize()
    return dp


@pytest.fixture(scope="module")
def bridge_validator():
    """Create bridge validator for staged comparison."""
    try:
        from ghidra.sleigh.bridge_validator import BridgeValidator
        bv = BridgeValidator(spec_dir=SPEC_DIR)
        return bv
    except ImportError:
        pytest.skip("bridge_validator not available")


# ---------------------------------------------------------------------------
# Diff summary helpers
# ---------------------------------------------------------------------------

@dataclass
class FuncFlowDiff:
    """Summary of flow-stage differences for a single function."""
    addr: int
    cpp_blocks: int = 0
    py_blocks: int = 0
    cpp_ops: int = 0
    py_ops: int = 0
    block_match: bool = False
    op_match: bool = False
    full_match: bool = False
    expected_only: bool = False  # True if all diffs are expected (fspec etc)
    error: str = ""
    diff_details: List[str] = field(default_factory=list)
    unexpected_count: int = 0
    expected_count: int = 0


def run_flow_comparison(cpp_engine, pe_info: PeInfo, func_addr: int) -> FuncFlowDiff:
    """Run flow-stage comparison for a single function."""
    from ghidra.sleigh.bridge_validator import BridgeValidator, _snapshot_from_cpp_dict, _snapshot_from_python_fd, _compare_snapshots
    from ghidra.sleigh.lifter import Lifter
    from ghidra.sleigh.decompiler_python import _split_basic_blocks

    result = FuncFlowDiff(addr=func_addr)
    
    # C++ flow
    try:
        cpp_result = cpp_engine.decompile_staged(
            SLA_PATH, TARGET, pe_info.image, pe_info.image_base,
            func_addr, 0, 'flow')
        cpp_snap = _snapshot_from_cpp_dict('flow', cpp_result)
        result.cpp_blocks = cpp_snap.num_blocks
        result.cpp_ops = cpp_snap.num_ops
    except Exception as e:
        result.error = f"C++ error: {e}"
        return result
    
    # Python flow
    try:
        context = {"addrsize": 1, "opsize": 1}
        lifter = Lifter(SLA_PATH, context)
        lifter.set_image(pe_info.image_base, pe_info.image)
        func_name = f"func_{func_addr:x}"
        fd = lifter.lift_function(func_name, func_addr, 0)
        _split_basic_blocks(fd, lifter=lifter)
        py_snap = _snapshot_from_python_fd('flow', fd)
        result.py_blocks = py_snap.num_blocks
        result.py_ops = py_snap.num_ops
    except Exception as e:
        result.error = f"Python error: {e}"
        return result
    
    # Compare
    diff = _compare_snapshots(cpp_snap, py_snap, 'flow')
    result.block_match = diff.block_count_match and not diff.block_diffs
    result.op_match = diff.op_count_match and not diff.op_diffs
    result.full_match = diff.is_match
    result.diff_details = diff.block_diffs[:5] + diff.op_diffs[:5]
    # Count unexpected vs expected diffs
    result.unexpected_count = sum(len(v) for v in diff.categorized_diffs.values())
    result.expected_count = sum(len(v) for v in diff.expected_diffs.values())
    result.expected_only = (not diff.is_match and
                            result.unexpected_count == 0 and
                            result.expected_count > 0)
    
    return result


def run_full_comparison(cpp_engine, pe_info: PeInfo, func_addr: int) -> dict:
    """Run full decompile on both engines and compare C code output."""
    result = {
        'addr': func_addr,
        'cpp_code': '',
        'py_code': '',
        'cpp_error': '',
        'py_error': '',
        'match': False,
    }
    
    # C++ full decompile
    try:
        cpp_out = cpp_engine.decompile(
            SLA_PATH, TARGET, pe_info.image, pe_info.image_base,
            func_addr, 0)
        result['cpp_code'] = cpp_out
    except Exception as e:
        result['cpp_error'] = str(e)
    
    # Python full decompile (with all modules enabled)
    try:
        from ghidra.sleigh.decompiler_python import DecompilerPython
        dp = DecompilerPython()
        dp.add_spec_path(SPEC_DIR)
        dp.initialize()
        dp.use_python_full_actions = True
        dp.use_python_printc = True
        py_out = dp.decompile(SLA_PATH, TARGET, pe_info.image,
                              pe_info.image_base, func_addr, 0)
        result['py_code'] = py_out
        result['py_error'] = dp.get_errors()
    except Exception as e:
        result['py_error'] = str(e)
    
    result['match'] = (result['cpp_code'] == result['py_code'] and
                       not result['cpp_error'] and not result['py_error'])
    return result


# ---------------------------------------------------------------------------
# Test: Baseline info
# ---------------------------------------------------------------------------

class TestPeLoading:
    """Verify PE loading infrastructure works correctly."""
    
    def test_pe_loads(self, pe_info):
        assert pe_info.image_base == 0x400000
        assert pe_info.entry_rva == 0x1000
        assert len(pe_info.image) > 0
        assert len(pe_info.functions) > 50  # Should find many functions
    
    def test_text_section(self, pe_info):
        assert pe_info.text_va == 0x1000
        assert pe_info.text_size > 0
    
    def test_entry_in_functions(self, pe_info):
        entry = pe_info.image_base + pe_info.entry_rva
        assert entry in pe_info.functions
    
    def test_function_count(self, pe_info):
        print(f"\nDiscovered {len(pe_info.functions)} functions in cp.exe")
        for f in pe_info.functions[:10]:
            print(f"  0x{f:08x}")
        if len(pe_info.functions) > 10:
            print(f"  ... and {len(pe_info.functions) - 10} more")


# ---------------------------------------------------------------------------
# Test: C++ decompiler baseline
# ---------------------------------------------------------------------------

class TestCppBaseline:
    """Verify C++ decompiler works on cp.exe functions."""
    
    def test_entry_point_decompiles(self, cpp_engine, pe_info):
        entry = pe_info.image_base + pe_info.entry_rva
        result = cpp_engine.decompile(
            SLA_PATH, TARGET, pe_info.image, pe_info.image_base, entry, 0)
        assert len(result) > 0
        assert 'func_' in result or 'void' in result or 'int' in result
    
    def test_first_10_functions_decompile(self, cpp_engine, pe_info):
        """Verify C++ can decompile the first 10 functions."""
        success = 0
        errors = []
        for func_addr in pe_info.functions[:10]:
            try:
                result = cpp_engine.decompile(
                    SLA_PATH, TARGET, pe_info.image, pe_info.image_base,
                    func_addr, 0)
                if len(result) > 0:
                    success += 1
            except Exception as e:
                errors.append(f"0x{func_addr:08x}: {e}")
        print(f"\nC++ decompiled {success}/10 functions successfully")
        for e in errors:
            print(f"  ERROR: {e}")
        assert success >= 8, f"Only {success}/10 functions decompiled"


# ---------------------------------------------------------------------------
# Test: Flow stage comparison (parametrized over all functions)
# ---------------------------------------------------------------------------

def _get_function_ids(max_count: int = 0) -> List[int]:
    """Get function addresses for parametrized tests."""
    if not os.path.isfile(BIN_PATH):
        return []
    try:
        info = load_pe(BIN_PATH)
        funcs = info.functions
        if max_count > 0:
            funcs = funcs[:max_count]
        return funcs
    except Exception:
        return []


# Get all function addresses for parametrization
ALL_FUNCTIONS = _get_function_ids()
FIRST_20_FUNCTIONS = _get_function_ids(20)


class TestFlowStageComparison:
    """Compare flow stage (basic blocks) between C++ and Python for cp.exe functions."""
    
    @pytest.mark.parametrize("func_addr", FIRST_20_FUNCTIONS,
                             ids=[f"0x{a:08x}" for a in FIRST_20_FUNCTIONS])
    def test_flow_first_20(self, cpp_engine, pe_info, func_addr):
        """Flow stage comparison for first 20 functions."""
        result = run_flow_comparison(cpp_engine, pe_info, func_addr)
        if result.error:
            pytest.skip(result.error)
        
        msg = (f"func 0x{func_addr:08x}: "
               f"C++ {result.cpp_blocks}blk/{result.cpp_ops}ops, "
               f"Python {result.py_blocks}blk/{result.py_ops}ops")
        if not result.full_match:
            details = "; ".join(result.diff_details[:3])
            msg += f" | diffs: {details}"
        
        # Report but don't fail yet - we're gathering baseline data
        print(f"\n{msg}")
        # Uncomment below to enforce matching:
        # assert result.full_match, msg


class TestFlowStageReport:
    """Generate aggregate flow-stage comparison report across all functions."""
    
    def test_flow_report_all(self, cpp_engine, pe_info):
        """Run flow comparison on all functions and generate summary report."""
        total = len(pe_info.functions)
        match_count = 0
        expected_only_count = 0
        block_match_count = 0
        op_match_count = 0
        error_count = 0
        unexpected_diff_count = 0
        diffs: List[FuncFlowDiff] = []
        
        for func_addr in pe_info.functions:
            result = run_flow_comparison(cpp_engine, pe_info, func_addr)
            diffs.append(result)
            
            if result.error:
                error_count += 1
                continue
            if result.full_match:
                match_count += 1
            elif result.expected_only:
                expected_only_count += 1
            else:
                unexpected_diff_count += 1
            if result.block_match:
                block_match_count += 1
            if result.op_match:
                op_match_count += 1
        
        effective_match = match_count + expected_only_count
        
        # Print summary
        print(f"\n{'='*60}")
        print("Flow Stage Comparison Report: cp.exe")
        print(f"{'='*60}")
        print(f"Total functions:       {total}")
        print(f"Full match:            {match_count}/{total} ({100*match_count/total:.1f}%)")
        print(f"Expected-only diff:    {expected_only_count}/{total} ({100*expected_only_count/total:.1f}%)")
        print(f"Effective match:       {effective_match}/{total} ({100*effective_match/total:.1f}%)")
        print(f"Unexpected diff:       {unexpected_diff_count}/{total} ({100*unexpected_diff_count/total:.1f}%)")
        print(f"Block match:           {block_match_count}/{total} ({100*block_match_count/total:.1f}%)")
        print(f"Op match:              {op_match_count}/{total} ({100*op_match_count/total:.1f}%)")
        print(f"Errors:                {error_count}/{total}")
        
        # Show unexpected mismatches
        unexpected = [d for d in diffs if not d.full_match and not d.expected_only and not d.error]
        if unexpected:
            print(f"\nUnexpected mismatches ({len(unexpected)}):")
            for d in unexpected[:15]:
                print(f"  0x{d.addr:08x}: C++={d.cpp_blocks}blk/{d.cpp_ops}ops "
                      f"Py={d.py_blocks}blk/{d.py_ops}ops "
                      f"unexpected={d.unexpected_count} expected={d.expected_count}")
                for detail in d.diff_details[:2]:
                    print(f"    {detail}")
        
        # Show errors
        error_funcs = [d for d in diffs if d.error]
        if error_funcs:
            print(f"\nFunctions with errors ({len(error_funcs)}):")
            for d in error_funcs[:10]:
                print(f"  0x{d.addr:08x}: {d.error}")
        
        print(f"\n{'='*60}")
        
        # Store report for inspection
        report_path = os.path.join(os.path.dirname(__file__), '..', 
                                    'flow_comparison_report.txt')
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("Flow Stage Comparison Report: cp.exe\n")
            f.write(f"Total: {total}, Match: {match_count}, "
                    f"Expected-only: {expected_only_count}, "
                    f"Effective: {effective_match}, "
                    f"Unexpected: {unexpected_diff_count}, "
                    f"Errors: {error_count}\n\n")
            for d in diffs:
                if d.full_match:
                    status = "MATCH"
                elif d.error:
                    status = "ERROR"
                elif d.expected_only:
                    status = "EXPECTED"
                else:
                    status = "DIFF"
                f.write(f"0x{d.addr:08x} [{status}] "
                        f"C++={d.cpp_blocks}blk/{d.cpp_ops}ops "
                        f"Py={d.py_blocks}blk/{d.py_ops}ops")
                if d.error:
                    f.write(f" | {d.error}")
                elif not d.full_match:
                    f.write(f" | unexpected={d.unexpected_count} expected={d.expected_count}")
                f.write("\n")
                for detail in d.diff_details:
                    f.write(f"  {detail}\n")
        
        print(f"Report written to: {report_path}")


# ---------------------------------------------------------------------------
# Heritage stage comparison
# ---------------------------------------------------------------------------

@dataclass
class FuncHeritageDiff:
    """Summary of heritage-stage differences for a single function."""
    addr: int
    cpp_blocks: int = 0
    py_blocks: int = 0
    cpp_ops: int = 0
    py_ops: int = 0
    block_match: bool = False
    op_match: bool = False
    full_match: bool = False
    expected_only: bool = False
    error: str = ""
    diff_details: List[str] = field(default_factory=list)
    unexpected_count: int = 0
    expected_count: int = 0


def run_heritage_comparison(cpp_engine, pe_info: PeInfo, func_addr: int) -> FuncHeritageDiff:
    """Run heritage-stage comparison for a single function."""
    from ghidra.sleigh.bridge_validator import (
        _snapshot_from_cpp_dict, _snapshot_from_python_fd, _compare_snapshots
    )
    from ghidra.sleigh.lifter import Lifter
    from ghidra.sleigh.decompiler_python import (
        _split_basic_blocks, _setup_call_specs, _inject_tracked_context,
        _run_prerequisite_actions, _ArchitectureShim,
    )

    result = FuncHeritageDiff(addr=func_addr)

    # C++ heritage
    try:
        cpp_result = cpp_engine.decompile_staged(
            SLA_PATH, TARGET, pe_info.image, pe_info.image_base,
            func_addr, 0, 'heritage')
        cpp_snap = _snapshot_from_cpp_dict('heritage', cpp_result)
        result.cpp_blocks = cpp_snap.num_blocks
        result.cpp_ops = cpp_snap.num_ops
    except Exception as e:
        result.error = f"C++ error: {e}"
        return result

    # Python heritage
    try:
        context = {"addrsize": 1, "opsize": 1}
        lifter = Lifter(SLA_PATH, context)
        lifter.set_image(pe_info.image_base, pe_info.image)
        func_name = f"func_{func_addr:x}"
        fd = lifter.lift_function(func_name, func_addr, 0)
        _split_basic_blocks(fd, lifter=lifter)
        arch_shim = _ArchitectureShim(lifter._spc_mgr)
        fd.setArch(arch_shim)
        _inject_tracked_context(fd, lifter)
        _setup_call_specs(fd, lifter)
        _run_prerequisite_actions(fd)
        fd.opHeritage()
        py_snap = _snapshot_from_python_fd('heritage', fd)
        result.py_blocks = py_snap.num_blocks
        result.py_ops = py_snap.num_ops
    except Exception as e:
        result.error = f"Python error: {e}"
        return result

    # Compare
    diff = _compare_snapshots(cpp_snap, py_snap, 'heritage')
    result.block_match = diff.block_count_match and not diff.block_diffs
    result.op_match = diff.op_count_match and not diff.op_diffs
    result.full_match = diff.is_match
    result.diff_details = diff.block_diffs[:5] + diff.op_diffs[:5]
    result.unexpected_count = sum(len(v) for v in diff.categorized_diffs.values())
    result.expected_count = sum(len(v) for v in diff.expected_diffs.values())
    result.expected_only = (not diff.is_match and
                            result.unexpected_count == 0 and
                            result.expected_count > 0)

    return result


class TestHeritageStageReport:
    """Generate aggregate heritage-stage comparison report across all functions."""

    def test_heritage_report_all(self, cpp_engine, pe_info):
        """Run heritage comparison on all functions and generate summary report."""
        total = len(pe_info.functions)
        match_count = 0
        expected_only_count = 0
        block_match_count = 0
        op_match_count = 0
        error_count = 0
        unexpected_diff_count = 0
        diffs: List[FuncHeritageDiff] = []

        for func_addr in pe_info.functions:
            result = run_heritage_comparison(cpp_engine, pe_info, func_addr)
            diffs.append(result)

            if result.error:
                error_count += 1
                continue
            if result.full_match:
                match_count += 1
            elif result.expected_only:
                expected_only_count += 1
            else:
                unexpected_diff_count += 1
            if result.block_match:
                block_match_count += 1
            if result.op_match:
                op_match_count += 1

        effective_match = match_count + expected_only_count

        # Print summary
        print(f"\n{'='*60}")
        print("Heritage Stage Comparison Report: cp.exe")
        print(f"{'='*60}")
        print(f"Total functions:       {total}")
        print(f"Full match:            {match_count}/{total} ({100*match_count/total:.1f}%)")
        print(f"Expected-only diff:    {expected_only_count}/{total} ({100*expected_only_count/total:.1f}%)")
        print(f"Effective match:       {effective_match}/{total} ({100*effective_match/total:.1f}%)")
        print(f"Unexpected diff:       {unexpected_diff_count}/{total} ({100*unexpected_diff_count/total:.1f}%)")
        print(f"Block match:           {block_match_count}/{total} ({100*block_match_count/total:.1f}%)")
        print(f"Op match:              {op_match_count}/{total} ({100*op_match_count/total:.1f}%)")
        print(f"Errors:                {error_count}/{total}")

        # Show unexpected mismatches (sample)
        unexpected = [d for d in diffs if not d.full_match and not d.expected_only and not d.error]
        if unexpected:
            print(f"\nUnexpected mismatches ({len(unexpected)}):")
            for d in unexpected[:15]:
                print(f"  0x{d.addr:08x}: C++={d.cpp_blocks}blk/{d.cpp_ops}ops "
                      f"Py={d.py_blocks}blk/{d.py_ops}ops "
                      f"unexpected={d.unexpected_count} expected={d.expected_count}")
                for detail in d.diff_details[:2]:
                    print(f"    {detail}")

        # Show errors
        error_funcs = [d for d in diffs if d.error]
        if error_funcs:
            print(f"\nFunctions with errors ({len(error_funcs)}):")
            for d in error_funcs[:10]:
                print(f"  0x{d.addr:08x}: {d.error}")

        print(f"\n{'='*60}")

        # Store report
        report_path = os.path.join(os.path.dirname(__file__), '..',
                                    'heritage_comparison_report.txt')
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("Heritage Stage Comparison Report: cp.exe\n")
            f.write(f"Total: {total}, Match: {match_count}, "
                    f"Expected-only: {expected_only_count}, "
                    f"Effective: {effective_match}, "
                    f"Unexpected: {unexpected_diff_count}, "
                    f"Errors: {error_count}\n\n")
            for d in diffs:
                if d.full_match:
                    status = "MATCH"
                elif d.error:
                    status = "ERROR"
                elif d.expected_only:
                    status = "EXPECTED"
                else:
                    status = "DIFF"
                f.write(f"0x{d.addr:08x} [{status}] "
                        f"C++={d.cpp_blocks}blk/{d.cpp_ops}ops "
                        f"Py={d.py_blocks}blk/{d.py_ops}ops")
                if d.error:
                    f.write(f" | {d.error}")
                elif not d.full_match:
                    f.write(f" | unexpected={d.unexpected_count} expected={d.expected_count}")
                f.write("\n")
                for detail in d.diff_details:
                    f.write(f"  {detail}\n")

        print(f"Report written to: {report_path}")


# ---------------------------------------------------------------------------
# Test: Full C code comparison (small set first)
# ---------------------------------------------------------------------------

class TestFullCodeComparison:
    """Compare final C code output between C++ and Python."""
    
    @pytest.mark.parametrize("func_addr", FIRST_20_FUNCTIONS[:5],
                             ids=[f"0x{a:08x}" for a in FIRST_20_FUNCTIONS[:5]])
    def test_full_code_first_5(self, cpp_engine, pe_info, func_addr):
        """Full decompile comparison for first 5 functions."""
        result = run_full_comparison(cpp_engine, pe_info, func_addr)
        
        print(f"\nfunc 0x{func_addr:08x}:")
        print(f"  C++ code length: {len(result['cpp_code'])}")
        print(f"  Python code length: {len(result['py_code'])}")
        print(f"  Match: {result['match']}")
        if result['cpp_error']:
            print(f"  C++ error: {result['cpp_error'][:200]}")
        if result['py_error']:
            print(f"  Python error: {result['py_error'][:200]}")
        if not result['match']:
            print(f"  C++ output:\n{result['cpp_code'][:300]}")
            print(f"  Python output:\n{result['py_code'][:300]}")
