"""Extract C++ public methods from .hh and compare with Python .py"""
import re

SKIP_NAMES = {
    'if', 'for', 'while', 'switch', 'return', 'class', 'struct',
    'void', 'int', 'bool', 'uint4', 'int4', 'uintb', 'intb', 'int2', 'uint2',
    'string', 'vector', 'list', 'map', 'set', 'pair', 'mutable',
    'const_iterator', 'iterator', 'size_t', 'size', 'const', 'static',
    'virtual', 'inline', 'explicit', 'union', 'enum', 'typedef', 'friend',
    'Address', 'Varnode', 'PcodeOp', 'BlockBasic', 'JumpTable', 'FlowBlock',
    'Heritage', 'Merge', 'Override', 'Datatype', 'FuncProto', 'ScopeLocal',
    'Symbol', 'SymbolEntry', 'HighVariable', 'BlockGraph', 'AddrSpace',
    'Architecture', 'Scope', 'VarnodeBank', 'PcodeOpBank', 'Encoder',
    'Decoder', 'FlowInfo', 'ResolvedUnion', 'ParamTrial', 'LoadGuard',
    'OpCode', 'SeqNum', 'VarnodeData', 'FuncCallSpecs', 'Cover',
    'AddrSpaceManager', 'VarnodeLocSet', 'VarnodeDefSet', 'ValueSet',
    'RecoveryMode', 'Funcdata',
}

def extract_cpp_public_methods(filepath, classname):
    """Extract public method names from a C++ class in a header file."""
    with open(filepath, encoding='utf-8') as f:
        content = f.read()
    pattern = r'(?:class|struct)\s+' + classname + r'\b[^;]*?\{'
    class_match = re.search(pattern, content)
    if not class_match:
        print(f"  WARNING: class {classname} not found in {filepath}")
        return set()
    is_struct = class_match.group().strip().startswith('struct')
    start = class_match.end()
    depth = 1
    pos = start
    while pos < len(content) and depth > 0:
        if content[pos] == '{': depth += 1
        elif content[pos] == '}': depth -= 1
        pos += 1
    class_body = content[start:pos-1]
    lines = class_body.split('\n')
    in_public = is_struct  # structs are public by default
    methods = set()
    for line in lines:
        stripped = line.strip()
        if stripped == 'public:': in_public = True; continue
        if stripped in ('private:', 'protected:'): in_public = False; continue
        if not in_public: continue
        if stripped.startswith('//') or stripped.startswith('*') or stripped.startswith('#'): continue
        if stripped.startswith('friend ') or stripped.startswith('typedef '): continue
        if stripped.startswith('enum ') and '{' in stripped: continue
        # find method name before '('
        m = re.search(r'\b([a-zA-Z_]\w*)\s*\(', stripped)
        if m:
            name = m.group(1)
            if name not in SKIP_NAMES and not name.startswith('~'):
                methods.add(name)
    return methods

def extract_py_methods(filepath, classname):
    """Extract method names from a Python class."""
    import ast
    with open(filepath, encoding='utf-8') as f:
        tree = ast.parse(f.read())
    methods = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == classname:
            for item in node.body:
                if isinstance(item, ast.FunctionDef):
                    methods.add(item.name)
    return methods

import sys
hh_file = sys.argv[1] if len(sys.argv) > 1 else r'd:\BIGAI\pyghidra\cpp\varnode.hh'
py_file = sys.argv[2] if len(sys.argv) > 2 else r'd:\BIGAI\pyghidra\python\ghidra\ir\varnode.py'
classname = sys.argv[3] if len(sys.argv) > 3 else 'Varnode'

print(f"=== Checking {classname} ===")
cpp_methods = extract_cpp_public_methods(hh_file, classname)
py_methods = extract_py_methods(py_file, classname)
missing = sorted(cpp_methods - py_methods)
extra = sorted(py_methods - cpp_methods)

print(f"C++ public methods: {len(cpp_methods)}")
print(f"Python methods: {len(py_methods)}")
print(f"Missing in Python: {len(missing)}")
for m in missing:
    print(f"  - {m}")
print(f"Extra in Python (not in C++): {len(extra)}")
for m in extra:
    print(f"  + {m}")
