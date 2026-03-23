"""Find stub methods in key Python files."""
import re

files = [
    r'd:\BIGAI\pyghidra\python\ghidra\analysis\funcdata.py',
    r'd:\BIGAI\pyghidra\python\ghidra\arch\architecture.py',
    r'd:\BIGAI\pyghidra\python\ghidra\database\database.py',
]

for path in files:
    with open(path, encoding='utf-8') as f:
        lines = f.readlines()
    
    stubs = []
    for i, line in enumerate(lines):
        if 'def ' in line and i + 1 < len(lines):
            next_line = lines[i + 1].strip()
            if next_line in ('pass', 'return', 'return 0', 'return None', 
                           'raise NotImplementedError', 'raise NotImplementedError()'):
                stubs.append((i + 1, line.strip()))
    
    name = path.split('\\')[-1]
    print(f"\n{name}: {len(stubs)} stubs")
    for ln, m in stubs[:20]:
        print(f"  L{ln}: {m}")
    if len(stubs) > 20:
        print(f"  ... and {len(stubs) - 20} more")
