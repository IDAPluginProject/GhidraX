import os, re

root_dir = r'd:\BIGAI\pyghidra\python\ghidra\transform'
stubs = []
for root2, dirs, files in os.walk(root_dir):
    for f in files:
        if not f.endswith('.py'):
            continue
        path = os.path.join(root2, f)
        with open(path, 'r', encoding='utf-8') as fh:
            lines = fh.readlines()
        for i, line in enumerate(lines):
            if 'def applyOp' in line:
                for j in range(i+1, min(i+6, len(lines))):
                    ns = lines[j].strip()
                    if ns == '' or ns.startswith('#') or ns.startswith('"""'):
                        continue
                    if ns == 'return 0' or re.match(r'^return 0\s+#', ns):
                        stubs.append((f, i+1, ns))
                    break

# Also scan analysis dir
root_dir2 = r'd:\BIGAI\pyghidra\python\ghidra\analysis'
for root2, dirs, files in os.walk(root_dir2):
    for f in files:
        if not f.endswith('.py'):
            continue
        path = os.path.join(root2, f)
        with open(path, 'r', encoding='utf-8') as fh:
            lines = fh.readlines()
        for i, line in enumerate(lines):
            if 'def applyOp' in line or 'def apply(' in line:
                for j in range(i+1, min(i+6, len(lines))):
                    ns = lines[j].strip()
                    if ns == '' or ns.startswith('#') or ns.startswith('"""'):
                        continue
                    if ns == 'return 0' or re.match(r'^return 0\s+#', ns):
                        stubs.append((f, i+1, ns))
                    break

print(f'Found {len(stubs)} shallow applyOp stubs:')
for f, ln, code in stubs:
    print(f'  {f}:{ln}  {code}')
