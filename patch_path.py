import re, sys
p = sys.argv[1]
with open(p, 'r', encoding='utf-8') as f:
    c = f.read()
new_line = 'PYGHIDRA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pyghidra")'
c = re.sub(r'^PYGHIDRA_PATH\s*=.*$', new_line, c, flags=re.MULTILINE)
with open(p, 'w', encoding='utf-8') as f:
    f.write(c)
print('Patched OK')
