"""Count rule stubs in ruleaction batch files."""
import re, os

base = r'd:\BIGAI\pyghidra\python\ghidra\transform'
files = sorted(f for f in os.listdir(base) if f.startswith('ruleaction') and f.endswith('.py'))

for fn in files:
    path = os.path.join(base, fn)
    with open(path, encoding='utf-8') as f:
        content = f.read()
    
    # Find all Rule classes
    classes = re.findall(r'class (Rule\w+)\(Rule\)', content)
    stubs = []
    for name in classes:
        idx = content.index('class ' + name)
        # Find the applyOp for this class
        chunk = content[idx:idx+2000]
        m = re.search(r'def applyOp\(self, op, data\):\s*\n(.*?)(?=\n    def |\nclass |\Z)', chunk, re.DOTALL)
        if m:
            body = m.group(1)
            lines = [l.strip() for l in body.split('\n') if l.strip() and not l.strip().startswith('#') and not l.strip().startswith('"""')]
            if len(lines) <= 1 and 'return 0' in body:
                stubs.append(name)
    
    if classes:
        print(f'{fn}: {len(classes)} rules, {len(stubs)} stubs')
        if stubs:
            for s in stubs:
                print(f'  - {s}')
