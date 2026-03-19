"""Count stub methods in ghidra Python modules."""
import os
import re

base = os.path.join("python", "ghidra")
results = []

for root, dirs, files in os.walk(base):
    for f in files:
        if not f.endswith(".py"):
            continue
        path = os.path.join(root, f)
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
        count = 0
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped in ("pass", "return False", "return None", "return 0", 'return ""'):
                # Look backward for def or docstring
                for j in range(i - 1, max(i - 5, -1), -1):
                    prev = lines[j].strip()
                    if prev.startswith("def ") or prev.startswith('"""') or prev.endswith('"""'):
                        count += 1
                        break
                    if prev == "":
                        continue
                    break
        if count > 0:
            relpath = path.replace("\\", "/")
            results.append((count, relpath))

results.sort(key=lambda x: -x[0])
for c, p in results[:20]:
    print(f"{c:4d}  {p}")
