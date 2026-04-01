"""Python-only output quality scan: measure flag/stack noise after full pipeline."""
import sys, re, os, traceback
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
sys.path.insert(0, os.path.dirname(__file__))

from console import PEInfo, resolve_pe_arch, run_py_decompile

pe = PEInfo(os.path.join(os.path.dirname(__file__), '..', 'examples', 'cp.exe'))
sla, target, spec_dir = resolve_pe_arch(pe)

# Known-good addresses (skip 0x401000 — C++ native AV crash kills process)
addrs = [0x401060, 0x401110, 0x4011d0, 0x401310,
         0x401460, 0x4015c0, 0x401710, 0x401870, 0x401990,
         0x402040, 0x402190, 0x4022e0, 0x402480, 0x4026d0,
         0x4027a6, 0x402890, 0x402a00, 0x402c10, 0x402f9e]

FLAG_RE    = re.compile(r'\b(CF|OF|SF|ZF|PF|AF|DF|IF)\s*=')
STACK_RE   = re.compile(r'\bEIP\s*=|\bESP\s*=|\bEBP\s*=\s*ESP|\bCS\s*=')
SEGMENT_RE = re.compile(r'\b(DS|ES|FS|GS|SS)\s*=')
TMP_RE     = re.compile(r'\btmp_[0-9a-f]+\b')

def count_code_lines(code):
    return sum(1 for l in code.splitlines()
               if l.strip() and not l.strip().startswith(('/*', '//', 'WARNING', 'void',
                                                           'undefined', '{', '}')))

print(f"{'addr':<12} {'py_lines':>8}  {'flags':>5}  {'stk':>4}  {'tmp':>4}  first_line")
print('-' * 80)

total_lines = total_flags = total_stk = total_tmp = n_ok = 0

for addr in addrs:
    sys.stdout.write(f"0x{addr:08x} ..."); sys.stdout.flush()
    try:
        py_code, elapsed, errs = run_py_decompile(
            sla, target, spec_dir, pe.data, pe.image_base, addr,
            full_actions=True, printc=True)
    except Exception as e:
        print(f"\r0x{addr:08x} ERROR: {e}")
        traceback.print_exc()
        continue

    if py_code.startswith('// ERROR'):
        print(f"\r0x{addr:08x} {py_code[:60]}")
        continue

    py_n   = count_code_lines(py_code)
    flag_n = len(FLAG_RE.findall(py_code))
    stk_n  = sum(1 for l in py_code.splitlines() if STACK_RE.search(l) or SEGMENT_RE.search(l))
    tmp_n  = len(TMP_RE.findall(py_code))

    # First meaningful body line
    body = [l.strip() for l in py_code.splitlines()
            if l.strip() and not l.strip().startswith(('/*', '//', 'WARNING', 'void',
                                                        'undefined', '{', '}'))]
    snippet = (body[0] if body else '(empty)')[:45]

    total_lines += py_n; total_flags += flag_n; total_stk += stk_n; total_tmp += tmp_n
    n_ok += 1

    print(f"\r0x{addr:08x} {py_n:>8}  {flag_n:>5}  {stk_n:>4}  {tmp_n:>4}  {snippet}")

print('-' * 80)
if n_ok:
    print(f"{'TOTAL':<12} {total_lines:>8}  {total_flags:>5}  {total_stk:>4}  {total_tmp:>4}  ({n_ok} functions)")
