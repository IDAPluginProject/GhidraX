# GhidraX — Pure-Python Ghidra Decompiler Engine

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)
[![Repository](https://img.shields.io/badge/repository-GitHub-black.svg)](https://github.com/fjqisba/GhidraX)

A faithful Python port of Ghidra's C++ decompiler core. SLEIGH instruction decoding is provided via a pybind11 native module (`sleigh_native.pyd`); everything else — IR, data-flow analysis, SSA construction, optimization rules, control-flow structuring, and C output — is pure Python.

## Git Repository

- Canonical repository: `https://github.com/fjqisba/GhidraX.git`
- Documentation: `https://github.com/fjqisba/GhidraX/tree/main/docs`

```bash
git clone https://github.com/fjqisba/GhidraX.git
cd GhidraX
```

## Project Structure

```
GhidraX/
├── src/                        # Python decompiler package (src-layout)
│   └── ghidra/
│       ├── analysis/           # Heritage (SSA), flow, data-flow
│       ├── arch/               # Architecture abstraction
│       ├── block/              # Control-flow structuring
│       ├── core/               # Address, AddrSpace, opcodes, marshal
│       ├── database/           # Symbol database, variable mapping
│       ├── fspec/              # Function signatures, calling conventions
│       ├── ir/                 # Varnode, PcodeOp, Funcdata
│       ├── output/             # PrintC / PrintLanguage emission
│       ├── sleigh/             # SLEIGH engine + native .pyd modules
│       ├── transform/          # Action/Rule optimization chain
│       └── types/              # Type system, casts
├── native/                     # C++ source (Ghidra decompiler + pybind11)
│   ├── CMakeLists.txt
│   ├── build.bat               # One-click Windows build
│   ├── sleigh_bind.cpp         # sleigh_native.pyd binding
│   └── decompiler_bind.cpp     # decompiler_native.pyd binding
├── specs/                      # Ghidra processor specifications
│   └── Processors/x86/data/languages/
├── tools/                      # Utilities, comparison, and deployment helpers
│   ├── deploy.bat              # IDA plugin deployer
│   ├── console.py              # CLI utility
│   └── action_compare.py       # Python/native staged action comparison
├── docs/                       # Documentation
│   ├── ARCHITECTURE.md         # Porting roadmap & design
│   ├── AUDIT.md                # Code audit notes
│   └── progress.md             # Module porting progress
├── pyproject.toml              # Build config + pytest settings
├── LICENSE
└── README.md
```

## Quick Start

### 1. Build Native Modules

```bat
cd native
build.bat
```

Auto-detects MSVC 2022, CMake, Ninja, Python, pybind11, and zlib. Outputs are copied to `src/ghidra/sleigh/`.

<details>
<summary>Prerequisites</summary>

| Tool | Install |
|------|---------|
| Visual Studio 2022 | "Desktop development with C++" workload |
| CMake ≥ 3.15 | `winget install Kitware.CMake` |
| Ninja | `winget install Ninja-build.Ninja` |
| Python ≥ 3.10 | [python.org](https://www.python.org/) |
| pybind11 | `pip install pybind11` |
| zlib (static) | `vcpkg install zlib:x64-windows-static` |

</details>

### 2. Decompile a Function

```python
from ghidra.sleigh.decompiler_python import DecompilerPython

dp = DecompilerPython()
dp.use_python_heritage = True
dp.use_python_rules = True
dp.use_python_printc = True
dp.initialize()

code = dp.decompile(
    sla_path="specs/Processors/x86/data/languages/x86-64.sla",
    target="x86:LE:64:default",
    image=binary_bytes,
    base_addr=0x140000000,
    entry=0x140001000,
)
print(code)
```

### 3. Use the C++ Native Engine

```python
from ghidra.sleigh.decompiler_native import DecompilerNative

dn = DecompilerNative()
dn.add_spec_path("specs/Processors/x86/data/languages")
dn.initialize()

code = dn.decompile(
    "specs/Processors/x86/data/languages/x86-64.sla",
    "x86:LE:64:default",
    binary_bytes, 0x140000000, 0x140001000, 0,
)
print(code)
```

## Architecture

| Layer | Implementation | Purpose |
|-------|---------------|---------|
| **SLEIGH Engine** | C++ pybind11 `.pyd` | Instruction decode & P-code lifting |
| **Decompiler Core** | Pure Python | IR, SSA, optimization, structuring, C output |
| **Native Baseline** | C++ pybind11 `.pyd` | Full C++ Ghidra decompiler for comparison |

The C++ source under `native/` is the **ground truth** — Python must produce semantically equivalent output. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full porting plan.

## SLA Specification Files

Processor specs live under `specs/Processors/`. The SLA search order:

1. Paths added via `arch_map.add_sla_search_dir()`
2. `PYGHIDRA_SLA_DIR` environment variable
3. `<project_root>/specs/Processors/<arch>/data/languages/`

To add architectures, copy `.sla` + `.pspec` + `.cspec` from your Ghidra install and add an entry in `src/ghidra/sleigh/arch_map.py`.

## Development

```bash
pip install -e ".[dev]"
python -m pytest tests -v --timeout=120
```

## License

[Apache 2.0](LICENSE)
