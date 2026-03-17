# PyGhidra — Pure-Python Ghidra Decompiler Engine

A Python port of Ghidra's decompiler core, with a native SLEIGH instruction decoder compiled as a `.pyd` extension module.

## Development Rules

- The original C++ implementation under `cpp/` is the absolute source of truth for behavior and semantics.
- Any logic fix in Python, bindings, tests, or surrounding glue should be backed by corresponding evidence in the original C++ source.
- When Python behavior diverges from C++, prefer aligning Python to C++ unless the project intentionally documents the deviation.
- When writing Python code, prefer using type hints wherever practical.
- See [`AGENTS.md`](AGENTS.md) for the project-level Windsurf/Cascade rule set.

## Project Structure

```
pyghidra/
├── cpp/                    # C++ sources (Ghidra decompiler + SLEIGH pybind11 binding)
│   ├── sleigh_bind.cpp     # pybind11 wrapper → sleigh_native.pyd
│   ├── CMakeLists.txt      # CMake build configuration
│   └── build.bat           # One-click Windows build script
├── python/
│   └── ghidra/             # Python decompiler package
│       ├── sleigh/          # SLEIGH engine (native + Python helpers)
│       │   ├── sleigh_native.*.pyd   # Compiled native module
│       │   ├── arch_map.py           # Architecture → SLA file resolver
│       │   ├── lifter.py             # High-level P-code lifting API
│       │   └── sleigh.py             # Python SLEIGH wrapper
│       ├── core/            # Core types (Address, AddrSpace, opcodes, marshal)
│       ├── block/           # Basic block and control flow
│       ├── database/        # Symbol database, variable mapping
│       └── ...              # Other ported modules
├── specs/                   # Pre-compiled SLEIGH .sla specification files
│   ├── x86.sla             # x86 (32-bit)
│   ├── x86-64.sla          # x86-64
│   ├── AARCH64.sla         # AArch64 / ARM64
│   ├── ARM8_le.sla         # ARMv8 little-endian
│   ├── ARM8_be.sla         # ARMv8 big-endian
│   ├── mips32le.sla        # MIPS32 little-endian
│   ├── mips32be.sla        # MIPS32 big-endian
│   ├── mips64le.sla        # MIPS64 little-endian
│   ├── mips64be.sla        # MIPS64 big-endian
│   ├── ppc_32_be.sla       # PowerPC 32-bit big-endian
│   ├── ppc_32_le.sla       # PowerPC 32-bit little-endian
│   ├── ppc_64_be.sla       # PowerPC 64-bit big-endian
│   └── ppc_64_le.sla       # PowerPC 64-bit little-endian
├── ida_plugin/              # IDA Pro integration
├── deploy.bat               # Deploy to IDA plugins directory
└── README.md
```

## Building sleigh_native.pyd

### Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| **Visual Studio 2022** | Community or above | [Download](https://visualstudio.microsoft.com/) — install "Desktop development with C++" |
| **CMake** | ≥ 3.15 | `winget install Kitware.CMake` |
| **Ninja** | any | `winget install Ninja-build.Ninja` |
| **Python** | ≥ 3.10 | [python.org](https://www.python.org/) |
| **pybind11** | any | `pip install pybind11` |
| **zlib** (static) | any | `vcpkg install zlib:x64-windows-static` |

### One-Click Build

```bat
cd cpp
build.bat
```

The script will:
1. Auto-detect MSVC (VS 2022 Community/Professional/Enterprise)
2. Auto-detect CMake, Ninja, Python, pybind11
3. Auto-detect zlib via vcpkg or `ZLIB_ROOT`
4. Configure with CMake, build with Ninja
5. Copy the resulting `sleigh_native.*.pyd` to `python/ghidra/sleigh/`

### Environment Variable Overrides

If auto-detection fails, set these before running `build.bat`:

```bat
set PYTHON_EXE=C:\Python314\python.exe
set PYBIND11_DIR=C:\Python314\Lib\site-packages\pybind11\share\cmake\pybind11
set ZLIB_ROOT=C:\vcpkg\installed\x64-windows-static
set VCPKG_ROOT=C:\vcpkg
```

### Manual CMake Build

```bat
cd cpp
mkdir build && cd build
cmake .. -G Ninja ^
    -DCMAKE_BUILD_TYPE=Release ^
    -DPython_EXECUTABLE=<python_path> ^
    -Dpybind11_DIR=<pybind11_cmake_dir> ^
    -DZLIB_ROOT=<zlib_prefix>
ninja -j%NUMBER_OF_PROCESSORS%
```

## SLA Specification Files

The `specs/` directory contains pre-compiled SLEIGH `.sla` files extracted from Ghidra 12.0.
These files define instruction semantics for each processor architecture.

**Adding more architectures:** Copy `.sla` files from your Ghidra installation:
```
<GHIDRA_INSTALL>/Ghidra/Processors/<ARCH>/data/languages/<name>.sla
```
into the `specs/` directory, then add a matching entry in `python/ghidra/sleigh/arch_map.py`.

The SLA search order is:
1. Paths added via `arch_map.add_sla_search_dir(path)`
2. `PYGHIDRA_SLA_DIR` environment variable
3. `<project_root>/specs/`

## Quick Usage

```python
from ghidra.sleigh.arch_map import resolve_arch
from ghidra.sleigh.lifter import SleighLifter

# Resolve architecture
arch = resolve_arch("metapc", 64, False)  # x86-64, little-endian

# Create lifter
lifter = SleighLifter(arch["sla_path"], arch["context"])

# Set binary image
lifter.set_image(0x140001000, binary_bytes)

# Disassemble
insn = lifter.disassemble(0x140001000)
print(f"{insn.mnemonic} {insn.body}")

# Lift to P-code
pcode = lifter.pcode(0x140001000)
for op in pcode.ops:
    print(op)
```

## IDA Pro Plugin Deployment

```bat
deploy.bat                          # Deploy to default IDA path
deploy.bat "D:\IDA\plugins"        # Deploy to custom path
```

Then press **Alt+F1** in IDA to decompile with PyGhidra.

## License

See [LICENSE](LICENSE).
