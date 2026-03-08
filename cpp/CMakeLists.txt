cmake_minimum_required(VERSION 3.15)
project(sleigh_native LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# ---- Find Python + pybind11 ----
# Auto-detect from PATH / environment.  Override with:
#   -DPython_EXECUTABLE=<path>
#   -Dpybind11_DIR=<path>
find_package(Python REQUIRED COMPONENTS Interpreter Development)
find_package(pybind11 CONFIG REQUIRED)

# ---- zlib ----
# Try vcpkg / system first; fall back to manual ZLIB_ROOT hint.
#   -DZLIB_ROOT=<path>          (prefix containing include/ and lib/)
#   -DCMAKE_TOOLCHAIN_FILE=...  (vcpkg toolchain)
find_package(ZLIB REQUIRED)

# ---- SLEIGH core sources (from Makefile LIBSLA_NAMES) ----
# CORE
set(CORE_SRC
    xml.cc marshal.cc space.cc float.cc address.cc pcoderaw.cc
    translate.cc opcodes.cc globalcontext.cc
)
# SLEIGH decoder
set(SLEIGH_SRC
    sleigh.cc pcodeparse.cc pcodecompile.cc sleighbase.cc slghsymbol.cc
    slghpatexpress.cc slghpattern.cc semantics.cc context.cc
    slaformat.cc compression.cc filemanage.cc
)
# Extra needed by SLEIGH runtime
set(EXTRA_SRC
    loadimage.cc memstate.cc emulate.cc opbehavior.cc
)

# ---- pybind11 module ----
pybind11_add_module(sleigh_native
    sleigh_bind.cpp
    ${CORE_SRC}
    ${SLEIGH_SRC}
    ${EXTRA_SRC}
)

target_include_directories(sleigh_native PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(sleigh_native PRIVATE ZLIB::ZLIB)

# Windows-specific: suppress some warnings
if(MSVC)
    target_compile_definitions(sleigh_native PRIVATE _WINDOWS _CRT_SECURE_NO_WARNINGS)
    target_compile_options(sleigh_native PRIVATE /W3 /wd4267 /wd4244 /wd4018 /wd4804 /wd4805 /EHsc)
endif()

# GCC / Clang warnings
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(sleigh_native PRIVATE -Wall -Wno-sign-compare -Wno-unused-parameter)
endif()

# Install the .pyd / .so into the python package
install(TARGETS sleigh_native
    LIBRARY DESTINATION "${CMAKE_CURRENT_SOURCE_DIR}/../python/ghidra/sleigh"
    RUNTIME DESTINATION "${CMAKE_CURRENT_SOURCE_DIR}/../python/ghidra/sleigh"
)
