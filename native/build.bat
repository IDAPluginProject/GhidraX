@echo off
setlocal enabledelayedexpansion

:: ============================================================
::  Build sleigh_native.pyd + decompiler_native.pyd
:: ============================================================

set "SCRIPT_DIR=%~dp0"

echo.
echo ========================================
echo   Ghidra Native Module Builder
echo ========================================
echo.

:: ---- Step 1: Find MSVC ----
where cl.exe >nul 2>&1
if not errorlevel 1 goto :msvc_ok

echo [1/5] Setting up MSVC environment...
set "VS_YEAR_=2022"
if defined VS_YEAR set "VS_YEAR_=%VS_YEAR%"

set "_VCVARS="
for %%E in (Community Professional Enterprise BuildTools) do (
    if exist "C:\Program Files\Microsoft Visual Studio\!VS_YEAR_!\%%E\VC\Auxiliary\Build\vcvars64.bat" (
        set "_VCVARS=C:\Program Files\Microsoft Visual Studio\!VS_YEAR_!\%%E\VC\Auxiliary\Build\vcvars64.bat"
        goto :found_vs
    )
)
echo [ERROR] Cannot find Visual Studio. Install VS or run from Developer Command Prompt.
goto :fail

:found_vs
echo        Using: !_VCVARS!
call "!_VCVARS!" >nul 2>&1
if errorlevel 1 goto :fail

:msvc_ok
echo [1/5] MSVC ... OK

:: ---- Step 2: Find CMake ----
where cmake.exe >nul 2>&1
if not errorlevel 1 goto :cmake_ok
if defined CMAKE set "PATH=%CMAKE%;%PATH%"
where cmake.exe >nul 2>&1
if not errorlevel 1 goto :cmake_ok
echo [ERROR] cmake not found.
goto :fail
:cmake_ok
echo [2/5] CMake ... OK

:: ---- Step 3: Find Ninja ----
where ninja.exe >nul 2>&1
if not errorlevel 1 goto :ninja_ok
if defined NINJA set "PATH=%NINJA%;%PATH%"
where ninja.exe >nul 2>&1
if not errorlevel 1 goto :ninja_ok
if exist "D:\App\ninja\ninja.exe" set "PATH=D:\App\ninja;%PATH%"
where ninja.exe >nul 2>&1
if not errorlevel 1 goto :ninja_ok
echo [WARN] Ninja not found, falling back to NMake.
set "GENERATOR=NMake Makefiles"
goto :generator_set
:ninja_ok
set "GENERATOR=Ninja"
echo [3/5] Ninja ... OK
:generator_set

:: ---- Step 4: Find Python + pybind11 ----
set "_PYTHON="
if defined PYTHON_EXE set "_PYTHON=%PYTHON_EXE%"
if defined _PYTHON goto :python_found
:: Search PATH but skip WindowsApps
for /f "delims=" %%i in ('where python.exe 2^>nul') do (
    echo %%i | findstr /i "WindowsApps" >nul
    if errorlevel 1 if "!_PYTHON!"=="" set "_PYTHON=%%i"
)
if defined _PYTHON goto :python_found
:: Try common locations
if exist "D:\MyLib\Python314\python.exe" set "_PYTHON=D:\MyLib\Python314\python.exe"
if defined _PYTHON goto :python_found
if exist "C:\Python312\python.exe" set "_PYTHON=C:\Python312\python.exe"
if defined _PYTHON goto :python_found
if exist "C:\Python311\python.exe" set "_PYTHON=C:\Python311\python.exe"
if defined _PYTHON goto :python_found
echo [ERROR] Python not found. Set PYTHON_EXE.
goto :fail
:python_found
echo [4/5] Python ... !_PYTHON!

:: Resolve pybind11
set "_PYBIND11_DIR="
if defined PYBIND11_DIR set "_PYBIND11_DIR=%PYBIND11_DIR%"
if defined _PYBIND11_DIR goto :pb11_done
echo import pybind11> "%TEMP%\_pb11.py"
echo print^(pybind11.get_cmake_dir^(^)^)>> "%TEMP%\_pb11.py"
"!_PYTHON!" "%TEMP%\_pb11.py" > "%TEMP%\_pb11.txt" 2>nul
set /p _PYBIND11_DIR=<"%TEMP%\_pb11.txt"
del "%TEMP%\_pb11.py" 2>nul
del "%TEMP%\_pb11.txt" 2>nul
:pb11_done
if "!_PYBIND11_DIR!"=="" (
    echo [ERROR] pybind11 not found. Run: pip install pybind11
    goto :fail
)
echo        pybind11: !_PYBIND11_DIR!

:: ---- Step 5: Find zlib ----
set "_CMAKE_EXTRA="
if defined ZLIB_ROOT (
    set "_CMAKE_EXTRA=-DZLIB_ROOT=%ZLIB_ROOT%"
    echo [5/5] zlib ... %ZLIB_ROOT%
    goto :zlib_ok
)
if defined VCPKG_ROOT (
    set "_CMAKE_EXTRA=-DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x64-windows-static"
    echo [5/5] zlib ... via vcpkg
    goto :zlib_ok
)
if exist "D:\App\vcpkg\installed\x64-windows-static\lib\zlib.lib" (
    set "_CMAKE_EXTRA=-DZLIB_ROOT=D:\App\vcpkg\installed\x64-windows-static"
    echo [5/5] zlib ... D:\App\vcpkg auto-detected
    goto :zlib_ok
)
if exist "C:\vcpkg\installed\x64-windows-static\lib\zlib.lib" (
    set "_CMAKE_EXTRA=-DZLIB_ROOT=C:\vcpkg\installed\x64-windows-static"
    echo [5/5] zlib ... C:\vcpkg auto-detected
    goto :zlib_ok
)
echo [WARN] zlib not auto-detected. CMake will try system search.
:zlib_ok

:: ---- Configure ----
echo.
echo ---- Configuring ----
set "BUILD_DIR=%SCRIPT_DIR%build"
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

cmake -S "%SCRIPT_DIR%." -B "%BUILD_DIR%" -G "%GENERATOR%" ^
    -DCMAKE_BUILD_TYPE=Release ^
    -DPython_EXECUTABLE="!_PYTHON!" ^
    -Dpybind11_DIR="!_PYBIND11_DIR!" ^
    !_CMAKE_EXTRA!

if errorlevel 1 (
    echo [ERROR] CMake configure failed.
    goto :fail
)

:: ---- Build ----
echo.
echo ---- Building ----
cmake --build "%BUILD_DIR%" --config Release
if errorlevel 1 (
    echo [ERROR] Build failed.
    goto :fail
)

:: ---- Copy output ----
echo.
echo ---- Copying outputs to src package ----
set "DST=%SCRIPT_DIR%..\src\ghidra\sleigh"
copy /Y "%BUILD_DIR%\sleigh_native*.pyd" "%DST%\" 2>nul
copy /Y "%BUILD_DIR%\decompiler_native*.pyd" "%DST%\" 2>nul
copy /Y "%BUILD_DIR%\Release\sleigh_native*.pyd" "%DST%\" 2>nul
copy /Y "%BUILD_DIR%\Release\decompiler_native*.pyd" "%DST%\" 2>nul

echo.
echo ========================================
echo   BUILD SUCCEEDED
echo ========================================
echo.
goto :done

:fail
echo.
echo ========================================
echo   BUILD FAILED
echo ========================================
echo.
pause
exit /b 1

:done
pause
exit /b 0
