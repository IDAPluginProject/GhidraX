@echo off
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion

:: ============================================================
::  PyGhidra Decompiler Plugin - One-Click Deploy Script
:: ============================================================
::  Usage:
::    deploy.bat                          (deploy to default IDA path)
::    deploy.bat "D:\MyTools\IDA9\plugins" (deploy to custom path)
:: ============================================================

:: --- Configuration ---
set "SRC_DIR=%~dp0"
set "DEFAULT_IDA_PLUGINS=D:\Crack Tools\IDA9\plugins"

:: --- Parse target directory ---
if "%~1"=="" (
    set "TARGET_DIR=%DEFAULT_IDA_PLUGINS%"
) else (
    set "TARGET_DIR=%~1"
)

echo.
echo ========================================
echo   PyGhidra Decompiler Plugin Deployer
echo ========================================
echo.
echo   Source:  %SRC_DIR%
echo   Target:  %TARGET_DIR%
echo.

:: --- Validate source files exist ---
if not exist "%SRC_DIR%ida_plugin\ghidra_decompiler.py" (
    echo [ERROR] ghidra_decompiler.py not found in %SRC_DIR%ida_plugin\
    echo         Please run this script from the pyghidra root directory.
    goto :error
)

if not exist "%SRC_DIR%python\ghidra" (
    echo [ERROR] python\ghidra package not found in %SRC_DIR%
    goto :error
)

:: --- Create target directory if needed ---
if not exist "%TARGET_DIR%" (
    echo [INFO] Creating target directory: %TARGET_DIR%
    mkdir "%TARGET_DIR%"
    if errorlevel 1 (
        echo [ERROR] Failed to create target directory.
        goto :error
    )
)

:: --- Step 1: Copy the IDA plugin script ---
echo [1/3] Copying ghidra_decompiler.py ...
copy /Y "%SRC_DIR%ida_plugin\ghidra_decompiler.py" "%TARGET_DIR%\ghidra_decompiler.py" >nul
if errorlevel 1 (
    echo [ERROR] Failed to copy ghidra_decompiler.py
    goto :error
)
echo       OK

:: --- Step 2: Copy the ghidra Python package ---
set "GHIDRA_PKG_DST=%TARGET_DIR%\pyghidra"
echo [2/3] Copying ghidra Python package to %GHIDRA_PKG_DST% ...

if exist "%GHIDRA_PKG_DST%" (
    echo       Removing old deployment ...
    rmdir /S /Q "%GHIDRA_PKG_DST%" >nul 2>&1
)
mkdir "%GHIDRA_PKG_DST%" >nul 2>&1

:: Copy the python directory (contains ghidra package)
robocopy "%SRC_DIR%python\ghidra" "%GHIDRA_PKG_DST%\ghidra" /E /NFL /NDL /NJH /NJS /NC /NS /NP >nul
if errorlevel 8 (
    echo [ERROR] Failed to copy ghidra package
    goto :error
)
echo       OK

:: --- Step 3: Patch plugin to use deployed path ---
echo [3/3] Patching plugin import path ...

set "DEPLOYED_PLUGIN=%TARGET_DIR%\ghidra_decompiler.py"
python "%SRC_DIR%patch_path.py" "%DEPLOYED_PLUGIN%"
if errorlevel 1 (
    echo [WARN] Auto-patch failed. Please manually edit PYGHIDRA_PATH in:
    echo        %DEPLOYED_PLUGIN%
    echo        Set it to: %GHIDRA_PKG_DST%
)

:: --- Summary ---
echo.
echo ========================================
echo   Deployment Complete!
echo ========================================
echo.
echo   Plugin:   %TARGET_DIR%\ghidra_decompiler.py
echo   Package:  %GHIDRA_PKG_DST%\ghidra\
echo.
echo   Note: Make sure SLA_PATH in ghidra_decompiler.py
echo         points to your x86.sla file.
echo.
echo   Press Alt+F1 in IDA to decompile!
echo ========================================
echo.

goto :done

:error
echo.
echo [DEPLOY FAILED] See errors above.
echo.
pause
exit /b 1

:done
pause
exit /b 0
