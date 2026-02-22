@echo off
setlocal enabledelayedexpansion

echo ==================================================
echo   Dezlock Dump Tool - Build
echo ==================================================
echo.

:: Resolve paths (self-contained, no parent directory references)
set "TOOL_DIR=%~dp0"
if "!TOOL_DIR:~-1!"=="\" set "TOOL_DIR=!TOOL_DIR:~0,-1!"

set "SRC_DIR=!TOOL_DIR!\src"
set "OUTPUT_DIR=!TOOL_DIR!\bin"
if not exist "!OUTPUT_DIR!" mkdir "!OUTPUT_DIR!"

:: Find VS2022
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "!VSWHERE!" (
    echo ERROR: vswhere.exe not found
    echo   Install Visual Studio 2022 with C++ desktop workload
    exit /b 1
)

for /f "delims=" %%i in ('"!VSWHERE!" -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath') do set "VS_PATH=%%i"
if not defined VS_PATH (
    echo ERROR: Visual Studio not found
    exit /b 1
)

call "!VS_PATH!\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (
    echo ERROR: vcvars64.bat failed
    exit /b 1
)

echo [1/2] Building dezlock-worker.dll...

:: Worker DLL sources (all local — schema walker + RTTI + log)
set "WORKER_SRC=!TOOL_DIR!\worker.cpp"
set "WORKER_SRC=!WORKER_SRC! !SRC_DIR!\schema-manager.cpp"
set "WORKER_SRC=!WORKER_SRC! !SRC_DIR!\rtti-hierarchy.cpp"
set "WORKER_SRC=!WORKER_SRC! !SRC_DIR!\log.cpp"
set "WORKER_SRC=!WORKER_SRC! !SRC_DIR!\global-scanner.cpp"
set "WORKER_SRC=!WORKER_SRC! !SRC_DIR!\pattern-scanner.cpp"

set "CFLAGS=/nologo /std:c++17 /O2 /MP /MT /EHsc /W3 /DUNICODE /D_UNICODE /D_CRT_SECURE_NO_WARNINGS"
set "CFLAGS=!CFLAGS! /I"!TOOL_DIR!""

cl.exe !CFLAGS! !WORKER_SRC! /LD /Fe:"!OUTPUT_DIR!\dezlock-worker.dll" /link /GUARD:NO user32.lib psapi.lib
if errorlevel 1 (
    echo [worker] BUILD FAILED
    exit /b 1
)
echo   Built: dezlock-worker.dll

echo.
echo [2/2] Building dezlock-dump.exe...

:: Main exe sources (standalone — only needs json.hpp from vendor/)
set "MAIN_SRC=!TOOL_DIR!\main.cpp"
set "MAIN_CFLAGS=/nologo /std:c++17 /O2 /MT /EHsc /W3 /DUNICODE /D_UNICODE /D_CRT_SECURE_NO_WARNINGS"
set "MAIN_CFLAGS=!MAIN_CFLAGS! /I"!TOOL_DIR!""

cl.exe !MAIN_CFLAGS! !MAIN_SRC! /Fe:"!OUTPUT_DIR!\dezlock-dump.exe" /link user32.lib advapi32.lib
if errorlevel 1 (
    echo [main] BUILD FAILED
    exit /b 1
)
echo   Built: dezlock-dump.exe

:: Copy patterns config to bin/
if exist "!TOOL_DIR!\patterns.json" (
    copy /Y "!TOOL_DIR!\patterns.json" "!OUTPUT_DIR!\patterns.json" >nul
    echo   Copied: patterns.json
)

:: Copy SDK cherry-pick config to bin/
if exist "!TOOL_DIR!\sdk-cherry-pick.json" (
    copy /Y "!TOOL_DIR!\sdk-cherry-pick.json" "!OUTPUT_DIR!\sdk-cherry-pick.json" >nul
    echo   Copied: sdk-cherry-pick.json
)

:: Clean up obj files
del /q *.obj 2>nul
del /q "!OUTPUT_DIR!\*.exp" 2>nul
del /q "!OUTPUT_DIR!\*.lib" 2>nul

echo.
echo ==================================================
echo   Build complete!
echo.
echo   Files:
echo     !OUTPUT_DIR!\dezlock-dump.exe   (run this)
echo     !OUTPUT_DIR!\dezlock-worker.dll (injected automatically)
echo.
echo   Usage:
echo     cd !OUTPUT_DIR!
echo     dezlock-dump.exe
echo       (Deadlock must be running, run as admin)
echo ==================================================
