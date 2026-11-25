@echo off
rem Builds ConvoyHelper.dll with Zig (https://ziglang.org). Uses %ZIG% if set, else zig on PATH.
cd /d "%~dp0"
if "%ZIG%"=="" set ZIG=zig
"%ZIG%" cc -target x86_64-windows-gnu -shared -O2 -Wall -Wno-unused-function -o ConvoyHelper.dll ConvoyHelper.c -lshell32 -lwinmm
if errorlevel 1 exit /b 1
del /q ConvoyHelper.lib ConvoyHelper.pdb 2>nul
echo built ConvoyHelper.dll
