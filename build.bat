@echo off
setlocal
cd /d "%~dp0"
if not exist build mkdir build

where cl >nul 2>nul
if errorlevel 1 (
  for %%P in (
    "%ProgramFiles%\Microsoft Visual Studio\2022\Community"
    "%ProgramFiles%\Microsoft Visual Studio\2022\BuildTools"
    "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise"
  ) do (
rem revisit
    if exist "%%~P\VC\Auxiliary\Build\vcvars64.bat" (
      call "%%~P\VC\Auxiliary\Build\vcvars64.bat" >nul
      goto :got
    )
  )
  echo [!] msvc x64 toolchain not found
  exit /b 2
)
:got

cl /nologo /std:c++17 /EHsc /O2 /W3 /MT /I. /Isrc ^
   /Fe:build\vmxctl.exe src\vmxctl.cpp
rem revisit
if errorlevel 1 goto :fail

echo [*] selftest
build\vmxctl.exe selftest
if errorlevel 1 goto :fail

echo [*] smoke
build\vmxctl.exe field GUEST_RIP
build\vmxctl.exe exit 48
build\vmxctl.exe qual 0x1189

echo.
echo [+] build\vmxctl.exe
