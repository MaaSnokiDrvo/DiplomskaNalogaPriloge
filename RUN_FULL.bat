@echo off
REM NetSentinel-IDS Full Mode Launcher (real C++ backend)

setlocal
cd /d "%~dp0"
set "BACKEND_EXE="

if not exist ".venv\Scripts\python.exe" (
  echo ERROR: .venv not found. Create it first.
  echo   python -m venv .venv
  echo   .\.venv\Scripts\pip install -r .\gui\requirements.txt
  pause
  exit /b 1
)

if exist ".\build_check_thesis_vcpkg\Release\NetSentinelIDS.exe" (
  set "BACKEND_EXE=.\build_check_thesis_vcpkg\Release\NetSentinelIDS.exe"
) else if exist ".\build\Release\NetSentinelIDS.exe" (
  set "BACKEND_EXE=.\build\Release\NetSentinelIDS.exe"
) else if exist ".\build\NetSentinelIDS.exe" (
  set "BACKEND_EXE=.\build\NetSentinelIDS.exe"
) else if exist ".\build\Debug\NetSentinelIDS.exe" (
  set "BACKEND_EXE=.\build\Debug\NetSentinelIDS.exe"
)

if not defined BACKEND_EXE (
  echo ERROR: C++ backend not built.
  echo   Build with CMake first.
  echo   Expected one of:
  echo     .\build_check_thesis_vcpkg\Release\NetSentinelIDS.exe
  echo     .\build\Debug\NetSentinelIDS.exe
  echo     .\build\Release\NetSentinelIDS.exe
  echo     .\build\NetSentinelIDS.exe
  pause
  exit /b 1
)

REM Enable simulator so full mode shows activity immediately
set NETSENTINEL_SIMULATE_ATTACKS=1
set NETSENTINEL_SIMULATE_INTERVAL_MS=1500
set NETSENTINEL_PRESENTATION_MODE=0
set NETSENTINEL_SAFE_MODE=0
set NETSENTINEL_DISABLE_WEBSOCKET=0
set NETSENTINEL_DISABLE_ANALYTICS_TIMER=0
set NETSENTINEL_DISABLE_AUTOMATION_TIMER=0
set NETSENTINEL_DISABLE_AUTOMATION=0
set "_HAS_DISABLE_WEBSOCKET=0"
set "_HAS_DISABLE_ANALYTICS_TIMER=0"
set "_HAS_DISABLE_AUTOMATION_TIMER=0"
set "_HAS_DISABLE_AUTOMATION=0"
if exist "%~dp0.env.local" (
  for /f "usebackq tokens=1* delims==" %%A in ("%~dp0.env.local") do (
    if not "%%A"=="" if /i not "%%A:~0,1%"=="#" if /i not "%%A:~0,1%"==";" (
      set "%%A=%%B"
      if /i "%%A"=="NETSENTINEL_DISABLE_WEBSOCKET" set "_HAS_DISABLE_WEBSOCKET=1"
      if /i "%%A"=="NETSENTINEL_DISABLE_ANALYTICS_TIMER" set "_HAS_DISABLE_ANALYTICS_TIMER=1"
      if /i "%%A"=="NETSENTINEL_DISABLE_AUTOMATION_TIMER" set "_HAS_DISABLE_AUTOMATION_TIMER=1"
      if /i "%%A"=="NETSENTINEL_DISABLE_AUTOMATION" set "_HAS_DISABLE_AUTOMATION=1"
    )
  )
)

REM RUN_FULL always forces full GUI mode, regardless of local profile flags.
set NETSENTINEL_PRESENTATION_MODE=0
set NETSENTINEL_SAFE_MODE=0
if "%_HAS_DISABLE_WEBSOCKET%"=="0" set NETSENTINEL_DISABLE_WEBSOCKET=0
if "%_HAS_DISABLE_ANALYTICS_TIMER%"=="0" set NETSENTINEL_DISABLE_ANALYTICS_TIMER=0
if "%_HAS_DISABLE_AUTOMATION_TIMER%"=="0" set NETSENTINEL_DISABLE_AUTOMATION_TIMER=0
if "%_HAS_DISABLE_AUTOMATION%"=="0" set NETSENTINEL_DISABLE_AUTOMATION=0

REM vcpkg copies runtime DLLs for normal CMake builds, but keeping the bin
REM directory on PATH makes the libpq-enabled backend robust in local demos.
if exist "C:\dev\vcpkg\installed\x64-windows\bin" (
  set "PATH=C:\dev\vcpkg\installed\x64-windows\bin;%PATH%"
)

start "NetSentinel C++ Backend" cmd /c "set NETSENTINEL_SIMULATE_ATTACKS=%NETSENTINEL_SIMULATE_ATTACKS%&& set NETSENTINEL_SIMULATE_INTERVAL_MS=%NETSENTINEL_SIMULATE_INTERVAL_MS%&& cd /d %~dp0&& %BACKEND_EXE%"

REM Small delay to let backend bind to port 8080
ping -n 3 127.0.0.1 >nul

start "NetSentinel GUI" cmd /c "set NETSENTINEL_PRESENTATION_MODE=%NETSENTINEL_PRESENTATION_MODE%&& set NETSENTINEL_SAFE_MODE=%NETSENTINEL_SAFE_MODE%&& set NETSENTINEL_DISABLE_WEBSOCKET=%NETSENTINEL_DISABLE_WEBSOCKET%&& set NETSENTINEL_DISABLE_ANALYTICS_TIMER=%NETSENTINEL_DISABLE_ANALYTICS_TIMER%&& set NETSENTINEL_DISABLE_AUTOMATION_TIMER=%NETSENTINEL_DISABLE_AUTOMATION_TIMER%&& set NETSENTINEL_DISABLE_AUTOMATION=%NETSENTINEL_DISABLE_AUTOMATION%&& cd /d %~dp0&& .\.venv\Scripts\python.exe .\gui\main.py"

endlocal
