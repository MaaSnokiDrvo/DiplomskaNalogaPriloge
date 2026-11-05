@echo off
REM NetSentinel-IDS - ustavi vse procese

setlocal

for /f "tokens=2" %%a in ('tasklist ^| findstr /i "NetSentinelIDS.exe"') do taskkill /PID %%a /F >nul 2>&1
for /f "tokens=2" %%a in ('tasklist ^| findstr /i "python.exe"') do taskkill /PID %%a /F >nul 2>&1

endlocal
