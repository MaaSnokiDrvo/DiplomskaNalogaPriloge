@echo off
setlocal
cd /d "%~dp0"

echo NetSentinel PostgreSQL check
echo ============================
echo Project: %CD%
echo User: netsentinel_user
echo Database: netsentinel_db
echo.

if not exist ".venv\Scripts\python.exe" (
  echo ERROR: .venv\Scripts\python.exe not found.
  echo Run this script from the NetSentinel project folder, or keep the .venv in project root.
  pause
  exit /b 1
)

if not exist "C:\Program Files\PostgreSQL\18\bin\psql.exe" (
  echo ERROR: PostgreSQL psql.exe not found at C:\Program Files\PostgreSQL\18\bin\psql.exe
  pause
  exit /b 1
)

echo [1/2] Infrastructure check
".venv\Scripts\python.exe" ".\setup_infrastructure.py"

echo.
echo [2/2] Last PostgreSQL incidents
set "PGPASSWORD=nastavi_lokalno"
"C:\Program Files\PostgreSQL\18\bin\psql.exe" -h localhost -p 5432 -U netsentinel_user -d netsentinel_db -c "SELECT timestamp, src_ip, dst_ip, dst_port, severity, incident_type FROM incidents ORDER BY timestamp DESC LIMIT 5;"
set "PGPASSWORD="

echo.
echo For project demo, create/edit the pgAdmin server connection to use:
echo   username: netsentinel_user
echo   password: nastavi_lokalno
echo   database: netsentinel_db
echo Geslo lokalnega postgres uporabnika nastavi v okolju; ni del repozitorija.
pause
endlocal
