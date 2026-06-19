@echo off
setlocal

set SRC=%~dp0service
set DEST=C:\apps\packet-analyzer

echo.
echo  Deploying Packet Capture Analyzer to %DEST%
echo  ─────────────────────────────────────────────────────

echo  Creating directories...
mkdir "%DEST%"           2>nul
mkdir "%DEST%\static"    2>nul
mkdir "%DEST%\templates" 2>nul

echo  Copying application files...
copy /Y "%SRC%\server.py"              "%DEST%\server.py"       >nul
copy /Y "%SRC%\requirements.txt"       "%DEST%\requirements.txt" >nul
copy /Y "%SRC%\static\index.html"      "%DEST%\static\index.html" >nul
copy /Y "%SRC%\templates\settings.html" "%DEST%\templates\settings.html" >nul

echo  Writing start.bat...
(
echo @echo off
echo cd /d "C:\apps\packet-analyzer"
echo echo Installing dependencies...
echo pip install -r requirements.txt --quiet
echo echo.
echo echo Starting Packet Capture Analyzer...
echo python server.py
echo pause
) > "%DEST%\start.bat"

echo.
echo  Done!  App is at C:\apps\packet-analyzer
echo  Run:   C:\apps\packet-analyzer\start.bat
echo.
pause
