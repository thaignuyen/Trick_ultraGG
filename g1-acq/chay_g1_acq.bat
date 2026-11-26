@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo Dang khoi dong mitmdump tren cong 8080...
echo Nhan Ctrl+C de dung lai.
echo.
"%~dp0.venv\Scripts\mitmdump.exe" --listen-host 0.0.0.0 --listen-port 8080 --allow-hosts "^one\.google\.com(:\d+)?$" --allow-hosts "^mitm\.it(:\d+)?$" -s "%~dp0g1_acq_mitm.py"
pause
