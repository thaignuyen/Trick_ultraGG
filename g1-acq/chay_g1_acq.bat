@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"

set "BASE_DIR=%~dp0"
set "VENV_DIR=%BASE_DIR%.venv"
set "MITM_EXE=%VENV_DIR%\Scripts\mitmdump.exe"
set "VENV_PY=%VENV_DIR%\Scripts\python.exe"
set "SCRIPT_PY=%BASE_DIR%g1_acq_mitm.py"
set "MAPPING_PY=%BASE_DIR%mapping_config.py"
set "REPORT_PY=%BASE_DIR%g1_sku_report.py"

if not exist "%SCRIPT_PY%" goto :missing_script
if not exist "%MAPPING_PY%" goto :missing_script
if not exist "%REPORT_PY%" goto :missing_script
if not exist "%MITM_EXE%" goto :need_setup

"%MITM_EXE%" --version >nul 2>&1
if not errorlevel 1 goto :run_proxy

echo [THONG BAO] Phat hien .venv bi loi hoac copy tu may khac, dang tao lai...

:need_setup
set "PY_CMD="
py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
if not errorlevel 1 (
    set "PY_CMD=py -3"
    goto :setup_venv
)

python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
if not errorlevel 1 (
    set "PY_CMD=python"
    goto :setup_venv
)

echo [LOI] May nay chua cai Python 3.10 tro len (hoac chua them Python vao PATH).
echo Vui long tai Python tai: https://www.python.org/downloads/
echo Luu y: Khi cai dat nho tich chon "Add python.exe to PATH".
pause
exit /b 1

:setup_venv
if exist "%VENV_DIR%" rmdir /s /q "%VENV_DIR%"
echo [1/2] Dang tao moi truong Python (.venv) tren may nay...
%PY_CMD% -m venv "%VENV_DIR%"
if errorlevel 1 (
    echo [LOI] Khong tao duoc moi truong .venv.
    pause
    exit /b 1
)

echo [2/2] Dang cai dat mitmproxy (chi mat khoang 30-60 giay lan dau)...
"%VENV_PY%" -m pip install mitmproxy
if errorlevel 1 (
    echo [LOI] Cai dat mitmproxy that bai. Kiem tra ket noi mang va thu lai.
    pause
    exit /b 1
)

if not exist "%MITM_EXE%" (
    echo [LOI] Khong tim thay mitmdump.exe sau khi cai dat.
    pause
    exit /b 1
)

:run_proxy
echo.
echo === Dia chi IP mang LAN cua may tinh nay (nhap vao Proxy iPhone, cong 8080) ===
ipconfig | findstr /i "IPv4"
echo.
echo Dang khoi dong mitmdump tren cong 8080...
echo Nhan Ctrl+C de dung lai.
echo.
"%MITM_EXE%" --listen-host 0.0.0.0 --listen-port 8080 --allow-hosts "^one\.google\.com(:\d+)?$" --allow-hosts "^mitm\.it(:\d+)?$" -s "%SCRIPT_PY%"
pause
exit /b 0

:missing_script
echo [LOI] Khong tim thay du cac file ma nguon (g1_acq_mitm.py, mapping_config.py, g1_sku_report.py) trong cung thu muc!
echo Hay dam bao chay_g1_acq.bat va cac file .py nam cung 1 folder.
pause
exit /b 1
