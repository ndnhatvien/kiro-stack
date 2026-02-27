@echo off
setlocal

title Kiro Stack Launcher

:: ============================================
:: Kiro Stack - Run without Docker
:: ============================================

:: Check .env file exists
if not exist ".env" (
    echo [ERROR] .env file not found.
    echo Please run: copy .env.example .env
    echo Then edit .env with your settings.
    pause
    exit /b 1
)

:: Parse .env file (skip comments and empty lines)
for /f "usebackq eol=# tokens=1,* delims==" %%A in (".env") do (
    if not "%%B"=="" set "%%A=%%B"
)

:: Validate required vars
if not defined ADMIN_PASSWORD (
    echo [ERROR] ADMIN_PASSWORD is not set in .env
    pause
    exit /b 1
)
if not defined INTERNAL_API_KEY (
    echo [ERROR] INTERNAL_API_KEY is not set in .env
    pause
    exit /b 1
)

:: Check Go installed
where go >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Go not found. Install from https://go.dev/dl/
    pause
    exit /b 1
)

:: Check Python installed
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found. Install from https://python.org/downloads/
    pause
    exit /b 1
)

echo ============================================
echo   Kiro Stack - Starting...
echo ============================================
echo.

:: Build kiro-go if needed
if not exist "kiro-go\kiro-go.exe" (
    echo [BUILD] Building kiro-go...
    pushd kiro-go
    go build -o kiro-go.exe .
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to build kiro-go
        popd
        pause
        exit /b 1
    )
    popd
    echo [BUILD] kiro-go built successfully.
)

:: Install Python deps if needed
pip show fastapi >nul 2>&1
if %errorlevel% neq 0 (
    echo [SETUP] Installing Python dependencies...
    pip install -r kiro-gateway\requirements.txt
)

echo.
echo [START] Starting kiro-gateway on port 8000...
start "Kiro Gateway" cmd /k "cd /d "%~dp0kiro-gateway" && set "PROXY_API_KEY=%INTERNAL_API_KEY%" && set "SKIP_STARTUP_CREDENTIAL_CHECK=true" && set "VPN_PROXY_URL=%VPN_PROXY_URL%" && set "DEBUG_MODE=%DEBUG_MODE%" && python main.py"

:: Wait for gateway to start
echo [WAIT] Waiting for gateway to start...
timeout /t 3 /nobreak >nul

echo [START] Starting kiro-go on port 8080...
start "Kiro Go" cmd /k "cd /d "%~dp0kiro-go" && set "ADMIN_PASSWORD=%ADMIN_PASSWORD%" && set "CONFIG_PATH=data\config.json" && set "KIRO_GATEWAY_BASE=http://127.0.0.1:8000" && set "KIRO_GATEWAY_API_KEY=%INTERNAL_API_KEY%" && kiro-go.exe"

echo.
echo ============================================
echo   Kiro Stack started.
echo.
echo   Admin Panel: http://127.0.0.1:8080/admin
echo   OpenAI API:  http://127.0.0.1:8080/v1/chat/completions
echo   Claude API:  http://127.0.0.1:8080/v1/messages
echo ============================================
echo.
pause
