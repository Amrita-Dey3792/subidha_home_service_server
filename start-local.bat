@echo off
echo Starting Subidha Home Services Server...
echo.
echo Checking if Node.js is installed...
node --version
if %errorlevel% neq 0 (
    echo Error: Node.js is not installed or not in PATH
    pause
    exit /b 1
)

echo.
echo Installing dependencies...
npm install

echo.
echo Starting server on http://localhost:5000
echo Press Ctrl+C to stop the server
echo.
npm start

pause
