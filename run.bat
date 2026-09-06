@echo off
title Nube Privada de Camila - Servidor Local
color 0D
echo ==============================================================================
echo                   NUBE PRIVADA DE CAMILA - SERVIDOR LOCAL
echo ==============================================================================
echo.
echo Iniciando backend y cargando archivos de Google Drive...
echo.

:: Abrir el navegador en segundo plano tras 2 segundos
start /min cmd /c "timeout /t 2 >nul & start http://127.0.0.1:8000"

:: Ejecutar FastAPI
py -3.11 main.py

pause
