@echo off
title Activar 400 GB para la Nube de Camila
color 0A
echo ==============================================================================
echo              ACTIVAR CUOTA DE 400 GB - NUBE DE CAMILA
echo ==============================================================================
echo.
echo Iniciando conexion OAuth 2.0 con tu cuenta de Google...
echo Se abrira una ventana en tu navegador para autorizar el acceso a Google Drive.
echo.
python setup_oauth.py
echo.
pause
