@echo off
title Farmacia - Control de Caducidades
cd /d "%~dp0"
echo.
echo  Iniciando sistema de farmacia...
echo  Abre tu navegador en: http://localhost:3000
echo.
start "" "http://localhost:3000"
node server.js
pause
