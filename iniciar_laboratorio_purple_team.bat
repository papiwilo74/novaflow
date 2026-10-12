@echo off
title Laboratorio Purple Team: OmniBreach vs NovaFlow en OrderFlowApp
color 0B
chcp 65001 > nul
cls
echo =========================================================================
echo       INICIANDO LABORATORIO PURPLE TEAM (OMNIBREACH vs NOVAFLOW)
echo =========================================================================
echo.
echo [1/3] Verificando entorno Python...
set PYTHON_EXE=C:\Users\villa\VulnScanner\venv\Scripts\python.exe
if not exist "%PYTHON_EXE%" (
    set PYTHON_EXE=python
)

echo [2/3] Ejecutando orquestador de ciberseguridad...
echo.
"%PYTHON_EXE%" tools\purple_team_lab.py

echo.
echo =========================================================================
echo [OK] Demostración finalizada. Presiona cualquier tecla para salir...
echo =========================================================================
pause > nul
