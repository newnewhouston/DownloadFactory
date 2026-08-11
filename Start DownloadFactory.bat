@echo off
REM ============================================================
REM  DownloadFactory v1.0 - launcher
REM  Starts the local shell on 127.0.0.1:8133 and opens the UI.
REM  Close this window (or Ctrl+C) to stop everything: the
REM  Transmission daemon, the yt-dlp worker and the VPN watchdog
REM  are all shut down cleanly on exit.
REM ============================================================
title DownloadFactory v1.0

REM UTF-8 for this window only, so the banner renders as lines
REM instead of mojibake.
chcp 65001 >nul

cd /d "%~dp0"

REM Find a python that actually runs. "python" on PATH is the Microsoft
REM Store stub on this machine - it errors instead of launching - so the
REM py launcher is tried first and the stub is never used.
set "PY="
py -3 -c "import sys" >nul 2>&1 && set "PY=py -3"

if not defined PY (
  for %%P in (
    "%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
    "%ProgramFiles%\Python313\python.exe"
    "%ProgramFiles%\Python312\python.exe"
  ) do (
    if not defined PY if exist %%P set "PY=%%P"
  )
)

if not defined PY (
  echo.
  echo   Could not find a working Python 3.
  echo   Install it from python.org, or from the Microsoft Store,
  echo   then run this file again.
  echo.
  pause
  exit /b 1
)

%PY% "DownloadFactory 1.0.py" %*

if errorlevel 1 (
  echo.
  echo   DownloadFactory exited with an error.
  pause
)
