@echo off
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest
set EXITCODE=%ERRORLEVEL%
echo %EXITCODE% > C:\nyx\result.txt
