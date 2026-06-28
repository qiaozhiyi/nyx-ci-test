@echo off
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_hwbp_blind
echo hwbp=%ERRORLEVEL% > C:\nyx\hwbp_result.txt
