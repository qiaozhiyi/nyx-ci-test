@echo off
echo === hwbp_blind ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_hwbp_blind
echo hwbp=%ERRORLEVEL%

echo === foliage_apc (2s) ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_foliage_apc
echo foliage_apc=%ERRORLEVEL%
