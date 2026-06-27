@echo off
echo === foliage_apc ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_foliage_apc >nul 2>&1
echo foliage_apc=!ERRORLEVEL!
echo === hwbp_blind ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_hwbp_blind >nul 2>&1
echo hwbp_blind=!ERRORLEVEL!
echo === blind_nttrace ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_blind_nttrace >nul 2>&1
echo blind_nttrace=!ERRORLEVEL!
echo === swap_armed ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_swap_armed >nul 2>&1
echo swap_armed=!ERRORLEVEL!
echo === selftest ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest >nul 2>&1
echo selftest=!ERRORLEVEL!
