@echo off
setlocal enabledelayedexpansion
echo === selftest ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest >nul 2>&1
echo selftest=!ERRORLEVEL!

echo === rt_steps ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_rt_steps >nul 2>&1
echo rt_steps=!ERRORLEVEL!

echo === gap_scan ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_gap_scan >nul 2>&1
echo gap_scan=!ERRORLEVEL!

echo === mem ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_mem >nul 2>&1
echo mem=!ERRORLEVEL!

echo === blind_nttrace ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_blind_nttrace >nul 2>&1
echo blind_nttrace=!ERRORLEVEL!

echo === antidebug ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_antidebug >nul 2>&1
echo antidebug=!ERRORLEVEL!

echo === inject ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_inject >nul 2>&1
echo inject=!ERRORLEVEL!

echo === hostinfo ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_hostinfo >nul 2>&1
echo hostinfo=!ERRORLEVEL!

echo === foliage ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_foliage >nul 2>&1
echo foliage=!ERRORLEVEL!

echo === foliage_apc ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_foliage_apc >nul 2>&1
echo foliage_apc=!ERRORLEVEL!

echo === swap_decision ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_swap_decision >nul 2>&1
echo swap_decision=!ERRORLEVEL!

echo === swap_armed ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_swap_armed >nul 2>&1
echo swap_armed=!ERRORLEVEL!

echo === hwbp_blind ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_hwbp_blind >nul 2>&1
echo hwbp_blind=!ERRORLEVEL!
