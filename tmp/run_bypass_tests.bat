@echo off
setlocal enabledelayedexpansion
rem === Nyx Full Bypass Module Selftest on WS2019 (17763) ===

set DLL=C:\nyx\nyx_implant_win.dll
set LOG=C:\nyx\bypass_test_log.txt

echo Nyx Bypass Module Full Selftest > %LOG%
echo Date: %DATE% %TIME% >> %LOG%
echo. >> %LOG%
echo ============================================ >> %LOG%

echo [01] calib42 (exit code propagation check)
echo [01] calib42 >> %LOG%
rundll32 %DLL%,nyx_selftest_calib42 >nul 2>&1
set c=!ERRORLEVEL!
echo   exit=!c!
echo   exit=!c! >> %LOG%

echo [02] antidebug (PEB + uptime + syscall)
echo [02] antidebug >> %LOG%
rundll32 %DLL%,nyx_selftest_antidebug >nul 2>&1
set c=!ERRORLEVEL!
echo   exit=!c!
echo   exit=!c! >> %LOG%

echo [03] syscall_rt (indirect syscall runtime)
echo [03] syscall_rt >> %LOG%
rundll32 %DLL%,nyx_selftest_syscall_rt >nul 2>&1
set c=!ERRORLEVEL!
echo   exit=!c!
echo   exit=!c! >> %LOG%

echo [04] rt_probe (runtime resolve probe)
echo [04] rt_probe >> %LOG%
rundll32 %DLL%,nyx_selftest_rt_probe >nul 2>&1
set c=!ERRORLEVEL!
echo   exit=!c!
echo   exit=!c! >> %LOG%

echo [05] rt_steps (runtime init steps)
echo [05] rt_steps >> %LOG%
rundll32 %DLL%,nyx_selftest_rt_steps >nul 2>&1
set c=!ERRORLEVEL!
echo   exit=!c!
echo   exit=!c! >> %LOG%

echo [06] blind_nttrace (ETW NtTraceEvent byte-patch)
echo [06] blind_nttrace >> %LOG%
rundll32 %DLL%,nyx_selftest_blind_nttrace >nul 2>&1
set c=!ERRORLEVEL!
echo   exit=!c!
echo   exit=!c! >> %LOG%

echo [07] hwbp_blind (HW breakpoint ETW/AMSI)
echo [07] hwbp_blind >> %LOG%
rundll32 %DLL%,nyx_selftest_hwbp_blind >nul 2>&1
set c=!ERRORLEVEL!
echo   exit=!c!
echo   exit=!c! >> %LOG%

echo [08] blind_provider (ETW provider disable)
echo [08] blind_provider >> %LOG%
rundll32 %DLL%,nyx_selftest_blind_provider >nul 2>&1
set c=!ERRORLEVEL!
echo   exit=!c!
echo   exit=!c! >> %LOG%

echo [09] foliage (basic sleep mask 1s)
echo [09] foliage >> %LOG%
rundll32 %DLL%,nyx_selftest_foliage >nul 2>&1
set c=!ERRORLEVEL!
echo   exit=!c!
echo   exit=!c! >> %LOG%

echo [10] foliage_apc (full APC chain 2s)
echo [10] foliage_apc >> %LOG%
rundll32 %DLL%,nyx_selftest_foliage_apc >nul 2>&1
set c=!ERRORLEVEL!
echo   exit=!c!
echo   exit=!c! >> %LOG%

echo [11] gap_scan (BYOUD-Gap enumeration)
echo [11] gap_scan >> %LOG%
rundll32 %DLL%,nyx_selftest_gap_scan >nul 2>&1
set c=!ERRORLEVEL!
echo   exit=!c!
echo   exit=!c! >> %LOG%

echo [12] swap_decision (stack spoof decision)
echo [12] swap_decision >> %LOG%
rundll32 %DLL%,nyx_selftest_swap_decision >nul 2>&1
set c=!ERRORLEVEL!
echo   exit=!c!
echo   exit=!c! >> %LOG%

echo [13] swap_armed (live RSP swap)
echo [13] swap_armed >> %LOG%
rundll32 %DLL%,nyx_selftest_swap_armed >nul 2>&1
set c=!ERRORLEVEL!
echo   exit=!c!
echo   exit=!c! >> %LOG%

echo [14] mem (RC4 memory mask/unmask)
echo [14] mem >> %LOG%
rundll32 %DLL%,nyx_selftest_mem >nul 2>&1
set c=!ERRORLEVEL!
echo   exit=!c!
echo   exit=!c! >> %LOG%

echo [15] inject (module stomping skeleton)
echo [15] inject >> %LOG%
rundll32 %DLL%,nyx_selftest_inject >nul 2>&1
set c=!ERRORLEVEL!
echo   exit=!c!
echo   exit=!c! >> %LOG%

echo [16] inject_armed (full module stomping)
echo [16] inject_armed >> %LOG%
rundll32 %DLL%,nyx_selftest_inject_armed >nul 2>&1
set c=!ERRORLEVEL!
echo   exit=!c!
echo   exit=!c! >> %LOG%

echo [17] hostinfo (hostname + user + PID)
echo [17] hostinfo >> %LOG%
rundll32 %DLL%,nyx_selftest_hostinfo >nul 2>&1
set c=!ERRORLEVEL!
echo   exit=!c!
echo   exit=!c! >> %LOG%

echo [18] alloc_probe (heap allocation)
echo [18] alloc_probe >> %LOG%
rundll32 %DLL%,nyx_selftest_alloc_probe >nul 2>&1
set c=!ERRORLEVEL!
echo   exit=!c!
echo   exit=!c! >> %LOG%

echo [19] shell (command execution)
echo [19] shell >> %LOG%
rundll32 %DLL%,nyx_selftest_shell >nul 2>&1
set c=!ERRORLEVEL!
echo   exit=!c!
echo   exit=!c! >> %LOG%

echo [20] net (network interfaces)
echo [20] net >> %LOG%
rundll32 %DLL%,nyx_selftest_net >nul 2>&1
set c=!ERRORLEVEL!
echo   exit=!c!
echo   exit=!c! >> %LOG%

echo. >> %LOG%
echo ============================================ >> %LOG%
echo TEST COMPLETE >> %LOG%
echo ============================================ >> %LOG%

echo.
echo ============================================
echo  TEST COMPLETE
echo ============================================
