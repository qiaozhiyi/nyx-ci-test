@echo off
rem === Remaining module selftests ===

echo === nyx_selftest_blind_provider ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_blind_provider
echo %ERRORLEVEL%

echo === nyx_selftest_screenshot ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_screenshot
echo %ERRORLEVEL%

echo === nyx_selftest_recon ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_recon
echo %ERRORLEVEL%

echo === nyx_selftest_calib42 ===
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_calib42
echo %ERRORLEVEL%
