@echo off
REM Script to block an IP address using Windows Firewall
REM Usage: block_ip.bat <IP_ADDRESS>

if "%1"=="" (
    echo Usage: %0 ^<IP_ADDRESS^>
    exit /b 1
)

set IP_ADDRESS=%1

REM Log the blocking action
echo %date% %time%: Blocking IP address %IP_ADDRESS% >> %TEMP%\cybersec-blocks.log

REM Create a Windows Firewall rule
netsh advfirewall firewall add rule name="CYBERSECJADE_BLOCK_%IP_ADDRESS:.=_%" dir=in action=block remoteip=%IP_ADDRESS%

if %ERRORLEVEL% == 0 (
    echo Successfully blocked IP address: %IP_ADDRESS%
    exit /b 0
) else (
    echo Failed to block IP address: %IP_ADDRESS%
    exit /b 1
)