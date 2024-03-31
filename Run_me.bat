cls
@echo off & setlocal enabledelayedexpansion
goto start

:: %%%%%%%%%%%%%%%%% find the best ip scanning for rest of code! %%%%%%%%%%%%%%%%%%%%%
:start
if not exist "warp.exe" echo Missing warp.exe file & pause & exit
@echo off
echo 162.159.192.0/24 > ips-v4.txt
echo 162.159.193.0/24 >> ips-v4.txt
echo 162.159.195.0/24 >> ips-v4.txt
echo 188.114.96.0/24 >> ips-v4.txt
echo 188.114.97.0/24 >> ips-v4.txt
echo 188.114.98.0/24 >> ips-v4.txt
echo 188.114.99.0/24 >> ips-v4.txt
goto main

:: my logo and title
:main
title CF WARP IP Scanner designed by mtmoein
echo designed by mtmoein
echo     __  __  _____  __  __   ___   _____  _  _   _ 
echo    ^|  \/  ^|^|_   _^|^|  \/  ^| / _ \ ^| ____^|^| ^|^| \ ^| ^|
echo    ^| ^|\/^| ^|  ^| ^|  ^| ^|\/^| ^|^| ^| ^| ^|^|  _^|  ^| ^|^|  \^| ^|
echo    ^| ^|  ^| ^|  ^| ^|  ^| ^|  ^| ^|^| ^|_^| ^|^| ^|___ ^| ^|^| ^|\  ^|
echo    ^|_^|  ^|_^|  ^|_^|  ^|_^|  ^|_^| \___/ ^|_____^|^|_^|^|_^| \_^|
echo.
set filename=ips-v4.txt & goto getv4
cls
goto main

:getv4
for /f "delims=" %%i in (%filename%) do (
    set !random!_%%i=randomsort
)
for /f "tokens=2,3,4 delims=_.=" %%i in ('set ^| findstr =randomsort ^| sort /m 10240') do (
    call :randomcidrv4
    if not defined %%i.%%j.%%k.!cidr! set %%i.%%j.%%k.!cidr!=anycastip & set /a n+=1
    if !n! EQU 100 goto getip
)
goto getv4

:randomcidrv4
set /a cidr=%random%%%256
goto :eof

:randomcidrv6
set str=0123456789abcdef
set /a r=%random%%%16
set cidr=!str:~%r%,1!
set /a r=%random%%%16
set cidr=!cidr!!str:~%r%,1!
set /a r=%random%%%16
set cidr=!cidr!!str:~%r%,1!
set /a r=%random%%%16
set cidr=!cidr!!str:~%r%,1!
set /a r=%random%%%16
set cidr=!cidr!:!str:~%r%,1!
set /a r=%random%%%16
set cidr=!cidr!!str:~%r%,1!
set /a r=%random%%%16
set cidr=!cidr!!str:~%r%,1!
set /a r=%random%%%16
set cidr=!cidr!!str:~%r%,1!
set /a r=%random%%%16
set cidr=!cidr!:!str:~%r%,1!
set /a r=%random%%%16
set cidr=!cidr!!str:~%r%,1!
set /a r=%random%%%16
set cidr=!cidr!!str:~%r%,1!
set /a r=%random%%%16
set cidr=!cidr!!str:~%r%,1!
set /a r=%random%%%16
set cidr=!cidr!!str:~%r%,1!
goto :eof

:getip
del ip.txt > nul 2>&1
set "first_ip="
for /f "tokens=1 delims==" %%i in ('set ^| findstr =randomsort') do (
    set %%i=
)
for /f "tokens=1 delims==" %%i in ('set ^| findstr =anycastip') do (
    if not defined first_ip set "first_ip=%%i"
    echo %%i>>ip.txt
)
for /f "tokens=1 delims==" %%i in ('set ^| findstr =anycastip') do (
    set %%i=
)
warp
del ip.txt > nul 2>&1
del ips-v4.txt

:: %%%%%%%%%%%%%%%%% Read the second line and extract the IP and port %%%%%%%%%%%%%%%%%%%%%
set "lineCount=0"
for /f "tokens=1* delims=," %%a in (result.csv) do (
    set /a lineCount+=1
    if !lineCount! EQU 2 (
        for /f "tokens=1,2 delims=:" %%i in ("%%a") do (
            set "ipPart=%%i"
            set "portPart=%%j"
            goto saveResult
        )
    )
)

:saveResult
echo !ipPart! > best_user_ip.txt
echo !portPart! >> best_user_ip.txt
echo IP and port have been achived to used in the next part
echo designed by mtmoein
echo     __  __  _____  __  __   ___   _____  _  _   _ 
echo    ^|  \/  ^|^|_   _^|^|  \/  ^| / _ \ ^| ____^|^| ^|^| \ ^| ^|
echo    ^| ^|\/^| ^|  ^| ^|  ^| ^|\/^| ^|^| ^| ^| ^|^|  _^|  ^| ^|^|  \^| ^|
echo    ^| ^|  ^| ^|  ^| ^|  ^| ^|  ^| ^|^| ^|_^| ^|^| ^|___ ^| ^|^| ^|\  ^|
echo    ^|_^|  ^|_^|  ^|_^|  ^|_^|  ^|_^| \___/ ^|_____^|^|_^|^|_^| \_^|

:: %%%%%%%%%%% Run the exe and redirect the output to a temporary file %%%%%%%%%%%%%%%
main-windows-amd64.exe > output.txt

:: Initialize variables to hold the data we want to extract
set private_key=
set reserved=
set v6=

:: Extract the required values from the output
for /F "tokens=1* delims=: " %%a in (output.txt) do (
    if "%%a"=="private_key" set private_key=%%b
    if "%%a"=="reserved" set reserved=%%b
    if "%%a"=="v6" set v6=%%b/128
)

:: Read the current txt file and store the first 2 lines
set "linecounter=0"
set "newcontent="
for /F "delims=" %%i in (best_user_ip.txt) do (
    set /a linecounter+=1
    if !linecounter! leq 2 (
        set newcontent=!newcontent!%%i^

    )
    if !linecounter! gtr 2 (
        goto :writeNewContent
    )
)

:writeNewContent
:: Write the first 2 lines, the exe output, and then the rest back to the txt file
(
    echo(!newcontent!
    echo(!private_key!
    echo(!reserved!
    echo(!v6!
) > best_user_ip.txt

echo first warp acc was made!
:: Read the file again for second time!
main-windows-amd64.exe > output.txt

:: Initialize variables to hold the data we want to extract
set private_key=
set reserved=
set v6=

:: Extract the required values from the output
for /F "tokens=1* delims=: " %%a in (output.txt) do (
    if "%%a"=="private_key" set private_key=%%b
    if "%%a"=="reserved" set reserved=%%b
    if "%%a"=="v6" set v6=%%b/128
)

:: Read the current txt file and store the first 7 lines
set "linecounter=0"
set "newcontent="
for /F "delims=" %%i in (best_user_ip.txt) do (
    set /a linecounter+=1
    if !linecounter! leq 7 (
        set newcontent=!newcontent!%%i^

    )
    if !linecounter! gtr 7 (
        goto :writeNewContent
    )
)

:writeNewContent
:: Write the first 7 lines, the exe output, and then the rest back to the txt file
(
    echo(!newcontent!
    echo(!private_key!
    echo(!reserved!
    echo(!v6!
) > best_user_ip.txt

del output.txt
echo second warp acc was made!
:: %%%%%%%%%%%%%%%%%%% Read values from best_user_ip.txt and assign them to variables %%%%%%%%%%%%%%%%%%%
set /a count=0
for /F "tokens=*" %%i in (best_user_ip.txt) do (
    set /a count+=1
    if !count!==1 set "A=%%i"
    if !count!==2 set "B=%%i"
    if !count!==4 set "C=%%i"
    if !count!==5 set "D=%%i"
    if !count!==6 set "E=%%i"
    if !count!==8 set "F=%%i"
    if !count!==9 set "G=%%i"
    if !count!==10 set "H=%%i"
)

:: clean best_user_ip_file
del best_user_ip.txt

:: Remove any leading and trailing spaces
for %%a in (A B C D E F G H) do (
    call :trim %%a
)

:: Create the JSON structure with the variables
> vpn.txt (
    echo { 
    echo   "outbounds": [
    echo     {
    echo       "type": "wireguard",
    echo       "tag": "Warp-IR",
    echo       "local_address": [
    echo         "172.16.0.2/32",
    echo         "!E!"
    echo       ],
    echo       "private_key": "!C!",
    echo       "server": "!A!",
    echo       "server_port": !B!,
    echo       "peer_public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
    echo       "reserved": !D!,
    echo       "mtu": 1280,
    echo       "fake_packets": "5-10"
    echo     },
    echo     {
    echo       "type": "wireguard",
    echo       "tag": "Warp-Main",
    echo       "detour": "Warp-IR",
    echo       "local_address": [
    echo         "172.16.0.2/32",
    echo         "!H!"
    echo       ],
    echo       "private_key": "!F!",
    echo       "server": "!A!",
    echo       "server_port": !B!,
    echo       "peer_public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
    echo       "reserved": !G!,
    echo       "mtu": 1280,
    echo       "fake_packets": "5-10"
    echo     }
    echo   ]
    echo }
)

:: Copy the output to the clipboard
type vpn.txt | clip
echo your vpn.txt file is ready now and copied to clipboard enjoy! :D



:trim
set "var=!%1!"
for /F "tokens=*" %%a in ("!var!") do set "var=%%a"
for /l %%a in (1,1,100) do if "!var:~-1!"==" " set "var=!var:~0,-1!"
for /l %%a in (1,1,100) do if "!var:~0,1!"==" " set "var=!var:~1!"
endlocal & set "%1=!var!"
goto :eof
