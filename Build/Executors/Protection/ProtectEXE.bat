@echo off
setlocal EnableExtensions DisableDelayedExpansion

rem ---------------------------------------------------------------------------
rem ProtectEXE.bat - VMProtect stage for the deployed launcher.
rem
rem Runs against the release copy of the Interface EXE (Build\Release\*.exe),
rem after Create.bat has produced it. The runtime DLL is untouched.
rem
rem One extra invariant is enforced here that the DLL stage does not need: the
rem launcher embeds the runtime DLL's SHA-256 as eight little-endian dwords and
rem refuses to start when they disagree. Virtualization rewrites the EXE's code
rem sections, so the embedded words are re-verified against the live runtime DLL
rem afterwards. A mismatch aborts rather than shipping a launcher that bricks on
rem start.
rem
rem CLI shape (vmpsoft.com console documentation):
rem   VMProtect_Con.exe <file> [output] [-pf proj] [-sf script] [-lf lic]
rem                                 [-bd yyyy-mm-dd] [-wm name] [-we]
rem Protection *modes* (Ultra / Mutation / Virtualization) and the Complexity
rem and Instances figures are properties of the .vmp project, not CLI flags.
rem ---------------------------------------------------------------------------

set "NO_PAUSE=0"
if defined CREATE_NO_PAUSE set "NO_PAUSE=%CREATE_NO_PAUSE%"
if /i "%~1"=="/nopause" set "NO_PAUSE=1"

set "C_RESET="
set "C_GREEN="
set "C_RED="
set "C_YELLOW="
if /i not "%AMEGER_NO_COLOR%"=="1" for /f %%A in ('echo prompt $E ^| cmd') do set "ESC=%%A"
if defined ESC (
    set "C_RESET=%ESC%[0m"
    set "C_GREEN=%ESC%[92m"
    set "C_RED=%ESC%[91m"
    set "C_YELLOW=%ESC%[93m"
)

rem This script lives in Build\Executors\Protection\, so the repository root is
rem three levels up. Two levels would land on Build\ itself.
for %%I in ("%~dp0..\..\..") do set "ROOT=%%~fI"
set "BUILD_DIR=%ROOT%\Build"
set "OUT_ROOT=%BUILD_DIR%\Release"
set "DLL_DIR=%OUT_ROOT%\DLLs"
set "RELEASE_CACHE=%OUT_ROOT%\Cache"
set "WORK_DIR=%RELEASE_CACHE%\Protect"
set "ASSET_TPL=%ROOT%\Assets\Template"
set "SCRIPTS_DIR=%BUILD_DIR%\Scripts"
set "BUILD_VMP_SCRIPT=%SCRIPTS_DIR%\BuildVMP.ps1"
set "STRIP_SCRIPT=%SCRIPTS_DIR%\StripExporting.ps1"
rem Kept outside WORK_DIR so the idempotency record survives the cleanup.
set "STATE_FILE=%RELEASE_CACHE%\Protect.exe.state"
set "VERIFY_SCRIPT=%BUILD_DIR%\Scripts\VerifyEmbedMagic.ps1"
set "VMP_PROJECT=%AMEGER_VMP_PROJECT_EXE%"
set "VMP_CON="

echo [%C_GREEN%1%C_RESET%/%C_GREEN%6%C_RESET%] Locating VMProtect console...
echo.
call :find_vmp_con
if errorlevel 1 goto :vmp_missing
echo   %C_GREEN%[+]%C_RESET% Console: %C_GREEN%%VMP_CON%%C_RESET%
echo.
echo.

echo [%C_GREEN%2%C_RESET%/%C_GREEN%6%C_RESET%] Resolving launcher target...
echo.
if not exist "%OUT_ROOT%" (
  echo   %C_RED%ERROR: release folder not found: %OUT_ROOT%%C_RESET%
  goto :failure
)
set "TARGET="
set "RUNTIME_DLL="
for %%F in ("%OUT_ROOT%\*.exe") do call :consider_exe "%%~fF"
if not defined TARGET goto :target_missing
if not exist "%TARGET%" goto :target_missing
for %%N in ("%TARGET%") do set "TARGET_NAME=%%~nxN"
echo   %C_GREEN%[+]%C_RESET% Target:  %C_GREEN%%TARGET%%C_RESET%
if defined RUNTIME_DLL (
  echo   %C_GREEN%[+]%C_RESET% Runtime: %C_GREEN%%RUNTIME_DLL%%C_RESET% ^(left unvirtualized^)
) else (
  echo   %C_YELLOW%[+]%C_RESET% Runtime DLL not found; embedded-hash check will be skipped.
)
call :check_already_protected
if defined VMP_PRESENT if /i not "%AMEGER_FORCE_VMP%"=="1" (
  echo   %C_GREEN%[+]%C_RESET% Already protected ^(segment %C_YELLOW%%VMP_PRESENT%%C_RESET%^); skipping.
  echo   %C_YELLOW%       Set AMEGER_FORCE_VMP=1 to virtualize anyway.%C_RESET%
  goto :already_protected
)
echo.
echo.

echo [%C_GREEN%3%C_RESET%/%C_GREEN%6%C_RESET%] Resolving VMProtect project...
echo.
call :find_project
if errorlevel 1 goto :project_missing
echo   %C_GREEN%[+]%C_RESET% Project: %C_GREEN%%VMP_PROJECT%%C_RESET%
echo.
call :check_project_input
if errorlevel 1 goto :project_mismatch
call :vmp_settings
echo.
call :read_state
echo.
if /i "%STATE_MATCH%"=="output" (
  echo   %C_GREEN%[+]%C_RESET% Already protected; nothing to do.
  goto :already_done
)
if /i "%STATE_MATCH%"=="unknown" (
  echo   %C_YELLOW%[+]%C_RESET% No prior state recorded; protecting now.
) else (
  echo   %C_GREEN%[+]%C_RESET% Source matches recorded build; protecting.
)
echo.
echo.

echo [%C_GREEN%4%C_RESET%/%C_GREEN%6%C_RESET%] Virtualizing launcher...
echo.
call :clean_work
if errorlevel 1 goto :work_error
if not exist "%WORK_DIR%" mkdir "%WORK_DIR%"
if not exist "%WORK_DIR%" goto :work_error
call :sha256_of "%TARGET%" SRC_SHA
if errorlevel 1 goto :hash_error
if not defined SRC_SHA goto :hash_error
echo   Source SHA-256: %C_GREEN%%SRC_SHA%%C_RESET%
rem Work on a build-local copy of the project with a randomized protector
rem segment name, so the segment is not a fixed executable section that
rem identifies every build as protected.
call :prepare_project
if errorlevel 1 goto :project_error
echo   %C_GREEN%[+]%C_RESET% Segment name: %C_GREEN%%SEG_NAME%%C_RESET% %C_YELLOW%(randomized per build)%C_RESET%
rem -we promotes VMProtect warnings to errors so a partial protection cannot
rem pass for a completed one.
"%VMP_CON%" "%TARGET%" "%WORK_DIR%\out.exe" -pf "%PROJ_WORK%" -we > "%WORK_DIR%\vmp.log" 2>&1
if errorlevel 1 (
  echo   %C_RED%ERROR: VMProtect reported a failure; see the log tail below.%C_RESET%
  call :tail_log
  goto :failure
)
call :validate_output
if errorlevel 1 goto :output_invalid
echo.
echo   %C_GREEN%OK%C_RESET% Protected output validated.
echo.
copy /y "%WORK_DIR%\out.exe" "%TARGET%" > nul
if errorlevel 1 goto :deploy_error
call :sha256_of "%TARGET%" OUT_SHA
if errorlevel 1 goto :hash_error
echo   %C_GREEN%[+]%C_RESET% Output SHA-256: %C_GREEN%%OUT_SHA%%C_RESET%
echo.
echo.

echo [%C_GREEN%5%C_RESET%/%C_GREEN%6%C_RESET%] Verifying embedded runtime hash...
echo.
rem The launcher will abort at startup if these eight dwords stop matching the
rem runtime DLL, so confirm virtualization did not disturb them.
if not defined RUNTIME_DLL goto :embed_skipped
if not exist "%VERIFY_SCRIPT%" goto :embed_skipped
call :runtime_hash_words
if errorlevel 1 goto :embed_error
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VERIFY_SCRIPT%" -Check Embed -Path "%TARGET%" -Words "%H0%,%H1%,%H2%,%H3%,%H4%,%H5%,%H6%,%H7%"
if errorlevel 1 goto :embed_error
echo   %C_GREEN%[+]%C_RESET% Embedded runtime hash intact after virtualization.
goto :embed_ok

:embed_skipped
echo   %C_YELLOW%[+]%C_RESET% Skipped; nothing to verify against.

:embed_ok
call :write_state
echo.
echo.

echo [%C_GREEN%6%C_RESET%/%C_GREEN%6%C_RESET%] Sweeping protection artifacts...
echo.
call :clean_work
if errorlevel 1 goto :cleanup_error
call :assert_clean
if errorlevel 1 goto :cleanup_error
echo   %C_GREEN%[+]%C_RESET% No VMProtect traces in %C_GREEN%%OUT_ROOT%%C_RESET%.
echo.
echo Launcher protection completed.
echo.
echo Interface x64: %C_GREEN%%TARGET%%C_RESET%
if "%NO_PAUSE%"=="0" pause
exit /b 0

rem ---------------------------------------------------------------------------

:already_protected
echo.
echo Launcher is already VMProtect-protected; release unchanged.
echo.
if "%NO_PAUSE%"=="0" pause
exit /b 0

:check_already_protected
rem Detect an already-protected image against the baseline that Create.bat
rem recorded in Cache\pe-sections.txt. A ".vmp*" name prefix is not a usable
rem signal (VMProtect 3.8.4 emitted ".Tlp" for this project), and neither is
rem "is the section name standard" (BuildPE.ps1 deliberately renames .text to
rem .main and friends, so that heuristic flags our own pristine build as
rem protected and blocks protection forever). Comparing against the recorded
rem post-mutation baseline is exact: any EXECUTABLE section absent from the
rem baseline was added by the protector.
set "VMP_PRESENT="
set "BASELINE="
if exist "%RELEASE_CACHE%\pe-sections.txt" for /f "usebackq tokens=1,* delims=:" %%A in ("%RELEASE_CACHE%\pe-sections.txt") do if /i "%%A"=="%TARGET_NAME%" set "BASELINE=%%B"
if not defined BASELINE set "BASELINE=@none@"
for /f "usebackq tokens=1,* delims==" %%A in (`powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$base=('%BASELINE%').Split(','); $b=[IO.File]::ReadAllBytes('%TARGET%'); $e=[BitConverter]::ToInt32($b,0x3C); $c=$e+4; $n=[BitConverter]::ToUInt16($b,$c+2); $z=[BitConverter]::ToUInt16($b,$c+16); $s=$c+20+$z; for($i=0;$i -lt $n;$i++){ $o=$s+40*$i; $nm=[Text.Encoding]::ASCII.GetString($b,$o,8).Trim([char]0); $x=[BitConverter]::ToUInt32($b,$o+36); if($x -band 0x20000000){ $tag=$nm+'+X' } else { $tag=$nm }; if($base -notcontains $tag){ Write-Output ('VMP_PRESENT=' + $nm) } }"`) do set "%%A=%%B"
exit /b 0

:already_done
echo.
echo [%C_GREEN%6%C_RESET%/%C_GREEN%6%C_RESET%] Sweeping protection artifacts...
echo.
call :clean_work
if errorlevel 1 goto :cleanup_error
call :assert_clean
if errorlevel 1 goto :cleanup_error
echo   %C_GREEN%[+]%C_RESET% No VMProtect traces in %C_GREEN%%OUT_ROOT%%C_RESET%.
echo.
echo Launcher already protected; release unchanged.
echo.
echo Interface x64: %C_GREEN%%TARGET%%C_RESET%
if "%NO_PAUSE%"=="0" pause
exit /b 0

:consider_exe
set "CANDIDATE=%~1"
if not defined CANDIDATE exit /b 0
if defined TARGET exit /b 0
set "TARGET=%CANDIDATE%"
for %%F in ("%DLL_DIR%\rtdll_*.dll") do if not defined RUNTIME_DLL set "RUNTIME_DLL=%%~fF"
exit /b 0

:prepare_project
rem Randomized per build so the protector's segment is not a stable signature.
set "PROJ_WORK=%WORK_DIR%\project.vmp"
set "SEG_NAME="
for /f "usebackq tokens=1,* delims==" %%A in (`powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%BUILD_VMP_SCRIPT%" -Project "%VMP_PROJECT%" -Out "%PROJ_WORK%"`) do set "%%A=%%B"
if not exist "%PROJ_WORK%" exit /b 1
if not defined SEG_NAME exit /b 1
exit /b 0

:find_vmp_con
if defined AMEGER_VMP_CON if exist "%AMEGER_VMP_CON%" (
  set "VMP_CON=%AMEGER_VMP_CON%"
  goto :vmp_con_bat_check
)
rem Match the install family, not one folder name. VMProtect ships as
rem "VMProtect", "VMProtect Professional", "VMProtect Ultimate" and so on, so a
rem hardcoded "VMProtect" prefix silently misses every edition except the
rem plain one. Later matches never override an earlier find.
call :scan_vmp_dirs "%ProgramFiles%"
call :scan_vmp_dirs "%ProgramW6432%"
call :scan_vmp_dirs "%ProgramFiles(x86)%"
call :scan_vmp_dirs "%LOCALAPPDATA%"
call :scan_vmp_dirs "%ALLUSERSPROFILE%"
if not defined VMP_CON for /f "delims=" %%E in ('where VMProtect_Con.exe 2^>nul') do if not defined VMP_CON set "VMP_CON=%%E"
if not defined VMP_CON for /f "delims=" %%E in ('where vmpconsole.exe 2^>nul') do if not defined VMP_CON set "VMP_CON=%%E"
if not defined VMP_CON exit /b 1
:vmp_con_bat_check
rem Normalize before use. AMEGER_VMP_CON is very commonly set with surrounding
rem quotes, and a for-variable scanned out of a quoted list can carry them too.
rem Either way a quoted value breaks the invocation below: "%VMP_CON%" expands
rem to ""C:\Program Files\..."" and cmd reports '""C:\Program" is not
rem recognized' because it parses the doubled quote as part of the command. A
rem filesystem path never legitimately contains a quote, so drop them all.
set "VMP_CON=%VMP_CON:"=%"
if not exist "%VMP_CON%" exit /b 1
rem Reject batch/cmd wrappers. Invoking a .bat without CALL transfers control
rem and never returns, so a wrapper's "exit /b 0" would end this script right
rem after the call site and report success having protected nothing.
echo "%VMP_CON%" | findstr /i /r "\.bat$ \.cmd$" > nul && exit /b 2
exit /b 0

:scan_vmp_dirs
rem "for /d" is required here: a plain "for" treats a quoted wildcard as a
rem literal filename and never expands it, so the family match silently finds
rem nothing. The quotes are still required because the install path has a space.
for /d %%D in ("%~1\VMProtect*") do if not defined VMP_CON for %%E in ("%%~fD\VMProtect_Con.exe" "%%~fD\VMProtect_Console.exe" "%%~fD\vmpconsole.exe") do if not defined VMP_CON if exist "%%E" set "VMP_CON=%%E"
exit /b 0

rem Project resolution order: explicit override, then a project named after the
rem resolved target (<name>.vmp), then any .vmp in the stage folder. The
rem name-matched step is load-bearing: the folder holds both the payload and
rem the launcher template, and a plain alphabetical scan would hand the
rem launcher stage the payload's project.
:find_project
if defined AMEGER_VMP_PROJECT_EXE if exist "%AMEGER_VMP_PROJECT_EXE%" (
  set "VMP_PROJECT=%AMEGER_VMP_PROJECT_EXE%"
  exit /b 0
)
if exist "%ASSET_TPL%\%TARGET_NAME%.vmp" (
  set "VMP_PROJECT=%ASSET_TPL%\%TARGET_NAME%.vmp"
  exit /b 0
)
if exist "%~dp0%TARGET_NAME%.vmp" (
  set "VMP_PROJECT=%~dp0%TARGET_NAME%.vmp"
  exit /b 0
)
for %%F in ("%ASSET_TPL%\*.vmp") do if not defined VMP_PROJECT set "VMP_PROJECT=%%~fF"
if defined VMP_PROJECT if exist "%VMP_PROJECT%" exit /b 0
for %%F in ("%~dp0*.vmp") do if not defined VMP_PROJECT set "VMP_PROJECT=%%~fF"
if defined VMP_PROJECT if exist "%VMP_PROJECT%" exit /b 0
set "VMP_PROJECT="
exit /b 1

:check_project_input
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$x=[xml][IO.File]::ReadAllText('%VMP_PROJECT%'); $i=[string]$x.Document.Protection.InputFileName; if($i -eq '%TARGET_NAME%'){exit 0}; Write-Host ('    project targets: ' + $i); exit 1"
exit /b %ERRORLEVEL%

:vmp_settings
rem Report what the resolved project actually contains rather than a hardcoded
rem reminder, so this block can never drift from the .vmp on disk. The
rem CompilationType values are reported verbatim and deliberately not
rem interpreted: VMProtect documents Mutation, Virtualization and
rem "ultra (virtualization+mutation)" as three distinct compilation types
rem (VMProtectBeginMutation / VMProtectBeginVirtualization /
rem VMProtectBeginUltra), so the numeric values are not a bitmask and this
rem script must not guess which one means what.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$x=[xml][IO.File]::ReadAllText('%VMP_PROJECT%'); $p=$x.Document.Protection; Write-Host ('    Input         : ' + $p.InputFileName); Write-Host ('    VM complexity : ' + $p.VMComplexity); Write-Host ('    VM instances  : ' + $p.VMInstances); Write-Host ('    Options       : ' + $p.Options); Write-Host '    Procedures    :'; foreach($q in $p.Procedures.Procedure){ Write-Host ('      - ' + $q.MapAddress + '  CompilationType=' + $q.CompilationType + '  Complexity=' + $q.Complexity) }"
exit /b 0

:read_state
set "STATE_MATCH=unknown"
set "STATE_HASH="
if not exist "%STATE_FILE%" exit /b 0
set "SRC="
set "OUT="
for /f "usebackq tokens=1,* delims==" %%A in ("%STATE_FILE%") do set "%%A=%%B"
if not defined OUT exit /b 0
call :sha256_of "%TARGET%" CUR
if errorlevel 1 exit /b 0
if /i "%CUR%"=="%OUT%" (
  set "STATE_MATCH=output"
  exit /b 0
)
if defined SRC if /i "%CUR%"=="%SRC%" (
  set "STATE_MATCH=source"
  set "STATE_HASH=%CUR%"
  exit /b 0
)
exit /b 0

rem Usage: call :sha256_of <file> <varname>
:sha256_of
set "SHA256="
if not exist "%~1" exit /b 1
for /f "usebackq tokens=1,2 delims==" %%A in (`powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$h=([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([IO.File]::ReadAllBytes('%~1'))) -replace '-',''); Write-Output ('SHA256=' + $h)"`) do set "%%A=%%B"
if not defined SHA256 exit /b 1
set "%~2=%SHA256%"
set "SHA256="
exit /b 0

:runtime_hash_words
set "H0="
set "H1="
set "H2="
set "H3="
set "H4="
set "H5="
set "H6="
set "H7="
for /f "usebackq tokens=1,2 delims==" %%A in (`powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$h=([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([IO.File]::ReadAllBytes('%RUNTIME_DLL%'))) -replace '-',''); 0..7 | ForEach-Object { Write-Output ('H' + $_ + '=0x' + $h.Substring($_*8,8)) }"`) do set "%%A=%%B"
if not defined H0 exit /b 1
if not defined H7 exit /b 1
exit /b 0

:validate_output
if not exist "%WORK_DIR%\out.exe" exit /b 1
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$b=[IO.File]::ReadAllBytes('%WORK_DIR%\out.exe'); if($b.Length -lt 2){exit 1}; if($b[0] -ne 0x4D -or $b[1] -ne 0x5A){exit 1}; exit 0"
if errorlevel 1 exit /b 1
rem A byte-identical output means VMProtect silently passed the file through,
rem which would mean the launcher is shipped unprotected.
fc /b "%WORK_DIR%\out.exe" "%TARGET%" > nul
if not errorlevel 1 exit /b 1
exit /b 0

:write_state
if not exist "%RELEASE_CACHE%" mkdir "%RELEASE_CACHE%"
>"%STATE_FILE%" echo SRC=%SRC_SHA%
>>"%STATE_FILE%" echo OUT=%OUT_SHA%
exit /b 0

:tail_log
if exist "%WORK_DIR%\vmp.log" for /f "usebackq delims=" %%L in ("%WORK_DIR%\vmp.log") do echo     %%L
exit /b 0

:clean_work
if exist "%WORK_DIR%" rmdir /s /q "%WORK_DIR%"
if exist "%WORK_DIR%" exit /b 1
exit /b 0

:assert_clean
for %%F in ("%OUT_ROOT%\*.vmp" "%OUT_ROOT%\*.log" "%OUT_ROOT%\*.bak" "%OUT_ROOT%\*.tmp") do if exist "%%~F" (
  echo   %C_RED%ERROR: protection artifact left in the release folder: %%~nxF%C_RESET%
  exit /b 1
)
exit /b 0

:vmp_missing
echo   %C_RED%ERROR: VMProtect console not found.%C_RESET%
echo   %C_YELLOW%       Searched:%%C_RESET%
echo         %PROGRAMFILES%\VMProtect*\VMProtect_Con.exe
echo         %PROGRAMW6432%\VMProtect*\VMProtect_Con.exe
echo         %PROGRAMFILES(X86)%\VMProtect*\VMProtect_Con.exe
echo         %LOCALAPPDATA%\VMProtect*\VMProtect_Con.exe
echo         PATH ^(VMProtect_Con.exe, vmpconsole.exe^)
echo   %C_YELLOW%       Fix: set AMEGER_VMP_CON to the full path, with no surrounding quotes,%C_RESET%
echo   %C_YELLOW%             e.g. set AMEGER_VMP_CON=C:\Program Files\VMProtect Ultimate\VMProtect_Con.exe%C_RESET%
echo   %C_YELLOW%       Leaving it unset is fine if VMProtect is installed normally.%C_RESET%
echo   %C_YELLOW%       Note: the console build is not included in the Lite edition.%C_RESET%
goto :failure

:target_missing
echo   %C_RED%ERROR: no launcher EXE found in the release folder.%C_RESET%
goto :failure

:project_missing
echo   %C_RED%ERROR: no .vmp project found; set AMEGER_VMP_PROJECT_EXE.%C_RESET%
goto :failure

:project_mismatch
echo   %C_RED%ERROR: the project does not target this binary.%C_RESET%
echo   %C_RED%       Refusing to protect with a crossed project.%C_RESET%
goto :failure

:work_error
echo   %C_RED%ERROR: unable to prepare the protection staging directory.%C_RESET%
goto :failure

:hash_error
echo   %C_RED%ERROR: unable to calculate a SHA-256 for the target or runtime.%C_RESET%
goto :failure

:output_invalid
echo   %C_RED%ERROR: VMProtect output failed validation; release left untouched.%C_RESET%
goto :failure

:deploy_error
echo   %C_RED%ERROR: unable to deploy the protected launcher.%C_RESET%
goto :failure

:embed_error
echo   %C_RED%ERROR: embedded runtime hash no longer matches the runtime DLL.%C_RESET%
echo   %C_RED%       The launcher would refuse to start; rebuild without protection.%C_RESET%
goto :failure

:cleanup_error
echo   %C_RED%ERROR: unable to remove generated protection artifacts.%C_RESET%
goto :failure

:failure
if "%NO_PAUSE%"=="0" pause
exit /b 1