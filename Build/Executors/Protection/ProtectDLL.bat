@echo off
setlocal EnableExtensions DisableDelayedExpansion

rem ---------------------------------------------------------------------------
rem ProtectDLL.bat - VMProtect stage for the deployed payload DLL.
rem
rem Runs against the *release* copy (Build\Release\DLLs\*.dll), never the
rem source asset. The runtime DLL is explicitly skipped by the name Create.bat
rem recorded in Cache\BuildNames.state: it is manual-mapped and must stay a
rem plain, unvirtualized PE. No rtdll_* prefix is assumed any more - the
rem deployed runtime name is random per build (V-03).
rem
rem Two consequences of protecting the payload are handled here and would
rem otherwise silently break the release:
rem   1. Jlov.dll's SHA-256 changes, so the PayloadSha256 pin in the plaintext
rem      master config is rewritten and the deployed config is re-encrypted.
rem      Without this the injector's startup hash check aborts at launch.
rem   2. VMProtect emits a log and an output PE. Both are staged inside
rem      Build\Release\Cache and removed; the release tree only ever ends up
rem      holding the protected DLL.
rem
rem CLI shape (vmpsoft.com console documentation):
rem   VMProtect_Con.exe <file> [output] [-pf proj] [-sf script] [-lf lic]
rem                                 [-bd yyyy-mm-dd] [-wm name] [-we]
rem Protection *modes* (Ultra / Mutation / Virtualization) and the Complexity
rem and Instances figures are properties of the .vmp project, not CLI flags.
rem This script therefore resolves a project and leaves them to it; the
rem required project settings are printed by :vmp_settings below.
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
set "STRIP_SCRIPT=%SCRIPTS_DIR%\StripExportDirs.ps1"
rem State lives beside WORK_DIR, not inside it, because WORK_DIR is deleted at
rem the end of every run. Deleting the state would make the script reprotect
rem an already-protected payload on the next invocation.
set "STATE_FILE=%RELEASE_CACHE%\Protect.payload.state"
set "CONFIG_MASTER=%BUILD_DIR%\Configuration.ini"
set "PAYLOAD_ASSET=%ROOT%\Assets\DLL\Jlov.dll"
set "CONFIG_SCRIPT=%SCRIPTS_DIR%\ProtectConfig.ps1"
set "DEPLOYED_CONFIG=%OUT_ROOT%\Configuration.ini"
rem Per-build deployed names (V-02/V-03). Create.bat records these before the
rem Protect stages run; they name the payload and runtime DLL on disk. Fail
rem closed if missing: the runtime DLL's random name cannot be guessed, so
rem without this the payload cannot be told apart from the runtime DLL.
set "NAMES_STATE=%RELEASE_CACHE%\BuildNames.state"
rem The .vmp project is matched against the ORIGINAL asset name, never the
rem random deployed name: Assets\Template holds both Jlov.dll.vmp and
rem "Host - x64.exe.vmp", and a plain scan can hand this stage the wrong project.
set "PAYLOAD_ORIGINAL_NAME=Jlov.dll"
set "PAYLOAD_NAME="
set "RUNTIME_NAME="
set "VMP_PROJECT="
set "TARGET_NAME="
set "VMP_CON="

echo [%C_GREEN%1%C_RESET%/%C_GREEN%6%C_RESET%] Locating VMProtect console...
echo.
call :find_vmp_con
if errorlevel 2 goto :vmp_wrapper
if errorlevel 1 goto :vmp_missing
echo   %C_GREEN%[+]%C_RESET% Console: %C_GREEN%%VMP_CON%%C_RESET%
echo.
echo.

echo [%C_GREEN%2%C_RESET%/%C_GREEN%6%C_RESET%] Resolving payload target...
echo.
call :read_names_state
if errorlevel 1 goto :names_missing
if not exist "%DLL_DIR%" (
  echo   %C_RED%ERROR: release DLL folder not found: %DLL_DIR%%C_RESET%
  goto :failure
)
set "TARGET="
set "DLL_CANDIDATES=0"
for %%F in ("%DLL_DIR%\*.dll") do call :consider_dll "%%~fF"
if not defined TARGET goto :target_missing
if not exist "%TARGET%" goto :target_missing
if not "%DLL_CANDIDATES%"=="1" goto :target_ambiguous
for %%N in ("%TARGET%") do set "TARGET_NAME=%%~nxN"
echo   %C_GREEN%[+]%C_RESET% Target:  %C_GREEN%%TARGET%%C_RESET%
echo   %C_GREEN%[+]%C_RESET% Skipped: %C_YELLOW%%RUNTIME_NAME% (manual-mapped, never virtualized)%C_RESET%
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
rem Deliberately not gated on AMEGER_FORCE_VMP: STATE_MATCH=output is an exact-hash match against our recorded protected output, so re-protecting would only double-virtualize. FORCE_VMP overrides the heuristic VMP_PRESENT check above instead.
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

echo [%C_GREEN%4%C_RESET%/%C_GREEN%6%C_RESET%] Virtualizing payload...
echo.
call :clean_work
if errorlevel 1 goto :work_error
if not exist "%WORK_DIR%" mkdir "%WORK_DIR%"
if not exist "%WORK_DIR%" goto :work_error
call :sha256_of "%TARGET%" SRC_SHA
if errorlevel 1 goto :hash_error
if not defined SRC_SHA goto :hash_error
echo   Source SHA-256:  %C_GREEN%%SRC_SHA%%C_RESET%
rem Work on a build-local copy of the project with a randomized protector
rem segment name, so the segment is not a fixed multi-megabyte executable
rem section that identifies every build as protected.
call :prepare_project
if errorlevel 1 goto :project_error
echo   %C_GREEN%[+]%C_RESET% Segment name: %C_GREEN%%SEG_NAME%%C_RESET% %C_YELLOW%(randomized per build)%C_RESET%
rem -we promotes VMProtect warnings to errors so a partial or skipped
rem protection cannot pass for a completed one.
"%VMP_CON%" "%TARGET%" "%WORK_DIR%\out.dll" -pf "%PROJ_WORK%" -we > "%WORK_DIR%\vmp.log" 2>&1
if errorlevel 1 (
  echo   %C_RED%ERROR: VMProtect reported a failure; see the log tail below.%C_RESET%
  call :tail_log
  goto :failure
)
call :validate_output
if errorlevel 2 goto :fc_error
if errorlevel 1 goto :output_invalid
echo.
echo   %C_GREEN%OK%C_RESET% Protected output validated.
rem Confirm the output really carries the VMProtect segment we asked for before
rem the bytes are deployed. Verification only: the binary is never renamed or
rem patched here.
call :verify_segment "%WORK_DIR%\out.dll"
if errorlevel 1 goto :segment_error
echo   %C_GREEN%[+]%C_RESET% VM segment: %C_GREEN%%VM_SEG%%C_RESET% (verified)
rem Strip the export directory before the bytes are deployed: on disk it is the
rem only identifying symbol, and nothing resolves it after a manual map.
call :strip_exports "%WORK_DIR%\out.dll"
if errorlevel 1 goto :strip_error
echo.
echo.

echo [%C_GREEN%5%C_RESET%/%C_GREEN%6%C_RESET%] Re-pinning payload hash...
echo.
rem The protected DLL has a different digest than the asset, so the pin in the
rem deployed config has to follow it or the launcher refuses to start.
rem
rem The plaintext MASTER must keep the asset digest. Create.bat re-copies the
rem unprotected asset into the release folder and verifies it against the
rem master, so rewriting the master to the protected digest here would make
rem every subsequent Create.bat abort with "deployed payload failed hash
rem verification". Protection happens after the build, so only the shipped
rem copy needs the protected digest. Encrypt a throwaway plaintext config
rem carrying it into the release folder and leave the master alone.
copy /y "%WORK_DIR%\out.dll" "%TARGET%" > nul
if errorlevel 1 goto :deploy_error
call :sha256_of "%TARGET%" OUT_SHA
if errorlevel 1 goto :hash_error
if not defined OUT_SHA goto :hash_error
rem [IO.File]::ReadAllText/WriteAllText rather than Get-Content/Set-Content:
rem the cmdlet pair can leave the read handle open, and Set-Content then fails
rem with "being used by another process" against the very file being rewritten.
set "PIN_SRC=%WORK_DIR%\pin.ini"
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$c=[IO.File]::ReadAllText('%CONFIG_MASTER%'); $c=[regex]::Replace($c,'(?m)^PayloadSha256\s*=.*$','PayloadSha256 = '+('%OUT_SHA%')); [IO.File]::WriteAllText('%PIN_SRC%',$c,[Text.Encoding]::ASCII)"
if errorlevel 1 goto :pin_error
if not exist "%PIN_SRC%" goto :pin_error
echo   %C_GREEN%[+]%C_RESET% PayloadSha256 = %C_GREEN%%OUT_SHA%%C_RESET% %C_YELLOW%(release copy only)%C_RESET%
if not exist "%CONFIG_SCRIPT%" goto :pin_error
if /i "%AMEGER_ENCRYPT_CONFIG%"=="0" goto :pin_plaintext
if not exist "%DEPLOYED_CONFIG%" goto :pin_error
rem No PayloadName/RuntimeName/ExportMap arguments here: ProtectConfig.ps1
rem preserves them from the existing deployed config, so the per-build
rem anti-detection values (V-02/V-03/V-32) survive the re-encryption exactly.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%CONFIG_SCRIPT%" -Source "%PIN_SRC%" -Destination "%DEPLOYED_CONFIG%"
if errorlevel 1 goto :pin_error
echo   %C_GREEN%[+]%C_RESET% Deployed config re-encrypted.
goto :pin_done

:pin_plaintext
rem Route through ProtectConfig.ps1 even in plaintext mode so the per-build
rem keys are carried over; a bare copy would drop them.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%CONFIG_SCRIPT%" -Source "%PIN_SRC%" -Destination "%DEPLOYED_CONFIG%" -Plaintext
if errorlevel 1 goto :pin_error

:pin_done
call :assert_master_pin
if errorlevel 1 goto :pin_error
call :write_state
echo.
echo.

echo [%C_GREEN%6%C_RESET%/%C_GREEN%6%C_RESET%] Sweeping protection artifacts...
echo.
call :clean_work
if errorlevel 1 goto :cleanup_error
call :assert_clean
if errorlevel 1 goto :cleanup_error
echo   %C_GREEN%[+]%C_RESET% No VMProtect traces in %C_GREEN%%DLL_DIR%%C_RESET%.
echo.
echo Payload protection completed.
echo Payload: %C_GREEN%%TARGET%%C_RESET%
echo.
echo.
if "%NO_PAUSE%"=="0" pause
exit /b 0

rem ---------------------------------------------------------------------------

:already_protected
echo.
echo Payload is already VMProtect-protected; release unchanged.
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
echo   %C_GREEN%[+]%C_RESET% No VMProtect traces in %C_GREEN%%DLL_DIR%%C_RESET%.
echo.
echo Payload already protected; release unchanged.
echo.
if defined VMSEG echo VM segment: %C_GREEN%%VMSEG%%C_RESET% (recorded)
echo Payload: %C_GREEN%%TARGET%%C_RESET%
if "%NO_PAUSE%"=="0" pause
exit /b 0

rem Reject the runtime DLL by the exact per-build name Create.bat recorded. The
rem release folder holds exactly two DLLs (the payload and the runtime), so
rem skipping the recorded runtime name leaves the payload.
:consider_dll
set "CANDIDATE=%~1"
if not defined CANDIDATE exit /b 0
if /i "%~nx1"=="%RUNTIME_NAME%" exit /b 0
set /a "DLL_CANDIDATES+=1"
if defined TARGET exit /b 0
set "TARGET=%CANDIDATE%"
exit /b 0

:prepare_project
rem Randomized per build so the protector's segment is not a stable signature.
set "PROJ_WORK=%WORK_DIR%\project.vmp"
set "SEG_NAME="
for /f "usebackq tokens=1,* delims==" %%A in (`powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%BUILD_VMP_SCRIPT%" -Project "%VMP_PROJECT%" -Out "%PROJ_WORK%"`) do set "%%A=%%B"
if not exist "%PROJ_WORK%" exit /b 1
if not defined SEG_NAME exit /b 1
exit /b 0

:strip_exports
rem %1 = file to scrub. Must be the PROTECTED output, not %TARGET%: %TARGET% is
rem about to be overwritten by the copy below, so scrubbing it first would wipe
rem the pristine input's exports and then restore them from the protected bytes.
rem The export directory is dead weight on disk: nothing resolves exports after
rem a manual map because there is no loader entry (see ManualMapping.cpp), and
rem the entry is reached by RVA. It carries the only identifying symbol in the
rem binary, so it is removed here, before deployment.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%STRIP_SCRIPT%" -Path "%~1"
exit /b %ERRORLEVEL%

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
rem after the call site and report success having protected nothing. Compare
rem the extension exactly: the old findstr matched the echoed, quoted path,
rem whose trailing quote defeated the "$" end-of-line anchor, so the guard
rem never fired and the caller's :vmp_wrapper branch was unreachable.
for %%X in ("%VMP_CON%") do if /i "%%~xX"==".bat" exit /b 2
for %%X in ("%VMP_CON%") do if /i "%%~xX"==".cmd" exit /b 2
exit /b 0

:scan_vmp_dirs
rem "for /d" is required here: a plain "for" treats a quoted wildcard as a
rem literal filename and never expands it, so the family match silently finds
rem nothing. The quotes are still required because the install path has a space.
for /d %%D in ("%~1\VMProtect*") do if not defined VMP_CON for %%E in ("%%~fD\VMProtect_Con.exe" "%%~fD\VMProtect_Console.exe" "%%~fD\vmpconsole.exe") do if not defined VMP_CON if exist "%%E" set "VMP_CON=%%E"
exit /b 0

rem Project resolution order: explicit override, then the shared template in
rem Assets\Template named after the ORIGINAL asset, then a copy beside this
rem script, then any project in either folder. Assets\Template is the canonical
rem home so the build tree stays free of .vmp files. The name-matched step is
rem load-bearing: two templates exist and a plain alphabetical scan can hand
rem this stage the wrong binary's project. The deployed payload name is random
rem per build (V-02), so the match uses the original asset name instead.
:find_project
if defined AMEGER_VMP_PROJECT_DLL if exist "%AMEGER_VMP_PROJECT_DLL%" (
  set "VMP_PROJECT=%AMEGER_VMP_PROJECT_DLL%"
  exit /b 0
)
if exist "%ASSET_TPL%\%PAYLOAD_ORIGINAL_NAME%.vmp" (
  set "VMP_PROJECT=%ASSET_TPL%\%PAYLOAD_ORIGINAL_NAME%.vmp"
  exit /b 0
)
if exist "%~dp0%PAYLOAD_ORIGINAL_NAME%.vmp" (
  set "VMP_PROJECT=%~dp0%PAYLOAD_ORIGINAL_NAME%.vmp"
  exit /b 0
)
for %%F in ("%ASSET_TPL%\*.vmp") do if not defined VMP_PROJECT set "VMP_PROJECT=%%~fF"
if defined VMP_PROJECT if exist "%VMP_PROJECT%" exit /b 0
for %%F in ("%~dp0*.vmp") do if not defined VMP_PROJECT set "VMP_PROJECT=%%~fF"
if defined VMP_PROJECT if exist "%VMP_PROJECT%" exit /b 0
set "VMP_PROJECT="
exit /b 1

rem Refuse a project whose InputFileName names a different binary. This is the
rem cheap guard against the two templates being crossed, which would otherwise
rem only show up as VMProtect protecting the wrong entry points. The project
rem still targets the original asset name, not the random deployed name.
:check_project_input
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$x=[xml][IO.File]::ReadAllText('%VMP_PROJECT%'); $i=[string]$x.Document.Protection.InputFileName; if($i -eq '%PAYLOAD_ORIGINAL_NAME%'){exit 0}; Write-Host ('    project targets: ' + $i); exit 1"
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

:validate_output
if not exist "%WORK_DIR%\out.dll" exit /b 1
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$b=[IO.File]::ReadAllBytes('%WORK_DIR%\out.dll'); if($b.Length -lt 2){exit 1}; if($b[0] -ne 0x4D -or $b[1] -ne 0x5A){exit 1}; exit 0"
if errorlevel 1 exit /b 1
rem A byte-identical output means VMProtect silently passed the file through,
rem which would leave the pin rewritten for a hash nothing changed.
rem fc returns 0 = identical, 1 = differ, 2 = open/compare error. Only 1 proves
rem the protector rewrote the bytes; a 2 is inconclusive and must fail closed.
fc /b "%WORK_DIR%\out.dll" "%TARGET%" > nul
if errorlevel 2 exit /b 2
if not errorlevel 1 exit /b 1
exit /b 0

rem Usage: call :verify_segment <protected PE>
rem Confirms the output carries a section whose name is the generated SEG_NAME
rem with an optional trailing digit run. VMProtect appends a numeric suffix, so
rem the project's ".XXXX" lands in the section table as ".XXXX0". Any other
rem name means protection did not run with our generated project, so fail
rem closed rather than deploy the artifact. Verification only: the binary is
rem never renamed or patched.
:verify_segment
set "VM_SEG="
set "VM_SEG_STATUS="
rem A status token is parsed instead of relying on the child's exit code:
rem for /f does not propagate a command's errorlevel reliably, and the value
rem would be silently lost. PowerShell always exits 0 and reports via stdout.
for /f "usebackq tokens=1,* delims==" %%A in (`powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$seg='%SEG_NAME%'; $b=[IO.File]::ReadAllBytes('%~1'); $e=[BitConverter]::ToInt32($b,0x3C); $c=$e+4; $n=[BitConverter]::ToUInt16($b,$c+2); $z=[BitConverter]::ToUInt16($b,$c+16); $s=$c+20+$z; $found=$null; for($i=0;$i -lt $n;$i++){ $o=$s+40*$i; $nm=[Text.Encoding]::ASCII.GetString($b,$o,8).Trim([char]0); if($nm.StartsWith($seg)){ $found=$nm; break } }; if($null -eq $found){ Write-Output 'VM_SEG_STATUS=missing'; Write-Output 'VM_SEG='; exit 0 }; Write-Output ('VM_SEG=' + $found); if($found -match ('^' + [regex]::Escape($seg) + '[0-9]*$')){ Write-Output 'VM_SEG_STATUS=ok' } else { Write-Output 'VM_SEG_STATUS=mismatch' }; exit 0"`) do set "%%A=%%B"
if /i "%VM_SEG_STATUS%"=="ok" exit /b 0
if /i "%VM_SEG_STATUS%"=="missing" (
  echo   %C_RED%ERROR: no VMProtect segment found in the protected output.%C_RESET%
) else (
  echo   %C_RED%ERROR: VMProtect segment name mismatch in the protected output.%C_RESET%
)
echo   %C_RED%       expected: %SEG_NAME% (optionally followed by digits)%C_RESET%
echo   %C_RED%       observed: %VM_SEG%%C_RESET%
exit /b 1

:assert_master_pin
rem Fail closed if the master no longer pins the pristine asset. That pin is
rem what Create.bat verifies the freshly copied payload against, so drift here
rem would silently break the next build rather than this one.
if not exist "%PAYLOAD_ASSET%" exit /b 1
call :sha256_of "%PAYLOAD_ASSET%" ASSET_SHA
if errorlevel 1 exit /b 1
if not defined ASSET_SHA exit /b 1
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$c=[IO.File]::ReadAllText('%CONFIG_MASTER%'); $m=[regex]::Match($c,'(?m)^PayloadSha256\s*=\s*([0-9A-Fa-f]{64})'); if(-not $m.Success){exit 1}; if($m.Groups[1].Value -ne '%ASSET_SHA%'){Write-Host ('    master pins : ' + $m.Groups[1].Value); Write-Host ('    asset is    : ' + '%ASSET_SHA%'); exit 1}; exit 0"
exit /b %ERRORLEVEL%

:write_state
if not exist "%RELEASE_CACHE%" mkdir "%RELEASE_CACHE%"
if not exist "%RELEASE_CACHE%" exit /b 1
>"%STATE_FILE%" echo SRC=%SRC_SHA%
>>"%STATE_FILE%" echo OUT=%OUT_SHA%
>>"%STATE_FILE%" echo VMSEG=%VM_SEG%
exit /b 0

:read_names_state
rem Load the per-build deployed names Create.bat recorded (V-02/V-03/V-32).
rem Fail closed when the state is missing or malformed: the runtime DLL's
rem random name cannot be guessed, so without it the payload cannot be told
rem apart from the runtime DLL and the wrong file could be virtualized.
set "PAYLOAD_NAME="
set "RUNTIME_NAME="
if not exist "%NAMES_STATE%" exit /b 1
for /f "usebackq tokens=1,* delims==" %%A in ("%NAMES_STATE%") do set "%%A=%%B"
if not defined PAYLOAD_NAME exit /b 1
if not defined RUNTIME_NAME exit /b 1
exit /b 0

:tail_log
if exist "%WORK_DIR%\vmp.log" for /f "usebackq delims=" %%L in ("%WORK_DIR%\vmp.log") do echo     %%L
exit /b 0

:clean_work
if exist "%WORK_DIR%" rmdir /s /q "%WORK_DIR%"
if exist "%WORK_DIR%" exit /b 1
exit /b 0

:assert_clean
rem Fail closed on any protector byproduct in the release tree: a stray .vmp,
rem .log or backup file is a build fingerprint that identifies the pipeline.
for %%F in ("%DLL_DIR%\*.vmp" "%DLL_DIR%\*.log" "%DLL_DIR%\*.bak" "%DLL_DIR%\*.tmp") do if exist "%%~F" (
  echo   %C_RED%ERROR: protection artifact left in the release folder: %%~nxF%C_RESET%
  exit /b 1
)
exit /b 0

:vmp_wrapper
echo   %C_RED%ERROR: AMEGER_VMP_CON points at a batch/cmd wrapper: %VMP_CON%%C_RESET%
echo   %C_RED%       A wrapper transfers control and never returns; use the real console.%C_RESET%
goto :failure

:vmp_missing
echo   %C_RED%ERROR: VMProtect console not found.%C_RESET%
echo   %C_YELLOW%       Searched:%C_RESET%
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

:names_missing
echo   %C_RED%ERROR: per-build name state not found or incomplete: %NAMES_STATE%%C_RESET%
echo   %C_RED%       Run Create.bat first; the deployed payload and runtime DLL cannot be resolved.%C_RESET%
goto :failure

:target_missing
echo   %C_RED%ERROR: no virtualizable payload DLL found in the release folder.%C_RESET%
goto :failure

:target_ambiguous
rem The release DLL folder must hold exactly one payload DLL plus the recorded
rem runtime DLL. A second candidate means a leftover or misnamed build output;
rem silently protecting the first match could virtualize the wrong file.
echo   %C_RED%ERROR: expected exactly one virtualizable payload DLL in %DLL_DIR%, found %DLL_CANDIDATES%.%C_RESET%
echo   %C_RED%       Refusing to guess which DLL to protect.%C_RESET%
goto :failure

:project_missing
echo   %C_RED%ERROR: no .vmp project found; set AMEGER_VMP_PROJECT_DLL.%C_RESET%
goto :failure

:project_mismatch
echo   %C_RED%ERROR: the project does not target this binary.%C_RESET%
echo   %C_RED%       Refusing to protect with a crossed project.%C_RESET%
goto :failure

:work_error
echo   %C_RED%ERROR: unable to prepare the protection staging directory.%C_RESET%
goto :failure

:hash_error
echo   %C_RED%ERROR: unable to calculate the payload SHA-256.%C_RESET%
goto :failure

:output_invalid
echo   %C_RED%ERROR: VMProtect output failed validation; release left untouched.%C_RESET%
goto :failure

:segment_error
echo   %C_RED%ERROR: the protected payload does not carry the generated VMProtect segment.%C_RESET%
echo   %C_RED%       Release left untouched; the output was not deployed.%C_RESET%
goto :failure

:fc_error
echo   %C_RED%ERROR: unable to compare the protected output against the source.%C_RESET%
echo   %C_RED%       fc failed; the output is unverified and will not ship.%C_RESET%
goto :failure

:project_error
echo   %C_RED%ERROR: unable to prepare the randomized project copy.%C_RESET%
goto :failure

:strip_error
echo   %C_RED%ERROR: unable to strip the payload export directory.%C_RESET%
echo   %C_RED%       The release payload would ship its only named symbol.%C_RESET%
goto :failure

:deploy_error
echo   %C_RED%ERROR: unable to deploy the protected payload.%C_RESET%
goto :failure

:pin_error
echo   %C_RED%ERROR: unable to re-pin the release config or re-encrypt it.%C_RESET%
echo   %C_RED%       The release payload and its shipped pin now disagree.%C_RESET%
goto :failure

:cleanup_error
echo   %C_RED%ERROR: unable to remove generated protection artifacts.%C_RESET%
goto :failure

:failure
if "%NO_PAUSE%"=="0" pause
exit /b 1