; Inno Setup script for the Tsunagi Windows installer.
;
; One installer that leaves a working machine:
;   * the agent (tsng.exe), as a Windows service that starts at boot
;   * Wintun, the driver library behind the overlay interface
;   * the tray application, started at sign-in
;   * `tsng` on the PATH, and an inbound Defender Firewall rule for the agent
;
; Built in CI (see .github/workflows/release.yml); locally:
;   ISCC.exe /DAppVersion=0.1.0 /DSourceDir=<dir with tsng.exe and tsunagi-tray.exe>
;            /DWintunDir=<wintun\bin\amd64> /O<output dir> dist\windows\tsunagi.iss
; Silent install: tsunagi-setup-<version>-x86_64.exe /VERYSILENT /SUPPRESSMSGBOXES
; Pick tasks with /TASKS="!autostart,addtopath,firewall".

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef SourceDir
  #error SourceDir must point at the directory holding tsng.exe and tsunagi-tray.exe
#endif
#ifndef WintunDir
  #error WintunDir must point at the directory holding wintun.dll
#endif

#define ServiceName "Tsunagi"

[Setup]
AppId={{F635E5DD-250D-499F-B0B3-AFC7CC64A15D}
AppName=Tsunagi
AppVersion={#AppVersion}
AppPublisher=Tsunagi
DefaultDirName={autopf}\Tsunagi
DefaultGroupName=Tsunagi
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputBaseFilename=tsunagi-setup-{#AppVersion}-x86_64
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ChangesEnvironment=yes
UninstallDisplayName=Tsunagi
; The service and the tray are stopped by hand below, so the installer does
; not need to ask Windows to close applications.
CloseApplications=no

[Tasks]
Name: "autostart"; Description: "Start the tray icon when I sign in"; GroupDescription: "Tsunagi:"
Name: "addtopath"; Description: "Add tsng to the PATH"; GroupDescription: "Tsunagi:"
Name: "firewall"; Description: "Allow the agent through Windows Firewall (direct connections between devices)"; GroupDescription: "Tsunagi:"

[Files]
Source: "{#SourceDir}\tsng.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\tsunagi-tray.exe"; DestDir: "{app}"; Flags: ignoreversion
; Wintun is the unmodified, signed library from wintun.net; its licence allows
; shipping it with an application and asks for the licence text beside it.
Source: "{#WintunDir}\wintun.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#WintunDir}\LICENSE.txt"; DestDir: "{app}\licenses"; DestName: "wintun-LICENSE.txt"; Flags: ignoreversion

[Dirs]
; Identity and network secrets live here; locked down below.
Name: "{commonappdata}\Tsunagi\data"
Name: "{commonappdata}\Tsunagi\cache"
Name: "{commonappdata}\Tsunagi\logs"

[Icons]
Name: "{group}\Tsunagi"; Filename: "{app}\tsunagi-tray.exe"
Name: "{commonstartup}\Tsunagi"; Filename: "{app}\tsunagi-tray.exe"; Tasks: autostart

[Registry]
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; \
    ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; \
    Check: NeedsAddPath('{app}'); Tasks: addtopath

[Run]
; Only the system account and administrators may read the state: it holds the
; device's key and every network's secret. SIDs, so it works in any language.
Filename: "{sys}\icacls.exe"; \
    Parameters: """{commonappdata}\Tsunagi\data"" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F"; \
    Flags: runhidden; StatusMsg: "Protecting the agent's data..."
Filename: "{sys}\icacls.exe"; \
    Parameters: """{commonappdata}\Tsunagi\cache"" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F"; \
    Flags: runhidden
Filename: "{sys}\icacls.exe"; \
    Parameters: """{commonappdata}\Tsunagi\logs"" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F"; \
    Flags: runhidden
; The tray runs as the person who installed, not elevated, like it does at sign-in.
Filename: "{app}\tsunagi-tray.exe"; Description: "Start the Tsunagi tray"; \
    Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallRun]
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""Tsunagi"""; \
    Flags: runhidden; RunOnceId: "RemoveFirewallRule"

[Code]
const
  ServiceName = '{#ServiceName}';
  EnvKey = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment';

function Sc(const Params: String): Integer;
var
  Code: Integer;
begin
  if Exec(ExpandConstant('{sys}\sc.exe'), Params, '', SW_HIDE, ewWaitUntilTerminated, Code) then
    Result := Code
  else
    Result := -1;
end;

function ServiceExists: Boolean;
begin
  // 1060 is ERROR_SERVICE_DOES_NOT_EXIST.
  Result := Sc('query ' + ServiceName) <> 1060;
end;

procedure StopService;
var
  Code: Integer;
begin
  // `net stop` waits until the service has stopped, or says it was not running.
  Exec(ExpandConstant('{sys}\net.exe'), 'stop ' + ServiceName, '', SW_HIDE, ewWaitUntilTerminated, Code);
end;

procedure StopTray;
var
  Code: Integer;
begin
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM tsunagi-tray.exe', '', SW_HIDE, ewWaitUntilTerminated, Code);
end;

// An agent started by hand (`tsng up`) holds the control pipe and the Wintun
// adapter, and the file about to be replaced: it cannot run beside the service.
procedure StopStrayAgents;
var
  Code: Integer;
begin
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM tsng.exe', '', SW_HIDE, ewWaitUntilTerminated, Code);
end;

function NeedsAddPath(Param: String): Boolean;
var
  Current: String;
begin
  if not RegQueryStringValue(HKLM, EnvKey, 'Path', Current) then
  begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Uppercase(ExpandConstant(Param)) + ';', ';' + Uppercase(Current) + ';') = 0;
end;

procedure RemoveFromPath;
var
  Current, Entry: String;
  At: Integer;
begin
  if not RegQueryStringValue(HKLM, EnvKey, 'Path', Current) then
    exit;
  Entry := ';' + ExpandConstant('{app}');
  At := Pos(Uppercase(Entry), Uppercase(Current));
  if At > 0 then
  begin
    Delete(Current, At, Length(Entry));
    RegWriteExpandStringValue(HKLM, EnvKey, 'Path', Current);
  end;
end;

// Stops what is about to be replaced: the files are in use while it runs.
function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  StopTray;
  if ServiceExists then
    StopService;
  StopStrayAgents;
  Result := '';
end;

procedure InstallService;
var
  App: String;
begin
  App := ExpandConstant('{app}\tsng.exe');
  // The command line is `tsng service`: it keeps its state under
  // %ProgramData%\Tsunagi and serves the system-wide control socket.
  if ServiceExists then
    Sc('config ' + ServiceName + ' binPath= "\"' + App + '\" service" start= auto obj= LocalSystem')
  else
    Sc('create ' + ServiceName + ' binPath= "\"' + App + '\" service" start= auto obj= LocalSystem DisplayName= "Tsunagi agent"');
  Sc('description ' + ServiceName + ' "Tsunagi: private mesh network agent"');
  // Restart after a crash, backing off, and forget the failures after a day.
  Sc('failure ' + ServiceName + ' reset= 86400 actions= restart/5000/restart/5000/restart/30000');
  Sc('start ' + ServiceName);
end;

procedure InstallFirewallRule;
var
  Code: Integer;
  Netsh: String;
begin
  Netsh := ExpandConstant('{sys}\netsh.exe');
  Exec(Netsh, 'advfirewall firewall delete rule name="Tsunagi"', '', SW_HIDE, ewWaitUntilTerminated, Code);
  if WizardIsTaskSelected('firewall') then
    Exec(Netsh,
      'advfirewall firewall add rule name="Tsunagi" dir=in action=allow enable=yes profile=any program="' +
      ExpandConstant('{app}\tsng.exe') + '"',
      '', SW_HIDE, ewWaitUntilTerminated, Code);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    InstallFirewallRule;
    InstallService;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
  begin
    StopTray;
    if ServiceExists then
    begin
      StopService;
      Sc('delete ' + ServiceName);
    end;
    StopStrayAgents;
    RemoveFromPath;
  end;
  if CurUninstallStep = usPostUninstall then
  begin
    // The data is the device's identity and its networks: kept unless asked,
    // and never removed by a silent uninstall.
    if (not UninstallSilent) and
       (MsgBox('Also delete this device''s identity, networks and logs?' + #13#10 +
               'Choose No to keep them for a later reinstall.', mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES) then
      DelTree(ExpandConstant('{commonappdata}\Tsunagi'), True, True, True);
  end;
end;
