; Build only after the compiled release authority has verified the Windows host.
#define Manifest GetEnv("HOST_MANIFEST")
#define Controller GetEnv("HOST_CONTROLLER")
#define Digest GetEnv("HOST_CONTROLLER_SHA256")
#define Candidate GetEnv("HOST_CANDIDATE")
#define RuntimeDir "{commonpf64}\Frameleaf\Runtimes\" + Manifest
#define ControllerDir "{commonpf64}\Frameleaf\Controllers\" + Manifest + "\" + Digest

[Setup]
AppName=Frameleaf Native Server
AppVersion=0.1.0
AppPublisher=Frameleaf
DefaultDirName={commonpf64}\Frameleaf
CreateAppDir=no
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64os
ArchitecturesInstallIn64BitMode=x64os
SetupMutex=Global\FrameleafNativeHostSetup
Uninstallable=no
CloseApplications=no
Compression=zip/fast
OutputDir={#GetEnv("HOST_OUTPUT")}
OutputBaseFilename=FrameleafNativeServer_0.1.0_x64-setup-unsigned
SetupLogging=yes

[Files]
Source: "{#Controller}"; DestName: "installer-controller.exe"; Flags: dontcopy
Source: "{#Controller}"; DestDir: "{#ControllerDir}"; Flags: ignoreversion; Check: FreshInstall
Source: "{#Candidate}\manifest.json"; DestDir: "{#RuntimeDir}"; Flags: ignoreversion; Check: FreshInstall
Source: "{#Candidate}\payload\*"; DestDir: "{#RuntimeDir}\payload"; Flags: ignoreversion recursesubdirs createallsubdirs; Check: FreshInstall
Source: "{#Candidate}\manifest.sig"; DestDir: "{#RuntimeDir}"; Flags: ignoreversion; Check: FreshInstall; AfterInstall: FinalizeFreshInstall

[Code]
var
  ExistingVerified: Boolean;

function FreshInstall: Boolean;
begin
  Result := not ExistingVerified;
end;

procedure RunChecked(const ProgramPath, Arguments: String);
var
  ExitCode: Integer;
begin
  if not Exec(ProgramPath, Arguments, '', SW_HIDE, ewWaitUntilTerminated, ExitCode) then
    RaiseException(SysErrorMessage(ExitCode));
  if ExitCode <> 0 then
    RaiseException(Format('%s failed (exit %d). See the setup log.', [ExtractFileName(ProgramPath), ExitCode]));
end;

procedure ControllerCommand(const Mode: String);
begin
  RunChecked(ExpandConstant('{tmp}\installer-controller.exe'),
    Mode + ' {#Manifest} {#Digest}');
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  try
    ExtractTemporaryFile('installer-controller.exe');
    if CompareText(GetSHA256OfFile(ExpandConstant('{tmp}\installer-controller.exe')), '{#Digest}') <> 0 then
      RaiseException('The installer controller failed verification.');
    if FileExists(ExpandConstant('{#RuntimeDir}\installation.json')) then begin
      ControllerCommand('--finalize-windows-package');
      ExistingVerified := True;
    end else
      ControllerCommand('--prepare-windows-package');
  except
    Result := GetExceptionMessage;
  end;
end;

procedure FinalizeFreshInstall;
var
  OwnerArgs: String;
begin
  OwnerArgs := '" /setowner *S-1-5-32-544 /T /Q';
  RunChecked(ExpandConstant('{sys}\icacls.exe'), '"\\?\' + ExpandConstant('{#RuntimeDir}') + OwnerArgs);
  RunChecked(ExpandConstant('{sys}\icacls.exe'), '"\\?\' + ExpandConstant('{#ControllerDir}') + OwnerArgs);
  ControllerCommand('--finalize-windows-package');
end;
