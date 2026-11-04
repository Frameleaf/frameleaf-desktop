; Build only after the compiled release authority has verified the Windows host.
#define Manifest GetEnv("HOST_MANIFEST")
#define Controller GetEnv("HOST_CONTROLLER")
#define Digest GetEnv("HOST_CONTROLLER_SHA256")
#define Archive GetEnv("HOST_ARCHIVE")
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
Compression=none
ArchiveExtraction=basic
ExtraDiskSpaceRequired=4294967296
OutputDir={#GetEnv("HOST_OUTPUT")}
OutputBaseFilename=FrameleafNativeServer_0.1.0_x64-setup-unsigned
SetupLogging=yes

[Files]
Source: "{#Controller}"; Flags: dontcopy
Source: "{#Archive}"; Flags: dontcopy

[Code]
procedure RunChecked(const ProgramPath, Arguments: String);
var
  ExitCode: Integer;
begin
  if not Exec(ProgramPath, Arguments, ExpandConstant('{sys}'), SW_HIDE, ewWaitUntilTerminated, ExitCode) then
    RaiseException(SysErrorMessage(ExitCode));
  if ExitCode <> 0 then
    RaiseException(Format('%s failed (exit %d). See the setup log.', [ExtractFileName(ProgramPath), ExitCode]));
end;

procedure InstallHost;
var
  RuntimeDir, ControllerDir, Controller, OwnerArgs: String;
  MadeRuntime, MadeController: Boolean;
begin
  RuntimeDir := ExpandConstant('{#RuntimeDir}');
  ControllerDir := ExpandConstant('{#ControllerDir}');
  ExtractTemporaryFile('frameleaf-native-host.exe');
  Controller := ExpandConstant('{tmp}\frameleaf-native-host.exe');
  if CompareText(GetSHA256OfFile(Controller), '{#Digest}') <> 0 then
    RaiseException('The installer controller failed verification.');

  if FileExists(RuntimeDir + '\installation.json') then begin
    RunChecked(Controller, '--finalize-windows-package {#Manifest} {#Digest}');
    Exit;
  end;
  ExtractTemporaryFile('windows-host.7z');
  RunChecked(Controller, '--prepare-windows-package {#Manifest} {#Digest}');
  MadeRuntime := False;
  MadeController := False;
  try
    MadeRuntime := CreateDir(RuntimeDir);
    if not MadeRuntime then RaiseException('Cannot create the new runtime directory.');
    MadeController := CreateDir(ControllerDir);
    if not MadeController then RaiseException('Cannot create the new controller directory.');
    if not CopyFile(Controller, ControllerDir + '\frameleaf-native-host.exe', True) then
      RaiseException('Cannot install the server controller.');
    WizardForm.StatusLabel.Caption := 'Installing verified server resources...';
    { ONNX test fixtures exceed MAX_PATH under the manifest-addressed directory. }
    ExtractArchive(ExpandConstant('{tmp}\windows-host.7z'), '\\?\' + RuntimeDir, '', True, nil);
    Log('Server archive extraction completed.');
    OwnerArgs := '" /setowner *S-1-5-32-544 /T /Q';
    RunChecked(ExpandConstant('{sys}\icacls.exe'), '"\\?\' + RuntimeDir + OwnerArgs);
    RunChecked(ExpandConstant('{sys}\icacls.exe'), '"\\?\' + ControllerDir + OwnerArgs);
    WizardForm.StatusLabel.Caption := 'Verifying the installed server...';
    RunChecked(Controller, '--finalize-windows-package {#Manifest} {#Digest}');
  except
    if MadeRuntime then DelTree('\\?\' + RuntimeDir, True, True, True);
    if MadeController then DelTree(ControllerDir, True, True, True);
    RaiseException(GetExceptionMessage);
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then InstallHost;
end;
