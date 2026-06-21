; GlyphWeave Installer
; Non-commercial use only

#define MyAppName "Glyphweave"
; CI overrides this via /DMyAppVersion=<tag> - this value is only used for local builds.
#define MyAppVersion "0.1.001"
#define MyAppPublisher "torporoverload"
#define MyAppURL "https://github.com/TorporOverload/glyphweave"
#define MyAppExeName "glyphweave.exe"
#define WinFspMsi "winfsp.msi"

[Setup]
AppId={{9DAFD5C5-C0B7-40F2-8BD1-F0BBA7C6D23C}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
UninstallDisplayIcon={app}\{#MyAppExeName}
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
DisableProgramGroupPage=yes
LicenseFile=license.txt
; Runs as a standard user unless WinFsp needs installing, in which case
; InitializeSetup re-launches with elevation automatically.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputBaseFilename=glyphweave-setup-{#MyAppVersion}
SolidCompression=yes
WizardStyle=modern polar

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "dist\glyphweave\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "dist\glyphweave\_internal\*"; DestDir: "{app}\_internal"; Flags: ignoreversion recursesubdirs createallsubdirs
; WinFsp MSI - extracted to {tmp} only when WinFsp is not already installed.
; Place winfsp.msi in a redist\ folder next to this .iss file.
; Download from: https://github.com/winfsp/winfsp/releases
Source: "redist\{#WinFspMsi}"; DestDir: "{tmp}"; Flags: deleteafterinstall; Check: NeedsWinFsp

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
; Install WinFsp silently before launching the app. The MSI is already in
; {tmp} because the [Files] entry above copied it there (guarded by the same
; NeedsWinFsp check).  /norestart suppresses the automatic reboot prompt;
; /qn runs fully silent with no UI.
Filename: "msiexec.exe"; \
  Parameters: "/i ""{tmp}\{#WinFspMsi}"" /qn /norestart"; \
  StatusMsg: "Installing WinFsp file system driver..."; \
  Check: NeedsWinFsp; Flags: waituntilterminated runhidden
Filename: "{app}\{#MyAppExeName}"; \
  Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; \
  Flags: nowait postinstall skipifsilent

[Code]

// Returns True if WinFsp is already installed on this machine.
// Checks for the WinFsp.Launcher service which is always present when WinFsp
// is installed. HKLM\SYSTEM is not WOW64-redirected so no HKLM64 fallback needed.
function WinFspInstalled: Boolean;
var
  S: String;
begin
  Result := RegQueryStringValue(HKLM, 'SYSTEM\CurrentControlSet\Services\WinFsp.Launcher', 'ImagePath', S);
end;

// Used as a Check: function in [Files] and [Run] to skip WinFsp steps
// when it is already present.
function NeedsWinFsp: Boolean;
begin
  Result := not WinFspInstalled;
end;

// If WinFsp is missing we need admin rights (kernel driver installation).
// Re-launch the installer elevated; the new elevated process will run the
// full install including the WinFsp MSI, then exit this non-admin instance.
function InitializeSetup: Boolean;
var
  ResultCode: Integer;
begin
  Result := True;

  if NeedsWinFsp and not IsAdmin then
  begin
    if ShellExec('runas', ExpandConstant('{srcexe}'), GetCmdTail, '', SW_SHOW, ewNoWait, ResultCode) then
      Result := False  // Exit this non-admin instance; elevated one takes over
    else
    begin
      MsgBox(
        'GlyphWeave requires WinFsp (a file-system driver) which needs Administrator rights to install.' + #13#10#13#10 +
        'Please re-run this installer as Administrator, or install WinFsp manually first:' + #13#10 +
        'https://github.com/winfsp/winfsp/releases',
        mbError, MB_OK
      );
      Result := False;
    end;
  end;
end;
