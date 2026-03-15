#define AppId GetEnv('PC_APP_ID')
#define AppName GetEnv('PC_APP_NAME')
#define AppVersion GetEnv('PC_APP_VERSION')
#define AppPublisher GetEnv('PC_APP_PUBLISHER')
#define AppDescription GetEnv('PC_APP_DESCRIPTION')
#define InstallDirName GetEnv('PC_INSTALL_DIR_NAME')
#define ExecutableName GetEnv('PC_EXECUTABLE_NAME')
#define DistRoot GetEnv('PC_DIST_ROOT')
#define ReleaseRoot GetEnv('PC_RELEASE_ROOT')

[Setup]
AppId={#AppId}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL=https://xpoliceclaw.com
AppSupportURL=https://xpoliceclaw.com
AppUpdatesURL=https://xpoliceclaw.com
AppComments={#AppDescription}
DefaultDirName={localappdata}\Programs\{#InstallDirName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir={#ReleaseRoot}
OutputBaseFilename=PoliceClaw-Setup-{#AppVersion}
Compression=lzma
SolidCompression=yes
WizardStyle=modern
SetupLogging=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#ExecutableName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
Source: "{#DistRoot}\{#ExecutableName}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#ExecutableName}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#ExecutableName}"; Tasks: desktopicon
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"

[Run]
Filename: "{app}\{#ExecutableName}"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent
