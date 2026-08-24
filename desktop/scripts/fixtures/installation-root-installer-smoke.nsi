Unicode true

!ifndef CONTRACT_INCLUDE
  !error "CONTRACT_INCLUDE is required"
!endif
!ifndef CONTRACT_OUTPUT
  !error "CONTRACT_OUTPUT is required"
!endif

Name "Nachuan Installation Root contract smoke"
OutFile "${CONTRACT_OUTPUT}"
RequestExecutionLevel admin
InstallDir "$TEMP\NachuanInstallerContractSmoke"

!define SHELL_CONTEXT HKLM
!define INSTALL_REGISTRY_KEY "Software\Nachuan\ContractSmoke"
!define UNINSTALL_REGISTRY_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\NachuanContractSmoke"
Var newStartMenuLink
Var newDesktopLink

!include "${CONTRACT_INCLUDE}"

Section "contract-smoke"
  !insertmacro customInstall
SectionEnd
