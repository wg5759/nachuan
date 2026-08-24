!include "LogicLib.nsh"

; The signed PyInstaller engine owns Known Folder resolution, ACL hardening,
; root creation and gateway-ledger binding.  NSIS passes no path or identity,
; so inherited environment variables cannot redirect the authority.
!macro customInstall
  DetailPrint "Initializing installation authority..."
  nsExec::ExecToStack /TIMEOUT=120000 '"$INSTDIR\resources\engine\engine.exe" --nachuan-provision-installation-root'
  Pop $R8 ; native exit code (or an nsExec error token)
  Pop $R9 ; bounded engine output; deliberately never printed to the install log
  ${If} $R8 != 0
    ; customInstall runs after files, shortcuts and registry records are staged.
    ; Remove that staged application on failure and return a hard MSI-style
    ; failure code.  The independent ProgramData tombstone/authority is never
    ; deleted here: a retry may verify completed steps, while damaged state
    ; must remain fail-closed for explicit maintenance.
    Delete "$newStartMenuLink"
    Delete "$newDesktopLink"
    DeleteRegKey SHELL_CONTEXT "${UNINSTALL_REGISTRY_KEY}"
    !ifdef UNINSTALL_REGISTRY_KEY_2
      DeleteRegKey SHELL_CONTEXT "${UNINSTALL_REGISTRY_KEY_2}"
    !endif
    DeleteRegKey SHELL_CONTEXT "${INSTALL_REGISTRY_KEY}"
    SetOutPath "$TEMP"
    ClearErrors
    RMDir /r "$INSTDIR"
    ${If} ${FileExists} "$INSTDIR\*.*"
      DetailPrint "Application rollback left inaccessible files; installation remains failed."
    ${EndIf}
    ${IfNot} ${Silent}
      MessageBox MB_ICONSTOP|MB_OK "Installation authority initialization failed. No application was installed."
    ${EndIf}
    SetErrorLevel 1603
    Quit
  ${EndIf}
!macroend
