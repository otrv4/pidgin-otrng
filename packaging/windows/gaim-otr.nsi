; Script based on generated HM NIS Edit Script Wizard.
; Forgive me, i am new at this. -- paul@cypherpunks.ca
;
; known issue. installer induced uninstaller abortion causes overwrite by installer without
; uninstall.
; v3.0.1    - Version for gaim-2.0.0 beta5
; v3.0.0   - Bump version number.
; v2.0.2   - Bump version number.
; v2.0.1   - Bump version number.
; v2.0.0-2 - linking to libotr-2.0.1
; v2.0.0   - Bump version number. Fixed upgrading gaim2-otr (it didn't overwrite the dll)
;            bug reported by Aldert Hazenberg <aldert@xelerance.com>
;          - Added many safeguards and fixed conditions of failures when gaim is running
;             during install, or failed to (un)install previously.
;           - Removed popup signifying gaim is found
; v1.99.0-1 - Bump version number, install Protocol.txt file
; v1.0.3-2  - Fix for detecting gaim if not installed by Administrator
;             bug report by Joanna Rutkowska <joanna@mailsnare.net>
;           - Fix for uninstalling the dll when not installed as Administrator
; v1.0.3    - Initial version


; todo: SetBrandingImage
; HM NIS Edit Wizard helper defines
!define PRODUCT_NAME "gaim-otr"
!define PRODUCT_VERSION "3.0.1"
!define PRODUCT_PUBLISHER "Cypherpunks CA"
!define PRODUCT_WEB_SITE "http://www.cypherpunks.ca/otr/"
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
!define PRODUCT_UNINST_ROOT_KEY "HKLM"

; MUI 1.67 compatible ------
!include "MUI.nsh"

; MUI Settings
!define MUI_ABORTWARNING
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\modern-uninstall.ico"

; Welcome page
!insertmacro MUI_PAGE_WELCOME
; License page
!insertmacro MUI_PAGE_LICENSE "c:\otr\COPYING.txt"
; Directory page
!insertmacro MUI_PAGE_DIRECTORY
; Instfiles page
!insertmacro MUI_PAGE_INSTFILES
; Finish page
!define MUI_FINISHPAGE_SHOWREADME "$INSTDIR\README.txt"
!insertmacro MUI_PAGE_FINISH

; Uninstaller pages
!insertmacro MUI_UNPAGE_INSTFILES

; Language files
!insertmacro MUI_LANGUAGE "English"

; MUI end ------

Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "${PRODUCT_NAME}-${PRODUCT_VERSION}.exe"
InstallDir "$PROGRAMFILES\gaim2-otr"
InstallDirRegKey HKEY_LOCAL_MACHINE SOFTWARE\gaim-otr "Install_Dir"
;WriteRegStr HKLM "SOFTWARE\gaim2-otr" "gaimdir" ""

Var "GaimDir"

ShowInstDetails show
ShowUnInstDetails show

Section "MainSection" SEC01
;InstallDir "$PROGRAMFILES\Gaim\plugins"

; uninstall previous gaim2-otr install if found.
Call UnInstOld
 ;Check for gaim installation
Call GetGaimInstPath
WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "SOFTWARE\gaim2-otr" "gaimdir" "$GaimDir"

	SetOutPath "$INSTDIR"
  SetOverwrite on
  File "c:\otr\gaim2-otr.dll"
  ; move to gaim plugin directory, check if not busy (gaim is running)
	call CopyDLL
  ; hard part is done, do the rest now.
  SetOverwrite on	  
  File "c:\otr\README.Toolkit.txt"
	File "c:\otr\README.txt"
	File "c:\otr\Protocol-v2.html"
	File "c:\otr\COPYING.txt"
	File "c:\otr\COPYING.LIB.txt"
	File "c:\otr\otr_mackey.exe"
	File "c:\otr\otr_modify.exe"
	File "c:\otr\otr_parse.exe"
	File "c:\otr\otr_readforge.exe"
	File "c:\otr\otr_remac.exe"
	File "c:\otr\otr_sesskeys.exe"
	File "c:\otr\gaim-otr.nsi"
SectionEnd

Section -AdditionalIcons
  CreateDirectory "$SMPROGRAMS\gaim2-otr"
  CreateShortCut "$SMPROGRAMS\gaim2-otr\Uninstall.lnk" "$INSTDIR\gaim2-otr-uninst.exe"
SectionEnd

Section -Post
  WriteUninstaller "$INSTDIR\gaim2-otr-uninst.exe"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayName" "$(^Name)"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "UninstallString" "$INSTDIR\gaim2-otr-uninst.exe"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "URLInfoAbout" "${PRODUCT_WEB_SITE}"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "Publisher" "${PRODUCT_PUBLISHER}"
 
SectionEnd

Function un.onUninstSuccess
  HideWindow
  MessageBox MB_ICONINFORMATION|MB_OK "$(^Name) was successfully removed from your computer."
FunctionEnd

Function un.onInit
  MessageBox MB_ICONQUESTION|MB_YESNO|MB_DEFBUTTON2 "Are you sure you want to completely remove $(^Name) and all of its components?" IDYES +2
  Abort
FunctionEnd

Section Uninstall
  Delete "$INSTDIR\gaim2-otr-uninst.exe"
	Delete "$INSTDIR\README.Toolkit.txt"
	Delete "$INSTDIR\README.txt"
	Delete "$INSTDIR\Protocol-v2.txt"
	Delete "$INSTDIR\COPYING.txt"
	Delete "$INSTDIR\COPYING.LIB.txt"
	Delete "$INSTDIR\otr_mackey.exe"
	Delete "$INSTDIR\otr_modify.exe"
	Delete "$INSTDIR\otr_parse.exe"
	Delete "$INSTDIR\otr_readforge.exe"
	Delete "$INSTDIR\otr_remac.exe"
	Delete "$INSTDIR\otr_sesskeys.exe"
	Delete "$INSTDIR\gaim2-otr.nsi"
  Delete "$SMPROGRAMS\gaim2-otr\Uninstall.lnk"
  RMDir "$SMPROGRAMS\gaim2-otr"
  RMDir "$INSTDIR"
  
	ReadRegStr $GaimDir HKLM Software\gaim-otr "gaimdir"
	IfFileExists "$GaimDir\plugins\gaim-otr.dll" dodelete
  ReadRegStr $GaimDir HKCU Software\gaim-otr "gaimdir"
	IfFileExists "$GaimDir\plugins\gaim-otr.dll" dodelete
	
  ReadRegStr $GaimDir HKLM Software\gaim2-otr "gaimdir"
	IfFileExists "$GaimDir\plugins\gaim2-otr.dll" dodelete
  ReadRegStr $GaimDir HKCU Software\gaim2-otr "gaimdir"
	IfFileExists "$GaimDir\plugins\gaim2-otr.dll" dodelete
  MessageBox MB_OK|MB_ICONINFORMATION "Could not find gaim plugin directory, gaim2-otr.dll not uninstalled!" IDOK ok
dodelete:
	Delete "$GaimDir\plugins\gaim-otr.dll"
	Delete "$GaimDir\plugins\gaim2-otr.dll"
	
	IfFileExists "$GaimDir\plugins\gaim2-otr.dll" 0 +2
		MessageBox MB_OK|MB_ICONINFORMATION "gaim2-otr.dll is busy. Probably Gaim is still running. Please delete $GaimDir\plugins\gaim2-otr.dll manually."
  DeleteRegKey ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}"
  DeleteRegKey ${PRODUCT_UNINST_ROOT_KEY} "SOFTWARE\gaim2-otr\gaimdir"
ok:
SetAutoClose true
SectionEnd
Function GetGaimInstPath
  Push $0
  ReadRegStr $0 HKLM "Software\gaim" ""
	IfFileExists "$0\gaim.exe" cont
	ReadRegStr $0 HKCU "Software\gaim" ""
	IfFileExists "$0\gaim.exe" cont
  MessageBox MB_OK|MB_ICONINFORMATION "Failed to find GAIM installation."
		Abort "Failed to find GAIM installation. Please install GAIM first."
cont:
	StrCpy $GaimDir $0
	;MessageBox MB_OK|MB_ICONINFORMATION "Gaim plugin directory found at $GaimDir\plugins ."
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "SOFTWARE\gaim2-otr" "gaimdir" "$GaimDir"
FunctionEnd

Function UnInstOld
	  Push $0
	  ReadRegStr $0 ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "UninstallString"
		IfFileExists "$0" deinst cont
	deinst:
		MessageBox MB_OK|MB_ICONEXCLAMATION  "gaim2-otr was already found on your system and will first be uninstalled"
		; the uninstaller copies itself to temp and execs itself there, so it can delete 
		; everything including its own original file location. To prevent the installer and
		; uninstaller racing you can't simply ExecWait.
		; We hide the uninstall because otherwise it gets really confusing window-wise
		;HideWindow
		  ClearErrors
			ExecWait '"$0" _?=$INSTDIR'
			IfErrors 0 cont
				MessageBox MB_OK|MB_ICONEXCLAMATION  "Uninstall failed or aborted"
				Abort "Uninstalling of the previous version gave an error. Install aborted."
			
		;BringToFront
	cont:
		;MessageBox MB_OK|MB_ICONINFORMATION "No old gaim2-otr found, continuing."
		
FunctionEnd

Function CopyDLL
SetOverwrite try
ClearErrors
; 3 hours wasted so you guys don't need a reboot!
; Rename /REBOOTOK "$INSTDIR\gaim2-otr.dll" "$GaimDir\plugins\gaim2-otr.dll"
IfFileExists "$GaimDir\plugins\gaim2-otr.dll" 0 copy ; remnant or uninstall prev version failed
Delete "$GaimDir\plugins\gaim2-otr.dll"
copy:
ClearErrors
Rename "$INSTDIR\gaim2-otr.dll" "$GaimDir\plugins\gaim2-otr.dll"
IfErrors dllbusy
	Return
dllbusy:
	MessageBox MB_RETRYCANCEL "gaim2-otr.dll is busy. Please close Gaim (including tray icon) and try again" IDCANCEL cancel
	Delete "$GaimDir\plugins\gaim2-otr.dll"
	Goto copy
	Return
cancel:
	Abort "Installation of gaim2-otr aborted"
FunctionEnd
