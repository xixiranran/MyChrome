#NoTrayIcon
Global Const $MEM_COMMIT = 4096
Global Const $MEM_RESERVE = 8192
Global Const $PAGE_READWRITE = 4
Global Const $MEM_RELEASE = 32768
Global Const $PROCESS_VM_OPERATION = 8
Global Const $PROCESS_VM_READ = 16
Global Const $PROCESS_VM_WRITE = 32
Global Const $SE_PRIVILEGE_ENABLED = 2
Global Enum $SECURITYANONYMOUS = 0 , $SECURITYIDENTIFICATION , $SECURITYIMPERSONATION , $SECURITYDELEGATION
Global Enum $TOKENUSER = 1 , $TOKENGROUPS , $TOKENPRIVILEGES , $TOKENOWNER , $TOKENPRIMARYGROUP , $TOKENDEFAULTDACL , $TOKENSOURCE , $TOKENTYPE , $TOKENIMPERSONATIONLEVEL , $TOKENSTATISTICS , $TOKENRESTRICTEDSIDS , $TOKENSESSIONID , $TOKENGROUPSANDPRIVILEGES , $TOKENSESSIONREFERENCE , $TOKENSANDBOXINERT , $TOKENAUDITPOLICY , $TOKENORIGIN , $TOKENELEVATIONTYPE , $TOKENLINKEDTOKEN , $TOKENELEVATION , $TOKENHASRESTRICTIONS , $TOKENACCESSINFORMATION , $TOKENVIRTUALIZATIONALLOWED , $TOKENVIRTUALIZATIONENABLED , $TOKENINTEGRITYLEVEL , $TOKENUIACCESS , $TOKENMANDATORYPOLICY , $TOKENLOGONSID
Global Const $TOKEN_QUERY = 8
Global Const $TOKEN_ADJUST_PRIVILEGES = 32
Func _WINAPI_GETLASTERROR ( Const $_ICURRENTERROR = @error , Const $_ICURRENTEXTENDED = @extended )
	Local $ARESULT = DllCall ( "kernel32.dll" , "dword" , "GetLastError" )
	Return SetError ( $_ICURRENTERROR , $_ICURRENTEXTENDED , $ARESULT [ 0 ] )
EndFunc
Func _WINAPI_SETLASTERROR ( $IERRORCODE , Const $_ICURRENTERROR = @error , Const $_ICURRENTEXTENDED = @extended )
	DllCall ( "kernel32.dll" , "none" , "SetLastError" , "dword" , $IERRORCODE )
	Return SetError ( $_ICURRENTERROR , $_ICURRENTEXTENDED , Null )
EndFunc
Func _SECURITY__ADJUSTTOKENPRIVILEGES ( $HTOKEN , $BDISABLEALL , $TNEWSTATE , $IBUFFERLEN , $TPREVSTATE = 0 , $PREQUIRED = 0 )
	Local $ACALL = DllCall ( "advapi32.dll" , "bool" , "AdjustTokenPrivileges" , "handle" , $HTOKEN , "bool" , $BDISABLEALL , "struct*" , $TNEWSTATE , "dword" , $IBUFFERLEN , "struct*" , $TPREVSTATE , "struct*" , $PREQUIRED )
	If @error Then Return SetError ( @error , @extended , False )
	Return Not ( $ACALL [ 0 ] = 0 )
EndFunc
Func _SECURITY__GETTOKENINFORMATION ( $HTOKEN , $ICLASS )
	Local $ACALL = DllCall ( "advapi32.dll" , "bool" , "GetTokenInformation" , "handle" , $HTOKEN , "int" , $ICLASS , "struct*" , 0 , "dword" , 0 , "dword*" , 0 )
	If @error Or Not $ACALL [ 5 ] Then Return SetError ( @error + 10 , @extended , 0 )
	Local $ILEN = $ACALL [ 5 ]
	Local $TBUFFER = DllStructCreate ( "byte[" & $ILEN & "]" )
	$ACALL = DllCall ( "advapi32.dll" , "bool" , "GetTokenInformation" , "handle" , $HTOKEN , "int" , $ICLASS , "struct*" , $TBUFFER , "dword" , DllStructGetSize ( $TBUFFER ) , "dword*" , 0 )
	If @error Or Not $ACALL [ 0 ] Then Return SetError ( @error , @extended , 0 )
	Return $TBUFFER
EndFunc
Func _SECURITY__IMPERSONATESELF ( $ILEVEL = $SECURITYIMPERSONATION )
	Local $ACALL = DllCall ( "advapi32.dll" , "bool" , "ImpersonateSelf" , "int" , $ILEVEL )
	If @error Then Return SetError ( @error , @extended , False )
	Return Not ( $ACALL [ 0 ] = 0 )
EndFunc
Func _SECURITY__ISVALIDSID ( $PSID )
	Local $ACALL = DllCall ( "advapi32.dll" , "bool" , "IsValidSid" , "struct*" , $PSID )
	If @error Then Return SetError ( @error , @extended , False )
	Return Not ( $ACALL [ 0 ] = 0 )
EndFunc
Func _SECURITY__LOOKUPPRIVILEGEVALUE ( $SSYSTEM , $SNAME )
	Local $ACALL = DllCall ( "advapi32.dll" , "bool" , "LookupPrivilegeValueW" , "wstr" , $SSYSTEM , "wstr" , $SNAME , "int64*" , 0 )
	If @error Or Not $ACALL [ 0 ] Then Return SetError ( @error , @extended , 0 )
	Return $ACALL [ 3 ]
EndFunc
Func _SECURITY__OPENPROCESSTOKEN ( $HPROCESS , $IACCESS )
	Local $ACALL = DllCall ( "advapi32.dll" , "bool" , "OpenProcessToken" , "handle" , $HPROCESS , "dword" , $IACCESS , "handle*" , 0 )
	If @error Or Not $ACALL [ 0 ] Then Return SetError ( @error , @extended , 0 )
	Return $ACALL [ 3 ]
EndFunc
Func _SECURITY__OPENTHREADTOKEN ( $IACCESS , $HTHREAD = 0 , $BOPENASSELF = False )
	If $HTHREAD = 0 Then
		Local $ARESULT = DllCall ( "kernel32.dll" , "handle" , "GetCurrentThread" )
		If @error Then Return SetError ( @error + 10 , @extended , 0 )
		$HTHREAD = $ARESULT [ 0 ]
	EndIf
	Local $ACALL = DllCall ( "advapi32.dll" , "bool" , "OpenThreadToken" , "handle" , $HTHREAD , "dword" , $IACCESS , "bool" , $BOPENASSELF , "handle*" , 0 )
	If @error Or Not $ACALL [ 0 ] Then Return SetError ( @error , @extended , 0 )
	Return $ACALL [ 4 ]
EndFunc
Func _SECURITY__OPENTHREADTOKENEX ( $IACCESS , $HTHREAD = 0 , $BOPENASSELF = False )
	Local $HTOKEN = _SECURITY__OPENTHREADTOKEN ( $IACCESS , $HTHREAD , $BOPENASSELF )
	If $HTOKEN = 0 Then
		Local Const $ERROR_NO_TOKEN = 1008
		If _WINAPI_GETLASTERROR ( ) <> $ERROR_NO_TOKEN Then Return SetError ( 20 , _WINAPI_GETLASTERROR ( ) , 0 )
		If Not _SECURITY__IMPERSONATESELF ( ) Then Return SetError ( @error + 10 , _WINAPI_GETLASTERROR ( ) , 0 )
		$HTOKEN = _SECURITY__OPENTHREADTOKEN ( $IACCESS , $HTHREAD , $BOPENASSELF )
		If $HTOKEN = 0 Then Return SetError ( @error , _WINAPI_GETLASTERROR ( ) , 0 )
	EndIf
	Return $HTOKEN
EndFunc
Func _SECURITY__SETPRIVILEGE ( $HTOKEN , $SPRIVILEGE , $BENABLE )
	Local $ILUID = _SECURITY__LOOKUPPRIVILEGEVALUE ( "" , $SPRIVILEGE )
	If $ILUID = 0 Then Return SetError ( @error + 10 , @extended , False )
	Local Const $TAGTOKEN_PRIVILEGES = "dword Count;align 4;int64 LUID;dword Attributes"
	Local $TCURRSTATE = DllStructCreate ( $TAGTOKEN_PRIVILEGES )
	Local $ICURRSTATE = DllStructGetSize ( $TCURRSTATE )
	Local $TPREVSTATE = DllStructCreate ( $TAGTOKEN_PRIVILEGES )
	Local $IPREVSTATE = DllStructGetSize ( $TPREVSTATE )
	Local $TREQUIRED = DllStructCreate ( "int Data" )
	DllStructSetData ( $TCURRSTATE , "Count" , 1 )
	DllStructSetData ( $TCURRSTATE , "LUID" , $ILUID )
	If Not _SECURITY__ADJUSTTOKENPRIVILEGES ( $HTOKEN , False , $TCURRSTATE , $ICURRSTATE , $TPREVSTATE , $TREQUIRED ) Then Return SetError ( 2 , @error , False )
	DllStructSetData ( $TPREVSTATE , "Count" , 1 )
	DllStructSetData ( $TPREVSTATE , "LUID" , $ILUID )
	Local $IATTRIBUTES = DllStructGetData ( $TPREVSTATE , "Attributes" )
	If $BENABLE Then
		$IATTRIBUTES = BitOR ( $IATTRIBUTES , $SE_PRIVILEGE_ENABLED )
	Else
		$IATTRIBUTES = BitAND ( $IATTRIBUTES , BitNOT ( $SE_PRIVILEGE_ENABLED ) )
	EndIf
	DllStructSetData ( $TPREVSTATE , "Attributes" , $IATTRIBUTES )
	If Not _SECURITY__ADJUSTTOKENPRIVILEGES ( $HTOKEN , False , $TPREVSTATE , $IPREVSTATE , $TCURRSTATE , $TREQUIRED ) Then Return SetError ( 3 , @error , False )
	Return True
EndFunc
Func _SECURITY__SIDTOSTRINGSID ( $PSID )
	If Not _SECURITY__ISVALIDSID ( $PSID ) Then Return SetError ( @error + 10 , 0 , "" )
	Local $ACALL = DllCall ( "advapi32.dll" , "bool" , "ConvertSidToStringSidW" , "struct*" , $PSID , "ptr*" , 0 )
	If @error Or Not $ACALL [ 0 ] Then Return SetError ( @error , @extended , "" )
	Local $PSTRINGSID = $ACALL [ 2 ]
	Local $ALEN = DllCall ( "kernel32.dll" , "int" , "lstrlenW" , "struct*" , $PSTRINGSID )
	Local $SSID = DllStructGetData ( DllStructCreate ( "wchar Text[" & $ALEN [ 0 ] + 1 & "]" , $PSTRINGSID ) , "Text" )
	DllCall ( "kernel32.dll" , "handle" , "LocalFree" , "handle" , $PSTRINGSID )
	Return $SSID
EndFunc
Global Const $TAGPOINT = "struct;long X;long Y;endstruct"
Global Const $TAGRECT = "struct;long Left;long Top;long Right;long Bottom;endstruct"
Global Const $TAGREBARBANDINFO = "uint cbSize;uint fMask;uint fStyle;dword clrFore;dword clrBack;ptr lpText;uint cch;" & "int iImage;hwnd hwndChild;uint cxMinChild;uint cyMinChild;uint cx;handle hbmBack;uint wID;uint cyChild;uint cyMaxChild;" & "uint cyIntegral;uint cxIdeal;lparam lParam;uint cxHeader" & ( ( @OSVersion = "WIN_XP" ) ? "" : ";" & $TAGRECT & ";uint uChevronState" )
Global Const $TAGGUID = "struct;ulong Data1;ushort Data2;ushort Data3;byte Data4[8];endstruct"
Global Const $TAGMEMMAP = "handle hProc;ulong_ptr Size;ptr Mem"
Func _MEMFREE ( ByRef $TMEMMAP )
	Local $PMEMORY = DllStructGetData ( $TMEMMAP , "Mem" )
	Local $HPROCESS = DllStructGetData ( $TMEMMAP , "hProc" )
	Local $BRESULT = _MEMVIRTUALFREEEX ( $HPROCESS , $PMEMORY , 0 , $MEM_RELEASE )
	DllCall ( "kernel32.dll" , "bool" , "CloseHandle" , "handle" , $HPROCESS )
	If @error Then Return SetError ( @error , @extended , False )
	Return $BRESULT
EndFunc
Func _MEMINIT ( $HWND , $ISIZE , ByRef $TMEMMAP )
	Local $ARESULT = DllCall ( "user32.dll" , "dword" , "GetWindowThreadProcessId" , "hwnd" , $HWND , "dword*" , 0 )
	If @error Then Return SetError ( @error + 10 , @extended , 0 )
	Local $IPROCESSID = $ARESULT [ 2 ]
	If $IPROCESSID = 0 Then Return SetError ( 1 , 0 , 0 )
	Local $IACCESS = BitOR ( $PROCESS_VM_OPERATION , $PROCESS_VM_READ , $PROCESS_VM_WRITE )
	Local $HPROCESS = __MEM_OPENPROCESS ( $IACCESS , False , $IPROCESSID , True )
	Local $IALLOC = BitOR ( $MEM_RESERVE , $MEM_COMMIT )
	Local $PMEMORY = _MEMVIRTUALALLOCEX ( $HPROCESS , 0 , $ISIZE , $IALLOC , $PAGE_READWRITE )
	If $PMEMORY = 0 Then Return SetError ( 2 , 0 , 0 )
	$TMEMMAP = DllStructCreate ( $TAGMEMMAP )
	DllStructSetData ( $TMEMMAP , "hProc" , $HPROCESS )
	DllStructSetData ( $TMEMMAP , "Size" , $ISIZE )
	DllStructSetData ( $TMEMMAP , "Mem" , $PMEMORY )
	Return $PMEMORY
EndFunc
Func _MEMWRITE ( ByRef $TMEMMAP , $PSRCE , $PDEST = 0 , $ISIZE = 0 , $SSRCE = "struct*" )
	If $PDEST = 0 Then $PDEST = DllStructGetData ( $TMEMMAP , "Mem" )
	If $ISIZE = 0 Then $ISIZE = DllStructGetData ( $TMEMMAP , "Size" )
	Local $ARESULT = DllCall ( "kernel32.dll" , "bool" , "WriteProcessMemory" , "handle" , DllStructGetData ( $TMEMMAP , "hProc" ) , "ptr" , $PDEST , $SSRCE , $PSRCE , "ulong_ptr" , $ISIZE , "ulong_ptr*" , 0 )
	If @error Then Return SetError ( @error , @extended , False )
	Return $ARESULT [ 0 ]
EndFunc
Func _MEMVIRTUALALLOCEX ( $HPROCESS , $PADDRESS , $ISIZE , $IALLOCATION , $IPROTECT )
	Local $ARESULT = DllCall ( "kernel32.dll" , "ptr" , "VirtualAllocEx" , "handle" , $HPROCESS , "ptr" , $PADDRESS , "ulong_ptr" , $ISIZE , "dword" , $IALLOCATION , "dword" , $IPROTECT )
	If @error Then Return SetError ( @error , @extended , 0 )
	Return $ARESULT [ 0 ]
EndFunc
Func _MEMVIRTUALFREEEX ( $HPROCESS , $PADDRESS , $ISIZE , $IFREETYPE )
	Local $ARESULT = DllCall ( "kernel32.dll" , "bool" , "VirtualFreeEx" , "handle" , $HPROCESS , "ptr" , $PADDRESS , "ulong_ptr" , $ISIZE , "dword" , $IFREETYPE )
	If @error Then Return SetError ( @error , @extended , False )
	Return $ARESULT [ 0 ]
EndFunc
Func __MEM_OPENPROCESS ( $IACCESS , $BINHERIT , $IPROCESSID , $BDEBUGPRIV = False )
	Local $ARESULT = DllCall ( "kernel32.dll" , "handle" , "OpenProcess" , "dword" , $IACCESS , "bool" , $BINHERIT , "dword" , $IPROCESSID )
	If @error Then Return SetError ( @error + 10 , @extended , 0 )
	If $ARESULT [ 0 ] Then Return $ARESULT [ 0 ]
	If Not $BDEBUGPRIV Then Return 0
	Local $HTOKEN = _SECURITY__OPENTHREADTOKENEX ( BitOR ( $TOKEN_ADJUST_PRIVILEGES , $TOKEN_QUERY ) )
	If @error Then Return SetError ( @error + 20 , @extended , 0 )
	_SECURITY__SETPRIVILEGE ( $HTOKEN , "SeDebugPrivilege" , True )
	Local $IERROR = @error
	Local $ILASTERROR = @extended
	Local $IRET = 0
	If Not @error Then
		$ARESULT = DllCall ( "kernel32.dll" , "handle" , "OpenProcess" , "dword" , $IACCESS , "bool" , $BINHERIT , "dword" , $IPROCESSID )
		$IERROR = @error
		$ILASTERROR = @extended
		If $ARESULT [ 0 ] Then $IRET = $ARESULT [ 0 ]
		_SECURITY__SETPRIVILEGE ( $HTOKEN , "SeDebugPrivilege" , False )
		If @error Then
			$IERROR = @error + 30
			$ILASTERROR = @extended
		EndIf
	Else
		$IERROR = @error + 40
	EndIf
	DllCall ( "kernel32.dll" , "bool" , "CloseHandle" , "handle" , $HTOKEN )
	Return SetError ( $IERROR , $ILASTERROR , $IRET )
EndFunc
Global Const $UBOUND_DIMENSIONS = 0
Global Const $UBOUND_COLUMNS = 2
Global Const $MOUSEEVENTF_XDOWN = 128
Global Const $MOUSEEVENTF_XUP = 256
Global Const $FO_READ = 0
Global Const $FO_OVERWRITE = 2
Func _SENDMESSAGE ( $HWND , $IMSG , $WPARAM = 0 , $LPARAM = 0 , $IRETURN = 0 , $WPARAMTYPE = "wparam" , $LPARAMTYPE = "lparam" , $SRETURNTYPE = "lresult" )
	Local $ARESULT = DllCall ( "user32.dll" , $SRETURNTYPE , "SendMessageW" , "hwnd" , $HWND , "uint" , $IMSG , $WPARAMTYPE , $WPARAM , $LPARAMTYPE , $LPARAM )
	If @error Then Return SetError ( @error , @extended , "" )
	If $IRETURN >= 0 And $IRETURN <= 4 Then Return $ARESULT [ $IRETURN ]
	Return $ARESULT
EndFunc
Global Const $STR_REGEXPARRAYGLOBALMATCH = 3
Global Const $HGDI_ERROR = Ptr ( - 1 )
Global Const $INVALID_HANDLE_VALUE = Ptr ( - 1 )
Global Const $WH_MOUSE = 7
Global Const $KF_EXTENDED = 256
Global Const $KF_ALTDOWN = 8192
Global Const $KF_UP = 32768
Global Const $LLKHF_EXTENDED = BitShift ( $KF_EXTENDED , 8 )
Global Const $LLKHF_ALTDOWN = BitShift ( $KF_ALTDOWN , 8 )
Global Const $LLKHF_UP = BitShift ( $KF_UP , 8 )
Global Const $GWL_WNDPROC = 4294967292
Global $__G_AINPROCESS_WINAPI [ 64 ] [ 2 ] = [ [ 0 , 0 ] ]
Func _WINAPI_CALLWINDOWPROC ( $PPREVWNDFUNC , $HWND , $IMSG , $WPARAM , $LPARAM )
	Local $ARESULT = DllCall ( "user32.dll" , "lresult" , "CallWindowProc" , "ptr" , $PPREVWNDFUNC , "hwnd" , $HWND , "uint" , $IMSG , "wparam" , $WPARAM , "lparam" , $LPARAM )
	If @error Then Return SetError ( @error , @extended , - 1 )
	Return $ARESULT [ 0 ]
EndFunc
Func _WINAPI_CLOSEHANDLE ( $HOBJECT )
	Local $ARESULT = DllCall ( "kernel32.dll" , "bool" , "CloseHandle" , "handle" , $HOBJECT )
	If @error Then Return SetError ( @error , @extended , False )
	Return $ARESULT [ 0 ]
EndFunc
Func _WINAPI_CREATEEVENT ( $TATTRIBUTES = 0 , $BMANUALRESET = True , $BINITIALSTATE = True , $SNAME = "" )
	Local $SNAMETYPE = "wstr"
	If $SNAME = "" Then
		$SNAME = 0
		$SNAMETYPE = "ptr"
	EndIf
	Local $ARESULT = DllCall ( "kernel32.dll" , "handle" , "CreateEventW" , "struct*" , $TATTRIBUTES , "bool" , $BMANUALRESET , "bool" , $BINITIALSTATE , $SNAMETYPE , $SNAME )
	If @error Then Return SetError ( @error , @extended , 0 )
	Return $ARESULT [ 0 ]
EndFunc
Func _WINAPI_CREATEWINDOWEX ( $IEXSTYLE , $SCLASS , $SNAME , $ISTYLE , $IX , $IY , $IWIDTH , $IHEIGHT , $HPARENT , $HMENU = 0 , $HINSTANCE = 0 , $PPARAM = 0 )
	If $HINSTANCE = 0 Then $HINSTANCE = _WINAPI_GETMODULEHANDLE ( "" )
	Local $ARESULT = DllCall ( "user32.dll" , "hwnd" , "CreateWindowExW" , "dword" , $IEXSTYLE , "wstr" , $SCLASS , "wstr" , $SNAME , "dword" , $ISTYLE , "int" , $IX , "int" , $IY , "int" , $IWIDTH , "int" , $IHEIGHT , "hwnd" , $HPARENT , "handle" , $HMENU , "handle" , $HINSTANCE , "struct*" , $PPARAM )
	If @error Then Return SetError ( @error , @extended , 0 )
	Return $ARESULT [ 0 ]
EndFunc
Func _WINAPI_FREELIBRARY ( $HMODULE )
	Local $ARESULT = DllCall ( "kernel32.dll" , "bool" , "FreeLibrary" , "handle" , $HMODULE )
	If @error Then Return SetError ( @error , @extended , False )
	Return $ARESULT [ 0 ]
EndFunc
Func _WINAPI_GETCLASSNAME ( $HWND )
	If Not IsHWnd ( $HWND ) Then $HWND = GUICtrlGetHandle ( $HWND )
	Local $ARESULT = DllCall ( "user32.dll" , "int" , "GetClassNameW" , "hwnd" , $HWND , "wstr" , "" , "int" , 4096 )
	If @error Or Not $ARESULT [ 0 ] Then Return SetError ( @error , @extended , "" )
	Return SetExtended ( $ARESULT [ 0 ] , $ARESULT [ 2 ] )
EndFunc
Func _WINAPI_GETCURRENTPROCESS ( )
	Local $ARESULT = DllCall ( "kernel32.dll" , "handle" , "GetCurrentProcess" )
	If @error Then Return SetError ( @error , @extended , 0 )
	Return $ARESULT [ 0 ]
EndFunc
Func _WINAPI_GETMODULEHANDLE ( $SMODULENAME )
	Local $SMODULENAMETYPE = "wstr"
	If $SMODULENAME = "" Then
		$SMODULENAME = 0
		$SMODULENAMETYPE = "ptr"
	EndIf
	Local $ARESULT = DllCall ( "kernel32.dll" , "handle" , "GetModuleHandleW" , $SMODULENAMETYPE , $SMODULENAME )
	If @error Then Return SetError ( @error , @extended , 0 )
	Return $ARESULT [ 0 ]
EndFunc
Func _WINAPI_GETPROCADDRESS ( $HMODULE , $VNAME )
	Local $STYPE = "str"
	If IsNumber ( $VNAME ) Then $STYPE = "word"
	Local $ARESULT = DllCall ( "kernel32.dll" , "ptr" , "GetProcAddress" , "handle" , $HMODULE , $STYPE , $VNAME )
	If @error Or Not $ARESULT [ 0 ] Then Return SetError ( @error , @extended , 0 )
	Return $ARESULT [ 0 ]
EndFunc
Func _WINAPI_GETWINDOWTHREADPROCESSID ( $HWND , ByRef $IPID )
	Local $ARESULT = DllCall ( "user32.dll" , "dword" , "GetWindowThreadProcessId" , "hwnd" , $HWND , "dword*" , 0 )
	If @error Then Return SetError ( @error , @extended , 0 )
	$IPID = $ARESULT [ 2 ]
	Return $ARESULT [ 0 ]
EndFunc
Func _WINAPI_GUIDFROMSTRING ( $SGUID )
	Local $TGUID = DllStructCreate ( $TAGGUID )
	_WINAPI_GUIDFROMSTRINGEX ( $SGUID , $TGUID )
	If @error Then Return SetError ( @error + 10 , @extended , 0 )
	Return $TGUID
EndFunc
Func _WINAPI_GUIDFROMSTRINGEX ( $SGUID , $TGUID )
	Local $ARESULT = DllCall ( "ole32.dll" , "long" , "CLSIDFromString" , "wstr" , $SGUID , "struct*" , $TGUID )
	If @error Then Return SetError ( @error , @extended , False )
	Return $ARESULT [ 0 ]
EndFunc
Func _WINAPI_INPROCESS ( $HWND , ByRef $HLASTWND )
	If $HWND = $HLASTWND Then Return True
	For $II = $__G_AINPROCESS_WINAPI [ 0 ] [ 0 ] To 1 Step - 1
		If $HWND = $__G_AINPROCESS_WINAPI [ $II ] [ 0 ] Then
			If $__G_AINPROCESS_WINAPI [ $II ] [ 1 ] Then
				$HLASTWND = $HWND
				Return True
			Else
				Return False
			EndIf
		EndIf
	Next
	Local $IPID
	_WINAPI_GETWINDOWTHREADPROCESSID ( $HWND , $IPID )
	Local $ICOUNT = $__G_AINPROCESS_WINAPI [ 0 ] [ 0 ] + 1
	If $ICOUNT >= 64 Then $ICOUNT = 1
	$__G_AINPROCESS_WINAPI [ 0 ] [ 0 ] = $ICOUNT
	$__G_AINPROCESS_WINAPI [ $ICOUNT ] [ 0 ] = $HWND
	$__G_AINPROCESS_WINAPI [ $ICOUNT ] [ 1 ] = ( $IPID = @AutoItPID )
	Return $__G_AINPROCESS_WINAPI [ $ICOUNT ] [ 1 ]
EndFunc
Func _WINAPI_LOADLIBRARY ( $SFILENAME )
	Local $ARESULT = DllCall ( "kernel32.dll" , "handle" , "LoadLibraryW" , "wstr" , $SFILENAME )
	If @error Then Return SetError ( @error , @extended , 0 )
	Return $ARESULT [ 0 ]
EndFunc
Func _WINAPI_MAKELONG ( $ILO , $IHI )
	Return BitOR ( BitShift ( $IHI , - 16 ) , BitAND ( $ILO , 65535 ) )
EndFunc
Func _WINAPI_MOUSE_EVENT ( $IFLAGS , $IX = 0 , $IY = 0 , $IDATA = 0 , $IEXTRAINFO = 0 )
	DllCall ( "user32.dll" , "none" , "mouse_event" , "dword" , $IFLAGS , "dword" , $IX , "dword" , $IY , "dword" , $IDATA , "ulong_ptr" , $IEXTRAINFO )
	If @error Then Return SetError ( @error , @extended )
EndFunc
Func _WINAPI_SETWINDOWLONG ( $HWND , $IINDEX , $IVALUE )
	_WINAPI_SETLASTERROR ( 0 )
	Local $SFUNCNAME = "SetWindowLongW"
	If @AutoItX64 Then $SFUNCNAME = "SetWindowLongPtrW"
	Local $ARESULT = DllCall ( "user32.dll" , "long_ptr" , $SFUNCNAME , "hwnd" , $HWND , "int" , $IINDEX , "long_ptr" , $IVALUE )
	If @error Then Return SetError ( @error , @extended , 0 )
	Return $ARESULT [ 0 ]
EndFunc
Func _WINAPI_SETWINDOWSHOOKEX ( $IHOOK , $PPROC , $HDLL , $ITHREADID = 0 )
	Local $ARESULT = DllCall ( "user32.dll" , "handle" , "SetWindowsHookEx" , "int" , $IHOOK , "ptr" , $PPROC , "handle" , $HDLL , "dword" , $ITHREADID )
	If @error Then Return SetError ( @error , @extended , 0 )
	Return $ARESULT [ 0 ]
EndFunc
Func _WINAPI_STRINGLENW ( Const ByRef $TSTRING )
	Local $ARESULT = DllCall ( "kernel32.dll" , "int" , "lstrlenW" , "struct*" , $TSTRING )
	If @error Then Return SetError ( @error , @extended , 0 )
	Return $ARESULT [ 0 ]
EndFunc
Func _WINAPI_UNHOOKWINDOWSHOOKEX ( $HHOOK )
	Local $ARESULT = DllCall ( "user32.dll" , "bool" , "UnhookWindowsHookEx" , "handle" , $HHOOK )
	If @error Then Return SetError ( @error , @extended , False )
	Return $ARESULT [ 0 ]
EndFunc
Func _WINAPI_WAITFORSINGLEOBJECT ( $HHANDLE , $ITIMEOUT = - 1 )
	Local $ARESULT = DllCall ( "kernel32.dll" , "INT" , "WaitForSingleObject" , "handle" , $HHANDLE , "dword" , $ITIMEOUT )
	If @error Then Return SetError ( @error , @extended , - 1 )
	Return $ARESULT [ 0 ]
EndFunc
Func _WINAPI_WINDOWFROMPOINT ( ByRef $TPOINT )
	Local $ARESULT = DllCall ( "user32.dll" , "hwnd" , "WindowFromPoint" , "struct" , $TPOINT )
	If @error Then Return SetError ( @error , @extended , 0 )
	Return $ARESULT [ 0 ]
EndFunc
Global Const $TAGOSVERSIONINFO = "struct;dword OSVersionInfoSize;dword MajorVersion;dword MinorVersion;dword BuildNumber;dword PlatformId;wchar CSDVersion[128];endstruct"
Global Const $__WINVER = __WINVER ( )
Func _WINAPI_ISWOW64PROCESS ( $IPID = 0 )
	If Not $IPID Then $IPID = @AutoItPID
	Local $HPROCESS = DllCall ( "kernel32.dll" , "handle" , "OpenProcess" , "dword" , __IIF ( $__WINVER < 1536 , 1024 , 4096 ) , "bool" , 0 , "dword" , $IPID )
	If @error Or Not $HPROCESS [ 0 ] Then Return SetError ( @error + 20 , @extended , False )
	Local $ARET = DllCall ( "kernel32.dll" , "bool" , "IsWow64Process" , "handle" , $HPROCESS [ 0 ] , "bool*" , 0 )
	If __CHECKERRORCLOSEHANDLE ( $ARET , $HPROCESS [ 0 ] ) Then Return SetError ( @error , @extended , False )
	Return $ARET [ 2 ]
EndFunc
Func __CHECKERRORCLOSEHANDLE ( $ARET , $HFILE , $BLASTERROR = 0 , $ICURERR = @error , $ICUREXT = @extended )
	If Not $ICURERR And Not $ARET [ 0 ] Then $ICURERR = 10
	Local $ILASTERROR = _WINAPI_GETLASTERROR ( )
	DllCall ( "kernel32.dll" , "bool" , "CloseHandle" , "handle" , $HFILE )
	If $ICURERR Then _WINAPI_SETLASTERROR ( $ILASTERROR )
	If $BLASTERROR Then $ICUREXT = $ILASTERROR
	Return SetError ( $ICURERR , $ICUREXT , $ICURERR )
EndFunc
Func __IIF ( $BTEST , $VTRUE , $VFALSE )
	Return $BTEST ? $VTRUE : $VFALSE
EndFunc
Func __WINVER ( )
	Local $TOSVI = DllStructCreate ( $TAGOSVERSIONINFO )
	DllStructSetData ( $TOSVI , 1 , DllStructGetSize ( $TOSVI ) )
	Local $ARET = DllCall ( "kernel32.dll" , "bool" , "GetVersionExW" , "struct*" , $TOSVI )
	If @error Or Not $ARET [ 0 ] Then Return SetError ( @error , @extended , 0 )
	Return BitOR ( BitShift ( DllStructGetData ( $TOSVI , 2 ) , - 8 ) , DllStructGetData ( $TOSVI , 3 ) )
EndFunc
Func _DATEDIFF ( $STYPE , $SSTARTDATE , $SENDDATE )
	$STYPE = StringLeft ( $STYPE , 1 )
	If StringInStr ( "d,m,y,w,h,n,s" , $STYPE ) = 0 Or $STYPE = "" Then
		Return SetError ( 1 , 0 , 0 )
	EndIf
	If Not _DATEISVALID ( $SSTARTDATE ) Then
		Return SetError ( 2 , 0 , 0 )
	EndIf
	If Not _DATEISVALID ( $SENDDATE ) Then
		Return SetError ( 3 , 0 , 0 )
	EndIf
	Local $ASSTARTDATEPART [ 4 ] , $ASSTARTTIMEPART [ 4 ] , $ASENDDATEPART [ 4 ] , $ASENDTIMEPART [ 4 ]
	_DATETIMESPLIT ( $SSTARTDATE , $ASSTARTDATEPART , $ASSTARTTIMEPART )
	_DATETIMESPLIT ( $SENDDATE , $ASENDDATEPART , $ASENDTIMEPART )
	Local $ADAYSDIFF = _DATETODAYVALUE ( $ASENDDATEPART [ 1 ] , $ASENDDATEPART [ 2 ] , $ASENDDATEPART [ 3 ] ) - _DATETODAYVALUE ( $ASSTARTDATEPART [ 1 ] , $ASSTARTDATEPART [ 2 ] , $ASSTARTDATEPART [ 3 ] )
	Local $ITIMEDIFF , $IYEARDIFF , $ISTARTTIMEINSECS , $IENDTIMEINSECS
	If $ASSTARTTIMEPART [ 0 ] > 1 And $ASENDTIMEPART [ 0 ] > 1 Then
		$ISTARTTIMEINSECS = $ASSTARTTIMEPART [ 1 ] * 3600 + $ASSTARTTIMEPART [ 2 ] * 60 + $ASSTARTTIMEPART [ 3 ]
		$IENDTIMEINSECS = $ASENDTIMEPART [ 1 ] * 3600 + $ASENDTIMEPART [ 2 ] * 60 + $ASENDTIMEPART [ 3 ]
		$ITIMEDIFF = $IENDTIMEINSECS - $ISTARTTIMEINSECS
		If $ITIMEDIFF < 0 Then
			$ADAYSDIFF = $ADAYSDIFF - 1
			$ITIMEDIFF = $ITIMEDIFF + 24 * 60 * 60
		EndIf
	Else
		$ITIMEDIFF = 0
	EndIf
	Select
	Case $STYPE = "d"
		Return $ADAYSDIFF
	Case $STYPE = "m"
		$IYEARDIFF = $ASENDDATEPART [ 1 ] - $ASSTARTDATEPART [ 1 ]
		Local $IMONTHDIFF = $ASENDDATEPART [ 2 ] - $ASSTARTDATEPART [ 2 ] + $IYEARDIFF * 12
		If $ASENDDATEPART [ 3 ] < $ASSTARTDATEPART [ 3 ] Then $IMONTHDIFF = $IMONTHDIFF - 1
		$ISTARTTIMEINSECS = $ASSTARTTIMEPART [ 1 ] * 3600 + $ASSTARTTIMEPART [ 2 ] * 60 + $ASSTARTTIMEPART [ 3 ]
		$IENDTIMEINSECS = $ASENDTIMEPART [ 1 ] * 3600 + $ASENDTIMEPART [ 2 ] * 60 + $ASENDTIMEPART [ 3 ]
		$ITIMEDIFF = $IENDTIMEINSECS - $ISTARTTIMEINSECS
		If $ASENDDATEPART [ 3 ] = $ASSTARTDATEPART [ 3 ] And $ITIMEDIFF < 0 Then $IMONTHDIFF = $IMONTHDIFF - 1
		Return $IMONTHDIFF
	Case $STYPE = "y"
		$IYEARDIFF = $ASENDDATEPART [ 1 ] - $ASSTARTDATEPART [ 1 ]
		If $ASENDDATEPART [ 2 ] < $ASSTARTDATEPART [ 2 ] Then $IYEARDIFF = $IYEARDIFF - 1
		If $ASENDDATEPART [ 2 ] = $ASSTARTDATEPART [ 2 ] And $ASENDDATEPART [ 3 ] < $ASSTARTDATEPART [ 3 ] Then $IYEARDIFF = $IYEARDIFF - 1
		$ISTARTTIMEINSECS = $ASSTARTTIMEPART [ 1 ] * 3600 + $ASSTARTTIMEPART [ 2 ] * 60 + $ASSTARTTIMEPART [ 3 ]
		$IENDTIMEINSECS = $ASENDTIMEPART [ 1 ] * 3600 + $ASENDTIMEPART [ 2 ] * 60 + $ASENDTIMEPART [ 3 ]
		$ITIMEDIFF = $IENDTIMEINSECS - $ISTARTTIMEINSECS
		If $ASENDDATEPART [ 2 ] = $ASSTARTDATEPART [ 2 ] And $ASENDDATEPART [ 3 ] = $ASSTARTDATEPART [ 3 ] And $ITIMEDIFF < 0 Then $IYEARDIFF = $IYEARDIFF - 1
		Return $IYEARDIFF
	Case $STYPE = "w"
		Return Int ( $ADAYSDIFF / 7 )
	Case $STYPE = "h"
		Return $ADAYSDIFF * 24 + Int ( $ITIMEDIFF / 3600 )
	Case $STYPE = "n"
		Return $ADAYSDIFF * 24 * 60 + Int ( $ITIMEDIFF / 60 )
	Case $STYPE = "s"
		Return $ADAYSDIFF * 24 * 60 * 60 + $ITIMEDIFF
	EndSelect
EndFunc
Func _DATEISLEAPYEAR ( $IYEAR )
	If StringIsInt ( $IYEAR ) Then
		Select
		Case Mod ( $IYEAR , 4 ) = 0 And Mod ( $IYEAR , 100 ) <> 0
			Return 1
		Case Mod ( $IYEAR , 400 ) = 0
			Return 1
	Case Else
			Return 0
		EndSelect
	EndIf
	Return SetError ( 1 , 0 , 0 )
EndFunc
Func _DATEISVALID ( $SDATE )
	Local $ASDATEPART [ 4 ] , $ASTIMEPART [ 4 ]
	_DATETIMESPLIT ( $SDATE , $ASDATEPART , $ASTIMEPART )
	If Not StringIsInt ( $ASDATEPART [ 1 ] ) Then Return 0
	If Not StringIsInt ( $ASDATEPART [ 2 ] ) Then Return 0
	If Not StringIsInt ( $ASDATEPART [ 3 ] ) Then Return 0
	$ASDATEPART [ 1 ] = Int ( $ASDATEPART [ 1 ] )
	$ASDATEPART [ 2 ] = Int ( $ASDATEPART [ 2 ] )
	$ASDATEPART [ 3 ] = Int ( $ASDATEPART [ 3 ] )
	Local $INUMDAYS = _DAYSINMONTH ( $ASDATEPART [ 1 ] )
	If $ASDATEPART [ 1 ] < 1000 Or $ASDATEPART [ 1 ] > 2999 Then Return 0
	If $ASDATEPART [ 2 ] < 1 Or $ASDATEPART [ 2 ] > 12 Then Return 0
	If $ASDATEPART [ 3 ] < 1 Or $ASDATEPART [ 3 ] > $INUMDAYS [ $ASDATEPART [ 2 ] ] Then Return 0
	If $ASTIMEPART [ 0 ] < 1 Then Return 1
	If $ASTIMEPART [ 0 ] < 2 Then Return 0
	If $ASTIMEPART [ 0 ] = 2 Then $ASTIMEPART [ 3 ] = "00"
	If Not StringIsInt ( $ASTIMEPART [ 1 ] ) Then Return 0
	If Not StringIsInt ( $ASTIMEPART [ 2 ] ) Then Return 0
	If Not StringIsInt ( $ASTIMEPART [ 3 ] ) Then Return 0
	$ASTIMEPART [ 1 ] = Int ( $ASTIMEPART [ 1 ] )
	$ASTIMEPART [ 2 ] = Int ( $ASTIMEPART [ 2 ] )
	$ASTIMEPART [ 3 ] = Int ( $ASTIMEPART [ 3 ] )
	If $ASTIMEPART [ 1 ] < 0 Or $ASTIMEPART [ 1 ] > 23 Then Return 0
	If $ASTIMEPART [ 2 ] < 0 Or $ASTIMEPART [ 2 ] > 59 Then Return 0
	If $ASTIMEPART [ 3 ] < 0 Or $ASTIMEPART [ 3 ] > 59 Then Return 0
	Return 1
EndFunc
Func _DATETIMESPLIT ( $SDATE , ByRef $ADATEPART , ByRef $ITIMEPART )
	Local $SDATETIME = StringSplit ( $SDATE , " T" )
	If $SDATETIME [ 0 ] > 0 Then $ADATEPART = StringSplit ( $SDATETIME [ 1 ] , "/-." )
	If $SDATETIME [ 0 ] > 1 Then
		$ITIMEPART = StringSplit ( $SDATETIME [ 2 ] , ":" )
		If UBound ( $ITIMEPART ) < 4 Then ReDim $ITIMEPART [ 4 ]
	Else
		Dim $ITIMEPART [ 4 ]
	EndIf
	If UBound ( $ADATEPART ) < 4 Then ReDim $ADATEPART [ 4 ]
	For $X = 1 To 3
		If StringIsInt ( $ADATEPART [ $X ] ) Then
			$ADATEPART [ $X ] = Int ( $ADATEPART [ $X ] )
		Else
			$ADATEPART [ $X ] = - 1
		EndIf
		If StringIsInt ( $ITIMEPART [ $X ] ) Then
			$ITIMEPART [ $X ] = Int ( $ITIMEPART [ $X ] )
		Else
			$ITIMEPART [ $X ] = 0
		EndIf
	Next
	Return 1
EndFunc
Func _DATETODAYVALUE ( $IYEAR , $IMONTH , $IDAY )
	If Not _DATEISVALID ( StringFormat ( "%04d/%02d/%02d" , $IYEAR , $IMONTH , $IDAY ) ) Then
		Return SetError ( 1 , 0 , "" )
	EndIf
	If $IMONTH < 3 Then
		$IMONTH = $IMONTH + 12
		$IYEAR = $IYEAR - 1
	EndIf
	Local $I_FACTORA = Int ( $IYEAR / 100 )
	Local $I_FACTORB = Int ( $I_FACTORA / 4 )
	Local $I_FACTORC = 2 - $I_FACTORA + $I_FACTORB
	Local $I_FACTORE = Int ( 1461 * ( $IYEAR + 4716 ) / 4 )
	Local $I_FACTORF = Int ( 153 * ( $IMONTH + 1 ) / 5 )
	Local $IJULIANDATE = $I_FACTORC + $IDAY + $I_FACTORE + $I_FACTORF - 1524.5
	Return $IJULIANDATE
EndFunc
Func _NOWCALC ( )
	Return @YEAR & "/" & @MON & "/" & @MDAY & " " & @HOUR & ":" & @MIN & ":" & @SEC
EndFunc
Func _DAYSINMONTH ( $IYEAR )
	Local $ADAYS = [ 12 , 31 , ( _DATEISLEAPYEAR ( $IYEAR ) ? 29 : 28 ) , 31 , 30 , 31 , 30 , 31 , 31 , 30 , 31 , 30 , 31 ]
	Return $ADAYS
EndFunc
Global Const $TRAY_EVENT_PRIMARYDOWN = - 7
Global Const $GUI_EVENT_CLOSE = - 3
Global Const $GUI_CHECKED = 1
Global Const $GUI_UNCHECKED = 4
Global Const $GUI_ENABLE = 64
Global Const $GUI_DISABLE = 128
Global Const $GUI_FOCUS = 256
Global Const $ES_AUTOVSCROLL = 64
Global Const $ES_AUTOHSCROLL = 128
Global Const $ES_WANTRETURN = 4096
Global Const $ES_NUMBER = 8192
Global Const $CBS_DROPDOWNLIST = 3
Global Const $CB_GETCOMBOBOXINFO = 356
Global Const $CB_SELECTSTRING = 333
Global Const $CB_SETEDITSEL = 322
Global Const $_UDF_GLOBALIDS_OFFSET = 2
Global Const $_UDF_GLOBALID_MAX_WIN = 16
Global Const $_UDF_STARTID = 10000
Global Const $_UDF_GLOBALID_MAX_IDS = 55535
Global Const $__UDFGUICONSTANT_WS_VISIBLE = 268435456
Global Const $__UDFGUICONSTANT_WS_CHILD = 1073741824
Global $__G_AUDF_GLOBALIDS_USED [ $_UDF_GLOBALID_MAX_WIN ] [ $_UDF_GLOBALID_MAX_IDS + $_UDF_GLOBALIDS_OFFSET + 1 ]
Func __UDF_GETNEXTGLOBALID ( $HWND )
	Local $NCTRLID , $IUSEDINDEX = - 1 , $BALLUSED = True
	If Not WinExists ( $HWND ) Then Return SetError ( - 1 , - 1 , 0 )
	For $IINDEX = 0 To $_UDF_GLOBALID_MAX_WIN - 1
		If $__G_AUDF_GLOBALIDS_USED [ $IINDEX ] [ 0 ] <> 0 Then
			If Not WinExists ( $__G_AUDF_GLOBALIDS_USED [ $IINDEX ] [ 0 ] ) Then
				For $X = 0 To UBound ( $__G_AUDF_GLOBALIDS_USED , $UBOUND_COLUMNS ) - 1
					$__G_AUDF_GLOBALIDS_USED [ $IINDEX ] [ $X ] = 0
				Next
				$__G_AUDF_GLOBALIDS_USED [ $IINDEX ] [ 1 ] = $_UDF_STARTID
				$BALLUSED = False
			EndIf
		EndIf
	Next
	For $IINDEX = 0 To $_UDF_GLOBALID_MAX_WIN - 1
		If $__G_AUDF_GLOBALIDS_USED [ $IINDEX ] [ 0 ] = $HWND Then
			$IUSEDINDEX = $IINDEX
			ExitLoop
		EndIf
	Next
	If $IUSEDINDEX = - 1 Then
		For $IINDEX = 0 To $_UDF_GLOBALID_MAX_WIN - 1
			If $__G_AUDF_GLOBALIDS_USED [ $IINDEX ] [ 0 ] = 0 Then
				$__G_AUDF_GLOBALIDS_USED [ $IINDEX ] [ 0 ] = $HWND
				$__G_AUDF_GLOBALIDS_USED [ $IINDEX ] [ 1 ] = $_UDF_STARTID
				$BALLUSED = False
				$IUSEDINDEX = $IINDEX
				ExitLoop
			EndIf
		Next
	EndIf
	If $IUSEDINDEX = - 1 And $BALLUSED Then Return SetError ( 16 , 0 , 0 )
	If $__G_AUDF_GLOBALIDS_USED [ $IUSEDINDEX ] [ 1 ] = $_UDF_STARTID + $_UDF_GLOBALID_MAX_IDS Then
		For $IIDINDEX = $_UDF_GLOBALIDS_OFFSET To UBound ( $__G_AUDF_GLOBALIDS_USED , $UBOUND_COLUMNS ) - 1
			If $__G_AUDF_GLOBALIDS_USED [ $IUSEDINDEX ] [ $IIDINDEX ] = 0 Then
				$NCTRLID = ( $IIDINDEX - $_UDF_GLOBALIDS_OFFSET ) + 10000
				$__G_AUDF_GLOBALIDS_USED [ $IUSEDINDEX ] [ $IIDINDEX ] = $NCTRLID
				Return $NCTRLID
			EndIf
		Next
		Return SetError ( - 1 , $_UDF_GLOBALID_MAX_IDS , 0 )
	EndIf
	$NCTRLID = $__G_AUDF_GLOBALIDS_USED [ $IUSEDINDEX ] [ 1 ]
	$__G_AUDF_GLOBALIDS_USED [ $IUSEDINDEX ] [ 1 ] += 1
	$__G_AUDF_GLOBALIDS_USED [ $IUSEDINDEX ] [ ( $NCTRLID - 10000 ) + $_UDF_GLOBALIDS_OFFSET ] = $NCTRLID
	Return $NCTRLID
EndFunc
Global Const $__COMBOBOXCONSTANT_EM_REPLACESEL = 194
Global Const $TAGCOMBOBOXINFO = "dword Size;struct;long EditLeft;long EditTop;long EditRight;long EditBottom;endstruct;" & "struct;long BtnLeft;long BtnTop;long BtnRight;long BtnBottom;endstruct;dword BtnState;hwnd hCombo;hwnd hEdit;hwnd hList"
Func _GUICTRLCOMBOBOX_GETCOMBOBOXINFO ( $HWND , ByRef $TINFO )
	If Not IsHWnd ( $HWND ) Then $HWND = GUICtrlGetHandle ( $HWND )
	$TINFO = DllStructCreate ( $TAGCOMBOBOXINFO )
	Local $IINFO = DllStructGetSize ( $TINFO )
	DllStructSetData ( $TINFO , "Size" , $IINFO )
	Return _SENDMESSAGE ( $HWND , $CB_GETCOMBOBOXINFO , 0 , $TINFO , 0 , "wparam" , "struct*" ) <> 0
EndFunc
Func _GUICTRLCOMBOBOX_REPLACEEDITSEL ( $HWND , $STEXT )
	If Not IsHWnd ( $HWND ) Then $HWND = GUICtrlGetHandle ( $HWND )
	Local $TINFO
	If _GUICTRLCOMBOBOX_GETCOMBOBOXINFO ( $HWND , $TINFO ) Then
		Local $HEDIT = DllStructGetData ( $TINFO , "hEdit" )
		_SENDMESSAGE ( $HEDIT , $__COMBOBOXCONSTANT_EM_REPLACESEL , True , $STEXT , 0 , "wparam" , "wstr" )
	EndIf
EndFunc
Func _GUICTRLCOMBOBOX_SELECTSTRING ( $HWND , $STEXT , $IINDEX = - 1 )
	If Not IsHWnd ( $HWND ) Then $HWND = GUICtrlGetHandle ( $HWND )
	Return _SENDMESSAGE ( $HWND , $CB_SELECTSTRING , $IINDEX , $STEXT , 0 , "wparam" , "wstr" )
EndFunc
Func _GUICTRLCOMBOBOX_SETEDITSEL ( $HWND , $ISTART , $ISTOP )
	If Not HWnd ( $HWND ) Then $HWND = GUICtrlGetHandle ( $HWND )
	Return _SENDMESSAGE ( $HWND , $CB_SETEDITSEL , 0 , _WINAPI_MAKELONG ( $ISTART , $ISTOP ) ) <> - 1
EndFunc
Func _GUICTRLCOMBOBOX_SETEDITTEXT ( $HWND , $STEXT )
	If Not IsHWnd ( $HWND ) Then $HWND = GUICtrlGetHandle ( $HWND )
	_GUICTRLCOMBOBOX_SETEDITSEL ( $HWND , 0 , - 1 )
	_GUICTRLCOMBOBOX_REPLACEEDITSEL ( $HWND , $STEXT )
EndFunc
Global Const $__STATUSBARCONSTANT_WM_USER = 1024
Global Const $SB_GETUNICODEFORMAT = 8192 + 6
Global Const $SB_ISSIMPLE = ( $__STATUSBARCONSTANT_WM_USER + 14 )
Global Const $SB_SETPARTS = ( $__STATUSBARCONSTANT_WM_USER + 4 )
Global Const $SB_SETTEXTA = ( $__STATUSBARCONSTANT_WM_USER + 1 )
Global Const $SB_SETTEXTW = ( $__STATUSBARCONSTANT_WM_USER + 11 )
Global Const $SB_SETTEXT = $SB_SETTEXTA
Global Const $SB_SIMPLEID = 255
Global $__G_HSBLASTWND
Global Const $__STATUSBARCONSTANT_CLASSNAME = "msctls_statusbar32"
Global Const $__STATUSBARCONSTANT_WM_SIZE = 5
Func _GUICTRLSTATUSBAR_CREATE ( $HWND , $VPARTEDGE = - 1 , $VPARTTEXT = "" , $ISTYLES = - 1 , $IEXSTYLES = 0 )
	If Not IsHWnd ( $HWND ) Then Return SetError ( 1 , 0 , 0 )
	Local $ISTYLE = BitOR ( $__UDFGUICONSTANT_WS_CHILD , $__UDFGUICONSTANT_WS_VISIBLE )
	If $ISTYLES = - 1 Then $ISTYLES = 0
	If $IEXSTYLES = - 1 Then $IEXSTYLES = 0
	Local $APARTWIDTH [ 1 ] , $APARTTEXT [ 1 ]
	If @NumParams > 1 Then
		If IsArray ( $VPARTEDGE ) Then
			$APARTWIDTH = $VPARTEDGE
		Else
			$APARTWIDTH [ 0 ] = $VPARTEDGE
		EndIf
		If @NumParams = 2 Then
			ReDim $APARTTEXT [ UBound ( $APARTWIDTH ) ]
		Else
			If IsArray ( $VPARTTEXT ) Then
				$APARTTEXT = $VPARTTEXT
			Else
				$APARTTEXT [ 0 ] = $VPARTTEXT
			EndIf
			If UBound ( $APARTWIDTH ) <> UBound ( $APARTTEXT ) Then
				Local $ILAST
				If UBound ( $APARTWIDTH ) > UBound ( $APARTTEXT ) Then
					$ILAST = UBound ( $APARTTEXT )
					ReDim $APARTTEXT [ UBound ( $APARTWIDTH ) ]
				Else
					$ILAST = UBound ( $APARTWIDTH )
					ReDim $APARTWIDTH [ UBound ( $APARTTEXT ) ]
					For $X = $ILAST To UBound ( $APARTWIDTH ) - 1
						$APARTWIDTH [ $X ] = $APARTWIDTH [ $X - 1 ] + 75
					Next
					$APARTWIDTH [ UBound ( $APARTTEXT ) - 1 ] = - 1
				EndIf
			EndIf
		EndIf
		If Not IsHWnd ( $HWND ) Then $HWND = HWnd ( $HWND )
		If @NumParams > 3 Then $ISTYLE = BitOR ( $ISTYLE , $ISTYLES )
	EndIf
	Local $NCTRLID = __UDF_GETNEXTGLOBALID ( $HWND )
	If @error Then Return SetError ( @error , @extended , 0 )
	Local $HWNDSBAR = _WINAPI_CREATEWINDOWEX ( $IEXSTYLES , $__STATUSBARCONSTANT_CLASSNAME , "" , $ISTYLE , 0 , 0 , 0 , 0 , $HWND , $NCTRLID )
	If @error Then Return SetError ( @error , @extended , 0 )
	If @NumParams > 1 Then
		_GUICTRLSTATUSBAR_SETPARTS ( $HWNDSBAR , UBound ( $APARTWIDTH ) , $APARTWIDTH )
		For $X = 0 To UBound ( $APARTTEXT ) - 1
			_GUICTRLSTATUSBAR_SETTEXT ( $HWNDSBAR , $APARTTEXT [ $X ] , $X )
		Next
	EndIf
	Return $HWNDSBAR
EndFunc
Func _GUICTRLSTATUSBAR_GETUNICODEFORMAT ( $HWND )
	Return _SENDMESSAGE ( $HWND , $SB_GETUNICODEFORMAT ) <> 0
EndFunc
Func _GUICTRLSTATUSBAR_ISSIMPLE ( $HWND )
	Return _SENDMESSAGE ( $HWND , $SB_ISSIMPLE ) <> 0
EndFunc
Func _GUICTRLSTATUSBAR_RESIZE ( $HWND )
	_SENDMESSAGE ( $HWND , $__STATUSBARCONSTANT_WM_SIZE )
EndFunc
Func _GUICTRLSTATUSBAR_SETPARTS ( $HWND , $APARTS = - 1 , $APARTWIDTH = 25 )
	Local $TPARTS , $IPARTS = 1
	If IsArray ( $APARTS ) <> 0 Then
		$APARTS [ UBound ( $APARTS ) - 1 ] = - 1
		$IPARTS = UBound ( $APARTS )
		$TPARTS = DllStructCreate ( "int[" & $IPARTS & "]" )
		For $X = 0 To $IPARTS - 2
			DllStructSetData ( $TPARTS , 1 , $APARTS [ $X ] , $X + 1 )
		Next
		DllStructSetData ( $TPARTS , 1 , - 1 , $IPARTS )
	ElseIf IsArray ( $APARTWIDTH ) <> 0 Then
		$IPARTS = UBound ( $APARTWIDTH )
		$TPARTS = DllStructCreate ( "int[" & $IPARTS & "]" )
		For $X = 0 To $IPARTS - 2
			DllStructSetData ( $TPARTS , 1 , $APARTWIDTH [ $X ] , $X + 1 )
		Next
		DllStructSetData ( $TPARTS , 1 , - 1 , $IPARTS )
	ElseIf $APARTS > 1 Then
		$IPARTS = $APARTS
		$TPARTS = DllStructCreate ( "int[" & $IPARTS & "]" )
		For $X = 1 To $IPARTS - 1
			DllStructSetData ( $TPARTS , 1 , $APARTWIDTH * $X , $X )
		Next
		DllStructSetData ( $TPARTS , 1 , - 1 , $IPARTS )
	Else
		$TPARTS = DllStructCreate ( "int" )
		DllStructSetData ( $TPARTS , $IPARTS , - 1 )
	EndIf
	If _WINAPI_INPROCESS ( $HWND , $__G_HSBLASTWND ) Then
		_SENDMESSAGE ( $HWND , $SB_SETPARTS , $IPARTS , $TPARTS , 0 , "wparam" , "struct*" )
	Else
		Local $ISIZE = DllStructGetSize ( $TPARTS )
		Local $TMEMMAP
		Local $PMEMORY = _MEMINIT ( $HWND , $ISIZE , $TMEMMAP )
		_MEMWRITE ( $TMEMMAP , $TPARTS )
		_SENDMESSAGE ( $HWND , $SB_SETPARTS , $IPARTS , $PMEMORY , 0 , "wparam" , "ptr" )
		_MEMFREE ( $TMEMMAP )
	EndIf
	_GUICTRLSTATUSBAR_RESIZE ( $HWND )
	Return True
EndFunc
Func _GUICTRLSTATUSBAR_SETTEXT ( $HWND , $STEXT = "" , $IPART = 0 , $IUFLAG = 0 )
	Local $BUNICODE = _GUICTRLSTATUSBAR_GETUNICODEFORMAT ( $HWND )
	Local $IBUFFER = StringLen ( $STEXT ) + 1
	Local $TTEXT
	If $BUNICODE Then
		$TTEXT = DllStructCreate ( "wchar Text[" & $IBUFFER & "]" )
		$IBUFFER *= 2
	Else
		$TTEXT = DllStructCreate ( "char Text[" & $IBUFFER & "]" )
	EndIf
	DllStructSetData ( $TTEXT , "Text" , $STEXT )
	If _GUICTRLSTATUSBAR_ISSIMPLE ( $HWND ) Then $IPART = $SB_SIMPLEID
	Local $IRET
	If _WINAPI_INPROCESS ( $HWND , $__G_HSBLASTWND ) Then
		$IRET = _SENDMESSAGE ( $HWND , $SB_SETTEXTW , BitOR ( $IPART , $IUFLAG ) , $TTEXT , 0 , "wparam" , "struct*" )
	Else
		Local $TMEMMAP
		Local $PMEMORY = _MEMINIT ( $HWND , $IBUFFER , $TMEMMAP )
		_MEMWRITE ( $TMEMMAP , $TTEXT )
		If $BUNICODE Then
			$IRET = _SENDMESSAGE ( $HWND , $SB_SETTEXTW , BitOR ( $IPART , $IUFLAG ) , $PMEMORY , 0 , "wparam" , "ptr" )
		Else
			$IRET = _SENDMESSAGE ( $HWND , $SB_SETTEXT , BitOR ( $IPART , $IUFLAG ) , $PMEMORY , 0 , "wparam" , "ptr" )
		EndIf
		_MEMFREE ( $TMEMMAP )
	EndIf
	Return $IRET <> 0
EndFunc
Global Const $WS_VSCROLL = 2097152
Global Const $WS_BORDER = 8388608
Global Const $WM_KEYDOWN = 256
Global Const $WM_CHAR = 258
Global Const $WM_SYSKEYDOWN = 260
Global Const $WM_SYSCHAR = 262
Func _ARRAYPUSH ( ByRef $AARRAY , $VVALUE , $IDIRECTION = 0 )
	If $IDIRECTION = Default Then $IDIRECTION = 0
	If ( Not IsArray ( $AARRAY ) ) Then Return SetError ( 1 , 0 , 0 )
	If UBound ( $AARRAY , $UBOUND_DIMENSIONS ) <> 1 Then Return SetError ( 3 , 0 , 0 )
	Local $IUBOUND = UBound ( $AARRAY ) - 1
	If IsArray ( $VVALUE ) Then
		Local $IUBOUNDS = UBound ( $VVALUE )
		If ( $IUBOUNDS - 1 ) > $IUBOUND Then Return SetError ( 2 , 0 , 0 )
		If $IDIRECTION Then
			For $I = $IUBOUND To $IUBOUNDS Step - 1
				$AARRAY [ $I ] = $AARRAY [ $I - $IUBOUNDS ]
			Next
			For $I = 0 To $IUBOUNDS - 1
				$AARRAY [ $I ] = $VVALUE [ $I ]
			Next
		Else
			For $I = 0 To $IUBOUND - $IUBOUNDS
				$AARRAY [ $I ] = $AARRAY [ $I + $IUBOUNDS ]
			Next
			For $I = 0 To $IUBOUNDS - 1
				$AARRAY [ $I + $IUBOUND - $IUBOUNDS + 1 ] = $VVALUE [ $I ]
			Next
		EndIf
	Else
		If $IUBOUND > - 1 Then
			If $IDIRECTION Then
				For $I = $IUBOUND To 1 Step - 1
					$AARRAY [ $I ] = $AARRAY [ $I - 1 ]
				Next
				$AARRAY [ 0 ] = $VVALUE
			Else
				For $I = 0 To $IUBOUND - 1
					$AARRAY [ $I ] = $AARRAY [ $I + 1 ]
				Next
				$AARRAY [ $IUBOUND ] = $VVALUE
			EndIf
		EndIf
	EndIf
	Return 1
EndFunc
Global Const $HKEY_CLASSES_ROOT = 2147483648
Global Const $HKEY_CURRENT_USER = 2147483649
Global Const $HKEY_LOCAL_MACHINE = 2147483650
Global Const $KEY_NOTIFY = 16
Global Const $REG_NOTIFY_CHANGE_LAST_SET = 4
Func _WINAPI_REGCLOSEKEY ( $HKEY , $BFLUSH = False )
	If $BFLUSH Then
		If Not _WINAPI_REGFLUSHKEY ( $HKEY ) Then
			Return SetError ( @error + 10 , @extended , 0 )
		EndIf
	EndIf
	Local $ARET = DllCall ( "advapi32.dll" , "long" , "RegCloseKey" , "handle" , $HKEY )
	If @error Then Return SetError ( @error , @extended , 0 )
	If $ARET [ 0 ] Then Return SetError ( 10 , $ARET [ 0 ] , 0 )
	Return 1
EndFunc
Func _WINAPI_REGFLUSHKEY ( $HKEY )
	Local $ARET = DllCall ( "advapi32.dll" , "long" , "RegFlushKey" , "handle" , $HKEY )
	If @error Then Return SetError ( @error , @extended , 0 )
	If $ARET [ 0 ] Then Return SetError ( 10 , $ARET [ 0 ] , 0 )
	Return 1
EndFunc
Func _WINAPI_REGNOTIFYCHANGEKEYVALUE ( $HKEY , $IFILTER , $BSUBTREE = False , $BASYNC = False , $HEVENT = 0 )
	Local $ARET = DllCall ( "advapi32.dll" , "long" , "RegNotifyChangeKeyValue" , "handle" , $HKEY , "bool" , $BSUBTREE , "dword" , $IFILTER , "handle" , $HEVENT , "bool" , $BASYNC )
	If @error Then Return SetError ( @error , @extended , 0 )
	If $ARET [ 0 ] Then Return SetError ( 10 , $ARET [ 0 ] , 0 )
	Return 1
EndFunc
Func _WINAPI_REGOPENKEY ( $HKEY , $SSUBKEY = "" , $IACCESS = 983103 )
	Local $SSUBKEYTYPE = "wstr"
	If Not IsString ( $SSUBKEY ) Then $SSUBKEYTYPE = "ptr"
	Local $ARET = DllCall ( "advapi32.dll" , "long" , "RegOpenKeyExW" , "handle" , $HKEY , $SSUBKEYTYPE , $SSUBKEY , "dword" , 0 , "dword" , $IACCESS , "ulong_ptr*" , 0 )
	If @error Then Return SetError ( @error , @extended , 0 )
	If $ARET [ 0 ] Then Return SetError ( 10 , $ARET [ 0 ] , 0 )
	Return $ARET [ 5 ]
EndFunc
Func _WINAPI_HASHDATA ( $PMEMORY , $ISIZE , $ILENGTH = 32 )
	If ( $ILENGTH <= 0 ) Or ( $ILENGTH > 256 ) Then Return SetError ( 11 , 0 , 0 )
	Local $TDATA = DllStructCreate ( "byte[" & $ILENGTH & "]" )
	Local $ARET = DllCall ( "shlwapi.dll" , "uint" , "HashData" , "struct*" , $PMEMORY , "dword" , $ISIZE , "struct*" , $TDATA , "dword" , $ILENGTH )
	If @error Then Return SetError ( @error , @extended , 0 )
	If $ARET [ 0 ] Then Return SetError ( 10 , $ARET [ 0 ] , 0 )
	Return DllStructGetData ( $TDATA , 1 )
EndFunc
Func _WINAPI_HASHSTRING ( $SSTRING , $BCASESENSITIVE = True , $ILENGTH = 32 )
	Local $ILENGTHS = StringLen ( $SSTRING )
	If Not $ILENGTHS Or ( $ILENGTH > 256 ) Then Return SetError ( 12 , 0 , 0 )
	Local $TSTRING = DllStructCreate ( "wchar[" & ( $ILENGTHS + 1 ) & "]" )
	If Not $BCASESENSITIVE Then
		$SSTRING = StringLower ( $SSTRING )
	EndIf
	DllStructSetData ( $TSTRING , 1 , $SSTRING )
	Local $SHASH = _WINAPI_HASHDATA ( $TSTRING , 2 * $ILENGTHS , $ILENGTH )
	If @error Then Return SetError ( @error , @extended , 0 )
	Return $SHASH
EndFunc
Func _WINAPI_GETKEYNAMETEXT ( $LPARAM )
	Local $ARET = DllCall ( "user32.dll" , "int" , "GetKeyNameTextW" , "long" , $LPARAM , "wstr" , "" , "int" , 128 )
	If @error Or Not $ARET [ 0 ] Then Return SetError ( @error , @extended , "" )
	Return $ARET [ 2 ]
EndFunc
Func _WINAPI_GETVERSION ( )
	Return BitAND ( BitShift ( $__WINVER , 8 ) , 255 ) & "." & BitAND ( $__WINVER , 255 )
EndFunc
Func _ISPRESSED ( $SHEXKEY , $VDLL = "user32.dll" )
	Local $A_R = DllCall ( $VDLL , "short" , "GetAsyncKeyState" , "int" , "0x" & $SHEXKEY )
	If @error Then Return SetError ( @error , @extended , False )
	Return BitAND ( $A_R [ 0 ] , 32768 ) <> 0
EndFunc
Global Const $INET_DOWNLOADREAD = 0
Global Const $INET_DOWNLOADCOMPLETE = 2
Global Const $INTERNET_DEFAULT_PORT = 0
Global Const $ICU_ESCAPE = 2147483648
Global Const $WINHTTP_FLAG_ASYNC = 268435456
Global Const $WINHTTP_FLAG_ESCAPE_DISABLE = 64
Global Const $WINHTTP_FLAG_SECURE = 8388608
Global Const $WINHTTP_ACCESS_TYPE_NO_PROXY = 1
Global Const $WINHTTP_ACCESS_TYPE_NAMED_PROXY = 3
Global Const $WINHTTP_NO_PROXY_NAME = ""
Global Const $WINHTTP_NO_PROXY_BYPASS = ""
Global Const $WINHTTP_NO_REFERER = ""
Global Const $WINHTTP_DEFAULT_ACCEPT_TYPES = 0
Global Const $WINHTTP_NO_ADDITIONAL_HEADERS = ""
Global Const $WINHTTP_NO_REQUEST_DATA = ""
Global Const $WINHTTP_HEADER_NAME_BY_INDEX = ""
Global Const $WINHTTP_NO_HEADER_INDEX = 0
Global Const $WINHTTP_OPTION_CALLBACK = 1
Global Const $WINHTTP_OPTION_RESOLVE_TIMEOUT = 2
Global Const $WINHTTP_OPTION_CONNECT_TIMEOUT = 3
Global Const $WINHTTP_OPTION_CONNECT_RETRIES = 4
Global Const $WINHTTP_OPTION_SEND_TIMEOUT = 5
Global Const $WINHTTP_OPTION_RECEIVE_TIMEOUT = 6
Global Const $WINHTTP_OPTION_RECEIVE_RESPONSE_TIMEOUT = 7
Global Const $WINHTTP_OPTION_HANDLE_TYPE = 9
Global Const $WINHTTP_OPTION_READ_BUFFER_SIZE = 12
Global Const $WINHTTP_OPTION_WRITE_BUFFER_SIZE = 13
Global Const $WINHTTP_OPTION_PARENT_HANDLE = 21
Global Const $WINHTTP_OPTION_EXTENDED_ERROR = 24
Global Const $WINHTTP_OPTION_SECURITY_FLAGS = 31
Global Const $WINHTTP_OPTION_URL = 34
Global Const $WINHTTP_OPTION_SECURITY_KEY_BITNESS = 36
Global Const $WINHTTP_OPTION_PROXY = 38
Global Const $WINHTTP_OPTION_USER_AGENT = 41
Global Const $WINHTTP_OPTION_CONTEXT_VALUE = 45
Global Const $WINHTTP_OPTION_CLIENT_CERT_CONTEXT = 47
Global Const $WINHTTP_OPTION_REQUEST_PRIORITY = 58
Global Const $WINHTTP_OPTION_HTTP_VERSION = 59
Global Const $WINHTTP_OPTION_DISABLE_FEATURE = 63
Global Const $WINHTTP_OPTION_CODEPAGE = 68
Global Const $WINHTTP_OPTION_MAX_CONNS_PER_SERVER = 73
Global Const $WINHTTP_OPTION_MAX_CONNS_PER_1_0_SERVER = 74
Global Const $WINHTTP_OPTION_AUTOLOGON_POLICY = 77
Global Const $WINHTTP_OPTION_ENABLE_FEATURE = 79
Global Const $WINHTTP_OPTION_WORKER_THREAD_COUNT = 80
Global Const $WINHTTP_OPTION_PASSPORT_COBRANDING_TEXT = 81
Global Const $WINHTTP_OPTION_PASSPORT_COBRANDING_URL = 82
Global Const $WINHTTP_OPTION_CONFIGURE_PASSPORT_AUTH = 83
Global Const $WINHTTP_OPTION_SECURE_PROTOCOLS = 84
Global Const $WINHTTP_OPTION_ENABLETRACING = 85
Global Const $WINHTTP_OPTION_PASSPORT_SIGN_OUT = 86
Global Const $WINHTTP_OPTION_REDIRECT_POLICY = 88
Global Const $WINHTTP_OPTION_MAX_HTTP_AUTOMATIC_REDIRECTS = 89
Global Const $WINHTTP_OPTION_MAX_HTTP_STATUS_CONTINUE = 90
Global Const $WINHTTP_OPTION_MAX_RESPONSE_HEADER_SIZE = 91
Global Const $WINHTTP_OPTION_MAX_RESPONSE_DRAIN_SIZE = 92
Global Const $WINHTTP_OPTION_CONNECTION_INFO = 93
Global Const $WINHTTP_OPTION_SPN = 96
Global Const $WINHTTP_OPTION_GLOBAL_PROXY_CREDS = 97
Global Const $WINHTTP_OPTION_GLOBAL_SERVER_CREDS = 98
Global Const $WINHTTP_OPTION_REJECT_USERPWD_IN_URL = 100
Global Const $WINHTTP_OPTION_USE_GLOBAL_SERVER_CREDENTIALS = 101
Global Const $WINHTTP_OPTION_USERNAME = 4096
Global Const $WINHTTP_OPTION_PASSWORD = 4097
Global Const $WINHTTP_OPTION_PROXY_USERNAME = 4098
Global Const $WINHTTP_OPTION_PROXY_PASSWORD = 4099
Global Const $WINHTTP_AUTOLOGON_SECURITY_LEVEL_MEDIUM = 0
Global Const $WINHTTP_AUTOLOGON_SECURITY_LEVEL_LOW = 1
Global Const $WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH = 2
Global Const $WINHTTP_ENABLE_PASSPORT_AUTH = 268435456
Global Const $HTTP_STATUS_DENIED = 401
Global Const $HTTP_STATUS_PROXY_AUTH_REQ = 407
Global Const $WINHTTP_QUERY_CONTENT_TYPE = 1
Global Const $WINHTTP_QUERY_STATUS_CODE = 19
Global Const $WINHTTP_QUERY_RAW_HEADERS_CRLF = 22
Global Const $WINHTTP_AUTH_SCHEME_PASSPORT = 4
Global Const $WINHTTP_AUTOPROXY_CONFIG_URL = 2
Global Const $WINHTTP_AUTO_DETECT_TYPE_DHCP = 1
Global Const $WINHTTP_AUTO_DETECT_TYPE_DNS_A = 2
Global Const $HWINHTTPDLL__WINHTTP = DllOpen ( "winhttp.dll" )
DllOpen ( "winhttp.dll" )
Func _WINHTTPCLOSEHANDLE ( $HINTERNET )
	Local $ACALL = DllCall ( $HWINHTTPDLL__WINHTTP , "bool" , "WinHttpCloseHandle" , "handle" , $HINTERNET )
	If @error Or Not $ACALL [ 0 ] Then Return SetError ( 1 , 0 , 0 )
	Return 1
EndFunc
Func _WINHTTPCONNECT ( $HSESSION , $SSERVERNAME , $ISERVERPORT = Default )
	Local $AURL = _WINHTTPCRACKURL ( $SSERVERNAME )
	If @error Then
		__WINHTTPDEFAULT ( $ISERVERPORT , $INTERNET_DEFAULT_PORT )
	Else
		$SSERVERNAME = $AURL [ 2 ]
		$ISERVERPORT = $AURL [ 3 ]
	EndIf
	Local $ACALL = DllCall ( $HWINHTTPDLL__WINHTTP , "handle" , "WinHttpConnect" , "handle" , $HSESSION , "wstr" , $SSERVERNAME , "dword" , $ISERVERPORT , "dword" , 0 )
	If @error Or Not $ACALL [ 0 ] Then Return SetError ( 1 , 0 , 0 )
	Return $ACALL [ 0 ]
EndFunc
Func _WINHTTPCRACKURL ( $SURL , $IFLAG = Default )
	__WINHTTPDEFAULT ( $IFLAG , $ICU_ESCAPE )
	Local $TURL_COMPONENTS = DllStructCreate ( "dword StructSize;" & "ptr SchemeName;" & "dword SchemeNameLength;" & "int Scheme;" & "ptr HostName;" & "dword HostNameLength;" & "word Port;" & "ptr UserName;" & "dword UserNameLength;" & "ptr Password;" & "dword PasswordLength;" & "ptr UrlPath;" & "dword UrlPathLength;" & "ptr ExtraInfo;" & "dword ExtraInfoLength" )
	DllStructSetData ( $TURL_COMPONENTS , 1 , DllStructGetSize ( $TURL_COMPONENTS ) )
	Local $TBUFFERS [ 6 ]
	Local $IURLLEN = StringLen ( $SURL )
	For $I = 0 To 5
		$TBUFFERS [ $I ] = DllStructCreate ( "wchar[" & $IURLLEN + 1 & "]" )
	Next
	DllStructSetData ( $TURL_COMPONENTS , "SchemeNameLength" , $IURLLEN )
	DllStructSetData ( $TURL_COMPONENTS , "SchemeName" , DllStructGetPtr ( $TBUFFERS [ 0 ] ) )
	DllStructSetData ( $TURL_COMPONENTS , "HostNameLength" , $IURLLEN )
	DllStructSetData ( $TURL_COMPONENTS , "HostName" , DllStructGetPtr ( $TBUFFERS [ 1 ] ) )
	DllStructSetData ( $TURL_COMPONENTS , "UserNameLength" , $IURLLEN )
	DllStructSetData ( $TURL_COMPONENTS , "UserName" , DllStructGetPtr ( $TBUFFERS [ 2 ] ) )
	DllStructSetData ( $TURL_COMPONENTS , "PasswordLength" , $IURLLEN )
	DllStructSetData ( $TURL_COMPONENTS , "Password" , DllStructGetPtr ( $TBUFFERS [ 3 ] ) )
	DllStructSetData ( $TURL_COMPONENTS , "UrlPathLength" , $IURLLEN )
	DllStructSetData ( $TURL_COMPONENTS , "UrlPath" , DllStructGetPtr ( $TBUFFERS [ 4 ] ) )
	DllStructSetData ( $TURL_COMPONENTS , "ExtraInfoLength" , $IURLLEN )
	DllStructSetData ( $TURL_COMPONENTS , "ExtraInfo" , DllStructGetPtr ( $TBUFFERS [ 5 ] ) )
	Local $ACALL = DllCall ( $HWINHTTPDLL__WINHTTP , "bool" , "WinHttpCrackUrl" , "wstr" , $SURL , "dword" , $IURLLEN , "dword" , $IFLAG , "struct*" , $TURL_COMPONENTS )
	If @error Or Not $ACALL [ 0 ] Then Return SetError ( 1 , 0 , 0 )
	Local $ARET [ 8 ] = [ DllStructGetData ( $TBUFFERS [ 0 ] , 1 ) , DllStructGetData ( $TURL_COMPONENTS , "Scheme" ) , DllStructGetData ( $TBUFFERS [ 1 ] , 1 ) , DllStructGetData ( $TURL_COMPONENTS , "Port" ) , DllStructGetData ( $TBUFFERS [ 2 ] , 1 ) , DllStructGetData ( $TBUFFERS [ 3 ] , 1 ) , DllStructGetData ( $TBUFFERS [ 4 ] , 1 ) , DllStructGetData ( $TBUFFERS [ 5 ] , 1 ) ]
	Return $ARET
EndFunc
Func _WINHTTPGETIEPROXYCONFIGFORCURRENTUSER ( )
	Local $TWINHTTP_CURRENT_USER_IE_PROXY_CONFIG = DllStructCreate ( "int AutoDetect;" & "ptr AutoConfigUrl;" & "ptr Proxy;" & "ptr ProxyBypass;" )
	Local $ACALL = DllCall ( $HWINHTTPDLL__WINHTTP , "bool" , "WinHttpGetIEProxyConfigForCurrentUser" , "struct*" , $TWINHTTP_CURRENT_USER_IE_PROXY_CONFIG )
	If @error Or Not $ACALL [ 0 ] Then Return SetError ( 1 , 0 , 0 )
	Local $IAUTODETECT = DllStructGetData ( $TWINHTTP_CURRENT_USER_IE_PROXY_CONFIG , "AutoDetect" )
	Local $PAUTOCONFIGURL = DllStructGetData ( $TWINHTTP_CURRENT_USER_IE_PROXY_CONFIG , "AutoConfigUrl" )
	Local $PPROXY = DllStructGetData ( $TWINHTTP_CURRENT_USER_IE_PROXY_CONFIG , "Proxy" )
	Local $PPROXYBYPASS = DllStructGetData ( $TWINHTTP_CURRENT_USER_IE_PROXY_CONFIG , "ProxyBypass" )
	Local $SAUTOCONFIGURL
	If $PAUTOCONFIGURL Then
		Local $IAUTOCONFIGURLLEN = __WINHTTPPTRSTRINGLENW ( $PAUTOCONFIGURL )
		If Not @error Then
			Local $TAUTOCONFIGURL = DllStructCreate ( "wchar[" & $IAUTOCONFIGURLLEN + 1 & "]" , $PAUTOCONFIGURL )
			$SAUTOCONFIGURL = DllStructGetData ( $TAUTOCONFIGURL , 1 )
			__WINHTTPMEMGLOBALFREE ( $PAUTOCONFIGURL )
		EndIf
	EndIf
	Local $SPROXY
	If $PPROXY Then
		Local $IPROXYLEN = __WINHTTPPTRSTRINGLENW ( $PPROXY )
		If Not @error Then
			Local $TPROXY = DllStructCreate ( "wchar[" & $IPROXYLEN + 1 & "]" , $PPROXY )
			$SPROXY = DllStructGetData ( $TPROXY , 1 )
			__WINHTTPMEMGLOBALFREE ( $PPROXY )
		EndIf
	EndIf
	Local $SPROXYBYPASS
	If $PPROXYBYPASS Then
		Local $IPROXYBYPASSLEN = __WINHTTPPTRSTRINGLENW ( $PPROXYBYPASS )
		If Not @error Then
			Local $TPROXYBYPASS = DllStructCreate ( "wchar[" & $IPROXYBYPASSLEN + 1 & "]" , $PPROXYBYPASS )
			$SPROXYBYPASS = DllStructGetData ( $TPROXYBYPASS , 1 )
			__WINHTTPMEMGLOBALFREE ( $PPROXYBYPASS )
		EndIf
	EndIf
	Local $AOUTPUT [ 4 ] = [ $IAUTODETECT , $SAUTOCONFIGURL , $SPROXY , $SPROXYBYPASS ]
	Return $AOUTPUT
EndFunc
Func _WINHTTPOPEN ( $SUSERAGENT = Default , $IACCESSTYPE = Default , $SPROXYNAME = Default , $SPROXYBYPASS = Default , $IFLAG = Default )
	__WINHTTPDEFAULT ( $SUSERAGENT , "AutoIt/3.3 WinHTTP/5.1" )
	__WINHTTPDEFAULT ( $IACCESSTYPE , $WINHTTP_ACCESS_TYPE_NO_PROXY )
	__WINHTTPDEFAULT ( $SPROXYNAME , $WINHTTP_NO_PROXY_NAME )
	__WINHTTPDEFAULT ( $SPROXYBYPASS , $WINHTTP_NO_PROXY_BYPASS )
	__WINHTTPDEFAULT ( $IFLAG , 0 )
	Local $ACALL = DllCall ( $HWINHTTPDLL__WINHTTP , "handle" , "WinHttpOpen" , "wstr" , $SUSERAGENT , "dword" , $IACCESSTYPE , "wstr" , $SPROXYNAME , "wstr" , $SPROXYBYPASS , "dword" , $IFLAG )
	If @error Or Not $ACALL [ 0 ] Then Return SetError ( 1 , 0 , 0 )
	If $IFLAG = $WINHTTP_FLAG_ASYNC Then _WINHTTPSETOPTION ( $ACALL [ 0 ] , $WINHTTP_OPTION_CONTEXT_VALUE , $WINHTTP_FLAG_ASYNC )
	Return $ACALL [ 0 ]
EndFunc
Func _WINHTTPOPENREQUEST ( $HCONNECT , $SVERB = Default , $SOBJECTNAME = Default , $SVERSION = Default , $SREFERRER = Default , $SACCEPTTYPES = Default , $IFLAGS = Default )
	__WINHTTPDEFAULT ( $SVERB , "GET" )
	__WINHTTPDEFAULT ( $SOBJECTNAME , "" )
	__WINHTTPDEFAULT ( $SVERSION , "HTTP/1.1" )
	__WINHTTPDEFAULT ( $SREFERRER , $WINHTTP_NO_REFERER )
	__WINHTTPDEFAULT ( $IFLAGS , $WINHTTP_FLAG_ESCAPE_DISABLE )
	Local $PACCEPTTYPES
	If $SACCEPTTYPES = Default Or Number ( $SACCEPTTYPES ) = - 1 Then
		$PACCEPTTYPES = $WINHTTP_DEFAULT_ACCEPT_TYPES
	Else
		Local $ATYPES = StringSplit ( $SACCEPTTYPES , "," , 2 )
		Local $TACCEPTTYPES = DllStructCreate ( "ptr[" & UBound ( $ATYPES ) + 1 & "]" )
		Local $TTYPE [ UBound ( $ATYPES ) ]
		For $I = 0 To UBound ( $ATYPES ) - 1
			$TTYPE [ $I ] = DllStructCreate ( "wchar[" & StringLen ( $ATYPES [ $I ] ) + 1 & "]" )
			DllStructSetData ( $TTYPE [ $I ] , 1 , $ATYPES [ $I ] )
			DllStructSetData ( $TACCEPTTYPES , 1 , DllStructGetPtr ( $TTYPE [ $I ] ) , $I + 1 )
		Next
		$PACCEPTTYPES = DllStructGetPtr ( $TACCEPTTYPES )
	EndIf
	Local $ACALL = DllCall ( $HWINHTTPDLL__WINHTTP , "handle" , "WinHttpOpenRequest" , "handle" , $HCONNECT , "wstr" , StringUpper ( $SVERB ) , "wstr" , $SOBJECTNAME , "wstr" , StringUpper ( $SVERSION ) , "wstr" , $SREFERRER , "ptr" , $PACCEPTTYPES , "dword" , $IFLAGS )
	If @error Or Not $ACALL [ 0 ] Then Return SetError ( 1 , 0 , 0 )
	Return $ACALL [ 0 ]
EndFunc
Func _WINHTTPQUERYAUTHSCHEMES ( $HREQUEST , ByRef $ISUPPORTEDSCHEMES , ByRef $IFIRSTSCHEME , ByRef $IAUTHTARGET )
	Local $ACALL = DllCall ( $HWINHTTPDLL__WINHTTP , "bool" , "WinHttpQueryAuthSchemes" , "handle" , $HREQUEST , "dword*" , 0 , "dword*" , 0 , "dword*" , 0 )
	If @error Or Not $ACALL [ 0 ] Then Return SetError ( 1 , 0 , 0 )
	$ISUPPORTEDSCHEMES = $ACALL [ 2 ]
	$IFIRSTSCHEME = $ACALL [ 3 ]
	$IAUTHTARGET = $ACALL [ 4 ]
	Return 1
EndFunc
Func _WINHTTPQUERYDATAAVAILABLE ( $HREQUEST )
	Local $SREADTYPE = "dword*"
	If BitAND ( _WINHTTPQUERYOPTION ( _WINHTTPQUERYOPTION ( _WINHTTPQUERYOPTION ( $HREQUEST , $WINHTTP_OPTION_PARENT_HANDLE ) , $WINHTTP_OPTION_PARENT_HANDLE ) , $WINHTTP_OPTION_CONTEXT_VALUE ) , $WINHTTP_FLAG_ASYNC ) Then $SREADTYPE = "ptr"
	Local $ACALL = DllCall ( $HWINHTTPDLL__WINHTTP , "bool" , "WinHttpQueryDataAvailable" , "handle" , $HREQUEST , $SREADTYPE , 0 )
	If @error Then Return SetError ( 1 , 0 , 0 )
	Return SetExtended ( $ACALL [ 2 ] , $ACALL [ 0 ] )
EndFunc
Func _WINHTTPQUERYHEADERS ( $HREQUEST , $IINFOLEVEL = Default , $SNAME = Default , $IINDEX = Default )
	__WINHTTPDEFAULT ( $IINFOLEVEL , $WINHTTP_QUERY_RAW_HEADERS_CRLF )
	__WINHTTPDEFAULT ( $SNAME , $WINHTTP_HEADER_NAME_BY_INDEX )
	__WINHTTPDEFAULT ( $IINDEX , $WINHTTP_NO_HEADER_INDEX )
	Local $ACALL = DllCall ( $HWINHTTPDLL__WINHTTP , "bool" , "WinHttpQueryHeaders" , "handle" , $HREQUEST , "dword" , $IINFOLEVEL , "wstr" , $SNAME , "wstr" , "" , "dword*" , 65536 , "dword*" , $IINDEX )
	If @error Or Not $ACALL [ 0 ] Then Return SetError ( 1 , 0 , "" )
	Return SetExtended ( $ACALL [ 6 ] , $ACALL [ 4 ] )
EndFunc
Func _WINHTTPQUERYOPTION ( $HINTERNET , $IOPTION )
	Local $ACALL = DllCall ( $HWINHTTPDLL__WINHTTP , "bool" , "WinHttpQueryOption" , "handle" , $HINTERNET , "dword" , $IOPTION , "ptr" , 0 , "dword*" , 0 )
	If @error Or $ACALL [ 0 ] Then Return SetError ( 1 , 0 , "" )
	Local $ISIZE = $ACALL [ 4 ]
	Local $TBUFFER
	Switch $IOPTION
	Case $WINHTTP_OPTION_CONNECTION_INFO , $WINHTTP_OPTION_PASSWORD , $WINHTTP_OPTION_PROXY_PASSWORD , $WINHTTP_OPTION_PROXY_USERNAME , $WINHTTP_OPTION_URL , $WINHTTP_OPTION_USERNAME , $WINHTTP_OPTION_USER_AGENT , $WINHTTP_OPTION_PASSPORT_COBRANDING_TEXT , $WINHTTP_OPTION_PASSPORT_COBRANDING_URL
		$TBUFFER = DllStructCreate ( "wchar[" & $ISIZE + 1 & "]" )
	Case $WINHTTP_OPTION_PARENT_HANDLE , $WINHTTP_OPTION_CALLBACK
		$TBUFFER = DllStructCreate ( "ptr" )
	Case $WINHTTP_OPTION_CONNECT_TIMEOUT , $WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH , $WINHTTP_AUTOLOGON_SECURITY_LEVEL_LOW , $WINHTTP_AUTOLOGON_SECURITY_LEVEL_MEDIUM , $WINHTTP_OPTION_CONFIGURE_PASSPORT_AUTH , $WINHTTP_OPTION_CONNECT_RETRIES , $WINHTTP_OPTION_EXTENDED_ERROR , $WINHTTP_OPTION_HANDLE_TYPE , $WINHTTP_OPTION_MAX_CONNS_PER_1_0_SERVER , $WINHTTP_OPTION_MAX_CONNS_PER_SERVER , $WINHTTP_OPTION_MAX_HTTP_AUTOMATIC_REDIRECTS , $WINHTTP_OPTION_RECEIVE_RESPONSE_TIMEOUT , $WINHTTP_OPTION_RECEIVE_TIMEOUT , $WINHTTP_OPTION_RESOLVE_TIMEOUT , $WINHTTP_OPTION_SECURITY_FLAGS , $WINHTTP_OPTION_SECURITY_KEY_BITNESS , $WINHTTP_OPTION_SEND_TIMEOUT
		$TBUFFER = DllStructCreate ( "int" )
	Case $WINHTTP_OPTION_CONTEXT_VALUE
		$TBUFFER = DllStructCreate ( "dword_ptr" )
Case Else
		$TBUFFER = DllStructCreate ( "byte[" & $ISIZE & "]" )
	EndSwitch
	$ACALL = DllCall ( $HWINHTTPDLL__WINHTTP , "bool" , "WinHttpQueryOption" , "handle" , $HINTERNET , "dword" , $IOPTION , "struct*" , $TBUFFER , "dword*" , $ISIZE )
	If @error Or Not $ACALL [ 0 ] Then Return SetError ( 2 , 0 , "" )
	Return DllStructGetData ( $TBUFFER , 1 )
EndFunc
Func _WINHTTPREADDATA ( $HREQUEST , $IMODE = Default , $INUMBEROFBYTESTOREAD = Default , $PBUFFER = Default )
	__WINHTTPDEFAULT ( $IMODE , 0 )
	__WINHTTPDEFAULT ( $INUMBEROFBYTESTOREAD , 8192 )
	Local $TBUFFER , $VOUTONERROR = ""
	If $IMODE = 2 Then $VOUTONERROR = Binary ( $VOUTONERROR )
	Switch $IMODE
	Case 1 , 2
		If $PBUFFER And $PBUFFER <> Default Then
			$TBUFFER = DllStructCreate ( "byte[" & $INUMBEROFBYTESTOREAD & "]" , $PBUFFER )
		Else
			$TBUFFER = DllStructCreate ( "byte[" & $INUMBEROFBYTESTOREAD & "]" )
		EndIf
Case Else
		$IMODE = 0
		If $PBUFFER And $PBUFFER <> Default Then
			$TBUFFER = DllStructCreate ( "char[" & $INUMBEROFBYTESTOREAD & "]" , $PBUFFER )
		Else
			$TBUFFER = DllStructCreate ( "char[" & $INUMBEROFBYTESTOREAD & "]" )
		EndIf
	EndSwitch
	Local $SREADTYPE = "dword*"
	If BitAND ( _WINHTTPQUERYOPTION ( _WINHTTPQUERYOPTION ( _WINHTTPQUERYOPTION ( $HREQUEST , $WINHTTP_OPTION_PARENT_HANDLE ) , $WINHTTP_OPTION_PARENT_HANDLE ) , $WINHTTP_OPTION_CONTEXT_VALUE ) , $WINHTTP_FLAG_ASYNC ) Then $SREADTYPE = "ptr"
	Local $ACALL = DllCall ( $HWINHTTPDLL__WINHTTP , "bool" , "WinHttpReadData" , "handle" , $HREQUEST , "struct*" , $TBUFFER , "dword" , $INUMBEROFBYTESTOREAD , $SREADTYPE , 0 )
	If @error Or Not $ACALL [ 0 ] Then Return SetError ( 1 , 0 , "" )
	If Not $ACALL [ 4 ] Then Return SetError ( - 1 , 0 , $VOUTONERROR )
	If $ACALL [ 4 ] < $INUMBEROFBYTESTOREAD Then
		Switch $IMODE
		Case 0
			Return SetExtended ( $ACALL [ 4 ] , StringLeft ( DllStructGetData ( $TBUFFER , 1 ) , $ACALL [ 4 ] ) )
		Case 1
			Return SetExtended ( $ACALL [ 4 ] , BinaryToString ( BinaryMid ( DllStructGetData ( $TBUFFER , 1 ) , 1 , $ACALL [ 4 ] ) , 4 ) )
		Case 2
			Return SetExtended ( $ACALL [ 4 ] , BinaryMid ( DllStructGetData ( $TBUFFER , 1 ) , 1 , $ACALL [ 4 ] ) )
		EndSwitch
	Else
		Switch $IMODE
		Case 0 , 2
			Return SetExtended ( $ACALL [ 4 ] , DllStructGetData ( $TBUFFER , 1 ) )
		Case 1
			Return SetExtended ( $ACALL [ 4 ] , BinaryToString ( DllStructGetData ( $TBUFFER , 1 ) , 4 ) )
		EndSwitch
	EndIf
EndFunc
Func _WINHTTPRECEIVERESPONSE ( $HREQUEST )
	Local $ACALL = DllCall ( $HWINHTTPDLL__WINHTTP , "bool" , "WinHttpReceiveResponse" , "handle" , $HREQUEST , "ptr" , 0 )
	If @error Or Not $ACALL [ 0 ] Then Return SetError ( 1 , 0 , 0 )
	Return 1
EndFunc
Func _WINHTTPSENDREQUEST ( $HREQUEST , $SHEADERS = Default , $SOPTIONAL = Default , $ITOTALLENGTH = Default , $ICONTEXT = Default )
	__WINHTTPDEFAULT ( $SHEADERS , $WINHTTP_NO_ADDITIONAL_HEADERS )
	__WINHTTPDEFAULT ( $SOPTIONAL , $WINHTTP_NO_REQUEST_DATA )
	__WINHTTPDEFAULT ( $ITOTALLENGTH , 0 )
	__WINHTTPDEFAULT ( $ICONTEXT , 0 )
	Local $POPTIONAL = 0 , $IOPTIONALLENGTH = 0
	If @NumParams > 2 Then
		Local $TOPTIONAL
		$IOPTIONALLENGTH = BinaryLen ( $SOPTIONAL )
		$TOPTIONAL = DllStructCreate ( "byte[" & $IOPTIONALLENGTH & "]" )
		If $IOPTIONALLENGTH Then $POPTIONAL = DllStructGetPtr ( $TOPTIONAL )
		DllStructSetData ( $TOPTIONAL , 1 , $SOPTIONAL )
	EndIf
	If Not $ITOTALLENGTH Or $ITOTALLENGTH < $IOPTIONALLENGTH Then $ITOTALLENGTH += $IOPTIONALLENGTH
	Local $ACALL = DllCall ( $HWINHTTPDLL__WINHTTP , "bool" , "WinHttpSendRequest" , "handle" , $HREQUEST , "wstr" , $SHEADERS , "dword" , 0 , "ptr" , $POPTIONAL , "dword" , $IOPTIONALLENGTH , "dword" , $ITOTALLENGTH , "dword_ptr" , $ICONTEXT )
	If @error Or Not $ACALL [ 0 ] Then Return SetError ( 1 , 0 , 0 )
	Return 1
EndFunc
Func _WINHTTPSETCREDENTIALS ( $HREQUEST , $IAUTHTARGETS , $IAUTHSCHEME , $SUSERNAME , $SPASSWORD )
	Local $ACALL = DllCall ( $HWINHTTPDLL__WINHTTP , "bool" , "WinHttpSetCredentials" , "handle" , $HREQUEST , "dword" , $IAUTHTARGETS , "dword" , $IAUTHSCHEME , "wstr" , $SUSERNAME , "wstr" , $SPASSWORD , "ptr" , 0 )
	If @error Or Not $ACALL [ 0 ] Then Return SetError ( 1 , 0 , 0 )
	Return 1
EndFunc
Func _WINHTTPSETOPTION ( $HINTERNET , $IOPTION , $VSETTING , $ISIZE = Default )
	If $ISIZE = Default Then $ISIZE = - 1
	If IsBinary ( $VSETTING ) Then
		$ISIZE = DllStructCreate ( "byte[" & BinaryLen ( $VSETTING ) & "]" )
		DllStructSetData ( $ISIZE , 1 , $VSETTING )
		$VSETTING = $ISIZE
		$ISIZE = DllStructGetSize ( $VSETTING )
	EndIf
	Local $STYPE
	Switch $IOPTION
	Case $WINHTTP_OPTION_AUTOLOGON_POLICY , $WINHTTP_OPTION_CODEPAGE , $WINHTTP_OPTION_CONFIGURE_PASSPORT_AUTH , $WINHTTP_OPTION_CONNECT_RETRIES , $WINHTTP_OPTION_CONNECT_TIMEOUT , $WINHTTP_OPTION_DISABLE_FEATURE , $WINHTTP_OPTION_ENABLE_FEATURE , $WINHTTP_OPTION_ENABLETRACING , $WINHTTP_OPTION_MAX_CONNS_PER_1_0_SERVER , $WINHTTP_OPTION_MAX_CONNS_PER_SERVER , $WINHTTP_OPTION_MAX_HTTP_AUTOMATIC_REDIRECTS , $WINHTTP_OPTION_MAX_HTTP_STATUS_CONTINUE , $WINHTTP_OPTION_MAX_RESPONSE_DRAIN_SIZE , $WINHTTP_OPTION_MAX_RESPONSE_HEADER_SIZE , $WINHTTP_OPTION_READ_BUFFER_SIZE , $WINHTTP_OPTION_RECEIVE_TIMEOUT , $WINHTTP_OPTION_RECEIVE_RESPONSE_TIMEOUT , $WINHTTP_OPTION_REDIRECT_POLICY , $WINHTTP_OPTION_REJECT_USERPWD_IN_URL , $WINHTTP_OPTION_REQUEST_PRIORITY , $WINHTTP_OPTION_RESOLVE_TIMEOUT , $WINHTTP_OPTION_SECURE_PROTOCOLS , $WINHTTP_OPTION_SECURITY_FLAGS , $WINHTTP_OPTION_SECURITY_KEY_BITNESS , $WINHTTP_OPTION_SEND_TIMEOUT , $WINHTTP_OPTION_SPN , $WINHTTP_OPTION_USE_GLOBAL_SERVER_CREDENTIALS , $WINHTTP_OPTION_WORKER_THREAD_COUNT , $WINHTTP_OPTION_WRITE_BUFFER_SIZE
		$STYPE = "dword*"
		$ISIZE = 4
	Case $WINHTTP_OPTION_CALLBACK , $WINHTTP_OPTION_PASSPORT_SIGN_OUT
		$STYPE = "ptr*"
		$ISIZE = 4
		If @AutoItX64 Then $ISIZE = 8
		If Not IsPtr ( $VSETTING ) Then Return SetError ( 3 , 0 , 0 )
	Case $WINHTTP_OPTION_CONTEXT_VALUE
		$STYPE = "dword_ptr*"
		$ISIZE = 4
		If @AutoItX64 Then $ISIZE = 8
	Case $WINHTTP_OPTION_PASSWORD , $WINHTTP_OPTION_PROXY_PASSWORD , $WINHTTP_OPTION_PROXY_USERNAME , $WINHTTP_OPTION_USER_AGENT , $WINHTTP_OPTION_USERNAME
		$STYPE = "wstr"
		If ( IsDllStruct ( $VSETTING ) Or IsPtr ( $VSETTING ) ) Then Return SetError ( 3 , 0 , 0 )
		If $ISIZE < 1 Then $ISIZE = StringLen ( $VSETTING )
	Case $WINHTTP_OPTION_CLIENT_CERT_CONTEXT , $WINHTTP_OPTION_GLOBAL_PROXY_CREDS , $WINHTTP_OPTION_GLOBAL_SERVER_CREDS , $WINHTTP_OPTION_HTTP_VERSION , $WINHTTP_OPTION_PROXY
		$STYPE = "ptr"
		If Not ( IsDllStruct ( $VSETTING ) Or IsPtr ( $VSETTING ) ) Then Return SetError ( 3 , 0 , 0 )
Case Else
		Return SetError ( 1 , 0 , 0 )
	EndSwitch
	If $ISIZE < 1 Then
		If IsDllStruct ( $VSETTING ) Then
			$ISIZE = DllStructGetSize ( $VSETTING )
		Else
			Return SetError ( 2 , 0 , 0 )
		EndIf
	EndIf
	Local $ACALL
	If IsDllStruct ( $VSETTING ) Then
		$ACALL = DllCall ( $HWINHTTPDLL__WINHTTP , "bool" , "WinHttpSetOption" , "handle" , $HINTERNET , "dword" , $IOPTION , $STYPE , DllStructGetPtr ( $VSETTING ) , "dword" , $ISIZE )
	Else
		$ACALL = DllCall ( $HWINHTTPDLL__WINHTTP , "bool" , "WinHttpSetOption" , "handle" , $HINTERNET , "dword" , $IOPTION , $STYPE , $VSETTING , "dword" , $ISIZE )
	EndIf
	If @error Or Not $ACALL [ 0 ] Then Return SetError ( 4 , 0 , 0 )
	Return 1
EndFunc
Func _WINHTTPSETTIMEOUTS ( $HINTERNET , $IRESOLVETIMEOUT = Default , $ICONNECTTIMEOUT = Default , $ISENDTIMEOUT = Default , $IRECEIVETIMEOUT = Default )
	__WINHTTPDEFAULT ( $IRESOLVETIMEOUT , 0 )
	__WINHTTPDEFAULT ( $ICONNECTTIMEOUT , 60000 )
	__WINHTTPDEFAULT ( $ISENDTIMEOUT , 30000 )
	__WINHTTPDEFAULT ( $IRECEIVETIMEOUT , 30000 )
	Local $ACALL = DllCall ( $HWINHTTPDLL__WINHTTP , "bool" , "WinHttpSetTimeouts" , "handle" , $HINTERNET , "int" , $IRESOLVETIMEOUT , "int" , $ICONNECTTIMEOUT , "int" , $ISENDTIMEOUT , "int" , $IRECEIVETIMEOUT )
	If @error Or Not $ACALL [ 0 ] Then Return SetError ( 1 , 0 , 0 )
	Return 1
EndFunc
Func _WINHTTPSIMPLEREADDATA ( $HREQUEST , $IMODE = Default )
	If $IMODE = Default Then
		$IMODE = 0
		If __WINHTTPCHARSET ( _WINHTTPQUERYHEADERS ( $HREQUEST , $WINHTTP_QUERY_CONTENT_TYPE ) ) = 65001 Then $IMODE = 1
	Else
		__WINHTTPDEFAULT ( $IMODE , 0 )
	EndIf
	If $IMODE > 2 Or $IMODE < 0 Then Return SetError ( 1 , 0 , "" )
	Local $VDATA = Binary ( "" )
	If _WINHTTPQUERYDATAAVAILABLE ( $HREQUEST ) Then
		Do
			$VDATA &= _WINHTTPREADDATA ( $HREQUEST , 2 )
		Until @error
		Switch $IMODE
		Case 0
			Return BinaryToString ( $VDATA )
		Case 1
			Return BinaryToString ( $VDATA , 4 )
	Case Else
			Return $VDATA
		EndSwitch
	EndIf
	Return SetError ( 2 , 0 , $VDATA )
EndFunc
Func _WINHTTPSIMPLESENDSSLREQUEST ( $HCONNECT , $STYPE = Default , $SPATH = Default , $SREFERRER = Default , $SDATA = Default , $SHEADER = Default )
	__WINHTTPDEFAULT ( $STYPE , "GET" )
	__WINHTTPDEFAULT ( $SPATH , "" )
	__WINHTTPDEFAULT ( $SREFERRER , $WINHTTP_NO_REFERER )
	__WINHTTPDEFAULT ( $SDATA , $WINHTTP_NO_REQUEST_DATA )
	__WINHTTPDEFAULT ( $SHEADER , $WINHTTP_NO_ADDITIONAL_HEADERS )
	Local $HREQUEST = _WINHTTPOPENREQUEST ( $HCONNECT , $STYPE , $SPATH , Default , $SREFERRER , Default , BitOR ( $WINHTTP_FLAG_SECURE , $WINHTTP_FLAG_ESCAPE_DISABLE ) )
	If Not $HREQUEST Then Return SetError ( 1 , @error , 0 )
	If $STYPE = "POST" And $SHEADER = $WINHTTP_NO_ADDITIONAL_HEADERS Then $SHEADER = "Content-Type: application/x-www-form-urlencoded" & @CRLF
	_WINHTTPSENDREQUEST ( $HREQUEST , $SHEADER , $SDATA )
	If @error Then Return SetError ( 2 , 0 * _WINHTTPCLOSEHANDLE ( $HREQUEST ) , 0 )
	_WINHTTPRECEIVERESPONSE ( $HREQUEST )
	If @error Then Return SetError ( 3 , 0 * _WINHTTPCLOSEHANDLE ( $HREQUEST ) , 0 )
	Return $HREQUEST
EndFunc
Func _WINHTTPSIMPLESSLREQUEST ( $HCONNECT , $STYPE = Default , $SPATH = Default , $SREFERRER = Default , $SDATA = Default , $SHEADER = Default , $FGETHEADERS = Default , $IMODE = Default , $SCREDNAME = Default , $SCREDPASS = Default )
	__WINHTTPDEFAULT ( $STYPE , "GET" )
	__WINHTTPDEFAULT ( $SPATH , "" )
	__WINHTTPDEFAULT ( $SREFERRER , $WINHTTP_NO_REFERER )
	__WINHTTPDEFAULT ( $SDATA , $WINHTTP_NO_REQUEST_DATA )
	__WINHTTPDEFAULT ( $SHEADER , $WINHTTP_NO_ADDITIONAL_HEADERS )
	__WINHTTPDEFAULT ( $FGETHEADERS , False )
	__WINHTTPDEFAULT ( $IMODE , Default )
	__WINHTTPDEFAULT ( $SCREDNAME , "" )
	__WINHTTPDEFAULT ( $SCREDPASS , "" )
	If $IMODE > 2 Or $IMODE < 0 Then Return SetError ( 4 , 0 , 0 )
	Local $HREQUEST = _WINHTTPSIMPLESENDSSLREQUEST ( $HCONNECT , $STYPE , $SPATH , $SREFERRER , $SDATA , $SHEADER )
	If @error Then Return SetError ( @error , 0 , 0 )
	__WINHTTPSETCREDENTIALS ( $HREQUEST , $SHEADER , $SDATA , $SCREDNAME , $SCREDPASS )
	If $FGETHEADERS Then
		Local $ADATA [ 2 ] = [ _WINHTTPQUERYHEADERS ( $HREQUEST ) , _WINHTTPSIMPLEREADDATA ( $HREQUEST , $IMODE ) ]
		_WINHTTPCLOSEHANDLE ( $HREQUEST )
		Return $ADATA
	EndIf
	Local $SOUTDATA = _WINHTTPSIMPLEREADDATA ( $HREQUEST , $IMODE )
	_WINHTTPCLOSEHANDLE ( $HREQUEST )
	Return $SOUTDATA
EndFunc
Func __WINHTTPCHARSET ( $SCONTENTTYPE )
	Local $ACONTENTTYPE = StringRegExp ( $SCONTENTTYPE , "(?i).*?\Qcharset=\E(?U)([^ ]+)(;| |\Z)" , 2 )
	If Not @error Then $SCONTENTTYPE = $ACONTENTTYPE [ 1 ]
	If StringLeft ( $SCONTENTTYPE , 2 ) = "cp" Then Return Int ( StringTrimLeft ( $SCONTENTTYPE , 2 ) )
	If $SCONTENTTYPE = "utf-8" Then Return 65001
EndFunc
Func __WINHTTPSETCREDENTIALS ( $HREQUEST , $SHEADERS = "" , $SOPTIONAL = "" , $SCREDNAME = "" , $SCREDPASS = "" )
	If $SCREDNAME And $SCREDPASS Then
		Local $ISTATUSCODE = _WINHTTPQUERYHEADERS ( $HREQUEST , $WINHTTP_QUERY_STATUS_CODE )
		If $ISTATUSCODE = $HTTP_STATUS_DENIED Or $ISTATUSCODE = $HTTP_STATUS_PROXY_AUTH_REQ Then
			Local $ISUPPORTEDSCHEMES , $IFIRSTSCHEME , $IAUTHTARGET
			If _WINHTTPQUERYAUTHSCHEMES ( $HREQUEST , $ISUPPORTEDSCHEMES , $IFIRSTSCHEME , $IAUTHTARGET ) Then
				If $IFIRSTSCHEME = $WINHTTP_AUTH_SCHEME_PASSPORT And $ISTATUSCODE = $HTTP_STATUS_PROXY_AUTH_REQ Then
					_WINHTTPSETOPTION ( $HREQUEST , $WINHTTP_OPTION_CONFIGURE_PASSPORT_AUTH , $WINHTTP_ENABLE_PASSPORT_AUTH )
					_WINHTTPSETOPTION ( $HREQUEST , $WINHTTP_OPTION_PROXY_USERNAME , $SCREDNAME )
					_WINHTTPSETOPTION ( $HREQUEST , $WINHTTP_OPTION_PROXY_PASSWORD , $SCREDPASS )
				Else
					_WINHTTPSETCREDENTIALS ( $HREQUEST , $IAUTHTARGET , $IFIRSTSCHEME , $SCREDNAME , $SCREDPASS )
				EndIf
				_WINHTTPSENDREQUEST ( $HREQUEST , $SHEADERS , $SOPTIONAL )
				_WINHTTPRECEIVERESPONSE ( $HREQUEST )
			EndIf
		EndIf
	EndIf
EndFunc
Func __WINHTTPDEFAULT ( ByRef $VINPUT , $VOUTPUT )
	If $VINPUT = Default Or Number ( $VINPUT ) = - 1 Then $VINPUT = $VOUTPUT
EndFunc
Func __WINHTTPMEMGLOBALFREE ( $PMEM )
	Local $ACALL = DllCall ( "kernel32.dll" , "ptr" , "GlobalFree" , "ptr" , $PMEM )
	If @error Or $ACALL [ 0 ] Then Return SetError ( 1 , 0 , 0 )
	Return 1
EndFunc
Func __WINHTTPPTRSTRINGLENW ( $PSTRING )
	Local $ACALL = DllCall ( "kernel32.dll" , "dword" , "lstrlenW" , "ptr" , $PSTRING )
	If @error Then Return SetError ( 1 , 0 , 0 )
	Return $ACALL [ 0 ]
EndFunc
Global Const $CLSID_SHELLLINK = "{00021401-0000-0000-C000-000000000046}"
Global Const $SIID_ISHELLLINKW = "{000214F9-0000-0000-C000-000000000046}"
Global Const $TAG_ISHELLLINKW = "GetPath hresult(long;long;long;long);" & "GetIDList hresult(long);" & "SetIDList hresult(long);" & "GetDescription hresult(long;long);" & "SetDescription hresult(wstr);" & "GetWorkingDirectory hresult(long;long);" & "SetWorkingDirectory hresult(long;long);" & "GetArguments hresult(long;long);" & "SetArguments hresult(ptr);" & "GetHotkey hresult(long);" & "SetHotkey hresult(word);" & "GetShowCmd hresult(long);" & "SetShowCmd hresult(int);" & "GetIconLocation hresult(long;long;long);" & "SetIconLocation hresult(wstr;int);" & "SetRelativePath hresult(long;long);" & "Resolve hresult(long;long);" & "SetPath hresult(wstr);"
Global Const $TAG_IPERSIST = "GetClassID hresult(long);"
Global Const $SIID_IPERSISTFILE = "{0000010b-0000-0000-C000-000000000046}"
Global Const $TAG_IPERSISTFILE = $TAG_IPERSIST & "IsDirty hresult();" & "Load hresult(wstr;dword);" & "Save hresult(wstr;bool);" & "SaveCompleted hresult(long);" & "GetCurFile hresult(long);"
Global Const $STGM_READ = 0
Global Const $STGM_READWRITE = 2
Global Const $STGM_SHARE_DENY_NONE = 64
Global Const $TAGPROPERTYKEY = "struct;ulong Data1;ushort Data2;ushort Data3;byte Data4[8];DWORD pid;endstruct"
Global $TAGPROPVARIANT = "USHORT vt;" & "WORD wReserved1;" & "WORD wReserved2;" & "WORD wReserved3;" & "LONG;PTR"
Global Const $SIID_IPROPERTYSTORE = "{886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99}"
Global Const $VT_EMPTY = 0 , $VT_LPWSTR = 31
Func _WINDOWAPPID ( $HWND , $APPID = Default )
	Local $TPIPROPERTYSTORE = DllStructCreate ( "ptr" )
	_WINAPI_SHGETPROPERTYSTOREFORWINDOW ( $HWND , $SIID_IPROPERTYSTORE , $TPIPROPERTYSTORE )
	Local $PPROPERTYSTORE = DllStructGetData ( $TPIPROPERTYSTORE , 1 )
	Local $OPROPERTYSTORE = ObjCreateInterface ( $PPROPERTYSTORE , $SIID_IPROPERTYSTORE , "GetCount HRESULT(PTR);GetAt HRESULT(DWORD; PTR);GetValue HRESULT(PTR;PTR);" & "SetValue HRESULT(PTR;PTR);Commit HRESULT()" )
	If Not IsObj ( $OPROPERTYSTORE ) Then Return SetError ( 1 , 0 , "" )
	Local $TPKEY = _PKEY_APPUSERMODEL_ID ( )
	Local $TPROPVARIANT = DllStructCreate ( $TAGPROPVARIANT )
	Local $SAPPID
	If $APPID = Default Then
		$OPROPERTYSTORE .GetValue ( DllStructGetPtr ( $TPKEY ) , DllStructGetPtr ( $TPROPVARIANT ) )
		If DllStructGetData ( $TPROPVARIANT , "vt" ) <> $VT_EMPTY Then
			Local $BUF = DllStructCreate ( "wchar[128]" )
			DllCall ( "Propsys.dll" , "long" , "PropVariantToString" , "ptr" , DllStructGetPtr ( $TPROPVARIANT ) , "ptr" , DllStructGetPtr ( $BUF ) , "uint" , DllStructGetSize ( $BUF ) )
			If Not @error Then
				$SAPPID = DllStructGetData ( $BUF , 1 )
			EndIf
		EndIf
	Else
		_WINAPI_INITPROPVARIANTFROMSTRING ( $APPID , $TPROPVARIANT )
		$OPROPERTYSTORE .SetValue ( DllStructGetPtr ( $TPKEY ) , DllStructGetPtr ( $TPROPVARIANT ) )
		$OPROPERTYSTORE .Commit ( )
		$SAPPID = $APPID
	EndIf
	Return SetError ( ( $SAPPID == "" ) * 2 , 0 , $SAPPID )
EndFunc
Func _SHORTCUTAPPID ( $LNKFILE , $APPID = Default )
	Local $OISHELLLINKW = ObjCreateInterface ( $CLSID_SHELLLINK , $SIID_ISHELLLINKW , $TAG_ISHELLLINKW )
	If Not IsObj ( $OISHELLLINKW ) Then Return SetError ( 1 , 0 , "" )
	Local $PIPERSISTFILE , $OIPERSISTFILE , $OPROPERTYSTORE , $RET , $SAPPID
	Local $TRIID_IPERSISTFILE = _WINAPI_GUIDFROMSTRING ( $SIID_IPERSISTFILE )
	$OISHELLLINKW .QueryInterface ( $TRIID_IPERSISTFILE , $PIPERSISTFILE )
	$OIPERSISTFILE = ObjCreateInterface ( $PIPERSISTFILE , $SIID_IPERSISTFILE , $TAG_IPERSISTFILE )
	If IsObj ( $OIPERSISTFILE ) Then
		If $APPID == Default Then
			$RET = $OIPERSISTFILE .Load ( $LNKFILE , BitOR ( $STGM_READ , $STGM_SHARE_DENY_NONE ) )
		Else
			$RET = $OIPERSISTFILE .Load ( $LNKFILE , $STGM_READWRITE )
		EndIf
		If $RET = 0 Then
			Local $TPKEY = _PKEY_APPUSERMODEL_ID ( )
			Local $TPROPVARIANT = DllStructCreate ( $TAGPROPVARIANT )
			$TRIID_IPROPERTYSTORE = _WINAPI_GUIDFROMSTRING ( $SIID_IPROPERTYSTORE )
			Local $PPROPERTYSTORE
			$OISHELLLINKW .QueryInterface ( $TRIID_IPROPERTYSTORE , $PPROPERTYSTORE )
			$OPROPERTYSTORE = ObjCreateInterface ( $PPROPERTYSTORE , $SIID_IPROPERTYSTORE , "GetCount HRESULT(PTR);GetAt HRESULT(DWORD;PTR);GetValue HRESULT(PTR;PTR);" & "SetValue HRESULT(PTR;PTR);Commit HRESULT()" )
			If IsObj ( $OPROPERTYSTORE ) Then
				If $APPID == Default Then
					$OPROPERTYSTORE .GetValue ( DllStructGetPtr ( $TPKEY ) , DllStructGetPtr ( $TPROPVARIANT ) )
					If DllStructGetData ( $TPROPVARIANT , "vt" ) <> $VT_EMPTY Then
						Local $BUF = DllStructCreate ( "wchar[128]" )
						DllCall ( "Propsys.dll" , "long" , "PropVariantToString" , "ptr" , DllStructGetPtr ( $TPROPVARIANT ) , "ptr" , DllStructGetPtr ( $BUF ) , "uint" , DllStructGetSize ( $BUF ) )
						$SAPPID = DllStructGetData ( $BUF , 1 )
					EndIf
				Else
					_WINAPI_INITPROPVARIANTFROMSTRING ( $APPID , $TPROPVARIANT )
					$OPROPERTYSTORE .SetValue ( DllStructGetPtr ( $TPKEY ) , DllStructGetPtr ( $TPROPVARIANT ) )
					$OPROPERTYSTORE .Commit ( )
					$OIPERSISTFILE .Save ( $LNKFILE , True )
					$SAPPID = $APPID
				EndIf
			EndIf
		EndIf
	EndIf
	If IsObj ( $OPROPERTYSTORE ) Then $OPROPERTYSTORE .Release ( )
	If IsObj ( $OIPERSISTFILE ) Then $OIPERSISTFILE .Release ( )
	If IsObj ( $OISHELLLINKW ) Then $OISHELLLINKW .Release ( )
	Return SetError ( ( $SAPPID == "" ) * 2 , 0 , $SAPPID )
EndFunc
Func _WINAPI_INITPROPVARIANTFROMSTRING ( $SUNICODESTRING , ByRef $TPROPVARIANT )
	DllStructSetData ( $TPROPVARIANT , "vt" , $VT_LPWSTR )
	Local $ARET = DllCall ( "Shlwapi.dll" , "LONG" , "SHStrDupW" , "WSTR" , $SUNICODESTRING , "PTR" , DllStructGetPtr ( $TPROPVARIANT ) + 8 )
	If @error Then Return SetError ( @error , @extended , False )
	Local $BSUCCESS = $ARET [ 0 ] == 0
	If ( Not $BSUCCESS ) Then $TPROPVARIANT = DllStructCreate ( $TAGPROPVARIANT )
	Return SetExtended ( $ARET [ 0 ] , $BSUCCESS )
EndFunc
Func _PKEY_APPUSERMODEL_ID ( )
	Local $TPKEY = DllStructCreate ( $TAGPROPERTYKEY )
	_WINAPI_GUIDFROMSTRINGEX ( "{9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3}" , DllStructGetPtr ( $TPKEY ) )
	DllStructSetData ( $TPKEY , "pid" , 5 )
	Return $TPKEY
EndFunc
Func _WINAPI_SHGETPROPERTYSTOREFORWINDOW ( $HWND , $SIID , ByRef $TPOINTER )
	Local $TIID = _WINAPI_GUIDFROMSTRING ( $SIID )
	Local $PP = IsPtr ( $TPOINTER ) ? $TPOINTER : DllStructGetPtr ( $TPOINTER )
	Local $ARET = DllCall ( "Shell32.dll" , "LONG" , "SHGetPropertyStoreForWindow" , "HWND" , $HWND , "STRUCT*" , $TIID , "PTR" , $PP )
	If @error Then Return SetError ( @error , @extended , False )
	Return SetExtended ( $ARET [ 0 ] , ( $ARET [ 0 ] = 0 ) )
EndFunc
Global Const $SCLSID_MMDEVICEENUMERATOR = "{BCDE0395-E52F-467C-8E3D-C4579291692E}"
Global Const $SIID_IMMDEVICEENUMERATOR = "{A95664D2-9614-4F35-A746-DE8DB63617E6}"
Global Const $STAGIMMDEVICEENUMERATOR = "EnumAudioEndpoints hresult(int;dword;ptr*);" & "GetDefaultAudioEndpoint hresult(int;int;ptr*);" & "GetDevice hresult(wstr;ptr*);" & "RegisterEndpointNotificationCallback hresult(ptr);" & "UnregisterEndpointNotificationCallback hresult(ptr)"
Global Const $SIID_IMMDEVICE = "{D666063F-1587-4E43-81F1-B948E807363F}"
Global Const $STAGIMMDEVICE = "Activate hresult(struct*;dword;ptr;ptr*);" & "OpenPropertyStore hresult(dword;ptr*);" & "GetId hresult(wstr*);" & "GetState hresult(dword*)"
Global Const $SIID_IAUDIOSESSIONMANAGER2 = "{77aa99a0-1bd6-484f-8bc7-2c654c9a9b6f}"
Global Const $STAGIAUDIOSESSIONMANAGER = "GetAudioSessionControl hresult(ptr;dword;ptr*);" & "GetSimpleAudioVolume hresult(ptr;dword;ptr*);"
Global Const $STAGIAUDIOSESSIONMANAGER2 = $STAGIAUDIOSESSIONMANAGER & "GetSessionEnumerator hresult(ptr*);" & "RegisterSessionNotification hresult(ptr);" & "UnregisterSessionNotification hresult(ptr);" & "RegisterDuckNotification hresult(wstr;ptr);" & "UnregisterDuckNotification hresult(ptr)"
Global Const $SIID_IAUDIOSESSIONENUMERATOR = "{e2f5bb11-0570-40ca-acdd-3aa01277dee8}"
Global Const $STAGIAUDIOSESSIONENUMERATOR = "GetCount hresult(int*);GetSession hresult(int;ptr*)"
Global Const $STAGIAUDIOSESSIONCONTROL = "GetState hresult(int*);GetDisplayName hresult(ptr);" & "SetDisplayName hresult(wstr);GetIconPath hresult(ptr);" & "SetIconPath hresult(wstr;ptr);GetGroupingParam hresult(ptr*);" & "SetGroupingParam hresult(ptr;ptr);RegisterAudioSessionNotification hresult(ptr);" & "UnregisterAudioSessionNotification hresult(ptr);"
Global Const $SIID_IAUDIOSESSIONCONTROL2 = "{bfb7ff88-7239-4fc9-8fa2-07c950be9c6d}"
Global Const $STAGIAUDIOSESSIONCONTROL2 = $STAGIAUDIOSESSIONCONTROL & "GetSessionIdentifier hresult(ptr)" & "GetSessionInstanceIdentifier hresult(ptr);" & "GetProcessId hresult(dword*);IsSystemSoundsSession hresult();" & "SetDuckingPreferences hresult(bool);"
Global Const $SIID_ISIMPLEAUDIOVOLUME = "{87CE5498-68D6-44E5-9215-6DA47EF883D8}"
Global Const $STAGISIMPLEAUDIOVOLUME = "SetMasterVolume hresult(float;ptr);" & "GetMasterVolume hresult(float*);" & "SetMute hresult(int;ptr);" & "GetMute hresult(int*)"
Global $__OIAUDIOSESSIONMANAGER2
Func AUDIO_SETAPPMUTE ( $PID , $BMUTE = 0 )
	If Not IsObj ( $__OIAUDIOSESSIONMANAGER2 ) Then
		$__OIAUDIOSESSIONMANAGER2 = AUDIO_GETIAUDIOSESSIONMANAGER2 ( )
	EndIf
	If Not IsObj ( $__OIAUDIOSESSIONMANAGER2 ) Then Return
	Local $PIAUDIOSESSIONENUMERATOR , $OIAUDIOSESSIONENUMERATOR
	If $__OIAUDIOSESSIONMANAGER2 .GetSessionEnumerator ( $PIAUDIOSESSIONENUMERATOR ) < 0 Then Return
	$OIAUDIOSESSIONENUMERATOR = ObjCreateInterface ( $PIAUDIOSESSIONENUMERATOR , $SIID_IAUDIOSESSIONENUMERATOR , $STAGIAUDIOSESSIONENUMERATOR )
	If Not IsObj ( $OIAUDIOSESSIONENUMERATOR ) Then Return SetError ( 1 )
	Local $I , $NSESSIONS , $PIAUDIOSESSIONCONTROL2 , $OIAUDIOSESSIONCONTROL2
	Local $PROCESSID , $OISIMPLEAUDIOVOLUME , $OK = 0
	If $OIAUDIOSESSIONENUMERATOR .GetCount ( $NSESSIONS ) >= 0 Then
		For $I = 0 To $NSESSIONS - 1
			If $OIAUDIOSESSIONENUMERATOR .GetSession ( $I , $PIAUDIOSESSIONCONTROL2 ) >= 0 Then
				$OIAUDIOSESSIONCONTROL2 = ObjCreateInterface ( $PIAUDIOSESSIONCONTROL2 , $SIID_IAUDIOSESSIONCONTROL2 , $STAGIAUDIOSESSIONCONTROL2 )
				If @error Then ContinueLoop
				$OIAUDIOSESSIONCONTROL2 .GetProcessId ( $PROCESSID )
				If $PROCESSID = $PID Then
					$OISIMPLEAUDIOVOLUME = ObjCreateInterface ( $PIAUDIOSESSIONCONTROL2 , $SIID_ISIMPLEAUDIOVOLUME , $STAGISIMPLEAUDIOVOLUME )
					If @error Then ContinueLoop
					$OIAUDIOSESSIONCONTROL2 .AddRef ( )
					If $OISIMPLEAUDIOVOLUME .SetMute ( $BMUTE , 0 ) >= 0 Then
						$OK = 1
						ExitLoop
					EndIf
				EndIf
			EndIf
		Next
	EndIf
	$OISIMPLEAUDIOVOLUME = 0
	$OIAUDIOSESSIONCONTROL2 = 0
	$OIAUDIOSESSIONENUMERATOR = 0
	Return $OK
EndFunc
Func AUDIO_GETIAUDIOSESSIONMANAGER2 ( )
	Local $OIAUDIOSESSIONMANAGER2 = 0
	Local Const $EMULTIMEDIA = 1 , $CLSCTX_INPROC_SERVER = 1
	Local $PIMMDEVICE , $OMMDEVICE , $PIAUDIOSESSIONMANAGER2
	Local $OMMDEVICEENUMERATOR = ObjCreateInterface ( $SCLSID_MMDEVICEENUMERATOR , $SIID_IMMDEVICEENUMERATOR , $STAGIMMDEVICEENUMERATOR )
	If IsObj ( $OMMDEVICEENUMERATOR ) Then
		If $OMMDEVICEENUMERATOR .GetDefaultAudioEndpoint ( 0 , $EMULTIMEDIA , $PIMMDEVICE ) >= 0 Then
			$OMMDEVICE = ObjCreateInterface ( $PIMMDEVICE , $SIID_IMMDEVICE , $STAGIMMDEVICE )
			If IsObj ( $OMMDEVICE ) Then
				If $OMMDEVICE .Activate ( __UUIDOF ( $SIID_IAUDIOSESSIONMANAGER2 ) , $CLSCTX_INPROC_SERVER , 0 , $PIAUDIOSESSIONMANAGER2 ) >= 0 Then
					$OIAUDIOSESSIONMANAGER2 = ObjCreateInterface ( $PIAUDIOSESSIONMANAGER2 , $SIID_IAUDIOSESSIONMANAGER2 , $STAGIAUDIOSESSIONMANAGER2 )
				EndIf
				$OMMDEVICE = 0
			EndIf
		EndIf
		$OMMDEVICEENUMERATOR = 0
	EndIf
	If IsObj ( $OIAUDIOSESSIONMANAGER2 ) Then
		Return $OIAUDIOSESSIONMANAGER2
	EndIf
EndFunc
Func __UUIDOF ( $SGUID )
	Local $TGUID = DllStructCreate ( "ulong Data1;ushort Data2;ushort Data3;byte Data4[8]" )
	DllCall ( "ole32.dll" , "long" , "CLSIDFromString" , "wstr" , $SGUID , "struct*" , $TGUID )
	If @error Then Return SetError ( @error , @extended , 0 )
	Return $TGUID
EndFunc
Func _RUNDOS ( $SCOMMAND )
	Local $NRESULT = RunWait ( @ComSpec & " /C " & $SCOMMAND , "" , @SW_HIDE )
	Return SetError ( @error , @extended , $NRESULT )
EndFunc
Global Const $SCS_32BIT_BINARY = 0
Global Const $SCS_64BIT_BINARY = 6
Func _WINAPI_GETBINARYTYPE ( $SFILEPATH )
	Local $ARET = DllCall ( "kernel32.dll" , "int" , "GetBinaryTypeW" , "wstr" , $SFILEPATH , "dword*" , 0 )
	If @error Then Return SetError ( @error , @extended , 0 )
	If Not $ARET [ 0 ] Then $ARET [ 2 ] = 0
	Return SetExtended ( $ARET [ 2 ] , $ARET [ 0 ] )
EndFunc
Func _STRINGENDSWITH ( $SINPUT , $SSEARCH , $FCASESENSITIVE = False )
	$ISEARCHLEN = StringLen ( $SSEARCH )
	$IINPUTLEN = StringLen ( $SINPUT )
	If ( ( $SINPUT = "" ) Or ( $SSEARCH = "" ) ) Then
		SetError ( 2 )
		Return False
	EndIf
	If ( $ISEARCHLEN > $IINPUTLEN ) Then
		SetError ( 1 )
		Return False
	EndIf
	If ( $FCASESENSITIVE == True ) Then
		If ( StringMid ( $SINPUT , $IINPUTLEN - $ISEARCHLEN + 1 , $ISEARCHLEN ) == $SSEARCH ) Then
			Return True
		EndIf
	Else
		If ( StringMid ( $SINPUT , $IINPUTLEN - $ISEARCHLEN + 1 , $ISEARCHLEN ) = $SSEARCH ) Then
			Return True
		EndIf
	EndIf
	SetError ( 0 )
	Return False
EndFunc
Global $WINVERSION = _WINAPI_GETVERSION ( )
Global Const $APPVERSION = "3.9.6"
Global $APPNAME = StringRegExpReplace ( @ScriptName , "\.[^.]*$" , "" )
Global $INIFILE = @ScriptDir & "\" & $APPNAME & ".ini"
Global $LANGUAGE = IniRead ( $INIFILE , "Settings" , "Language" , "Auto" )
Global $LANGFILE = LANGCHECK ( )
Global $PROXYTYPE , $PROXYSEVER , $PROXYPORT
Global $USERAGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"
Global $__HWND_VARS
If $CMDLINE [ 0 ] > 0 And $CMDLINE [ 1 ] = "child_thread_by" Then
	$__HWND_VARS = HWnd ( $CMDLINE [ 2 ] )
	Local $I , $P = ""
	For $I = 4 To $CMDLINE [ 0 ]
		$P &= """" & $CMDLINE [ $I ] & ""","
	Next
	$P = StringTrimRight ( $P , 1 )
	Execute ( $CMDLINE [ 3 ] & "(" & $P & ")" )
	Exit
EndIf
; Per-monitor scaling: without this the whole UI is blurry at 125% and above.
DllCall ( "user32.dll" , "bool" , "SetProcessDPIAware" )
$__HWND_VARS = GUICreate ( "main thread" )
GUICtrlCreateEdit ( "" , 0 , 0 , 350 )
If _HASPARAM ( "/selftest" ) Then
	Exit _SELFTEST ( )
EndIf
Func _STARTTHREAD ( $EXE , $FUNCTION , $P1 = "" , $P2 = "" , $P3 = "" , $P4 = "" , $P5 = "" , $P6 = "" , $P7 = "" , $P8 = "" , $P9 = "" , $P10 = "" )
	Local $I , $P , $PARA
	For $I = 1 To 10
		$P = Eval ( "p" & $I )
		If StringInStr ( $P , " " ) Then
			$P = """" & $P & """"
		EndIf
		$PARA &= " " & $P
	Next
	$PARA = StringStripWS ( $PARA , 3 )
	If $EXE == @ScriptFullPath Or $EXE == @ScriptName Then
		If @Compiled Then
			Return Run ( """" & @AutoItExe & """ child_thread_by " & $__HWND_VARS & " " & $FUNCTION & " " & $PARA )
		Else
			Return Run ( """" & @AutoItExe & """ """ & @ScriptFullPath & """ child_thread_by " & $__HWND_VARS & " " & $FUNCTION & " " & $PARA )
		EndIf
	ElseIf FileExists ( $EXE ) Then
		Return ShellExecute ( $EXE , " child_thread_by " & $__HWND_VARS & " " & $FUNCTION & " " & $PARA , "" , "open" , @SW_HIDE )
	EndIf
EndFunc
Func _KILLTHREAD ( $THREAD )
	If $THREAD And ProcessExists ( $THREAD ) Then
		Run ( @ComSpec & " /c taskkill /PID " & $THREAD & " /T /F" , "" , @SW_HIDE )
		Return SetError ( Not ProcessExists ( $THREAD ) )
	EndIf
EndFunc
Func _SETVAR ( $VAR , $IT = "" )
	Local $TEXT = ControlGetText ( $__HWND_VARS , "" , "Edit1" )
	$TEXT = StringRegExpReplace ( $TEXT , "(?i)(?m)^" & $VAR & "=.*$" , $VAR & "=" & $IT )
	If Not @extended Then
		$TEXT &= @CRLF & $VAR & "=" & $IT
	EndIf
	ControlSetText ( $__HWND_VARS , "" , "Edit1" , $TEXT )
EndFunc
Func _GETVAR ( $VAR )
	Local $TEXT = ControlGetText ( $__HWND_VARS , "" , "Edit1" )
	Local $MATCH = StringRegExp ( $TEXT , "(?i)(?m)^" & $VAR & "=(.*)$" , 1 )
	If Not @error Then
		Return SetError ( 0 , 0 , $MATCH [ 0 ] )
	Else
		Return SetError ( 1 , 0 , "" )
	EndIf
EndFunc
Global Const $ROLE_SYSTEM_PAGETAB = 37
Global Const $ROLE_SYSTEM_STATICTEXT = 41
Global Const $ROLE_SYSTEM_PUSHBUTTON = 43
Global Const $ROLE_SYSTEM_PAGETABLIST = 60
Global Const $SIID_IACCESSIBLE = "{618736E0-3C3D-11CF-810C-00AA00389B71}"
Global Const $DTAGIACCESSIBLE = "QueryInterface;" & "AddRef;" & "Release;" & "GetTypeInfoCount hresult(uint*);" & "GetTypeInfo hresult(uint;int;ptr*);" & "GetIDsOfNames hresult(struct*;wstr;uint;int;int);" & "Invoke hresult(int;struct*;int;word;ptr*;ptr*;ptr*;uint*);" & "get_accParent hresult(ptr*);" & "get_accChildCount hresult(long*);" & "get_accChild hresult(variant;idispatch*);" & "get_accName hresult(variant;bstr*);" & "get_accValue hresult(variant;bstr*);" & "get_accDescription hresult(variant;bstr*);" & "get_accRole hresult(variant;variant*);" & "get_accState hresult(variant;variant*);" & "get_accHelp hresult(variant;bstr*);" & "get_accHelpTopic hresult(bstr*;variant;long*);" & "get_accKeyboardShortcut hresult(variant;bstr*);" & "get_accFocus hresult(struct*);" & "get_accSelection hresult(variant*);" & "get_accDefaultAction hresult(variant;bstr*);" & "accSelect hresult(long;variant);" & "accLocation hresult(long*;long*;long*;long*;variant);" & "accNavigate hresult(long;variant;variant*);" & "accHitTest hresult(long;long;variant*);" & "accDoDefaultAction hresult(variant);" & "put_accName hresult(variant;bstr);" & "put_accValue hresult(variant;bstr);"
If @AutoItX64 Then
	Global $TAGVARIANT = "dword[6];"
Else
	Global $TAGVARIANT = "dword[4];"
EndIf
Global $HDLLOLEACC
Func ACCESSIBLEINI ( )
	$HDLLOLEACC = DllOpen ( "oleacc.dll" )
	DllCall ( $HDLLOLEACC , "long" , "CoInitializeEx" , "ptr" , 0 , "dword" , 2 )
	OnAutoItExitRegister ( "AccessibleExit" )
EndFunc
Func ACCESSIBLEEXIT ( )
	DllClose ( $HDLLOLEACC )
EndFunc
Func ACCESSIBLEPARENT ( $OACC , $IROLE , $ILEVEL )
	If Not IsObj ( $OACC ) Then Return
	Local $PACC , $SNAME , $ROLE
	For $I = 1 To $ILEVEL
		$OACC .get_accParent ( $PACC )
		$OACC = ObjCreateInterface ( $PACC , $SIID_IACCESSIBLE , $DTAGIACCESSIBLE )
		If Not IsObj ( $OACC ) Then Return
		$OACC .AddRef ( )
		$OACC .get_accRole ( 0 , $ROLE )
		If $ROLE = $IROLE Then
			Dim $OP = [ $PACC , $OACC ]
			Return $OP
		EndIf
	Next
EndFunc
Func ACCESSIBLEOBJECTFROMPOINT ( $X , $Y , ByRef $PACCESSIBLE , ByRef $TVARCHILD )
	Local $TPOINT = DllStructCreate ( "long;long" )
	DllStructSetData ( $TPOINT , 1 , $X )
	DllStructSetData ( $TPOINT , 2 , $Y )
	Local $TPOINT64 = DllStructCreate ( "int64" , DllStructGetPtr ( $TPOINT ) )
	Local $TVARIANT = DllStructCreate ( $TAGVARIANT )
	Local $ARET = DllCall ( $HDLLOLEACC , "int" , "AccessibleObjectFromPoint" , "int64" , DllStructGetData ( $TPOINT64 , 1 ) , "ptr*" , 0 , "struct*" , $TVARIANT )
	If @error Or $ARET [ 0 ] Then Return SetError ( 1 )
	$PACCESSIBLE = $ARET [ 2 ]
	$TVARCHILD = $ARET [ 3 ]
	Return 1
EndFunc
Opt ( "TrayAutoPause" , 0 )
Opt ( "TrayMenuMode" , 3 )
Opt ( "TrayOnEventMode" , 1 )
Opt ( "GUIOnEventMode" , 1 )
Opt ( "WinTitleMatchMode" , 4 )
Global $FIRSTRUN = 0 , $CHROMEPATH , $CHROMEDIR , $CHROMEEXE , $USERDATADIR , $PARAMS
Global $CACHEDIR , $CACHESIZE , $PORTABLEPARAM
Global $CHROMESOURCE , $GET_LATEST_CHROME_VER = "get_latest_chrome_ver"
Global $LASTCHECKUPDATE , $UPDATEINTERVAL , $CHANNEL , $ISUPDATING = 0 , $X86 = 0
Global $APPUPDATE , $APPUPDATELASTCHECK
Global $RUNINBACKGROUND , $EXAPP , $EXAPPAUTOEXIT , $EXAPP2 , $APPPID_BROWSER , $EXAPPPID
Global $TASKBARDIR = @AppDataDir & "\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
Global $TASKBARLASTCHANGE
Global $AEXAPP , $AEXAPP2 , $AEXAPPPID [ 2 ]
Global $DICKEYS , $BOSSKEY , $BOSSKEYM , $HIDE2TRAY
Global $KEEPLASTTAB
Global $MOUSECLICK2CLOSETAB
Global $MOUSE2SWITCHTAB
Global $CANCELAPPUPDATE
Global $HSETTINGS , $SETTINGSOK
Global $HSETTINGSOK , $HSETTINGSAPPLY , $HSTAUSBAR
Global $HCHROMEPATH , $HGETCHROMEPATH , $HCHROMESOURCE , $HCHECKUPDATE
Global $HCHANNEL , $HX86 , $HUPDATEINTERVAL , $HLATESTCHROMEVER , $HCURRENTVER , $HUSERDATADIR , $HCOPYDATA , $HURLLIST
Global $HAPPUPDATE , $HCACHEDIR , $HSELECTCACHEDIR , $HCACHESIZE
Global $HPARAMS , $HDOWNLOADTHREADS , $HPROXYTYPE , $HPROXYSEVER , $HPROXYPORT
Global $HRUNINBACKGROUND , $HLANGUAGE , $HEXAPP , $HEXAPPAUTOEXIT , $HEXAPP2
Global $HBOSSKEY , $HBOSSKEYM , $HBOSSKEYM1 , $HBOSSKEYM2 , $HWNDPROC , $HHIDE2TRAY
Global $HKEEPLASTTAB , $HDOUBLECLICK2CLOSETAB , $HRIGHTCLICK2CLOSETAB , $HMOUSE2SWITCHTAB
Global $CHROMEFILEVERSION , $LATESTCHROMEVER , $LATESTCHROMEURLS , $SELECTEDURL
Global $DEFAULTCHROMEDIR , $DEFAULTCHROMEVER , $DEFAULTUSERDATADIR
Global $TRAYTIPPROGRESS = 0
Global $ITHREADPID , $DOWNLOADTHREADS
Global $MOUSECLICK2CLOSETAB2 , $RIGHTCLICK2CLOSETAB2 , $MOUSE2SWITCHTAB2 , $AMOUSEINC , $BMOUSEINC , $GREENCHROME , $HGREENCHROME , $SETGC , $GCSETTING , $CHROMEPLUSPLUS , $HCHROMEPLUSPLUS , $SETCPP , $CPPSETTINGTIPS , $TABPLUS , $HTABPLUS , $HOOKBOX , $HHOOKBOX , $MOUSEINCA , $MOUSEINCB , $NOTFOUND , $PLEASECHECK , $AND , $WUXIAOAPP , $INJECTGC1 , $INJECTCPP1 , $INJECTEPP1 , $INJECTGC2 , $INJECTCPP2 , $INJECTEPP2 , $INJECTGC3 , $INJECTCPP3 , $INJECTEPP3 , $REMOVEGC1 , $REMOVECPP1 , $REMOVEEPP1 , $REMOVEGC2 , $REMOVECPP2 , $REMOVEEPP2 , $REMOVEGC3 , $REMOVECPP3 , $REMOVEEPP3 , $PLEASEDOWNLOAD , $ABOUT2 , $HURLCOPY , $HURLDOWNLOAD , $ISCHROME , $ISCHROMIUM , $ISEDGE , $ISVIVALDI , $ISBRAVE , $ISFIREFOX , $ISCENT , $ISCENTPRO , $PLATFORM , $HPLATFORM , $BROWSERTYPE , $HBROWSERTYPE , $VERSION1 , $EDGEFILEVERSION , $LANGCHROMESOURCESYS , $LANGCHROMESOURCEINSTALLER , $GUANFANG , $CPPAUTOSET , $EPPAUTOSET , $GCAUTOSET , $GREENCHROMEAUTO , $CHROMEPLUSPLUSAUTO , $BROWSERBIT , $HPROGRESS1 , $LATEST , $FIRSTUPDATECHECK
Global $CACHESIZESMART , $CHECKDEFAULTBROWSER
Global $DEFAULTPROFDIR , $HPROFILEDIR
Global $HCOPYPROFILE , $HPLUGINSDIR , $PLUGINSDIR , $HGETPLUGINSDIR
Global $HGETCACHEDIR , $HCACHESIZESMART
Global $AEXAPP , $AEXAPP2 , $AEXAPPPID [ 2 ]
Global $HEVENT , $CLIENTKEY , $FILEASSO , $URLASSO
Const $AU3_LCLICK = 1024 + 6658
Const $AU3_LDCLICK = 1024 + 6660
Const $AU3_LDROP = 1024 + 6662
Const $AU3_RCLICK = 1024 + 6914
Const $AU3_RDCLICK = 1024 + 6916
Const $AU3_RDROP = 1024 + 6918
Const $AU3_MCLICK = 1024 + 7170
Const $AU3_MDCLICK = 1024 + 7172
Const $AU3_MDROP = 1024 + 7174
Const $AU3_XCLICK = 1024 + 7426
Const $AU3_XDCLICK = 1024 + 7428
Const $AU3_XDROP = 1024 + 7430
Const $AU3_WHEELUP = 1024 + 7938
Const $AU3_WHEELDOWN = 1024 + 7940
Global $CHROMEISHIDDEN
Global $HHOOKDLL , $HHOOKLIB , $HMOUSEHOOK
Global $HEVENT_REG , $CLIENTKEY , $PROGID
Global $AREG [ 7 ] [ 3 ] = [ [ $HKEY_CURRENT_USER , "Software\Clients\StartMenuInternet" ] , [ $HKEY_LOCAL_MACHINE , "Software\Clients\StartMenuInternet" ] , [ $HKEY_CLASSES_ROOT , "ftp" ] , [ $HKEY_CLASSES_ROOT , "http" ] , [ $HKEY_CLASSES_ROOT , "https" ] , [ $HKEY_CLASSES_ROOT , "" ] , [ $HKEY_CLASSES_ROOT , "" ] ]
If Not @AutoItX64 Then
	$HKLM_SOFTWARE_32 = "HKLM\SOFTWARE"
	$HKLM_SOFTWARE_64 = "HKLM64\SOFTWARE"
Else
	$HKLM_SOFTWARE_32 = "HKLM\SOFTWARE\Wow6432Node"
	$HKLM_SOFTWARE_64 = "HKLM64\SOFTWARE"
EndIf
Global $AFILEASSO [ 6 ] = [ ".htm" , ".html" , ".shtml" , ".webp" , ".xht" , ".xhtml" ]
Global $AURLASSO [ 13 ] = [ "ftp" , "http" , "https" , "irc" , "mailto" , "mms" , "news" , "nntp" , "sms" , "smsto" , "tel" , "urn" , "webcal" ]
FileChangeDir ( @ScriptDir )
Global $ENVID = RegRead ( "HKLM64\SOFTWARE\Microsoft\Cryptography" , "MachineGuid" )
$ENVID &= RegRead ( "HKLM64\SOFTWARE\Microsoft\Windows NT\CurrentVersion" , "InstallDate" )
$ENVID &= DriveGetSerial ( @HomeDrive & "\" )
$ENVID = StringTrimLeft ( _WINAPI_HASHSTRING ( $ENVID , 0 , 16 ) , 2 )
$NOTFOUND = StringFormat ( LANG ( "GUI" , "NotFound" , "未找到" ) )
$PLEASECHECK = StringFormat ( LANG ( "GUI" , "PleaseCheck" , "，请检查配置" ) )
$AND = StringFormat ( LANG ( "GUI" , "And" , "和" ) )
$WUXIAOAPP = StringFormat ( LANG ( "GUI" , "wuxiaoapp" , " 不是有效的32位或64位 Windows 应用程序" ) )
$INJECTGC1 = StringFormat ( LANG ( "GUI" , "injectgc1" , "注入GreenChrome成功，重启浏览器生效！" ) )
$INJECTGC2 = StringFormat ( LANG ( "GUI" , "injectgc2" , "注入GreenChrome成功！" ) )
$INJECTGC3 = StringFormat ( LANG ( "GUI" , "injectgc3" , "注入GreenChrome失败！" ) )
$REMOVEGC1 = StringFormat ( LANG ( "GUI" , "removegc1" , "解除GreenChrome成功，重启浏览器生效！" ) )
$REMOVEGC2 = StringFormat ( LANG ( "GUI" , "removegc2" , "解除GreenChrome成功！" ) )
$REMOVEGC3 = StringFormat ( LANG ( "GUI" , "removegc3" , "解除GreenChrome失败！" ) )
$PLEASEDOWNLOAD = StringFormat ( LANG ( "GUI" , "PleaseDownload" , " ,请先下载程序文件！\n是否立即下载？\n\n【是】:按[常规]选项卡里面的设置立即下载  【否】:不下载" ) )
$GUANFANG = StringFormat ( LANG ( "GUI" , "guanfang" , "官方" ) )
$CHROMESOURCE = $GUANFANG
If Not FileExists ( $INIFILE ) Then
	$FIRSTRUN = 1
	IniWrite ( $INIFILE , "Settings" , "AppVersion" , $APPVERSION )
	IniWrite ( $INIFILE , "Settings" , "Language" , "Auto" )
	IniWrite ( $INIFILE , "Settings" , "ChromePath" , ".\App\chrome.exe" )
	IniWrite ( $INIFILE , "Settings" , "UserDataDir" , ".\Data" )
	IniWrite ( $INIFILE , "Settings" , "PluginsDir" , "" )
	IniWrite ( $INIFILE , "Settings" , "CacheDir" , "" )
	IniWrite ( $INIFILE , "Settings" , "CacheSize" , 0 )
	IniWrite ( $INIFILE , "Settings" , "CacheSizeSmart" , 0 )
	IniWrite ( $INIFILE , "Settings" , "Platform" , "win" )
	IniWrite ( $INIFILE , "Settings" , "BrowserType" , "Chrome" )
	IniWrite ( $INIFILE , "Settings" , "Channel" , "Stable" )
	IniWrite ( $INIFILE , "Settings" , "x86" , 1 )
	IniWrite ( $INIFILE , "Settings" , "ChromeSource" , $GUANFANG )
	IniWrite ( $INIFILE , "Settings" , "LastCheckUpdate" , "2016/05/01 00:00:00" )
	IniWrite ( $INIFILE , "Settings" , "UpdateInterval" , 0 )
	IniWrite ( $INIFILE , "Settings" , "ProxyType" , "DIRECT" )
	IniWrite ( $INIFILE , "Settings" , "UpdateProxy" , "" )
	IniWrite ( $INIFILE , "Settings" , "UpdatePort" , "" )
	IniWrite ( $INIFILE , "Settings" , "DownloadThreads" , 3 )
	IniWrite ( $INIFILE , "Settings" , "Params" , "--with-greenchrome --disable-features=RendererCodeIntegrity --test-type --no-first-run --no-default-browser-check" )
	IniWrite ( $INIFILE , "Settings" , "RunInBackground" , 1 )
	IniWrite ( $INIFILE , "Settings" , "FirstUpdateCheck" , 1 )
	IniWrite ( $INIFILE , "Settings" , "AppUpdate" , 1 )
	IniWrite ( $INIFILE , "Settings" , "AppUpdateLastCheck" , "2016/05/01 00:00:00" )
	IniWrite ( $INIFILE , "Settings" , "CheckDefaultBrowser" , 1 )
	IniWrite ( $INIFILE , "Settings" , "ExApp" , "" )
	IniWrite ( $INIFILE , "Settings" , "ExAppAutoExit" , 1 )
	IniWrite ( $INIFILE , "Settings" , "ExApp2" , "" )
	IniWrite ( $INIFILE , "Settings" , "Bosskey" , "^`" )
	IniWrite ( $INIFILE , "Settings" , "BosskeyM" , $AU3_RDCLICK )
	IniWrite ( $INIFILE , "Settings" , "Hide2Tray" , 1 )
	IniWrite ( $INIFILE , "Settings" , "MouseClick2CloseTab" , 7684 & "|" & 7938 )
	IniWrite ( $INIFILE , "Settings" , "Mouse2SwitchTab" , 8964 & "|" & 8962 )
	IniWrite ( $INIFILE , "Settings" , "KeepLastTab" , 0 )
	IniWrite ( $INIFILE , "Settings" , "MouseIncA" , 0 )
	IniWrite ( $INIFILE , "Settings" , "MouseIncB" , 0 )
	IniWrite ( $INIFILE , "Settings" , "HookBox" , 0 )
	IniWrite ( $INIFILE , "Settings" , "TabPlus" , 1 )
	IniWrite ( $INIFILE , "Settings" , "GreenChrome" , 0 )
	IniWrite ( $INIFILE , "Settings" , "GreenChromeAuto" , 1 )
	IniWrite ( $INIFILE , "Settings" , "LastChromePath" , "" )
	IniWrite ( $INIFILE , "Settings" , "LastUserDataDir" , "" )
EndIf
$CHROMEPATH = IniRead ( $INIFILE , "Settings" , "ChromePath" , "" )
$USERDATADIR = IniRead ( $INIFILE , "Settings" , "UserDataDir" , "" )
$PLUGINSDIR = IniRead ( $INIFILE , "Settings" , "PluginsDir" , "" )
$CACHEDIR = IniRead ( $INIFILE , "Settings" , "CacheDir" , "" )
$CACHESIZE = IniRead ( $INIFILE , "Settings" , "CacheSize" , "" )
$CACHESIZESMART = IniRead ( $INIFILE , "Settings" , "CacheSizeSmart" , "" )
$PLATFORM = IniRead ( $INIFILE , "Settings" , "Platform" , "" )
$BROWSERTYPE = IniRead ( $INIFILE , "Settings" , "BrowserType" , "" )
$CHANNEL = IniRead ( $INIFILE , "Settings" , "Channel" , "" )
$X86 = IniRead ( $INIFILE , "Settings" , "x86" , "" )
$CHROMESOURCE = IniRead ( $INIFILE , "Settings" , "ChromeSource" , "" )
$GET_LATEST_CHROME_VER = "get_latest_chrome_ver"
$LASTCHECKUPDATE = IniRead ( $INIFILE , "Settings" , "LastCheckUpdate" , "" )
$UPDATEINTERVAL = IniRead ( $INIFILE , "Settings" , "UpdateInterval" , "" )
$PROXYTYPE = IniRead ( $INIFILE , "Settings" , "ProxyType" , "" )
$PROXYSEVER = IniRead ( $INIFILE , "Settings" , "UpdateProxy" , "" )
$PROXYPORT = IniRead ( $INIFILE , "Settings" , "UpdatePort" , "" )
$DOWNLOADTHREADS = IniRead ( $INIFILE , "Settings" , "DownloadThreads" , "" )
$PARAMS = IniRead ( $INIFILE , "Settings" , "Params" , "" )
$RUNINBACKGROUND = IniRead ( $INIFILE , "Settings" , "RunInBackground" , "" )
$FIRSTUPDATECHECK = IniRead ( $INIFILE , "Settings" , "FirstUpdateCheck" , "" )
$APPUPDATE = IniRead ( $INIFILE , "Settings" , "AppUpdate" , "" )
$APPUPDATELASTCHECK = IniRead ( $INIFILE , "Settings" , "AppUpdateLastCheck" , "" )
$CHECKDEFAULTBROWSER = IniRead ( $INIFILE , "Settings" , "CheckDefaultBrowser" , "" )
$EXAPP = IniRead ( $INIFILE , "Settings" , "ExApp" , "" )
$EXAPPAUTOEXIT = IniRead ( $INIFILE , "Settings" , "ExAppAutoExit" , "" )
$EXAPP2 = IniRead ( $INIFILE , "Settings" , "ExApp2" , "" )
$BOSSKEY = IniRead ( $INIFILE , "Settings" , "Bosskey" , "" )
$BOSSKEYM = IniRead ( $INIFILE , "Settings" , "BosskeyM" , "" )
$HIDE2TRAY = IniRead ( $INIFILE , "Settings" , "Hide2Tray" , "" )
$MOUSECLICK2CLOSETAB = IniRead ( $INIFILE , "Settings" , "MouseClick2CloseTab" , "" )
$MOUSE2SWITCHTAB = IniRead ( $INIFILE , "Settings" , "Mouse2SwitchTab" , "" )
$KEEPLASTTAB = IniRead ( $INIFILE , "Settings" , "KeepLastTab" , "" )
$MOUSEINCA = IniRead ( $INIFILE , "Settings" , "MouseIncA" , "" )
$MOUSEINCB = IniRead ( $INIFILE , "Settings" , "MouseIncB" , "" )
$HOOKBOX = IniRead ( $INIFILE , "Settings" , "HookBox" , "" )
$TABPLUS = IniRead ( $INIFILE , "Settings" , "TabPlus" , "" )
$GREENCHROME = IniRead ( $INIFILE , "Settings" , "GreenChrome" , "" )
$GREENCHROMEAUTO = IniRead ( $INIFILE , "Settings" , "GreenChromeAuto" , "" )
$CHROMEPLUSPLUS = IniRead ( $INIFILE , "Settings" , "ChromePlusPlus" , "" )
$CHROMEPLUSPLUSAUTO = IniRead ( $INIFILE , "Settings" , "ChromePlusPlusAuto" , "" )
$LASTCHROMEPATH = IniRead ( $INIFILE , "Settings" , "LastChromePath" , "" )
$LASTUSERDATADIR = IniRead ( $INIFILE , "Settings" , "LastUserDataDir" , "" )
If $APPVERSION <> IniRead ( $INIFILE , "Settings" , "AppVersion" , "" ) Then
	$FIRSTRUN = 1
	IniWrite ( $INIFILE , "Settings" , "AppVersion" , $APPVERSION )
EndIf
Opt ( "ExpandEnvStrings" , 1 )
EnvSet ( "APP" , @ScriptDir )
If ( $CMDLINE [ 0 ] = 1 And $CMDLINE [ 1 ] = "-set" ) Or $FIRSTRUN Or Not FileExists ( $CHROMEPATH ) Or Not FileExists ( $USERDATADIR ) Then
	CREATESETTINGSSHORTCUT ( @ScriptDir & "\" & $APPNAME & ".vbs" )
	SETTINGS ( )
EndIf
$CHROMEPATH = FULLPATH ( $CHROMEPATH )
SPLITPATH ( $CHROMEPATH , $CHROMEDIR , $CHROMEEXE )
$USERDATADIR = FULLPATH ( $USERDATADIR )
If IsAdmin ( ) And $CMDLINE [ 0 ] = 1 And $CMDLINE [ 1 ] = "-SetDefaultGlobal" Then
	If StringInStr ( IniRead ( $INIFILE , "Settings" , "BrowserType" , "" ) , "Firefox" ) Then
		FIREFOXCHECKDEFAULTBROWSER ( $CHROMEPATH )
	Else
		CHECKDEFAULTBROWSER ( $CHROMEPATH )
	EndIf
	Exit
EndIf
Func CHECKSETTING ( )
	If FileExists ( $CHROMEPATH ) Then
		If _WINAPI_GETBINARYTYPE ( $CHROMEPATH ) Then
			Switch @extended
			Case $SCS_32BIT_BINARY , $SCS_64BIT_BINARY
		Case Else
				$MSG = """" & $CHROMEPATH & """" & $WUXIAOAPP & $PLEASECHECK
				MsgBox ( 64 , "MyBrowser" , $MSG )
				Return
			EndSwitch
		Else
			$MSG = """" & $CHROMEPATH & """" & $WUXIAOAPP & $PLEASECHECK
			MsgBox ( 64 , "MyBrowser" , $MSG )
			Return
		EndIf
	EndIf
EndFunc
CHECKSETTING ( )
For $I = 1 To $CMDLINE [ 0 ]
	If StringInStr ( $CMDLINE [ $I ] , " " ) Then
		$PARAMS &= " """ & $CMDLINE [ $I ] & """"
	Else
		$PARAMS &= " " & $CMDLINE [ $I ]
	EndIf
Next
If StringInStr ( IniRead ( $INIFILE , "Settings" , "BrowserType" , "" ) , "Firefox" ) Then
	If $PLUGINSDIR <> "" Then
		$PLUGINSDIR = FULLPATH ( $PLUGINSDIR )
		EnvSet ( "MOZ_PLUGIN_PATH" , $PLUGINSDIR )
	EndIf
	FileDelete ( $CHROMEDIR & "\defaults\pref\mybrowser.js" )
	FileDelete ( $CHROMEDIR & "\mybrowser.cfg" )
	Local $CHROMEISRUNNING = PROFILEINUSE ( $USERDATADIR )
	If Not $CHROMEISRUNNING Then
		Local $CONFIG = CHECKPREFS ( )
		If $CONFIG Then
			FileWrite ( $CHROMEDIR & "\defaults\pref\mybrowser.js" , "pref(""general.config.obscure_value"", 0);" & @CRLF & "pref(""general.config.filename"", ""mybrowser.cfg"");" & @CRLF )
			FileWrite ( $CHROMEDIR & "\mybrowser.cfg" , $CONFIG )
		EndIf
	EndIf
	If $LASTCHROMEPATH <> "" Or $LASTUSERDATADIR <> "" Then
		If $LASTCHROMEPATH <> $CHROMEPATH Or $LASTUSERDATADIR <> $USERDATADIR Then
			UPDATEADDONSTARUP ( )
			UPDATEEXTENSIONSJSON ( )
		EndIf
	EndIf
	If $MOUSEINCA = 1 Then
		MOUSEINC ( )
	Else
		If FileExists ( $CHROMEDIR & "\MouseInc.exe" ) Then FileDelete ( $CHROMEDIR & "\MouseInc.exe" )
		If FileExists ( $CHROMEDIR & "\MouseInc.Settings.zip" ) Then FileDelete ( $CHROMEDIR & "\MouseInc.Settings.zip" )
		If FileExists ( $CHROMEDIR & "\MouseInc.json" ) Then FileDelete ( $CHROMEDIR & "\MouseInc.json" )
	EndIf
	If $TABPLUS = 1 Then
		If $MOUSECLICK2CLOSETAB Or $MOUSE2SWITCHTAB Then
			TABPLUS ( )
		EndIf
	Else
		If FileExists ( $CHROMEDIR & "\TabPlus.exe" ) Then FileDelete ( $CHROMEDIR & "\TabPlus.exe" )
		If FileExists ( $CHROMEDIR & "\TabPlus.ini" ) Then FileDelete ( $CHROMEDIR & "\TabPlus.ini" )
	EndIf
	$APPPID_BROWSER = Run ( $CHROMEPATH & " -profile """ & $USERDATADIR & """ " & $PARAMS , $CHROMEDIR )
	FileChangeDir ( @ScriptDir )
	CREATESETTINGSSHORTCUT ( @ScriptDir & "\" & $APPNAME & ".vbs" )
	If $CHROMEISRUNNING Then
		$EXE = StringRegExpReplace ( @AutoItExe , ".*\\" , "" )
		$LIST = ProcessList ( $EXE )
		For $I = 1 To $LIST [ 0 ] [ 0 ]
			If $LIST [ $I ] [ 1 ] <> @AutoItPID And GETPROCPATH ( $LIST [ $I ] [ 1 ] ) = @AutoItExe Then
				Exit
			EndIf
		Next
	EndIf
	If $EXAPP <> "" Then
		$AEXAPP = StringSplit ( $EXAPP , "||" , 1 )
		ReDim $AEXAPPPID [ $AEXAPP [ 0 ] + 1 ]
		$AEXAPPPID [ 0 ] = $AEXAPP [ 0 ]
		For $I = 1 To $AEXAPP [ 0 ]
			$MATCH = StringRegExp ( $AEXAPP [ $I ] , "^""(.*?)"" *(.*)" , 1 )
			If @error Then
				$FILE = $AEXAPP [ $I ]
				$ARGS = ""
			Else
				$FILE = $MATCH [ 0 ]
				$ARGS = $MATCH [ 1 ]
			EndIf
			$FILE = FULLPATH ( $FILE )
			$AEXAPPPID [ $I ] = ProcessExists ( StringRegExpReplace ( $FILE , ".*\\" , "" ) )
			If Not $AEXAPPPID [ $I ] And FileExists ( $FILE ) Then
				$AEXAPPPID [ $I ] = ShellExecute ( $FILE , $ARGS , StringRegExpReplace ( $FILE , "\\[^\\]+$" , "" ) )
			EndIf
		Next
	EndIf
	If $CHECKDEFAULTBROWSER Then
		FIREFOXCHECKDEFAULTBROWSER ( $CHROMEPATH )
	EndIf
	WinWait ( "[REGEXPCLASS:(?i)MozillaWindowClass;REGEXPTITLE:(?i)Firefox]" , "" , 15 )
	$HWND_BROWSER = GETHWNDBYPID ( $APPPID_BROWSER , "MozillaWindowClass" )
	Global $APPUSERMODELID
	If FileExists ( $TASKBARDIR ) Then
		$APPUSERMODELID = _WINDOWAPPID ( $HWND_BROWSER )
		CHECKFIREFOXPINNEDPROGRAMS ( $CHROMEPATH )
	EndIf
	If Not $RUNINBACKGROUND Then
		Exit
	EndIf
	If $CHECKDEFAULTBROWSER Then
		$HEVENT = _WINAPI_CREATEEVENT ( )
		For $I = 0 To UBound ( $AREG ) - 1
			If $AREG [ $I ] [ 1 ] Then
				$AREG [ $I ] [ 2 ] = _WINAPI_REGOPENKEY ( $AREG [ $I ] [ 0 ] , $AREG [ $I ] [ 1 ] , $KEY_NOTIFY )
				If $AREG [ $I ] [ 2 ] Then
					_WINAPI_REGNOTIFYCHANGEKEYVALUE ( $AREG [ $I ] [ 2 ] , $REG_NOTIFY_CHANGE_LAST_SET , 1 , 1 , $HEVENT )
				EndIf
			EndIf
		Next
	EndIf
	OnAutoItExitRegister ( "CloseRegHandle" )
	If $KEEPLASTTAB Or $MOUSECLICK2CLOSETAB Or $MOUSE2SWITCHTAB Then
		ACCESSIBLEINI ( )
	EndIf
	If $HOOKBOX Then
		If $BOSSKEYM Or $KEEPLASTTAB Or $MOUSECLICK2CLOSETAB Or $MOUSE2SWITCHTAB Then
			HOOKMOUSE ( )
		EndIf
	EndIf
	If $BOSSKEY Then
		HotKeySet ( $BOSSKEY , "Bosskey" )
	EndIf
	If $BOSSKEY Or $BOSSKEYM Then
		OnAutoItExitRegister ( "ResumeWindows" )
	EndIf
	REDUCEMEMORY ( )
	AdlibRegister ( "ReduceMemory" , 300000 )
	$APPISRUNNING = 0
	While 1
		Sleep ( 500 )
		If $HWND_BROWSER Then
			$APPISRUNNING = WinExists ( $HWND_BROWSER )
		Else
			$APPISRUNNING = ProcessExists ( $APPPID_BROWSER )
		EndIf
		If Not $APPISRUNNING Then
			$APPPID_BROWSER = APPISRUNNING ( $CHROMEPATH )
			If Not $APPPID_BROWSER Then
				If $TABPLUS Then
					If $MOUSECLICK2CLOSETAB Or $MOUSE2SWITCHTAB Then
						If ProcessExists ( "TabPlus.exe" ) Then ProcessClose ( "TabPlus.exe" )
						If ProcessExists ( "AutoHotkey.exe" ) Then ProcessClose ( "AutoHotkey.exe" )
					EndIf
				EndIf
				If ProcessExists ( "MouseInc.exe" ) And $MOUSEINCB = 1 Then ProcessClose ( "MouseInc.exe" )
				ExitLoop
			EndIf
			$APPISRUNNING = 1
			$HWND_BROWSER = GETHWNDBYPID ( $APPPID_BROWSER , "MozillaWindowClass" )
		EndIf
		If $TASKBARLASTCHANGE Then
			CHECKFIREFOXPINNEDPROGRAMS ( $CHROMEPATH )
		EndIf
		If $HEVENT And Not _WINAPI_WAITFORSINGLEOBJECT ( $HEVENT , 0 ) Then
			Sleep ( 500 )
			FIREFOXCHECKDEFAULTBROWSER ( $CHROMEPATH )
			For $I = 0 To UBound ( $AREG ) - 1
				If $AREG [ $I ] [ 2 ] Then
					_WINAPI_REGNOTIFYCHANGEKEYVALUE ( $AREG [ $I ] [ 2 ] , $REG_NOTIFY_CHANGE_LAST_SET , 1 , 1 , $HEVENT )
				EndIf
			Next
		EndIf
	WEnd
Else
	$PORTABLEPARAM = "--user-data-dir=""" & $USERDATADIR & """"
	If $CACHEDIR <> "" Then
		$CACHEDIR = FULLPATH ( $CACHEDIR )
		$PORTABLEPARAM &= " --disk-cache-dir=""" & $CACHEDIR & """"
	EndIf
	If $CACHESIZE <> 0 Then
		$PORTABLEPARAM &= " --disk-cache-size=" & $CACHESIZE
	EndIf
	Local $CHROMEISRUNNING = APPISRUNNING ( $CHROMEPATH )
	If Not $CHROMEISRUNNING And FileExists ( $CHROMEDIR & "\~updated" ) Then
		APPLYUPDATE ( )
	EndIf
	If $GREENCHROME = 1 Then
		$GREENCHROMEDLL = $CHROMEDIR & "\GreenChrome.dll"
		$GREENCHROMEINI = $CHROMEDIR & "\GreenChrome.ini"
		If FileExists ( $GREENCHROMEDLL ) Then
			If Not FileExists ( $GREENCHROMEINI ) Then
				$MSG = $NOTFOUND & """" & $GREENCHROMEINI & """" & $PLEASECHECK
				MsgBox ( 64 , "MyBrowser" , $MSG )
				Exit
			EndIf
		Else
			If FileExists ( $GREENCHROMEINI ) Then
				$MSG = $NOTFOUND & """" & $GREENCHROMEDLL & """" & $PLEASECHECK
				MsgBox ( 64 , "MyBrowser" , $MSG )
			Else
				$MSG = $NOTFOUND & """" & $GREENCHROMEDLL & """" & $AND & """" & $GREENCHROMEINI & """" & $PLEASECHECK
				MsgBox ( 64 , "MyBrowser" , $MSG )
			EndIf
			Exit
		EndIf
		If FileExists ( $CHROMEPATH & "~" ) Then FileDelete ( $CHROMEPATH & "~" )
		If FileExists ( $CHROMEPATH & "#" ) Then FileDelete ( $CHROMEPATH & "#" )
	EndIf
	If $CHROMEPLUSPLUS = 1 Then
		$CHROMEPLUSPLUSDLL = $CHROMEDIR & "\Chrome++.dll"
		$CHROMEPLUSPLUSINI = $CHROMEDIR & "\Chrome++.ini"
		If FileExists ( $CHROMEPLUSPLUSDLL ) Then
			If Not FileExists ( $CHROMEPLUSPLUSINI ) Then
				$MSG = $NOTFOUND & $CHROMEPLUSPLUSINI & $PLEASECHECK
				MsgBox ( 64 , "MyBrowser" , $MSG )
				Exit
			EndIf
		Else
			If FileExists ( $CHROMEPLUSPLUSINI ) Then
				$MSG = $NOTFOUND & """" & $CHROMEPLUSPLUSDLL & """" & $PLEASECHECK
				MsgBox ( 64 , "MyBrowser" , $MSG )
			Else
				$MSG = $NOTFOUND & """" & $CHROMEPLUSPLUSDLL & """" & $AND & """" & $CHROMEPLUSPLUSINI & """" & $PLEASECHECK
				MsgBox ( 64 , "MyBrowser" , $MSG )
			EndIf
			Exit
		EndIf
		If FileExists ( $CHROMEPATH & "~" ) Then FileDelete ( $CHROMEPATH & "~" )
		If FileExists ( $CHROMEPATH & "#" ) Then FileDelete ( $CHROMEPATH & "#" )
	EndIf
	If $MOUSEINCA = 1 Then
		MOUSEINC ( )
	Else
		If FileExists ( $CHROMEDIR & "\MouseInc.exe" ) Then FileDelete ( $CHROMEDIR & "\MouseInc.exe" )
		If FileExists ( $CHROMEDIR & "\MouseInc.Settings.zip" ) Then FileDelete ( $CHROMEDIR & "\MouseInc.Settings.zip" )
		If FileExists ( $CHROMEDIR & "\MouseInc.json" ) Then FileDelete ( $CHROMEDIR & "\MouseInc.json" )
	EndIf
	If $TABPLUS = 1 Then
		If $MOUSECLICK2CLOSETAB Or $MOUSE2SWITCHTAB Then
			TABPLUS ( )
		EndIf
	Else
		If FileExists ( $CHROMEDIR & "\TabPlus.exe" ) Then FileDelete ( $CHROMEDIR & "\TabPlus.exe" )
		If FileExists ( $CHROMEDIR & "\TabPlus.ini" ) Then FileDelete ( $CHROMEDIR & "\TabPlus.ini" )
	EndIf
	$APPPID_BROWSER = Run ( """" & $CHROMEPATH & """ " & $PORTABLEPARAM & " " & $PARAMS , $CHROMEDIR )
	FileChangeDir ( @ScriptDir )
	CREATESETTINGSSHORTCUT ( @ScriptDir & "\" & $APPNAME & ".vbs" )
	If @Compiled Then
		$LIST = ProcessList ( StringRegExpReplace ( @AutoItExe , ".*\\" , "" ) )
		For $I = 1 To $LIST [ 0 ] [ 0 ]
			If $LIST [ $I ] [ 1 ] <> @AutoItPID And GETPROCPATH ( $LIST [ $I ] [ 1 ] ) = @AutoItExe Then
				Exit
			EndIf
		Next
	EndIf
	If $EXAPP <> "" Then
		$AEXAPP = StringSplit ( $EXAPP , "||" , 1 )
		ReDim $AEXAPPPID [ $AEXAPP [ 0 ] + 1 ]
		$AEXAPPPID [ 0 ] = $AEXAPP [ 0 ]
		For $I = 1 To $AEXAPP [ 0 ]
			$MATCH = StringRegExp ( $AEXAPP [ $I ] , "^""(.*?)"" *(.*)" , 1 )
			If @error Then
				$FILE = $AEXAPP [ $I ]
				$ARGS = ""
			Else
				$FILE = $MATCH [ 0 ]
				$ARGS = $MATCH [ 1 ]
			EndIf
			$FILE = FULLPATH ( $FILE )
			$AEXAPPPID [ $I ] = ProcessExists ( StringRegExpReplace ( $FILE , ".*\\" , "" ) )
			If Not $AEXAPPPID [ $I ] And FileExists ( $FILE ) Then
				$AEXAPPPID [ $I ] = ShellExecute ( $FILE , $ARGS , StringRegExpReplace ( $FILE , "\\[^\\]+$" , "" ) )
			EndIf
		Next
	EndIf
	If $CHECKDEFAULTBROWSER Then
		CHECKDEFAULTBROWSER ( $CHROMEPATH )
	EndIf
	WinWait ( "[REGEXPCLASS:(?i)Chrome; REGEXPTITLE:\S+]" , "" , 10 )
	For $I = 1 To 5
		$HWND_BROWSER = GETHWNDBYPID ( $APPPID_BROWSER , "Chrome" , "\S+" )
		If $HWND_BROWSER Then ExitLoop
		Sleep ( 2000 )
	Next
	Global $APPUSERMODELID
	If FileExists ( $TASKBARDIR ) Then
		$APPUSERMODELID = _WINDOWAPPID ( $HWND_BROWSER )
		CHECKPINNEDPROGRAMS ( $CHROMEPATH )
	EndIf
	If Not $RUNINBACKGROUND Then
		UPDATECHECK ( )
		Exit
	EndIf
	If $CHECKDEFAULTBROWSER Then
		$HEVENT_REG = _WINAPI_CREATEEVENT ( )
		For $I = 0 To UBound ( $AREG ) - 1
			If $AREG [ $I ] [ 1 ] Then
				$AREG [ $I ] [ 2 ] = _WINAPI_REGOPENKEY ( $AREG [ $I ] [ 0 ] , $AREG [ $I ] [ 1 ] , $KEY_NOTIFY )
				If $AREG [ $I ] [ 2 ] Then
					_WINAPI_REGNOTIFYCHANGEKEYVALUE ( $AREG [ $I ] [ 2 ] , $REG_NOTIFY_CHANGE_LAST_SET , 1 , 1 , $HEVENT_REG )
				EndIf
			EndIf
		Next
		OnAutoItExitRegister ( "CloseRegHandle" )
	EndIf
	If $KEEPLASTTAB Or $MOUSECLICK2CLOSETAB Or $MOUSE2SWITCHTAB Then
		ACCESSIBLEINI ( )
	EndIf
	If $HOOKBOX Then
		If $BOSSKEYM Or $KEEPLASTTAB Or $MOUSECLICK2CLOSETAB Or $MOUSE2SWITCHTAB Then
			HOOKMOUSE ( )
		EndIf
	EndIf
	If $BOSSKEY Then
		HotKeySet ( $BOSSKEY , "Bosskey" )
	EndIf
	If $BOSSKEY Or $BOSSKEYM Then
		OnAutoItExitRegister ( "ResumeWindows" )
	EndIf
	If StringInStr ( IniRead ( $INIFILE , "Settings" , "BrowserType" , "" ) , "Chrome" ) Or StringInStr ( IniRead ( $INIFILE , "Settings" , "BrowserType" , "" ) , "Chromium" ) Or StringInStr ( IniRead ( $INIFILE , "Settings" , "BrowserType" , "" ) , "Brave" ) Or StringInStr ( IniRead ( $INIFILE , "Settings" , "BrowserType" , "" ) , "Edge" ) Then
		If StringInStr ( IniRead ( $INIFILE , "Settings" , "FirstUpdateCheck" , "" ) , 1 ) Then
			IniWrite ( $INIFILE , "Settings" , "FirstUpdateCheck" , 0 )
		Else
			AdlibRegister ( "UpdateCheck" , 10000 )
		EndIf
	EndIf
	REDUCEMEMORY ( )
	$APPISRUNNING = 1
	While 1
		Sleep ( 500 )
		If $HWND_BROWSER Then
			$APPISRUNNING = WinExists ( $HWND_BROWSER )
		Else
			$APPISRUNNING = ProcessExists ( $APPPID_BROWSER )
		EndIf
		If Not $APPISRUNNING Then
			$APPPID_BROWSER = APPISRUNNING ( $CHROMEPATH )
			If Not $APPPID_BROWSER Then
				If $TABPLUS Then
					If $MOUSECLICK2CLOSETAB Or $MOUSE2SWITCHTAB Then
						If ProcessExists ( "TabPlus.exe" ) Then ProcessClose ( "TabPlus.exe" )
						If ProcessExists ( "AutoHotkey.exe" ) Then ProcessClose ( "AutoHotkey.exe" )
					EndIf
				EndIf
				If ProcessExists ( "MouseInc.exe" ) And $MOUSEINCB = 1 Then ProcessClose ( "MouseInc.exe" )
				ExitLoop
			EndIf
			$APPISRUNNING = 1
			$HWND_BROWSER = GETHWNDBYPID ( $APPPID_BROWSER , "Chrome" , "\S+" )
		EndIf
		If $TASKBARLASTCHANGE Then
			CHECKPINNEDPROGRAMS ( $CHROMEPATH )
		EndIf
		If $HEVENT_REG And Not _WINAPI_WAITFORSINGLEOBJECT ( $HEVENT_REG , 0 ) Then
			Sleep ( 50 )
			CHECKDEFAULTBROWSER ( $CHROMEPATH )
			For $I = 0 To UBound ( $AREG ) - 1
				If $AREG [ $I ] [ 2 ] Then
					_WINAPI_REGNOTIFYCHANGEKEYVALUE ( $AREG [ $I ] [ 2 ] , $REG_NOTIFY_CHANGE_LAST_SET , 1 , 1 , $HEVENT_REG )
				EndIf
			Next
		EndIf
	WEnd
EndIf
If $EXAPPAUTOEXIT And $EXAPP <> "" Then
	$CMD = ""
	For $I = 1 To $AEXAPPPID [ 0 ]
		If Not $AEXAPPPID [ $I ] Then ContinueLoop
		$CMD &= " /PID " & $AEXAPPPID [ $I ]
	Next
	If $CMD Then
		$CMD = "taskkill" & $CMD & " /T /F"
		Run ( @ComSpec & " /c " & $CMD , "" , @SW_HIDE )
	EndIf
EndIf
If $EXAPP2 <> "" Then
	$AEXAPP2 = StringSplit ( $EXAPP2 , "||" , 1 )
	For $I = 1 To $AEXAPP2 [ 0 ]
		$MATCH = StringRegExp ( $AEXAPP2 [ $I ] , "^""(.*?)"" *(.*)" , 1 )
		If @error Then
			$FILE = $AEXAPP2 [ $I ]
			$ARGS = ""
		Else
			$FILE = $MATCH [ 0 ]
			$ARGS = $MATCH [ 1 ]
		EndIf
		$FILE = FULLPATH ( $FILE )
		If Not ProcessExists ( StringRegExpReplace ( $FILE , ".*\\" , "" ) ) Then
			If FileExists ( $FILE ) Then
				ShellExecute ( $FILE , $ARGS , StringRegExpReplace ( $FILE , "\\[^\\]+$" , "" ) )
			EndIf
		EndIf
	Next
EndIf
If 0 Then
	GET_LATEST_CHROME_VER ( "win" , "Chrome" , "Stable" )
	DOWNLOAD_CHROME ( "" , "" )
EndIf
Exit
Func MOUSEINC ( )
	$MOUSEINC1 = $CHROMEDIR & "\MouseInc.exe"
	$MOUSEINC2 = $CHROMEDIR & "\MouseInc.json"
	$MOUSEINC3 = $CHROMEDIR & "\MouseInc.Settings.zip"
	If Not FileExists ( $MOUSEINC1 ) Then FileInstall ( "MouseInc.exe" , $MOUSEINC1 , 1 )
	If Not FileExists ( $MOUSEINC2 ) Then FileInstall ( "MouseInc.json" , $MOUSEINC2 , 1 )
	If Not FileExists ( $MOUSEINC3 ) Then FileInstall ( "MouseInc.Settings.zip" , $MOUSEINC3 , 1 )
	$CMD = "cd /d """ & $CHROMEDIR & """ && start /b MouseInc.exe"
	If Not ProcessExists ( "MouseInc.exe" ) Then Run ( @ComSpec & " /c " & $CMD , "" , @SW_HIDE )
EndFunc
Func MOUSE_EVENT ( $HGUI , $MSGID , $WPARAM , $LPARAM )
	$X = BitAND ( $LPARAM , 65535 )
	$Y = BitShift ( $LPARAM , 16 )
	$BLOCKED = BitAND ( $MSGID , 1 )
	$EVENT = BitAND ( $MSGID , 4294967294 )
	If WinGetProcess ( $WPARAM ) <> $APPPID_BROWSER Then
		If $BLOCKED Then
			PASSMOUSEEVENT ( $EVENT )
		EndIf
		Return
	EndIf
	$TPOINT = DllStructCreate ( $TAGPOINT )
	$TPOINT .X = $X
	$TPOINT .Y = $Y
	$HWND = _WINAPI_WINDOWFROMPOINT ( $TPOINT )
	$CLASS = _WINAPI_GETCLASSNAME ( $HWND )
	If $EVENT = $AU3_RCLICK And _ISPRESSED ( "10" ) Then
		If $BLOCKED Then
			PASSMOUSEEVENT ( $EVENT )
		EndIf
		Return
	EndIf
	Local $BLOCKEVENT = 0
	If $CLASS = "Chrome_RenderWidgetHostHWND" Then
		If $EVENT = $BOSSKEYM Then
			If $BLOCKED Then
				DllCall ( $HHOOKDLL , "int" , "IgnoreEvents" , "int" , 1 )
				Switch $EVENT
				Case $AU3_RDCLICK , $AU3_RDROP
					MouseUp ( "left" )
				Case $AU3_MDROP
					MouseUp ( "middle" )
				Case $AU3_MDCLICK
					MouseDown ( "middle" )
				EndSwitch
				Sleep ( 50 )
				DllCall ( $HHOOKDLL , "int" , "IgnoreEvents" , "int" , 0 )
				$BLOCKEVENT = 1
			EndIf
			BOSSKEY ( )
		EndIf
	ElseIf $CLASS = "Chrome_WidgetWin_1" Then
		If ( $KEEPLASTTAB And ( $EVENT = $AU3_MCLICK Or $EVENT = $AU3_LCLICK ) ) Or StringInStr ( $MOUSECLICK2CLOSETAB , $EVENT ) Or StringInStr ( $MOUSE2SWITCHTAB , $EVENT ) Then
			$BLOCKEVENT = TABPROCESS ( $HWND , $EVENT , $X , $Y )
		EndIf
	EndIf
	If $BLOCKED And Not $BLOCKEVENT Then
		PASSMOUSEEVENT ( $EVENT )
	EndIf
EndFunc
Func PASSMOUSEEVENT ( $EVENT )
	DllCall ( $HHOOKDLL , "int" , "IgnoreEvents" , "int" , 1 )
	Switch $EVENT
	Case $AU3_LCLICK , $AU3_LDROP
		MouseUp ( "left" )
	Case $AU3_LDCLICK
		MouseDown ( "left" )
	Case $AU3_RCLICK , $AU3_RDCLICK , $AU3_RDROP
		MouseUp ( "right" )
	Case $AU3_MCLICK , $AU3_MDROP
		MouseUp ( "middle" )
	Case $AU3_MDCLICK
		MouseDown ( "middle" )
	Case $AU3_XCLICK , $AU3_XDROP
		_WINAPI_MOUSE_EVENT ( $MOUSEEVENTF_XUP )
	Case $AU3_XDCLICK
		_WINAPI_MOUSE_EVENT ( $MOUSEEVENTF_XDOWN )
	EndSwitch
	Sleep ( 50 )
	DllCall ( $HHOOKDLL , "int" , "IgnoreEvents" , "int" , 0 )
EndFunc
Func TABPLUS ( )
	$TABPLUS = $CHROMEDIR & "\TabPlus.exe"
	If Not FileExists ( $TABPLUS ) Then FileInstall ( "TabPlus.exe" , $TABPLUS , 1 )
	$INIFILE1 = $CHROMEDIR & "\TabPlus.ini"
	If Not FileExists ( $INIFILE1 ) Then FileInstall ( "TabPlus.ini" , $INIFILE1 , 1 )
	$CMD = "cd /d """ & $CHROMEDIR & """ && start /b TabPlus.exe"
	If Not ProcessExists ( "TabPlus.exe" ) Then Run ( @ComSpec & " /c " & $CMD , "" , @SW_HIDE )
EndFunc
Func EDGEDOWNLOAD ( )
	$EDGEDOWNLOAD = MsgBox ( 64 + 4 , "MyBrowser" , StringFormat ( LANG ( "Update" , "edgedownload" , "是否打开Edge网页下载链接？" ) ) , 0 , $HSETTINGS )
	If $EDGEDOWNLOAD = 6 Then ShellExecute ( "https://xixiranran.github.io/tools/edge/" )
EndFunc
Func HOOKMOUSE ( )
	Local $HOOKDLL , $IPID = 0
	$HOOKDLL = $CHROMEDIR & "\hook.dll"
	If _WINAPI_GETBINARYTYPE ( $CHROMEPATH ) Then
		Switch @extended
		Case $SCS_32BIT_BINARY
			If Not FileExists ( $HOOKDLL ) Then FileInstall ( "hook.dll" , $HOOKDLL , 1 )
		Case $SCS_64BIT_BINARY
			If Not FileExists ( $HOOKDLL ) Then FileInstall ( "hook64.dll" , $HOOKDLL , 1 )
		EndSwitch
	EndIf
	$HHOOKDLL = DllOpen ( $HOOKDLL )
	If $HHOOKDLL = - 1 Then Return
	OnAutoItExitRegister ( "UnhookMouse" )
	$HHOOKLIB = _WINAPI_LOADLIBRARY ( $HOOKDLL )
	$MOUSEHOOKPROC = _WINAPI_GETPROCADDRESS ( $HHOOKLIB , "MouseProc" )
	If Not $MOUSEHOOKPROC Then Return
	$ITHREAD = _WINAPI_GETWINDOWTHREADPROCESSID ( $HWND_BROWSER , $IPID )
	$HMOUSEHOOK = _WINAPI_SETWINDOWSHOOKEX ( $WH_MOUSE , $MOUSEHOOKPROC , $HHOOKLIB , $ITHREAD )
	Local $EVENTS = "|" & $BOSSKEYM & "|" & $MOUSECLICK2CLOSETAB
	If $KEEPLASTTAB Then
		$EVENTS &= "|" & $AU3_MCLICK
	EndIf
	$EVENTS &= "|" & $MOUSE2SWITCHTAB
	Local $BLOCKEVENTS = $AU3_RCLICK & "|" & $AU3_RDCLICK & "|" & $AU3_RDROP & "|" & $AU3_MCLICK
	DllCall ( $HHOOKDLL , "int" , "SetValuesMouse" , "hwnd" , $__HWND_VARS , "hwnd" , $HMOUSEHOOK )
	DllCall ( $HHOOKDLL , "int" , "MouseEvents" , "str" , $EVENTS )
	DllCall ( $HHOOKDLL , "int" , "BlockEvents" , "str" , $BLOCKEVENTS )
	GUIRegisterMsg ( $AU3_LDCLICK , "Mouse_Event" )
	GUIRegisterMsg ( $AU3_LDCLICK + 1 , "Mouse_Event" )
	GUIRegisterMsg ( $AU3_LDROP , "Mouse_Event" )
	GUIRegisterMsg ( $AU3_LDROP + 1 , "Mouse_Event" )
	GUIRegisterMsg ( $AU3_RCLICK , "Mouse_Event" )
	GUIRegisterMsg ( $AU3_RCLICK + 1 , "Mouse_Event" )
	GUIRegisterMsg ( $AU3_RDCLICK , "Mouse_Event" )
	GUIRegisterMsg ( $AU3_RDCLICK + 1 , "Mouse_Event" )
	GUIRegisterMsg ( $AU3_RDROP , "Mouse_Event" )
	GUIRegisterMsg ( $AU3_RDROP + 1 , "Mouse_Event" )
	GUIRegisterMsg ( $AU3_MCLICK , "Mouse_Event" )
	GUIRegisterMsg ( $AU3_MCLICK + 1 , "Mouse_Event" )
	GUIRegisterMsg ( $AU3_MDCLICK , "Mouse_Event" )
	GUIRegisterMsg ( $AU3_MDCLICK + 1 , "Mouse_Event" )
	GUIRegisterMsg ( $AU3_MDROP , "Mouse_Event" )
	GUIRegisterMsg ( $AU3_MDROP + 1 , "Mouse_Event" )
	GUIRegisterMsg ( $AU3_XCLICK , "Mouse_Event" )
	GUIRegisterMsg ( $AU3_XCLICK + 1 , "Mouse_Event" )
	GUIRegisterMsg ( $AU3_XDCLICK , "Mouse_Event" )
	GUIRegisterMsg ( $AU3_XDCLICK + 1 , "Mouse_Event" )
	GUIRegisterMsg ( $AU3_XDROP , "Mouse_Event" )
	GUIRegisterMsg ( $AU3_XDROP + 1 , "Mouse_Event" )
	GUIRegisterMsg ( $AU3_WHEELUP , "Mouse_Event" )
	GUIRegisterMsg ( $AU3_WHEELUP + 1 , "Mouse_Event" )
	GUIRegisterMsg ( $AU3_WHEELDOWN , "Mouse_Event" )
	GUIRegisterMsg ( $AU3_WHEELDOWN + 1 , "Mouse_Event" )
EndFunc
Func UNHOOKMOUSE ( )
	_WINAPI_UNHOOKWINDOWSHOOKEX ( $HMOUSEHOOK )
	_WINAPI_FREELIBRARY ( $HHOOKLIB )
	DllClose ( $HHOOKDLL )
EndFunc
Func TABPROCESS ( $HWND , $ACTION = $AU3_RCLICK , $MOUSEX = 0 , $MOUSEY = 0 )
	Local $PACC , $OACC , $TVARCHILD
	ACCESSIBLEOBJECTFROMPOINT ( $MOUSEX , $MOUSEY , $PACC , $TVARCHILD )
	If @error Then Return
	$OACC = ObjCreateInterface ( $PACC , $SIID_IACCESSIBLE , $DTAGIACCESSIBLE )
	If Not IsObj ( $OACC ) Then Return
	Local $IROLE , $ATAB [ 2 ]
	$OACC .get_accRole ( 0 , $IROLE )
	If $IROLE = $ROLE_SYSTEM_PAGETAB Then
		Dim $ATAB [ 2 ] = [ $PACC , $OACC ]
	ElseIf $IROLE <> $ROLE_SYSTEM_STATICTEXT And $IROLE <> $ROLE_SYSTEM_PUSHBUTTON Then
		Return
	EndIf
	If Not IsObj ( $ATAB [ 1 ] ) Then
		$ATAB = ACCESSIBLEPARENT ( $OACC , $ROLE_SYSTEM_PAGETAB , 1 )
		If Not IsArray ( $ATAB ) Then
			Return
		EndIf
	EndIf
	If $ACTION = $AU3_WHEELUP Then
		Send ( "^{PGUP}" )
		Return
	ElseIf $ACTION = $AU3_WHEELDOWN Then
		Send ( "^{PGDN}" )
		Return
	EndIf
	Local $ITAB = 0
	$ATABLIST = ACCESSIBLEPARENT ( $ATAB [ 1 ] , $ROLE_SYSTEM_PAGETABLIST , 1 )
	If Not IsArray ( $ATABLIST ) Or $ATABLIST [ 1 ] .get_accChildCount ( $ITAB ) Or Not $ITAB Then
		Return
	EndIf
	$ITAB -= 1
	If $ITAB > 1 Then
		If $ACTION = $AU3_LDCLICK Or $ACTION = $AU3_RCLICK Then
			DllCall ( $HHOOKDLL , "int" , "IgnoreEvents" , "int" , 1 )
			$POS = MouseGetPos ( )
			MouseMove ( $MOUSEX , $MOUSEY , 0 )
			MouseClick ( "middle" , $MOUSEX , $MOUSEY , 1 , 0 )
			MouseMove ( $POS [ 0 ] , $POS [ 1 ] , 0 )
			Sleep ( 10 )
			DllCall ( $HHOOKDLL , "int" , "IgnoreEvents" , "int" , 0 )
			Return 1
		EndIf
		Return
	EndIf
	If $KEEPLASTTAB Then
		Send ( "^t" )
		Sleep ( 50 )
	EndIf
	If $ACTION = $AU3_LDCLICK Or $ACTION = $AU3_RCLICK Then
		DllCall ( $HHOOKDLL , "int" , "IgnoreEvents" , "int" , 1 )
		$POS = MouseGetPos ( )
		MouseMove ( $MOUSEX , $MOUSEY , 0 )
		MouseClick ( "middle" , $MOUSEX , $MOUSEY , 1 , 0 )
		MouseMove ( $POS [ 0 ] , $POS [ 1 ] , 0 )
		Sleep ( 10 )
		DllCall ( $HHOOKDLL , "int" , "IgnoreEvents" , "int" , 0 )
	EndIf
	If $ACTION = $AU3_RCLICK Then
		Return 1
	EndIf
EndFunc
Func BOSSKEY ( )
	Local $ALIST , $PID
	If $CHROMEISHIDDEN Then
		RESUMEWINDOWS ( )
	Else
		$ALIST = WinList ( "[REGEXPCLASS:(?i)Chrome; REGEXPTITLE:\S+]" )
		If $ALIST [ 0 ] [ 0 ] < 1 Then Return
		For $I = 1 To $ALIST [ 0 ] [ 0 ]
			If BitAND ( WinGetState ( $ALIST [ $I ] [ 1 ] ) , 2 ) Then
				$PID = WinGetProcess ( $ALIST [ $I ] [ 1 ] )
				If $PID = $APPPID_BROWSER Then
					WinSetState ( $ALIST [ $I ] [ 1 ] , "" , @SW_HIDE )
					$CHROMEISHIDDEN = 1
				EndIf
			EndIf
		Next
		If VERSIONCOMPARE ( $WINVERSION , "6.1" ) >= 0 Then
			AUDIO_SETAPPMUTE ( $APPPID_BROWSER , 1 )
		EndIf
		If $HIDE2TRAY Then
			TraySetIcon ( $CHROMEPATH )
			TraySetOnEvent ( $TRAY_EVENT_PRIMARYDOWN , "ResumeWindows" )
			TraySetState ( 1 )
			TraySetToolTip ( StringFormat ( LANG ( "GUI" , "UnhideChrome" , "Chrome已隐藏\n点击取消隐藏" ) , 0 ) )
		EndIf
	EndIf
EndFunc
Func RESUMEWINDOWS ( )
	If $HIDE2TRAY Then
		TraySetOnEvent ( $TRAY_EVENT_PRIMARYDOWN , "" )
		TraySetToolTip ( )
		TraySetIcon ( )
		TraySetState ( 2 )
	EndIf
	Local $ALIST , $PID
	$ALIST = WinList ( "[REGEXPCLASS:(?i)Chrome; REGEXPTITLE:\S+]" )
	If $ALIST [ 0 ] [ 0 ] < 1 Then Return
	For $I = 1 To $ALIST [ 0 ] [ 0 ]
		If Not BitAND ( WinGetState ( $ALIST [ $I ] [ 1 ] ) , 2 ) Then
			$PID = WinGetProcess ( $ALIST [ $I ] [ 1 ] )
			If $PID = $APPPID_BROWSER Or GETPROCPATH ( $PID ) = $CHROMEPATH Then
				WinSetState ( $ALIST [ $I ] [ 1 ] , "" , @SW_SHOW )
			EndIf
		EndIf
	Next
	$CHROMEISHIDDEN = 0
	If VERSIONCOMPARE ( $WINVERSION , "6.1" ) >= 0 Then
		AUDIO_SETAPPMUTE ( $APPPID_BROWSER , 0 )
	EndIf
EndFunc
Func LANGCHECK ( )
	If $LANGUAGE = "Auto" And FileExists ( @ScriptDir & "\lang\lang.ini" ) Then
		Return @ScriptDir & "\lang\lang.ini"
	EndIf
	Local $LNGFILE
	If $LANGUAGE = "zh-CN" Then
		Return ""
	ElseIf $LANGUAGE = "zh-TW" Then
		$LNGFILE = @ScriptDir & "\Lang\zh-TW.ini"
	ElseIf $LANGUAGE = "en-US" Then
		$LNGFILE = @ScriptDir & "\Lang\en-US.ini"
	EndIf
	If Not $LNGFILE Then
		If @OSLang = "0004" Or @OSLang = "0804" Then
			Return ""
		ElseIf StringRight ( @OSLang , 2 ) = "04" Then
			$LNGFILE = @ScriptDir & "\Lang\zh-TW.ini"
		EndIf
	EndIf
	If Not FileExists ( @ScriptDir & "\Lang" ) Then
		DirCreate ( @ScriptDir & "\Lang\" )
	EndIf
	If Not $LNGFILE Then
		$LNGFILE = @ScriptDir & "\Lang\en-US.ini"
	EndIf
	If $LNGFILE = @ScriptDir & "\Lang\zh-TW.ini" Then
		If Not FileExists ( $LNGFILE ) Or IniRead ( $LNGFILE , "Lang" , "Version" , "" ) <> $APPVERSION Then
			FileInstall ( "zh-TW.ini" , $LNGFILE , 1 )
		EndIf
	Else
		If Not FileExists ( $LNGFILE ) Or IniRead ( $LNGFILE , "Lang" , "Version" , "" ) <> $APPVERSION Then
			FileInstall ( "en-US.ini" , $LNGFILE , 1 )
		EndIf
	EndIf
	Return $LNGFILE
EndFunc
Func LANG ( $SECTION , $KEY , $DEFALTSTR )
	If Not $LANGFILE Then
		Return $DEFALTSTR
	Else
		Return IniRead ( $LANGFILE , $SECTION , $KEY , $DEFALTSTR )
	EndIf
EndFunc
Func GETIEPROXY ( ByRef $SEVER , ByRef $PORT )
	$SEVER = ""
	$PORT = ""
	Local $AIEPROXY = _WINHTTPGETIEPROXYCONFIGFORCURRENTUSER ( )
	If Not @error Then
		$SPROXY = $AIEPROXY [ 2 ]
		If Not $SPROXY And $AIEPROXY [ 1 ] Then
			$PACADDRESS = $AIEPROXY [ 1 ]
			Local $WINHTTP_AUTOPROXY_OPTIONS = DllStructCreate ( "dword dwFlags;" & "dword dwAutoDetectFlags;" & "ptr lpszAutoConfigUrl;" & "ptr lpvReserved;" & "dword dwReserved;" & "dword fAutoLogonIfChallenged;" )
			Local $WINHTTP_PROXY_INFO = DllStructCreate ( "dword AccessType;ptr Proxy;ptr ProxyBypass" )
			DllStructSetData ( $WINHTTP_AUTOPROXY_OPTIONS , "dwFlags" , $WINHTTP_AUTOPROXY_CONFIG_URL )
			DllStructSetData ( $WINHTTP_AUTOPROXY_OPTIONS , "dwAutoDetectFlags" , BitOR ( $WINHTTP_AUTO_DETECT_TYPE_DHCP , $WINHTTP_AUTO_DETECT_TYPE_DNS_A ) )
			Local $TPACADDRESS = DllStructCreate ( "wchar[" & StringLen ( $PACADDRESS ) + 1 & "]" )
			DllStructSetData ( $TPACADDRESS , 1 , $PACADDRESS )
			DllStructSetData ( $WINHTTP_AUTOPROXY_OPTIONS , "lpszAutoConfigUrl" , DllStructGetPtr ( $TPACADDRESS ) )
			Local $HOPEN = _WINHTTPOPEN ( )
			$URL = "https://www.google.com"
			Local $ACALL = DllCall ( $HWINHTTPDLL__WINHTTP , "bool" , "WinHttpGetProxyForUrl" , "handle" , $HOPEN , "wstr" , $URL , "struct*" , DllStructGetPtr ( $WINHTTP_AUTOPROXY_OPTIONS ) , "struct*" , DllStructGetPtr ( $WINHTTP_PROXY_INFO ) )
			_WINHTTPCLOSEHANDLE ( $HOPEN )
			Local $PPROXY = DllStructGetData ( $WINHTTP_PROXY_INFO , "Proxy" )
			$SPROXY = DllStructGetData ( DllStructCreate ( "wchar[" & _WINAPI_STRINGLENW ( $PPROXY ) & "]" , $PPROXY ) , 1 )
		EndIf
		Local $MATCH
		If StringInStr ( $SPROXY , "https=" ) Then
			$MATCH = StringRegExp ( $SPROXY , "(?i)https=(\S+?:\d+)" , 1 )
			If Not @error Then $SPROXY = $MATCH [ 0 ]
		ElseIf StringInStr ( $SPROXY , "http=" ) Then
			$MATCH = StringRegExp ( $SPROXY , "(?i)http=(\S+?:\d+)" , 1 )
			If Not @error Then $SPROXY = $MATCH [ 0 ]
		EndIf
		$POS = StringInStr ( $SPROXY , ":" )
		If $POS Then
			$SEVER = StringLeft ( $SPROXY , $POS - 1 )
			$PORT = StringMid ( $SPROXY , $POS + 1 )
		EndIf
	EndIf
EndFunc
Func GETHWNDBYPID ( $PID , $CLASS = ".*" , $TITLE = ".*" )
	$LIST = WinList ( "[REGEXPCLASS:(?i)" & $CLASS & "; REGEXPTITLE:(?i)" & $TITLE & "]" )
	For $I = 1 To $LIST [ 0 ] [ 0 ]
		If Not BitAND ( WinGetState ( $LIST [ $I ] [ 1 ] ) , 2 ) Then ContinueLoop
		If $PID = WinGetProcess ( $LIST [ $I ] [ 1 ] ) Then
			Return $LIST [ $I ] [ 1 ]
		EndIf
	Next
EndFunc
Func CLOSEREGHANDLE ( )
	If $HEVENT_REG Then
		_WINAPI_CLOSEHANDLE ( $HEVENT_REG )
		For $I = 0 To UBound ( $AREG ) - 1
			_WINAPI_REGCLOSEKEY ( $AREG [ $I ] [ 2 ] )
		Next
	EndIf
	IniWrite ( $INIFILE , "Settings" , "LastChromePath" , $CHROMEPATH )
	IniWrite ( $INIFILE , "Settings" , "LastUserDataDir" , $USERDATADIR )
EndFunc
Func UPDATECHECK ( )
	Local $UPDATED , $VAR
	If $APPUPDATE <> 0 And _DATEDIFF ( "h" , $APPUPDATELASTCHECK , _NOWCALC ( ) ) >= 24 Then
		CHECKAPPUPDATE ( )
	EndIf
	If $UPDATEINTERVAL >= 0 Then
		If $UPDATEINTERVAL = 0 Then
			$UPDATED = UPDATECHROME ( $CHROMEPATH , $CHANNEL )
		Else
			Local $VAR = _DATEDIFF ( "h" , $LASTCHECKUPDATE , _NOWCALC ( ) )
			If $VAR >= $UPDATEINTERVAL Then
				$UPDATED = UPDATECHROME ( $CHROMEPATH , $CHANNEL )
			EndIf
		EndIf
		If $UPDATED And Not APPISRUNNING ( $CHROMEPATH ) Then
			If @Compiled Then
				Run ( """" & @AutoItExe & """ --restore-last-session" )
			Else
				Run ( """" & @AutoItExe & """ """ & @ScriptFullPath & """ --restore-last-session" )
			EndIf
			Exit
		EndIf
	EndIf
	If $RUNINBACKGROUND Then
		If $FIRSTUPDATECHECK Then
			AdlibRegister ( "UpdateCheck" , 300000 )
		EndIf
		REDUCEMEMORY ( )
	EndIf
EndFunc
Func CHECKPINNEDPROGRAMS ( $BROWSER_PATH )
	If Not FileExists ( $TASKBARDIR ) Then
		Return
	EndIf
	Local $FTIME = FileGetTime ( $TASKBARDIR , 0 , 1 )
	If $FTIME = $TASKBARLASTCHANGE Then
		Return
	EndIf
	$TASKBARLASTCHANGE = $FTIME
	Local $SEARCH = FileFindFirstFile ( $TASKBARDIR & "\*.lnk" )
	If $SEARCH = - 1 Then Return
	Local $FILE , $SHELLOBJ , $OBJSHORTCUT , $SHORTCUT_APPID
	$SHELLOBJ = ObjCreate ( "WScript.Shell" )
	If Not @error Then
		While 1
			$FILE = $TASKBARDIR & "\" & FileFindNextFile ( $SEARCH )
			If @error Then ExitLoop
			$OBJSHORTCUT = $SHELLOBJ .CreateShortCut ( $FILE )
			$PATH = $OBJSHORTCUT .TargetPath
			If $PATH == $BROWSER_PATH Or $PATH == @ScriptFullPath Then
				If $PATH == $BROWSER_PATH Then
					$OBJSHORTCUT .TargetPath = @ScriptFullPath
					$OBJSHORTCUT .Save
					$TASKBARLASTCHANGE = FileGetTime ( $TASKBARDIR , 0 , 1 )
				EndIf
				$SHORTCUT_APPID = _SHORTCUTAPPID ( $FILE )
				If Not $APPUSERMODELID Then
					If Not $HWND_BROWSER Then
						Sleep ( 3000 )
						$HWND_BROWSER = GETHWNDBYPID ( $APPPID_BROWSER , "Chrome" , "\S+" )
					EndIf
					$APPUSERMODELID = _WINDOWAPPID ( $HWND_BROWSER )
					If Not $APPUSERMODELID Then
						If $SHORTCUT_APPID Then
							$APPUSERMODELID = $SHORTCUT_APPID
						Else
							$APPUSERMODELID = "MyBrowser." & StringTrimLeft ( _WINAPI_HASHSTRING ( @ScriptFullPath , 0 , 16 ) , 2 )
						EndIf
						_WINDOWAPPID ( $HWND_BROWSER , $APPUSERMODELID )
					EndIf
				EndIf
				If $SHORTCUT_APPID <> $APPUSERMODELID Then
					_SHORTCUTAPPID ( $FILE , $APPUSERMODELID )
					$TASKBARLASTCHANGE = FileGetTime ( $TASKBARDIR , 0 , 1 )
				EndIf
				ExitLoop
			EndIf
		WEnd
		$OBJSHORTCUT = ""
		$SHELLOBJ = ""
	EndIf
	FileClose ( $SEARCH )
EndFunc
Func CREATESETTINGSSHORTCUT ( $FNAME )
	Local $VAR = FileRead ( $FNAME )
	If $VAR <> "CreateObject(""shell.application"").ShellExecute "".\" & @ScriptName & """, ""-set""" Then
		FileDelete ( $FNAME )
		FileWrite ( $FNAME , "CreateObject(""shell.application"").ShellExecute "".\" & @ScriptName & """, ""-set""" )
	EndIf
EndFunc
Func CHECKDEFAULTBROWSER ( $BROWSERPATH )
	Local $INTERNETCLIENT , $KEY , $I , $J , $VAR , $REGWRITEERROR = 0
	If Not $CLIENTKEY Then
		If @OSArch = "X86" Then
			Local $AROOT [ 2 ] = [ "HKCU\SOFTWARE" , $HKLM_SOFTWARE_32 ]
		Else
			Local $AROOT [ 3 ] = [ "HKCU\SOFTWARE" , $HKLM_SOFTWARE_32 , $HKLM_SOFTWARE_64 ]
		EndIf
		For $I = 0 To UBound ( $AROOT ) - 1
			$J = 1
			While 1
				$INTERNETCLIENT = RegEnumKey ( $AROOT [ $I ] & "\Clients\StartMenuInternet" , $J )
				If @error <> 0 Then ExitLoop
				$KEY = $AROOT [ $I ] & "\Clients\StartMenuInternet\" & $INTERNETCLIENT
				$VAR = RegRead ( $KEY & "\DefaultIcon" , "" )
				If StringInStr ( $VAR , $BROWSERPATH ) Then
					$CLIENTKEY = $KEY
					$PROGID = RegRead ( $CLIENTKEY & "\Capabilities\URLAssociations" , "http" )
					ExitLoop 2
				EndIf
				$J += 1
			WEnd
		Next
	EndIf
	If $CLIENTKEY Then
		$VAR = RegRead ( $CLIENTKEY & "\shell\open\command" , "" )
		If Not StringInStr ( $VAR , @ScriptFullPath ) Then
			$REGWRITEERROR += Not RegWrite ( $CLIENTKEY & "\shell\open\command" , "" , "REG_SZ" , """" & @ScriptFullPath & """" )
		EndIf
	EndIf
	If Not $PROGID Then
		$PROGID = FINDCHROMEPROGID ( $BROWSERPATH )
	EndIf
	If $PROGID Then
		$VAR = RegRead ( "HKCR\" & $PROGID & "\shell\open\command" , "" )
		If Not StringInStr ( $VAR , @ScriptFullPath ) Then
			RegWrite ( "HKCR\" & $PROGID & "\shell\open\ddeexec" , "" , "REG_SZ" , "" )
			RegDelete ( "HKCR\" & $PROGID & "\shell\open\command" , "DelegateExecute" )
			$REGWRITEERROR += Not RegWrite ( "HKCR\" & $PROGID & "\shell\open\command" , "" , "REG_SZ" , """" & @ScriptFullPath & """ -- ""%1""" )
		EndIf
		If Not $AREG [ 5 ] [ 1 ] Then
			$AREG [ 5 ] [ 1 ] = $PROGID
			$AREG [ 5 ] [ 2 ] = _WINAPI_REGOPENKEY ( $AREG [ 5 ] [ 0 ] , $AREG [ 5 ] [ 1 ] , $KEY_NOTIFY )
		EndIf
	EndIf
	Local $AASSO [ 3 ] = [ "ftp" , "http" , "https" ]
	For $I = 0 To 2
		$VAR = RegRead ( "HKCR\" & $AASSO [ $I ] & "\DefaultIcon" , "" )
		If StringInStr ( $VAR , $BROWSERPATH ) Then
			$VAR = RegRead ( "HKCR\" & $AASSO [ $I ] & "\shell\open\command" , "" )
			If Not StringInStr ( $VAR , @ScriptFullPath ) Then
				RegWrite ( "HKCR\" & $AASSO [ $I ] & "\shell\open\ddeexec" , "" , "REG_SZ" , "" )
				RegDelete ( "HKCR\" & $AASSO [ $I ] & "\shell\open\command" , "DelegateExecute" )
				$REGWRITEERROR += Not RegWrite ( "HKCR\" & $AASSO [ $I ] & "\shell\open\command" , "" , "REG_SZ" , """" & @ScriptFullPath & """ -- ""%1""" )
			EndIf
		EndIf
	Next
	If IsAdmin ( ) Then
		RegRead ( "HKLM64\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe" , "" )
		If Not @error Then
			RegWrite ( "HKLM64\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe" , "" , "REG_SZ" , @ScriptFullPath )
			RegWrite ( "HKLM64\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe" , "Path" , "REG_SZ" , @ScriptDir )
		EndIf
	EndIf
	If $REGWRITEERROR And Not _ISUACADMIN ( ) And @extended Then
		If @Compiled Then
			ShellExecute ( @ScriptName , "-SetDefaultGlobal" , @ScriptDir , "runas" )
		Else
			ShellExecute ( @AutoItExe , """" & @ScriptFullPath & """ -SetDefaultGlobal" , @ScriptDir , "runas" )
		EndIf
	EndIf
EndFunc
Func FINDCHROMEPROGID ( $BROWSERPATH )
	Local $I , $ID , $VAR
	RegRead ( "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts" , "" )
	If @error <> 1 Then
		For $I = 0 To UBound ( $AFILEASSO ) - 1
			$ID = RegRead ( "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\" & $AFILEASSO [ $I ] & "\UserChoice" , "Progid" )
			If $ID Then
				$VAR = RegRead ( "HKCR\" & $ID & "\DefaultIcon" , "" )
				If StringInStr ( $VAR , $BROWSERPATH ) Then
					Return $ID
				EndIf
			EndIf
		Next
	EndIf
	For $I = 0 To UBound ( $AFILEASSO ) - 1
		$ID = RegRead ( "HKCR\" & $AFILEASSO [ $I ] , "" )
		$VAR = RegRead ( "HKCR\" & $ID & "\DefaultIcon" , "" )
		If StringInStr ( $VAR , $BROWSERPATH ) Then
			Return $ID
		EndIf
	Next
	RegRead ( "HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations" , "" )
	If @error <> 1 Then
		For $I = 0 To UBound ( $AURLASSO ) - 1
			$ID = RegRead ( "HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\" & $AURLASSO [ $I ] & "\UserChoice" , "Progid" )
			If $ID Then
				$VAR = RegRead ( "HKCR\" & $ID & "\DefaultIcon" , "" )
				If StringInStr ( $VAR , $BROWSERPATH ) Then
					Return $ID
				EndIf
			EndIf
		Next
	EndIf
	Return ""
EndFunc
Func CHECKAPPUPDATE ( )
	Local $UPDATEINFO , $MATCH , $LATESTAPPVER , $MSG , $UPDATE , $URL , $UPDATED
	Local $FLAG_URL = "url" , $FLAG_UPDATE = "update"
	If @AutoItX64 Then
		$FLAG_URL &= "_x64"
	EndIf
	If $LANGFILE Then
		If StringInStr ( $LANGFILE , "zh-TW.ini" ) Then
			$FLAG_UPDATE &= "_zh-TW"
		Else
			$FLAG_UPDATE &= "_en-US"
		EndIf
	EndIf
	$APPUPDATELASTCHECK = _NOWCALC ( )
	IniWrite ( $INIFILE , "Settings" , "AppUpdateLastCheck" , $APPUPDATELASTCHECK )
	If $PROXYTYPE = "SYSTEM" Then
		HttpSetProxy ( 0 )
	ElseIf $PROXYTYPE = "DIRECT" Or Not $PROXYSEVER Then
		HttpSetProxy ( 1 )
	Else
		HttpSetProxy ( 2 , $PROXYSEVER & ":" & $PROXYPORT )
	EndIf
	$UPDATEINFO = BinaryToString ( InetRead ( "https://raw.githubusercontent.com/drsamonline/MyChrome/master/update.txt" , 27 ) , 4 )
	$UPDATEINFO = StringStripWS ( $UPDATEINFO , 3 )
	$LANGUPDATETIPS = LANG ( "AppUpdate" , "UpdateTips" , "%s 可以更新，是否立即下载？\n\n您的版本： %s，最新版本： %s\n\n%s" )
	$LANGUPDATED = LANG ( "AppUpdate" , "Updated" , "%s 已更新至 %s !" )
	$LANGUPDATEFAILED = LANG ( "AppUpdate" , "UpdateFailed" , "%s 自动更新失败！\n\n是否反馈给熙然？" )
	$MATCH = StringRegExp ( $UPDATEINFO , "(?ism)^\W*latest=(\N+)$.*^\W*" & $FLAG_URL & "=(\N+)$.*^\W*" & $FLAG_UPDATE & "=(\N*)$" , 1 )
	If Not @error Then
		$LATESTAPPVER = $MATCH [ 0 ]
		$URL = $MATCH [ 1 ]
		$UPDATE = StringReplace ( $MATCH [ 2 ] , "\n" , @CRLF )
		If VERSIONCOMPARE ( $LATESTAPPVER , $APPVERSION ) > 0 Then
			If IsHWnd ( $HSETTINGS ) Then
				$MSG = 6
			Else
				$MSG = MsgBox ( 68 , "MyBrowser" , StringFormat ( $LANGUPDATETIPS , "MyBrowser" , $APPVERSION , $LATESTAPPVER , $UPDATE ) )
			EndIf
			If $MSG = 6 Then
				$UPDATED = UPDATEAPP ( @ScriptFullPath , $URL )
				If $UPDATED = 1 Then
					MsgBox ( 64 , "MyBrowser" , StringFormat ( $LANGUPDATED , "MyBrowser" , $LATESTAPPVER ) )
				ElseIf $UPDATED = 0 Then
					$MSG = MsgBox ( 20 , "MyBrowser" , StringFormat ( $LANGUPDATEFAILED , "MyBrowser" ) )
					If $MSG = 6 Then
						OPENWEBSITE ( )
					EndIf
				EndIf
			EndIf
		EndIf
	EndIf
	Return $UPDATED
EndFunc
Func UPDATEAPP ( $EXE = @ScriptFullPath , $URL = "" )
	Local $TEMP = @ScriptDir & "\MyBrowser_temp"
	Local $FILE = $TEMP & "\MyBrowser.7z"
	Local $IBYTESSIZE , $UPDATED = 0
	If Not FileExists ( $TEMP ) Then DirCreate ( $TEMP )
	Local $HDOWNLOAD = InetGet ( $URL , $FILE , 19 , 1 )
	TraySetState ( 1 )
	TraySetClick ( 8 )
	TraySetToolTip ( "MyBrowser" )
	TraySetOnEvent ( $TRAY_EVENT_PRIMARYDOWN , "TrayTipProgress" )
	Local $ICANCEL = TrayCreateItem ( LANG ( "AppUpdate" , "CancelUpdate" , "取消更新" ) & " ..." )
	TrayItemSetOnEvent ( - 1 , "CancelAppUpdate" )
	$LANGDOWNLOADING = LANG ( "AppUpdate" , "Downloading" , "下载" )
	$LANGDOWNLOADTIPS = LANG ( "AppUpdate" , "DownloadTips" , "点击图标可查看下载进度" )
	TrayTip ( "MyBrowser" , StringFormat ( "%s %s ...\n%s" , $LANGDOWNLOADING , "MyBrowser" , $LANGDOWNLOADTIPS ) , 10 , 1 )
	$CANCELAPPUPDATE = False
	Do
		Sleep ( 250 )
		If $CANCELAPPUPDATE Then
			$UPDATED = - 1
			_GUICTRLSTATUSBAR_SETTEXT ( $HSTAUSBAR , "MyBrowser " & LANG ( "AppUpdate" , "UpdateCanceled" , "更新已取消" ) )
			ExitLoop
		EndIf
		$IBYTESSIZE = InetGetInfo ( $HDOWNLOAD , $INET_DOWNLOADREAD ) / 1024
		If IsHWnd ( $HSETTINGS ) Then
			_GUICTRLSTATUSBAR_SETTEXT ( $HSTAUSBAR , StringFormat ( "%s %s ...  %.1fKB" , $LANGDOWNLOADING , "MyBrowser" , $IBYTESSIZE ) )
		EndIf
		If $TRAYTIPPROGRESS Or TRAYTIPEXISTS ( StringFormat ( "%s %s" , $LANGDOWNLOADING , "MyBrowser" ) ) Then
			TrayTip ( "MyBrowser" , StringFormat ( "%s %s ...  %.1fKB" , $LANGDOWNLOADING , "MyBrowser" , $IBYTESSIZE ) , 10 , 1 )
			$TRAYTIPPROGRESS = 0
		EndIf
	Until InetGetInfo ( $HDOWNLOAD , $INET_DOWNLOADCOMPLETE )
	InetClose ( $HDOWNLOAD )
	FileSetAttrib ( $FILE , "+A" )
	If Not $CANCELAPPUPDATE Then
		FileInstall ( "7z.exe" , $TEMP & "\7z.exe" , 1 )
		FileInstall ( "7z.dll" , $TEMP & "\7z.dll" , 1 )
		RunWait ( $TEMP & "\7z.exe x """ & $FILE & """ -y" , $TEMP , @SW_HIDE )
		If FileExists ( $TEMP & "\MyBrowser.exe" ) Then
			If FileExists ( $EXE ) Then
				FileMove ( $EXE , $EXE & ".bak" , 9 )
			EndIf
			FileMove ( $TEMP & "\MyBrowser.exe" , $EXE , 9 )
			FileDelete ( $TEMP & "\7z.exe" )
			FileDelete ( $TEMP & "\7z.dll" )
			FileDelete ( $FILE )
			DirCopy ( $TEMP , @ScriptDir , 1 )
			$UPDATED = 1
		EndIf
	EndIf
	TrayItemDelete ( $ICANCEL )
	TraySetState ( 2 )
	$CANCELAPPUPDATE = False
	DirRemove ( $TEMP , 1 )
	Return $UPDATED
EndFunc
Func CANCELAPPUPDATE ( )
	$CANCELAPPUPDATE = True
EndFunc
Func SETTINGS ( )
	If StringInStr ( IniRead ( $INIFILE , "Settings" , "BrowserType" , "" ) , "Firefox" ) Then
		$DEFAULTPROFDIR = IniRead ( @AppDataDir & "\Mozilla\Firefox\profiles.ini" , "Profile0" , "Path" , "" )
		If $DEFAULTPROFDIR <> "" Then
			$DEFAULTPROFDIR = StringReplace ( $DEFAULTPROFDIR , "/" , "\" )
			$DEFAULTPROFDIR = @AppDataDir & "\Mozilla\Firefox\" & $DEFAULTPROFDIR
		EndIf
	EndIf
	SPLITPATH ( $CHROMEPATH , $CHROMEDIR , $CHROMEEXE )
	Local $LANGINTVNEVER = LANG ( "GUI" , "IntvNever" , "从不" )
	Local $LANGINTVEVERYWEEK = LANG ( "GUI" , "IntvEveryWeek" , "每周" )
	Local $LANGINTVEVERYDAY = LANG ( "GUI" , "IntvEveryDay" , "每天" )
	Local $LANGINTVEVERYHOUR = LANG ( "GUI" , "IntvEveryHour" , "每小时" )
	Local $LANGINTVONSTARTUP = LANG ( "GUI" , "IntvOnStartup" , "每次启动时" )
	Switch $UPDATEINTERVAL
	Case - 1
		$UPDATEINTERVAL = $LANGINTVNEVER
	Case 168
		$UPDATEINTERVAL = $LANGINTVEVERYWEEK
	Case 24
		$UPDATEINTERVAL = $LANGINTVEVERYDAY
	Case 1
		$UPDATEINTERVAL = $LANGINTVEVERYHOUR
Case Else
		$UPDATEINTERVAL = $LANGINTVONSTARTUP
	EndSwitch
	If FileExists ( $CHROMEDIR & "\chrome.dll" ) Then
		$CHROMEFILEVERSION = FileGetVersion ( $CHROMEDIR & "\chrome.dll" , "FileVersion" )
	ElseIf FileExists ( $CHROMEDIR & "\msedge.dll" ) Then
		$CHROMEFILEVERSION = FileGetVersion ( $CHROMEDIR & "\msedge.dll" , "FileVersion" )
	ElseIf FileExists ( $CHROMEDIR & "\firefox.exe" ) Then
		$CHROMEFILEVERSION = FileGetVersion ( $CHROMEDIR & "\firefox.exe" , "FileVersion" )
	ElseIf FileExists ( $CHROMEDIR & "\vivaldi.dll" ) Then
		$CHROMEFILEVERSION = FileGetVersion ( $CHROMEDIR & "\vivaldi.dll" , "FileVersion" )
	Else
	EndIf
	Opt ( "ExpandEnvStrings" , 0 )
	$HSETTINGS = GUICreate ( LANG ( "GUI" , "Title" , "MyBrowser - 熙然" ) , 500 , 530 )
	GUISetOnEvent ( $GUI_EVENT_CLOSE , "ExitApp" )
	Local $LANGCOPYRIGHT = LANG ( "GUI" , "Copyright" , "MyBrowser %s" )
	$LANGCOPYRIGHT = StringFormat ( $LANGCOPYRIGHT , $APPVERSION )
	GUICtrlCreateLabel ( $LANGCOPYRIGHT , 210 , 10 , - 1 , - 1 )
	GUICtrlSetCursor ( - 1 , 0 )
	GUICtrlSetColor ( - 1 , 255 )
	GUICtrlSetTip ( - 1 , LANG ( "GUI" , "About" , "关于" ) )
	GUICtrlSetOnEvent ( - 1 , "OpenWebsite" )
	GUICtrlCreateLabel ( LANG ( "GUI" , "Instructions" , "使用说明" ) , 425 , 10 , - 1 , - 1 )
	GUICtrlSetCursor ( - 1 , 0 )
	GUICtrlSetColor ( - 1 , 255 )
	GUICtrlSetOnEvent ( - 1 , "Instructions" )
	GUICtrlCreateTab ( 5 , 35 , 492 , 430 )
	GUICtrlCreateTabItem ( LANG ( "GUI" , "TabGeneral" , "常规" ) )
	GUICtrlCreateGroup ( LANG ( "GUI" , "GroupChromeApp" , "浏览器程序文件" ) , 10 , 80 , 480 , 190 )
	GUICtrlCreateLabel ( LANG ( "GUI" , "ChromePath" , "浏览器路径：" ) , 20 , 110 , - 1 , 20 )
	$HCHROMEPATH = GUICtrlCreateEdit ( $CHROMEPATH , 100 , 106 , 320 , 20 , $ES_AUTOHSCROLL )
	$HGETCHROMEPATH = GUICtrlCreateButton ( LANG ( "GUI" , "Browse" , "浏览" ) , 430 , 106 , 50 , 20 )
	GUICtrlSetOnEvent ( - 1 , "GUI_GetChromePath" )
	GUICtrlCreateLabel ( LANG ( "GUI" , "ChromeSource" , "浏览器来源：" ) , 20 , 144 , - 1 , 20 )
	$HCHROMESOURCE = GUICtrlCreateCombo ( "" , 100 , 140 , 160 , 20 , $CBS_DROPDOWNLIST )
	$LANGCHROMESOURCESYS = LANG ( "GUI" , "ChromeSourceSys" , "从系统中提取" )
	$LANGCHROMESOURCEINSTALLER = LANG ( "GUI" , "ChromeSourceInstaller" , "从离线安装包提取" )
	If StringInStr ( $PLATFORM , "win" ) Then
		If StringInStr ( $BROWSERTYPE , "Chrome" ) Or StringInStr ( $BROWSERTYPE , "Chromium" ) Then
			If $LANGUAGE = "en-US" Then
				GUICtrlSetData ( - 1 , $GUANFANG & "|" & $LANGCHROMESOURCESYS & "|" & $LANGCHROMESOURCEINSTALLER , "Official" )
			Else
				GUICtrlSetData ( - 1 , $GUANFANG & "|" & $LANGCHROMESOURCESYS & "|" & $LANGCHROMESOURCEINSTALLER , $CHROMESOURCE )
			EndIf
		ElseIf StringInStr ( $BROWSERTYPE , "Firefox" ) Or StringInStr ( $BROWSERTYPE , "Edge" ) Or StringInStr ( $BROWSERTYPE , "Vivaldi" ) Or StringInStr ( $BROWSERTYPE , "Brave" ) Or StringInStr ( $BROWSERTYPE , "Cent" ) Then
			If $LANGUAGE = "en-US" Then
				GUICtrlSetData ( - 1 , $GUANFANG & "|" & $LANGCHROMESOURCEINSTALLER , "Official" )
			Else
				GUICtrlSetData ( - 1 , $GUANFANG & "|" & $LANGCHROMESOURCEINSTALLER , $CHROMESOURCE )
			EndIf
		EndIf
	ElseIf StringInStr ( $PLATFORM , "mac" ) Or StringInStr ( $PLATFORM , "linux" ) Or StringInStr ( $PLATFORM , "android" ) Then
		If $LANGUAGE = "en-US" Then
			GUICtrlSetData ( - 1 , $GUANFANG , "Official" )
		Else
			GUICtrlSetData ( - 1 , $GUANFANG , $GUANFANG )
		EndIf
	EndIf
	GUICtrlSetOnEvent ( - 1 , "GUI_EventChromeSource" )
	GUICtrlCreateLabel ( LANG ( "GUI" , "Channel" , "分支：" ) , 20 , 174 , - 1 , 20 )
	$HPLATFORM = GUICtrlCreateCombo ( "" , 70 , 170 , 70 , 20 , $CBS_DROPDOWNLIST )
	GUICtrlSetData ( - 1 , "win|mac|linux|android" , $PLATFORM )
	GUICtrlSetOnEvent ( - 1 , "GUI_CheckPlatform" )
	$HBROWSERTYPE = GUICtrlCreateCombo ( "" , 145 , 170 , 75 , 20 , $CBS_DROPDOWNLIST )
	GUICtrlSetData ( - 1 , "Chrome|Chromium|Edge|Brave|Firefox|Vivaldi|Cent" , $BROWSERTYPE )
	GUICtrlSetOnEvent ( - 1 , "GUI_CheckBrowserType" )
	$HCHANNEL = GUICtrlCreateCombo ( "" , 225 , 170 , 70 , 20 , $CBS_DROPDOWNLIST )
	GUICtrlSetData ( - 1 , "Stable|Beta|Dev|Canary" , $CHANNEL )
	GUICtrlSetOnEvent ( - 1 , "GUI_CheckChrome" )
	GUICtrlCreateButton ( LANG ( "GUI" , "CreateChromeShortcut" , "创建快捷方式" ) , 360 , 139 , 120 , 22 )
	GUICtrlSetTip ( - 1 , LANG ( "GUI" , "CreateChromeShortcutTip" , "创建当前浏览器的快捷方式到桌面（不支持中文路径）" ) )
	GUICtrlSetOnEvent ( - 1 , "CreateChromeShortcut" )
	GUICtrlCreateLabel ( LANG ( "GUI" , "CheckBrowserWeishu" , "浏览器位数：" ) , 20 , 204 , - 1 , 20 )
	$HX86 = GUICtrlCreateCombo ( "" , 130 , 200 , 130 , 20 , $CBS_DROPDOWNLIST )
	If $X86 = 1 Then
		$BROWSERBIT = "x86"
	ElseIf $X86 = 0 Then
		$BROWSERBIT = "x64"
	EndIf
	GUICtrlSetData ( - 1 , "x86|x64" , $BROWSERBIT )
	If StringInStr ( $BROWSERTYPE , "Vivaldi" ) Or StringInStr ( $BROWSERTYPE , "Cent" ) Then
		GUICtrlSetState ( - 1 , $GUI_DISABLE )
	EndIf
	GUICtrlSetOnEvent ( - 1 , "GUI_Eventx86" )
	GUICtrlCreateLabel ( LANG ( "GUI" , "CheckBrowserUpdate" , "检查浏览器更新：" ) , 20 , 235 , 110 , 20 )
	$HUPDATEINTERVAL = GUICtrlCreateCombo ( "" , 130 , 230 , 130 , 20 , $CBS_DROPDOWNLIST )
	$VAR = StringFormat ( "%s|%s|%s|%s|%s" , $LANGINTVONSTARTUP , $LANGINTVEVERYHOUR , $LANGINTVEVERYDAY , $LANGINTVEVERYWEEK , $LANGINTVNEVER )
	GUICtrlSetData ( - 1 , $VAR , $UPDATEINTERVAL )
	$HCHECKUPDATE = GUICtrlCreateButton ( LANG ( "GUI" , "UpdateNow" , "立即更新" ) , 360 , 169 , 120 , 22 )
	GUICtrlSetOnEvent ( - 1 , "GUI_Start_End_ChromeUpdate" )
	GUICtrlCreateLabel ( LANG ( "GUI" , "LatestVersion" , "最新版本：" ) , 280 , 204 , 100 , 20 )
	$HLATESTCHROMEVER = GUICtrlCreateLabel ( "" , 380 , 204 , 90 , 20 )
	GUICtrlSetTip ( - 1 , LANG ( "GUI" , "ClickToViewUrl" , "点击查看下载地址" ) )
	GUICtrlSetCursor ( - 1 , 0 )
	GUICtrlSetColor ( - 1 , 255 )
	GUICtrlSetOnEvent ( - 1 , "GUI_ShowUrl" )
	GUICtrlCreateLabel ( LANG ( "GUI" , "CurrentVersion" , "当前版本：" ) , 280 , 235 , 100 , 20 )
	$HCURRENTVER = GUICtrlCreateLabel ( "" , 380 , 235 , 90 , 20 )
	GUICtrlSetData ( - 1 , $CHROMEFILEVERSION )
	GUICtrlCreateGroup ( LANG ( "GUI" , "ChromeUserData" , "浏览器用户数据文件" ) , 10 , 290 , 480 , 80 )
	GUICtrlCreateLabel ( LANG ( "GUI" , "UserDataDir" , "用户数据文件夹：" ) , 20 , 320 , 110 , 20 )
	$HUSERDATADIR = GUICtrlCreateEdit ( $USERDATADIR , 130 , 315 , 290 , 20 , $ES_AUTOHSCROLL )
	GUICtrlCreateButton ( LANG ( "GUI" , "Browse" , "浏览" ) , 430 , 315 , 50 , 20 )
	GUICtrlSetOnEvent ( - 1 , "GUI_GetUserDataDir" )
	$HCOPYDATA = GUICtrlCreateCheckbox ( LANG ( "GUI" , "CopyDataFromeSys" , "从系统中提取用户数据文件" ) , 20 , 340 , - 1 , 20 )
	If Not $LANGFILE Then
		$LANGSTR = "显示语言："
	Else
		$LANGSTR = "Language: "
	EndIf
	GUICtrlCreateLabel ( $LANGSTR , 20 , 390 , 110 , 20 )
	$HLANGUAGE = GUICtrlCreateCombo ( "" , 130 , 386 , 130 , 20 , $CBS_DROPDOWNLIST )
	If $LANGUAGE = "zh-CN" Then
		$SLANG = "简体中文"
	ElseIf $LANGUAGE = "zh-TW" Then
		$SLANG = "繁體中文"
	ElseIf $LANGUAGE = "en-US" Then
		$SLANG = "English"
	Else
		$SLANG = "Auto"
	EndIf
	GUICtrlSetData ( - 1 , "Auto|简体中文|繁體中文|English" , $SLANG )
	GUICtrlSetOnEvent ( - 1 , "GUI_LanguageEvent" )
	GUICtrlCreateLabel ( LANG ( "GUI" , "LangSupport" , "语言支持：" ) , 280 , 390 , 110 , 20 )
	GUICtrlCreateLabel ( IniRead ( $LANGFILE , "Lang" , "LangSupport" , "" ) , 390 , 390 , 100 , 40 )
	GUICtrlSetCursor ( - 1 , 0 )
	GUICtrlSetColor ( - 1 , 255 )
	GUICtrlSetOnEvent ( - 1 , "GUI_LangSupport" )
	$HAPPUPDATE = GUICtrlCreateCheckbox ( LANG ( "GUI" , "NotifyMyBrowserUpdate" , "MyBrowser 发布新版时通知我" ) , 20 , 415 , - 1 , 20 )
	GUICtrlSetTip ( - 1 , LANG ( "GUI" , "NotifyMyBrowserUpdateTips" , "每24小时检查更新一次" ) )
	If $APPUPDATE = 1 Then
		GUICtrlSetState ( $HAPPUPDATE , $GUI_CHECKED )
	EndIf
	$HRUNINBACKGROUND = GUICtrlCreateCheckbox ( LANG ( "GUI" , "MyBrowserRunInBackground" , "MyBrowser 在后台运行直至浏览器退出" ) , 20 , 440 , - 1 , 20 )
	GUICtrlSetOnEvent ( - 1 , "GUI_RunInBackground" )
	If $RUNINBACKGROUND = 1 Then
		GUICtrlSetState ( $HRUNINBACKGROUND , $GUI_CHECKED )
	EndIf
	GUICtrlCreateTabItem ( LANG ( "GUI" , "TabAdvanced" , "高级" ) )
	GUICtrlCreateGroup ( LANG ( "GUI" , "ChromeCache" , "浏览器缓存" ) , 10 , 70 , 480 , 90 )
	GUICtrlCreateLabel ( LANG ( "GUI" , "PluginsDir" , "插件目录(Firefox)：" ) , 20 , 90 , 150 , 20 )
	$HPLUGINSDIR = GUICtrlCreateEdit ( $PLUGINSDIR , 130 , 85 , 290 , 20 , $ES_AUTOHSCROLL )
	GUICtrlSetTip ( - 1 , LANG ( "GUI" , "PluginsDirTip" , "浏览器插件目录" ) & @CRLF & LANG ( "GUI" , "DefaultDir" , "空白=默认位置" ) )
	$HGETPLUGINSDIR = GUICtrlCreateButton ( LANG ( "GUI" , "Browse" , "浏览" ) , 430 , 85 , 50 , 20 )
	GUICtrlSetTip ( - 1 , LANG ( "GUI" , "PluginsDirToTip" , "指定浏览器插件目录" ) )
	GUICtrlSetOnEvent ( - 1 , "GetPluginsDir" )
	GUICtrlCreateLabel ( LANG ( "GUI" , "CacheDir" , "缓存位置：" ) , 20 , 115 , 150 , 20 )
	$HCACHEDIR = GUICtrlCreateEdit ( $CACHEDIR , 130 , 110 , 290 , 20 , $ES_AUTOHSCROLL )
	Local $LANGCACHETIPS = LANG ( "GUI" , "ChromeCacheTips" , "浏览器缓存位置\n空白 = 默认路径\n支持%TEMP%等环境变量" )
	GUICtrlSetTip ( - 1 , StringFormat ( $LANGCACHETIPS , 0 ) )
	$HSELECTCACHEDIR = GUICtrlCreateButton ( LANG ( "GUI" , "Browse" , "浏览" ) , 430 , 110 , 50 , 20 )
	GUICtrlSetOnEvent ( - 1 , "GUI_SelectCacheDir" )
	GUICtrlCreateLabel ( LANG ( "GUI" , "CacheSize" , "缓存大小：" ) , 20 , 140 , 150 , 20 )
	$HCACHESIZE = GUICtrlCreateEdit ( Round ( $CACHESIZE / 1024 / 1024 ) , 130 , 136 , 70 , 20 , $ES_AUTOHSCROLL )
	Local $LANGCACHESIZETIPS = LANG ( "GUI" , "ChromeCacheSizeTips" , "缓存大小\n0 = 默认" )
	GUICtrlSetTip ( - 1 , StringFormat ( $LANGCACHESIZETIPS , 0 ) )
	GUICtrlCreateLabel ( " MB" , 200 , 140 , 35 , 20 )
	$HCACHESIZESMART = GUICtrlCreateCheckbox ( LANG ( "GUI" , "AutoCacheSize" , " 自动控制缓存大小(Firefox)" ) , 230 , 135 , - 1 , 20 )
	If $CACHESIZESMART Then GUICtrlSetState ( - 1 , $GUI_CHECKED )
	GUICtrlCreateLabel ( LANG ( "GUI" , "CommandLine" , "浏览器启动参数：" ) , 20 , 180 )
	Local $LPARAMS = StringReplace ( $PARAMS , " --" , Chr ( 13 ) & Chr ( 10 ) & "--" )
	$HPARAMS = GUICtrlCreateEdit ( $LPARAMS , 20 , 200 , 460 , 60 , BitOR ( $ES_WANTRETURN , $WS_VSCROLL , $ES_AUTOVSCROLL ) )
	Local $LANGCOMMANDLINETIPS = LANG ( "GUI" , "CommandLineTips" , "Chrome 启动参数，每行写一个参数。\n支持%TEMP%等环境变量，\n特别地，%APP%代表 MyBrowser 所在目录。" )
	GUICtrlSetTip ( - 1 , StringFormat ( $LANGCOMMANDLINETIPS , 0 ) )
	GUICtrlCreateGroup ( LANG ( "GUI" , "NetworkSettings" , "网络设置" ) , 10 , 280 , 480 , 115 )
	GUICtrlCreateLabel ( LANG ( "GUI" , "ThreadsNum" , "下载线程数(1-10)：" ) , 20 , 310 , 130 , 20 )
	$HDOWNLOADTHREADS = GUICtrlCreateInput ( $DOWNLOADTHREADS , 150 , 306 , 60 , 20 , $ES_NUMBER )
	Local $LANGTHREADSTIPS = LANG ( "GUI" , "ThreadsTips" , "增减线程数可调节下载速度\n仅适用于下载chrome更新" )
	GUICtrlSetTip ( - 1 , StringFormat ( $LANGTHREADSTIPS , 0 ) )
	GUICtrlSetOnEvent ( - 1 , "GUI_CheckThreadsNum" )
	GUICtrlCreateUpdown ( $HDOWNLOADTHREADS )
	GUICtrlSetLimit ( - 1 , 10 , 1 )
	GUICtrlCreateLabel ( LANG ( "GUI" , "ProxyType" , "代理类型：" ) , 20 , 340 , 130 , 20 )
	$HPROXYTYPE = GUICtrlCreateCombo ( "" , 150 , 336 , 120 , 20 , $CBS_DROPDOWNLIST )
	GUICtrlSetOnEvent ( - 1 , "GUI_SetProxy" )
	Local $LANGPROXYDIRECT = LANG ( "GUI" , "ProxyDirect" , "直接连接" )
	Local $LANGPROXYIE = LANG ( "GUI" , "ProxyIE" , "跟随系统" )
	If $PROXYTYPE = "DIRECT" Then
		$SPROXYTYPE = $LANGPROXYDIRECT
	ElseIf $PROXYTYPE = "SYSTEM" Then
		$SPROXYTYPE = $LANGPROXYIE
	Else
		$SPROXYTYPE = "HTTP"
	EndIf
	GUICtrlSetData ( - 1 , $LANGPROXYDIRECT & "|" & $LANGPROXYIE & "|HTTP" , $SPROXYTYPE )
	GUICtrlCreateLabel ( LANG ( "GUI" , "ProxyServer" , "代理服务器：" ) , 20 , 370 , 130 , 20 )
	$HPROXYSEVER = GUICtrlCreateCombo ( "" , 150 , 366 , 120 , 20 )
	GUICtrlSetData ( - 1 , "127.0.0.1" )
	_GUICTRLCOMBOBOX_SETEDITTEXT ( $HPROXYSEVER , $PROXYSEVER )
	GUICtrlCreateLabel ( LANG ( "GUI" , "ProxyPort" , "代理端口：" ) , 290 , 370 , 80 , 20 )
	$HPROXYPORT = GUICtrlCreateCombo ( "" , 370 , 366 , 80 , 20 )
	GUICtrlSetData ( - 1 , "1080|10808|4411" )
	_GUICTRLCOMBOBOX_SETEDITTEXT ( $HPROXYPORT , $PROXYPORT )
	GUI_SETPROXY ( )
	GUICtrlCreateGroup ( LANG ( "GUI" , "chromium" , "Chromium设置" ) , 10 , 405 , 480 , 45 )
	GUICtrlCreateButton ( LANG ( "GUI" , "setapion" , "导入GoogleAPI" ) , 20 , 422 , 140 , 22 )
	GUICtrlSetOnEvent ( - 1 , "GUI_setapion" )
	GUICtrlSetTip ( - 1 , LANG ( "GUI" , "setapionTips" , "导入GoogleAPI密钥Chromium才能登录谷歌账号" ) )
	GUICtrlCreateButton ( LANG ( "GUI" , "setapino" , "清除GoogleAPI提示" ) , 180 , 422 , 140 , 22 )
	GUICtrlSetOnEvent ( - 1 , "GUI_setapino" )
	GUICtrlSetTip ( - 1 , LANG ( "GUI" , "setapinoTips" , "不导入GoogleAPI密钥只清除缺少GoogleAPI密钥提示" ) )
	GUICtrlCreateButton ( LANG ( "GUI" , "setapioff" , "清除GoogleAPI" ) , 340 , 422 , 140 , 22 )
	GUICtrlSetOnEvent ( - 1 , "GUI_setapioff" )
	GUICtrlSetTip ( - 1 , LANG ( "GUI" , "setapioffTips" , "缺少GoogleAPI密钥会导致Chromium不能登录谷歌账号" ) )
	GUICtrlCreateTabItem ( LANG ( "GUI" , "FuZhu" , "辅助" ) )
	GUICtrlCreateLabel ( LANG ( "GUI" , "StartWithChrome" , "浏览器启动时运行：" ) , 20 , 80 , - 1 , 20 )
	$HEXAPPAUTOEXIT = GUICtrlCreateCheckbox ( LANG ( "GUI" , "QuitOnChromeExit" , " 浏览器退出后自动关闭*" ) , 240 , 75 , - 1 , 20 )
	If $EXAPPAUTOEXIT = 1 Then
		GUICtrlSetState ( $HEXAPPAUTOEXIT , $GUI_CHECKED )
	EndIf
	$HEXAPP = GUICtrlCreateEdit ( "" , 20 , 100 , 410 , 50 , BitOR ( $ES_WANTRETURN , $WS_VSCROLL , $ES_AUTOVSCROLL ) )
	If $EXAPP <> "" Then
		GUICtrlSetData ( - 1 , StringReplace ( $EXAPP , "||" , @CRLF ) & @CRLF )
	EndIf
	Local $LANGEXAPPSTIPS = LANG ( "GUI" , "ExAppsTips" , "支持批处理、vbs文件等，\n如需启动参数，可添加在程序路径之后。" )
	GUICtrlSetTip ( - 1 , StringFormat ( $LANGEXAPPSTIPS , 0 ) )
	GUICtrlCreateButton ( LANG ( "GUI" , "AddApp" , "添加" ) , 440 , 100 , 40 , 20 )
	GUICtrlSetTip ( - 1 , LANG ( "GUI" , "AddAppTips" , "添加外部程序" ) )
	GUICtrlSetOnEvent ( - 1 , "GUI_AddExApp" )
	GUICtrlCreateLabel ( LANG ( "GUI" , "RunOnChromeExit" , "浏览器退出后运行*：" ) , 20 , 170 , - 1 , 20 )
	$HEXAPP2 = GUICtrlCreateEdit ( "" , 20 , 190 , 410 , 50 , BitOR ( $ES_WANTRETURN , $WS_VSCROLL , $ES_AUTOVSCROLL ) )
	If $EXAPP2 <> "" Then
		GUICtrlSetData ( - 1 , StringReplace ( $EXAPP2 , "||" , @CRLF ) & @CRLF )
	EndIf
	Local $LANGEXAPPS2TIPS = LANG ( "GUI" , "ExApps2Tips" , "支持批处理、vbs文件等，\n如需启动参数，可添加在程序路径之后。" )
	GUICtrlSetTip ( - 1 , StringFormat ( $LANGEXAPPS2TIPS , 0 ) )
	GUICtrlCreateButton ( LANG ( "GUI" , "AddApp" , "添加" ) , 440 , 190 , 40 , 20 )
	GUICtrlSetTip ( - 1 , LANG ( "GUI" , "AddAppTips" , "添加外部程序" ) )
	GUICtrlSetOnEvent ( - 1 , "GUI_AddExApp2" )
	GUICtrlCreateGroup ( LANG ( "GUI" , "Bosskey" , "老板键*" ) , 10 , 250 , 480 , 90 )
	GUICtrlCreateLabel ( LANG ( "GUI" , "Hotkey" , "键盘：" ) , 20 , 280 , 110 , 20 )
	$HBOSSKEY = GUICtrlCreateInput ( "" , 130 , 276 , 140 , 20 )
	Local $KEY = StringRegExpReplace ( $BOSSKEY , "[!+#^]+" , "" )
	Local $KEY1
	If $KEY Then
		If StringInStr ( $BOSSKEY , "+" ) Then
			$KEY1 &= " + Shift"
		EndIf
		If StringInStr ( $BOSSKEY , "^" ) Then
			$KEY1 &= " + Ctrl"
		EndIf
		If StringInStr ( $BOSSKEY , "!" ) Then
			$KEY1 &= " + Alt"
		EndIf
		If StringInStr ( $BOSSKEY , "#" ) Then
			$KEY1 &= " + Win"
		EndIf
		If Not $KEY1 Then
			$KEY1 = "Ctrl"
		Else
			$KEY1 = StringTrimLeft ( $KEY1 , 3 )
		EndIf
		$KEY = $KEY1 & " + " & $KEY
		GUICtrlSetData ( $HBOSSKEY , $KEY )
	EndIf
	Local $MBUTTON = LANG ( "GUI" , "MiddleButton" , "中键" )
	Local $RBUTTON = LANG ( "GUI" , "RightButton" , "右键" )
	Local $DBCLICK = LANG ( "GUI" , "DoubleClick" , "双击" )
	Local $DRAGDROP = LANG ( "GUI" , "DragDrop" , "拖拽" )
	$HBOSSKEYM = GUICtrlCreateCheckbox ( LANG ( "GUI" , "MouseClick" , "鼠标：" ) , 20 , 306 , 110 , 20 )
	GUICtrlSetOnEvent ( - 1 , "Gui_EventMouseClick" )
	$HBOSSKEYM1 = GUICtrlCreateCombo ( "" , 130 , 306 , 140 , 20 , $CBS_DROPDOWNLIST )
	$HBOSSKEYM2 = GUICtrlCreateCombo ( "" , 290 , 306 , 140 , 20 , $CBS_DROPDOWNLIST )
	Local $BUTTON , $ACT
	If $BOSSKEYM = $AU3_MDCLICK Or $BOSSKEYM = $AU3_MDROP Then
		$BUTTON = $MBUTTON
	Else
		$BUTTON = $RBUTTON
	EndIf
	If $BOSSKEYM = $AU3_RDROP Or $BOSSKEYM = $AU3_MDROP Then
		$ACT = $DRAGDROP
	Else
		$ACT = $DBCLICK
	EndIf
	GUICtrlSetData ( $HBOSSKEYM1 , $MBUTTON & "|" & $RBUTTON , $BUTTON )
	GUICtrlSetData ( $HBOSSKEYM2 , $DBCLICK & "|" & $DRAGDROP , $ACT )
	If $BOSSKEYM Then
		GUICtrlSetState ( $HBOSSKEYM , $GUI_CHECKED )
	Else
		GUICtrlSetState ( $HBOSSKEYM1 , $GUI_DISABLE )
		GUICtrlSetState ( $HBOSSKEYM2 , $GUI_DISABLE )
	EndIf
	$DICKEYS = CREATEKEYSDIC ( )
	$HFUNCHOTKEY = DllCallbackRegister ( "GUI_EventHotkey" , "lresult" , "hwnd;uint;wparam;lparam" )
	$HWNDPROC = _WINAPI_SETWINDOWLONG ( GUICtrlGetHandle ( $HBOSSKEY ) , $GWL_WNDPROC , DllCallbackGetPtr ( $HFUNCHOTKEY ) )
	$HHIDE2TRAY = GUICtrlCreateCheckbox ( LANG ( "GUI" , "Hide2Tray" , " 隐藏到系统托盘" ) , 290 , 276 , - 1 , 20 )
	If $HIDE2TRAY Then
		GUICtrlSetState ( $HHIDE2TRAY , $GUI_CHECKED )
	EndIf
	GUICtrlCreateGroup ( LANG ( "GUI" , "Tab" , "标签页*" ) , 10 , 346 , 480 , 110 )
	$HHOOKBOX = GUICtrlCreateCheckbox ( LANG ( "GUI" , "HookBox" , "启用Hook" ) , 20 , 366 , - 1 , 20 )
	GUICtrlSetOnEvent ( - 1 , "Gui_HookBox" )
	GUICtrlSetTip ( - 1 , StringFormat ( LANG ( "GUI" , "HookBoxTip" , "1.hook.dll能实现""双击关闭标签页""、""右键关闭标签页""、""滚轮切换标签页""、""保留最后一个标签页""和""老板键""功能，\n前四个功能对72及以上版本chrome核浏览器无效\n2.""双击关闭标签页""、""右键关闭标签页""、""滚轮切换标签页""的设置同时对TabPlus和Hook生效" ) ) )
	$HTABPLUS = GUICtrlCreateCheckbox ( LANG ( "GUI" , "TabPlus" , "启用TabPlus" ) , 240 , 366 , - 1 , 20 )
	GUICtrlSetOnEvent ( - 1 , "Gui_TabPlus" )
	GUICtrlSetTip ( - 1 , StringFormat ( LANG ( "GUI" , "TabPlusTip" , "1.TabPlus能实现""双击关闭标签页""、""右键关闭标签页""、""滚轮切换标签页""功能\n2.""双击关闭标签页""、""右键关闭标签页""、""滚轮切换标签页""的设置同时对TabPlus和Hook生效" ) ) )
	$HDOUBLECLICK2CLOSETAB = GUICtrlCreateCheckbox ( LANG ( "GUI" , "DoubleClick2CloseTab" , "双击关闭标签页" ) , 20 , 396 , - 1 , 20 )
	GUICtrlSetTip ( - 1 , StringFormat ( LANG ( "GUI" , "DoubleClick2CloseTabTips" , "和WGesture、StrokesPlus等有冲突" ) ) )
	$HRIGHTCLICK2CLOSETAB = GUICtrlCreateCheckbox ( LANG ( "GUI" , "RightClick2CloseTab" , "右键关闭标签页" ) , 20 , 426 , - 1 , 20 )
	GUICtrlSetTip ( - 1 , StringFormat ( LANG ( "GUI" , "RightClick2CloseTabTips" , "Shift+右键或1+右键可显示右键菜单" ) ) )
	$HMOUSE2SWITCHTAB = GUICtrlCreateCheckbox ( LANG ( "GUI" , "Mouse2SwitchTab" , "滚轮切换标签页" ) , 240 , 396 , - 1 , 20 )
	$HKEEPLASTTAB = GUICtrlCreateCheckbox ( LANG ( "GUI" , "KeepLastTab" , "保留最后一个标签页" ) , 240 , 426 , - 1 , 20 )
	GUICtrlSetTip ( - 1 , LANG ( "GUI" , "KeepLastTabTips" , "对Chromium核72及以上版本无效" ) )
	If StringInStr ( $MOUSECLICK2CLOSETAB , $AU3_LDCLICK ) Then
		GUICtrlSetState ( $HDOUBLECLICK2CLOSETAB , $GUI_CHECKED )
	EndIf
	If StringInStr ( $MOUSECLICK2CLOSETAB , $AU3_RCLICK ) Then
		GUICtrlSetState ( $HRIGHTCLICK2CLOSETAB , $GUI_CHECKED )
	EndIf
	If StringInStr ( $MOUSE2SWITCHTAB , $AU3_WHEELDOWN ) Then
		GUICtrlSetState ( $HMOUSE2SWITCHTAB , $GUI_CHECKED )
	EndIf
	If $KEEPLASTTAB = 1 Then
		GUICtrlSetState ( $HKEEPLASTTAB , $GUI_CHECKED )
	Else
		GUICtrlSetState ( $HKEEPLASTTAB , $GUI_UNCHECKED )
	EndIf
	If $TABPLUS = 1 Then
		GUICtrlSetState ( $HTABPLUS , $GUI_CHECKED )
	Else
		GUICtrlSetState ( $HTABPLUS , $GUI_UNCHECKED )
	EndIf
	If $HOOKBOX = 1 Then
		GUICtrlSetState ( $HHOOKBOX , $GUI_CHECKED )
	Else
		GUICtrlSetState ( $HKEEPLASTTAB , $GUI_DISABLE )
		GUICtrlSetState ( $HBOSSKEYM , $GUI_DISABLE )
		GUICtrlSetState ( $HBOSSKEYM1 , $GUI_DISABLE )
		GUICtrlSetState ( $HBOSSKEYM2 , $GUI_DISABLE )
	EndIf
	If $TABPLUS = 0 And $HOOKBOX = 0 Then
		GUICtrlSetState ( $HDOUBLECLICK2CLOSETAB , $GUI_DISABLE )
		GUICtrlSetState ( $HRIGHTCLICK2CLOSETAB , $GUI_DISABLE )
		GUICtrlSetState ( $HMOUSE2SWITCHTAB , $GUI_DISABLE )
		GUICtrlSetState ( $HKEEPLASTTAB , $GUI_DISABLE )
	EndIf
	If GUICtrlRead ( $HDOUBLECLICK2CLOSETAB ) = $GUI_CHECKED Then $MOUSECLICK2CLOSETAB2 = "Check"
	If GUICtrlRead ( $HDOUBLECLICK2CLOSETAB ) = $GUI_UNCHECKED Then $MOUSECLICK2CLOSETAB2 = "unCheck"
	If GUICtrlRead ( $HRIGHTCLICK2CLOSETAB ) = $GUI_CHECKED Then $RIGHTCLICK2CLOSETAB2 = "Check"
	If GUICtrlRead ( $HRIGHTCLICK2CLOSETAB ) = $GUI_UNCHECKED Then $RIGHTCLICK2CLOSETAB2 = "unCheck"
	If GUICtrlRead ( $HMOUSE2SWITCHTAB ) = $GUI_CHECKED Then $MOUSE2SWITCHTAB2 = "Check"
	If GUICtrlRead ( $HMOUSE2SWITCHTAB ) = $GUI_UNCHECKED Then $MOUSE2SWITCHTAB2 = "unCheck"
	GUICtrlCreateTabItem ( LANG ( "GUI" , "kuozhan" , "扩展" ) )
	GUICtrlCreateGroup ( LANG ( "GUI" , "MouseInc" , "MouseInc鼠标手势" ) , 10 , 130 , 480 , 50 )
	$AMOUSEINC = GUICtrlCreateCheckbox ( LANG ( "GUI" , "MouseIncA" , "MouseInc鼠标手势" ) , 50 , 150 , - 1 , 20 )
	GUICtrlSetOnEvent ( - 1 , "Gui_EventMouseInc" )
	GUICtrlSetTip ( - 1 , LANG ( "GUI" , "MouseIncATips" , "和[右键关闭标签页]有冲突但不影响使用" ) )
	$BMOUSEINC = GUICtrlCreateCheckbox ( LANG ( "GUI" , "MouseIncB" , "MouseInc随浏览器关闭" ) , 300 , 150 , - 1 , 20 )
	GUICtrlSetOnEvent ( - 1 , "Gui_EventMouseInc" )
	GUICtrlSetTip ( - 1 , LANG ( "GUI" , "MouseIncBTips" , "需重启浏览器或MyBrowser才生效" ) )
	If $MOUSEINCA = 1 Then
		GUICtrlSetState ( $AMOUSEINC , $GUI_CHECKED )
		If $MOUSEINCB = 1 Then
			GUICtrlSetState ( $BMOUSEINC , $GUI_CHECKED )
		Else
			GUICtrlSetState ( $BMOUSEINC , $GUI_UNCHECKED )
		EndIf
	Else
		GUICtrlSetState ( $AMOUSEINC , $GUI_UNCHECKED )
		GUICtrlSetState ( $BMOUSEINC , $GUI_DISABLE )
	EndIf
	GUICtrlCreateGroup ( LANG ( "GUI" , "GreenChrome" , "GreenChrome设置" ) , 10 , 70 , 480 , 50 )
	$SETGC = GUICtrlCreateButton ( LANG ( "GUI" , "setgcon" , "注入GreenChrome" ) , 20 , 90 , 140 , 20 )
	GUICtrlSetOnEvent ( - 1 , "GUI_setgc" )
	GUICtrlSetTip ( - 1 , LANG ( "GUI" , "setgconTips" , "释放并注入GreenChrome" ) )
	$GCSETTING = GUICtrlCreateButton ( LANG ( "GUI" , "gcsetting" , "配置GreenChrome" ) , 180 , 90 , 140 , 20 )
	GUICtrlSetOnEvent ( - 1 , "GUI_gcsetting" )
	GUICtrlSetTip ( - 1 , LANG ( "GUI" , "gcsettingTips" , "打开GreenChrome配置文件" ) )
	$GCAUTOSET = GUICtrlCreateCheckbox ( LANG ( "GUI" , "AutoSet" , "自动注入" ) , 340 , 90 , 140 , 20 )
	GUICtrlSetOnEvent ( - 1 , "GUI_GCAutoSet" )
	GUICtrlSetTip ( - 1 , LANG ( "GUI" , "AutoSetTips" , "浏览器更新后自动注入" ) )
	If $GREENCHROME = 1 Then
		GUICtrlSetData ( $SETGC , LANG ( "GUI" , "setgcoff" , "解除GreenChrome" ) )
		GUICtrlSetTip ( $SETGC , LANG ( "GUI" , "setgcoffTips" , "解除并删除GreenChrome" ) )
		GUICtrlSetState ( $SETCPP , $GUI_DISABLE )
	Else
		GUICtrlSetState ( $GCSETTING , $GUI_DISABLE )
	EndIf
	If $GREENCHROMEAUTO = 1 Then
		GUICtrlSetState ( $GCAUTOSET , $GUI_CHECKED )
	EndIf
	If $CHROMEPLUSPLUS = 1 Then
		GUICtrlSetData ( $SETCPP , LANG ( "GUI" , "setcppoff" , "解除Chrome++" ) )
		GUICtrlSetTip ( $SETCPP , LANG ( "GUI" , "setcppoffTips" , "解除并删除Chrome++" ) )
		GUICtrlSetState ( $SETGC , $GUI_DISABLE )
	Else
		GUICtrlSetState ( $CPPSETTINGTIPS , $GUI_DISABLE )
	EndIf
	If $CHROMEPLUSPLUSAUTO = 1 Then
		GUICtrlSetState ( $CPPAUTOSET , $GUI_CHECKED )
		GUICtrlSetState ( $GCAUTOSET , $GUI_DISABLE )
	EndIf
	GUICtrlCreateTabItem ( "" )
	$HPROGRESS1 = GUICtrlCreateProgress ( 0 , 504 , 500 , 5 )
	$HSETTINGSOK = GUICtrlCreateButton ( LANG ( "GUI" , "OK" , "确定" ) , 260 , 471 , 70 , 25 )
	GUICtrlSetOnEvent ( - 1 , "GUI_SettingsOK" )
	If ( ( StringInStr ( $BROWSERTYPE , "Firefox" ) And Not FileExists ( $CHROMEDIR & "\firefox.exe" ) ) Or ( StringInStr ( $BROWSERTYPE , "Vivaldi" ) And Not FileExists ( $CHROMEDIR & "\vivaldi.exe" ) ) Or ( StringInStr ( $BROWSERTYPE , "Cent" ) And Not FileExists ( $CHROMEDIR & "\chrome.exe" ) ) ) Then
		GUICtrlSetState ( - 1 , $GUI_DISABLE )
	Else
		GUICtrlSetState ( - 1 , $GUI_FOCUS )
	EndIf
	GUICtrlCreateButton ( LANG ( "GUI" , "Cancel" , "取消" ) , 340 , 471 , 70 , 25 )
	GUICtrlSetOnEvent ( - 1 , "ExitApp" )
	$HSETTINGSAPPLY = GUICtrlCreateButton ( LANG ( "GUI" , "Apply" , "应用" ) , 420 , 471 , 70 , 25 )
	GUICtrlSetOnEvent ( - 1 , "GUI_SettingsApply" )
	$LANGSETTINGSTIPS = StringFormat ( LANG ( "GUI" , "SettingsTips" , "双击软件目录下的 ""%s.vbs"" 文件可显示此窗口" ) , $APPNAME )
	$HSTAUSBAR = _GUICTRLSTATUSBAR_CREATE ( $HSETTINGS , - 1 , $LANGSETTINGSTIPS )
	Opt ( "ExpandEnvStrings" , 1 )
	FileChangeDir ( @ScriptDir )
	If StringInStr ( IniRead ( $INIFILE , "Settings" , "BrowserType" , "" ) , "Firefox" ) Then
		If FileExists ( $DEFAULTPROFDIR ) Then
			GUICtrlSetState ( $HCOPYDATA , $GUI_ENABLE )
			If $FIRSTRUN And Not FileExists ( $USERDATADIR & "\prefs.js" ) Then GUICtrlSetState ( $HCOPYDATA , $GUI_CHECKED )
		Else
			GUICtrlSetState ( $HCOPYDATA , $GUI_DISABLE )
		EndIf
	Else
		If Not FileExists ( FULLPATH ( $USERDATADIR ) & "\Local State" ) And FileExists ( $DEFAULTUSERDATADIR & "\Local State" ) Then
			GUICtrlSetState ( $HCOPYDATA , $GUI_CHECKED )
		EndIf
	EndIf
	GUISetState ( @SW_SHOW )
	If $PLATFORM = "mac" Then
		GUICtrlSetData ( $HBROWSERTYPE , "|Chrome|Chromium|Firefox" , $BROWSERTYPE )
		If $BROWSERTYPE = "Chrome" Then
			GUICtrlSetData ( $HCHANNEL , "|Stable|Beta|Dev|Canary" , $CHANNEL )
		ElseIf $BROWSERTYPE = "Chromium" Or $BROWSERTYPE = "Firefox" Then
			GUICtrlSetData ( $HCHANNEL , "" )
			GUICtrlSetState ( $HCHANNEL , $GUI_DISABLE )
		EndIf
		GUICtrlSetState ( $HX86 , $GUI_DISABLE )
		GUICtrlSetState ( $HCHECKUPDATE , $GUI_DISABLE )
	ElseIf $PLATFORM = "linux" Then
		GUICtrlSetData ( $HBROWSERTYPE , "|Chromium|Firefox" , $BROWSERTYPE )
		If $BROWSERTYPE = "Chromium" Or $BROWSERTYPE = "Firefox" Then
			GUICtrlSetData ( $HCHANNEL , "" )
			GUICtrlSetState ( $HCHANNEL , $GUI_DISABLE )
		EndIf
		GUICtrlSetState ( $HCHECKUPDATE , $GUI_DISABLE )
	ElseIf $PLATFORM = "android" Then
		GUICtrlSetData ( $HBROWSERTYPE , "|Chromium" , $BROWSERTYPE )
		GUICtrlSetState ( $HX86 , $GUI_DISABLE )
		GUICtrlSetData ( $HCHANNEL , "" )
		GUICtrlSetState ( $HCHANNEL , $GUI_DISABLE )
		GUICtrlSetState ( $HCHECKUPDATE , $GUI_DISABLE )
	ElseIf $PLATFORM = "win" Then
		If $BROWSERTYPE = "Chromium" Or $BROWSERTYPE = "Vivaldi" Or $BROWSERTYPE = "Cent" Then
			GUICtrlSetData ( $HCHANNEL , "" )
			GUICtrlSetState ( $HCHANNEL , $GUI_DISABLE )
		ElseIf $BROWSERTYPE = "Brave" Then
			GUICtrlSetData ( $HCHANNEL , "|Release|Beta|Dev|Nightly" , $CHANNEL )
		ElseIf $BROWSERTYPE = "Firefox" Then
			GUICtrlSetData ( $HCHANNEL , "|Release|ESR|Beta|Dev|Nightly" , $CHANNEL )
		EndIf
	EndIf
	AdlibRegister ( "GUI_ShowLatestChromeVer" , 1000 )
	While Not $SETTINGSOK
		Sleep ( 100 )
	WEnd
	GUIDelete ( $HSETTINGS )
	DllCallbackFree ( $HFUNCHOTKEY )
	$DICKEYS = ""
	$HSETTINGS = ""
EndFunc
Func GUI_EVENTMOUSECLICK ( )
	If GUICtrlRead ( $HBOSSKEYM ) = $GUI_CHECKED Then
		GUICtrlSetState ( $HBOSSKEYM1 , $GUI_ENABLE )
		GUICtrlSetState ( $HBOSSKEYM2 , $GUI_ENABLE )
	Else
		GUICtrlSetState ( $HBOSSKEYM1 , $GUI_DISABLE )
		GUICtrlSetState ( $HBOSSKEYM2 , $GUI_DISABLE )
	EndIf
EndFunc
Func GUI_EVENTMOUSEINC ( )
	If GUICtrlRead ( $AMOUSEINC ) = $GUI_CHECKED Then
		GUICtrlSetState ( $BMOUSEINC , $GUI_ENABLE )
		$MOUSEINCA = IniWrite ( $INIFILE , "Settings" , "MouseIncA" , 1 )
	Else
		GUICtrlSetState ( $BMOUSEINC , $GUI_DISABLE )
		$MOUSEINCA = IniWrite ( $INIFILE , "Settings" , "MouseIncA" , 0 )
	EndIf
	If GUICtrlRead ( $BMOUSEINC ) = $GUI_CHECKED Then
		$MOUSEINCB = IniWrite ( $INIFILE , "Settings" , "MouseIncB" , 1 )
	Else
		$MOUSEINCB = IniWrite ( $INIFILE , "Settings" , "MouseIncB" , 0 )
	EndIf
EndFunc
Func GUI_HOOKBOX ( )
	If GUICtrlRead ( $HHOOKBOX ) = $GUI_CHECKED Then
		GUICtrlSetState ( $HKEEPLASTTAB , $GUI_ENABLE )
		GUICtrlSetState ( $HBOSSKEYM , $GUI_ENABLE )
		GUICtrlSetState ( $HBOSSKEYM1 , $GUI_ENABLE )
		GUICtrlSetState ( $HBOSSKEYM2 , $GUI_ENABLE )
		GUICtrlSetState ( $HDOUBLECLICK2CLOSETAB , $GUI_ENABLE )
		GUICtrlSetState ( $HRIGHTCLICK2CLOSETAB , $GUI_ENABLE )
		GUICtrlSetState ( $HMOUSE2SWITCHTAB , $GUI_ENABLE )
		Return
	EndIf
	$LANGHOOKBOX = LANG ( "GUI" , "HookBoxTips" , "说明：\n\n1. hook.dll能实现""双击关闭标签页""、""右键关闭标签页""、""滚轮切换标签页""、""保留最后一个标签页""和""老板键""功能，前四个功能对72及以上版本chrome核浏览器无效；\n2.""双击关闭标签页""、""右键关闭标签页""、""滚轮切换标签页""的设置同时对TabPlus和Hook生效。\n\n确定要取消此选项吗？" )
	$MSG = MsgBox ( 36 + 256 , "MyBrowser" , StringFormat ( $LANGHOOKBOX , 0 ) , 0 , $HSETTINGS )
	If $MSG = 6 Then
		GUICtrlSetState ( $HKEEPLASTTAB , $GUI_DISABLE )
		GUICtrlSetState ( $HBOSSKEYM , $GUI_DISABLE )
		GUICtrlSetState ( $HBOSSKEYM1 , $GUI_DISABLE )
		GUICtrlSetState ( $HBOSSKEYM2 , $GUI_DISABLE )
		If GUICtrlRead ( $HTABPLUS ) = $GUI_UNCHECKED Then
			GUICtrlSetState ( $HDOUBLECLICK2CLOSETAB , $GUI_DISABLE )
			GUICtrlSetState ( $HRIGHTCLICK2CLOSETAB , $GUI_DISABLE )
			GUICtrlSetState ( $HMOUSE2SWITCHTAB , $GUI_DISABLE )
		EndIf
	Else
		GUICtrlSetState ( $HHOOKBOX , $GUI_CHECKED )
	EndIf
EndFunc
Func GUI_TABPLUS ( )
	If GUICtrlRead ( $HTABPLUS ) = $GUI_CHECKED Then
		GUICtrlSetState ( $HDOUBLECLICK2CLOSETAB , $GUI_ENABLE )
		GUICtrlSetState ( $HRIGHTCLICK2CLOSETAB , $GUI_ENABLE )
		GUICtrlSetState ( $HMOUSE2SWITCHTAB , $GUI_ENABLE )
		Return
	EndIf
	$LANGTABPLUS = LANG ( "GUI" , "TabPlusTips" , "说明：\n\n1. TabPlus能实现""双击关闭标签页""、""右键关闭标签页""、""滚轮切换标签页""功能；\n2.""双击关闭标签页""、""右键关闭标签页""、""滚轮切换标签页""的设置同时对TabPlus和Hook生效。\n\n确定要取消此选项吗？" )
	$MSG = MsgBox ( 36 + 256 , "MyBrowser" , StringFormat ( $LANGTABPLUS , 0 ) , 0 , $HSETTINGS )
	If $MSG = 6 Then
		If GUICtrlRead ( $HHOOKBOX ) = $GUI_UNCHECKED Then
			GUICtrlSetState ( $HDOUBLECLICK2CLOSETAB , $GUI_DISABLE )
			GUICtrlSetState ( $HRIGHTCLICK2CLOSETAB , $GUI_DISABLE )
			GUICtrlSetState ( $HMOUSE2SWITCHTAB , $GUI_DISABLE )
		EndIf
	Else
		GUICtrlSetState ( $HTABPLUS , $GUI_CHECKED )
	EndIf
EndFunc
Func GUI_SETGC ( )
	$CHROMEPATH = $CHROMEDIR & "\" & $CHROMEEXE
	If FileExists ( $CHROMEPATH ) Then
		$GREENCHROMEDLL = $CHROMEDIR & "\GreenChrome.dll"
		$GREENCHROMEINI = $CHROMEDIR & "\GreenChrome.ini"
		$SETDLL = $CHROMEDIR & "\setdll.exe"
		If GUICtrlRead ( $SETGC ) = StringFormat ( LANG ( "GUI" , "setgcon" , "注入GreenChrome" ) ) Then
			If _WINAPI_GETBINARYTYPE ( $CHROMEPATH ) Then
				Switch @extended
				Case $SCS_32BIT_BINARY
					If FileExists ( $GREENCHROMEDLL ) Then FileDelete ( $GREENCHROMEDLL )
					FileInstall ( "GreenChrome.dll" , $GREENCHROMEDLL , 1 )
					If Not FileExists ( $SETDLL ) Then FileInstall ( "setdll.exe" , $SETDLL , 1 )
				Case $SCS_64BIT_BINARY
					If FileExists ( $GREENCHROMEDLL ) Then FileDelete ( $GREENCHROMEDLL )
					FileInstall ( "GreenChrome64.dll" , $GREENCHROMEDLL , 1 )
					If Not FileExists ( $SETDLL ) Then FileInstall ( "setdll64.exe" , $SETDLL , 1 )
			Case Else
					MsgBox ( 64 , "MyBrowser" , """" & $CHROMEPATH & """" & $WUXIAOAPP & $PLEASECHECK , 0 , $HSETTINGS )
					Return
				EndSwitch
			Else
				MsgBox ( 64 , "MyBrowser" , """" & $CHROMEPATH & """" & $WUXIAOAPP & $PLEASECHECK , 0 , $HSETTINGS )
				Return
			EndIf
			If Not FileExists ( $GREENCHROMEINI ) Then FileInstall ( "GreenChrome.ini" , $GREENCHROMEINI , 1 )
			$CMD = "cd /d """ & $CHROMEDIR & """ && setdll /d:GreenChrome.dll " & $CHROMEEXE
			Run ( @ComSpec & " /c " & $CMD , "" , @SW_HIDE )
			Sleep ( 1000 )
			If FileExists ( $CHROMEDIR & "\" & $CHROMEEXE & "~" ) Then
				If ProcessExists ( """" & $CHROMEEXE & """" ) Then
					MsgBox ( 0 , "MyBrowser" , $INJECTGC1 , 0 , $HSETTINGS )
				Else
					MsgBox ( 0 , "MyBrowser" , $INJECTGC2 , 0 , $HSETTINGS )
				EndIf
				FileDelete ( $CHROMEDIR & "\" & $CHROMEEXE & "~" )
				IniWrite ( $INIFILE , "Settings" , "GreenChrome" , 1 )
				GUICtrlSetData ( $SETGC , LANG ( "GUI" , "setgcoff" , "解除GreenChrome" ) )
				GUICtrlSetTip ( $SETGC , LANG ( "GUI" , "setgcoffTips" , "解除并删除GreenChrome" ) )
				GUICtrlSetState ( $GCSETTING , $GUI_ENABLE )
				GUICtrlSetState ( $SETCPP , $GUI_DISABLE )
				GUICtrlSetState ( $CPPAUTOSET , $GUI_UNCHECKED )
				If GUICtrlRead ( $GCAUTOSET ) = $GUI_CHECKED Then
					GUICtrlSetState ( $CPPAUTOSET , $GUI_DISABLE )
				EndIf
			EndIf
			If FileExists ( $CHROMEDIR & "\" & $CHROMEEXE & "#" ) Then
				If Not ProcessExists ( """" & $CHROMEEXE & """" ) Then FileDelete ( $CHROMEDIR & "\" & $CHROMEEXE & "#" )
				FileDelete ( $GREENCHROMEDLL )
				FileDelete ( $GREENCHROMEINI )
				MsgBox ( 64 , "MyBrowser" , $INJECTGC3 , 0 , $HSETTINGS )
			EndIf
			FileDelete ( $SETDLL )
		ElseIf GUICtrlRead ( $SETGC ) = StringFormat ( LANG ( "GUI" , "setgcoff" , "解除GreenChrome" ) ) Then
			If _WINAPI_GETBINARYTYPE ( $CHROMEPATH ) Then
				Switch @extended
				Case $SCS_32BIT_BINARY
					If Not FileExists ( $SETDLL ) Then FileInstall ( "setdll.exe" , $SETDLL , 1 )
				Case $SCS_64BIT_BINARY
					If Not FileExists ( $SETDLL ) Then FileInstall ( "setdll64.exe" , $SETDLL , 1 )
			Case Else
					MsgBox ( 64 , "MyBrowser" , """" & $CHROMEPATH & """" & $WUXIAOAPP & $PLEASECHECK , 0 , $HSETTINGS )
					Return
				EndSwitch
			Else
				MsgBox ( 64 , "MyBrowser" , """" & $CHROMEPATH & """" & $WUXIAOAPP & $PLEASECHECK , 0 , $HSETTINGS )
				Return
			EndIf
			If Not FileExists ( $GREENCHROMEDLL ) Then
				MsgBox ( 64 , "MyBrowser" , $NOTFOUND & """" & $GREENCHROMEDLL & """" & $PLEASECHECK , 0 , $HSETTINGS )
				Return
			EndIf
			$CMD = "cd /d """ & $CHROMEDIR & """ && setdll /r " & $CHROMEEXE
			Run ( @ComSpec & " /c " & $CMD , "" , @SW_HIDE )
			Sleep ( 1000 )
			If FileExists ( $CHROMEDIR & "\" & $CHROMEEXE & "~" ) Then
				If ProcessExists ( """" & $CHROMEEXE & """" ) Then
					MsgBox ( 0 , "MyBrowser" , $REMOVEGC1 , 0 , $HSETTINGS )
				Else
					MsgBox ( 0 , "MyBrowser" , $REMOVEGC2 , 0 , $HSETTINGS )
				EndIf
				FileDelete ( $CHROMEDIR & "\" & $CHROMEEXE & "~" )
				FileDelete ( $GREENCHROMEDLL )
				If FileExists ( $GREENCHROMEINI ) Then FileDelete ( $GREENCHROMEINI )
				IniWrite ( $INIFILE , "Settings" , "GreenChrome" , 0 )
				GUICtrlSetData ( $SETGC , LANG ( "GUI" , "setgcon" , "注入GreenChrome" ) )
				GUICtrlSetTip ( $SETGC , LANG ( "GUI" , "setgconTips" , "释放并注入GreenChrome" ) )
				GUICtrlSetState ( $GCSETTING , $GUI_DISABLE )
				GUICtrlSetState ( $SETCPP , $GUI_ENABLE )
				GUICtrlSetState ( $CPPAUTOSET , $GUI_ENABLE )
			EndIf
			If FileExists ( $CHROMEDIR & "\" & $CHROMEEXE & "#" ) Then
				If Not ProcessExists ( """" & $CHROMEEXE & """" ) Then FileDelete ( $CHROMEDIR & "\" & $CHROMEEXE & "#" )
				MsgBox ( 64 , "MyBrowser" , $REMOVEGC3 , 0 , $HSETTINGS )
			EndIf
			FileDelete ( $SETDLL )
		EndIf
	Else
		$MSG = MsgBox ( 64 + 4 , "MyBrowser" , $NOTFOUND & """" & $CHROMEPATH & """" & $PLEASEDOWNLOAD , 0 , $HSETTINGS )
		If $MSG = 6 Then
			GUI_START_END_CHROMEUPDATE ( )
		EndIf
	EndIf
EndFunc
Func GUI_GCSETTING ( )
	If FileExists ( $CHROMEPATH ) Then
		If _WINAPI_GETBINARYTYPE ( $CHROMEPATH ) Then
			Switch @extended
			Case $SCS_32BIT_BINARY , $SCS_64BIT_BINARY
		Case Else
				MsgBox ( 64 , "MyBrowser" , """" & $CHROMEPATH & """" & $WUXIAOAPP & $PLEASECHECK , 0 , $HSETTINGS )
				Return
			EndSwitch
		Else
			MsgBox ( 64 , "MyBrowser" , """" & $CHROMEPATH & """" & $WUXIAOAPP & $PLEASECHECK , 0 , $HSETTINGS )
			Return
		EndIf
		$GREENCHROMEDLL = $CHROMEDIR & "\GreenChrome.dll"
		$GREENCHROMEINI = $CHROMEDIR & "\GreenChrome.ini"
		If FileExists ( $GREENCHROMEDLL ) Then
			If Not FileExists ( $GREENCHROMEINI ) Then
				MsgBox ( 64 , "MyBrowser" , $NOTFOUND & """" & $GREENCHROMEINI & """" & $PLEASECHECK , 0 , $HSETTINGS )
				Return
			EndIf
		Else
			If FileExists ( $GREENCHROMEINI ) Then
				MsgBox ( 64 , "MyBrowser" , $NOTFOUND & """" & $GREENCHROMEDLL & """" & $PLEASECHECK , 0 , $HSETTINGS )
			Else
				MsgBox ( 64 , "MyBrowser" , $NOTFOUND & """" & $GREENCHROMEDLL & """" & $AND & """" & $GREENCHROMEINI & """" & $PLEASECHECK , 0 , $HSETTINGS )
			EndIf
			Return
		EndIf
		$CMD = "cd /d """ & $CHROMEDIR & """ && GreenChrome.ini"
		Run ( @ComSpec & " /c " & $CMD , "" , @SW_HIDE )
	Else
		$MSG = MsgBox ( 64 + 4 , "MyBrowser" , $NOTFOUND & """" & $CHROMEPATH & """" & $PLEASEDOWNLOAD , 0 , $HSETTINGS )
		If $MSG = 6 Then
			GUI_START_END_CHROMEUPDATE ( )
		EndIf
	EndIf
EndFunc
Func GUI_GCAUTOSET ( )
	If GUICtrlRead ( $GCAUTOSET ) = $GUI_CHECKED Then
		IniWrite ( $INIFILE , "Settings" , "GreenChromeAuto" , 1 )
	ElseIf GUICtrlRead ( $GCAUTOSET ) = $GUI_UNCHECKED Then
		IniWrite ( $INIFILE , "Settings" , "GreenChromeAuto" , 0 )
	EndIf
EndFunc
Func GUI_SETAPION ( )
	; The upstream build shipped a Google API key, OAuth client id and client secret
	; as literals and wrote them into the user environment with setx. Redistributing
	; someone else's credential is not something this fork does.
	MsgBox ( 0 , "MyBrowser" , LANG ( "GUI" , "GoogleApiRemoved" , "此版本不内置 Google API 密钥。如需使用，请自行设置环境变量 GOOGLE_API_KEY、GOOGLE_DEFAULT_CLIENT_ID 与 GOOGLE_DEFAULT_CLIENT_SECRET。" ) , 0 , $HSETTINGS )
EndFunc
Func GUI_SETAPINO ( )
	_RUNDOS ( "setx GOOGLE_API_KEY no" & "&setx GOOGLE_DEFAULT_CLIENT_ID no" & "&setx GOOGLE_DEFAULT_CLIENT_SECRET no" )
	MsgBox ( 0 , "MyBrowser" , LANG ( "GUI" , "qingchutishi" , "清除GoogleAPI密钥提示成功" ) , 0 , $HSETTINGS )
EndFunc
Func GUI_SETAPIOFF ( )
	_RUNDOS ( "wmic ENVIRONMENT where " & """" & "name='GOOGLE_API_KEY'" & """" & " delete" & "&wmic ENVIRONMENT where " & """" & "name='GOOGLE_DEFAULT_CLIENT_ID'" & """" & " delete" & "&wmic ENVIRONMENT where " & """" & "name='GOOGLE_DEFAULT_CLIENT_SECRET'" & """" & " delete" )
	MsgBox ( 0 , "MyBrowser" , LANG ( "GUI" , "qingchutishi" , "清除GoogleAPI密钥成功" ) , 0 , $HSETTINGS )
EndFunc
Func GUI_EVENTHOTKEY ( $HWND , $IMSG , $IWPARAM , $ILPARAM )
	Switch $IMSG
	Case $WM_CHAR , $WM_SYSCHAR , $WM_KEYDOWN , $WM_SYSKEYDOWN
		If $IWPARAM <> 16 And $IWPARAM <> 17 And $IWPARAM <> 18 And $IWPARAM <> 91 And $IWPARAM <> 92 Then
			If $IWPARAM = 8 Or $IWPARAM = 46 Then
				$KEY = ""
			Else
				$KEY = _WINAPI_GETKEYNAMETEXT ( $ILPARAM )
				If StringLen ( $KEY ) <= 1 Then
					$KEY = StringLower ( $KEY )
				Else
					If StringInStr ( $KEY , " " ) Then
						If $DICKEYS .Exists ( $KEY ) Then
							$KEY = $DICKEYS .Item ( $KEY )
						Else
							$KEY = StringReplace ( $KEY , " " , "" )
						EndIf
					EndIf
					$KEY = "{" & $KEY & "}"
				EndIf
				Local $K
				If _ISPRESSED ( "10" ) Then
					$K &= " + Shift"
				EndIf
				If _ISPRESSED ( "11" ) Then
					$K &= " + Ctrl"
				EndIf
				If _ISPRESSED ( "12" ) Then
					$K &= " + Alt"
				EndIf
				If _ISPRESSED ( "5B" ) Or _ISPRESSED ( "5C" ) Then
					$K &= " + Win"
				EndIf
				If Not $K Then
					$K = "Ctrl"
				Else
					$K = StringTrimLeft ( $K , 3 )
				EndIf
				$KEY = $K & " + " & $KEY
			EndIf
			GUICtrlSetData ( $HBOSSKEY , $KEY )
		EndIf
		Return
	EndSwitch
	Return _WINAPI_CALLWINDOWPROC ( $HWNDPROC , $HWND , $IMSG , $IWPARAM , $ILPARAM )
EndFunc
Func CREATEKEYSDIC ( )
	Local $ODIC = ObjCreate ( "Scripting.Dictionary" )
	$ODIC .Add ( "Page Up" , "PGUP" )
	$ODIC .Add ( "Page Down" , "PGDN" )
	$ODIC .Add ( "Num Lock" , "NUMLOCK" )
	$ODIC .Add ( "Caps Lock" , "CAPSLOCK" )
	$ODIC .Add ( "Scroll Lock" , "SCROLLLOCK" )
	$ODIC .Add ( "Num 0" , "NUMPAD0" )
	$ODIC .Add ( "Num 1" , "NUMPAD1" )
	$ODIC .Add ( "Num 2" , "NUMPAD2" )
	$ODIC .Add ( "Num 3" , "NUMPAD3" )
	$ODIC .Add ( "Num 4" , "NUMPAD4" )
	$ODIC .Add ( "Num 5" , "NUMPAD5" )
	$ODIC .Add ( "Num 6" , "NUMPAD6" )
	$ODIC .Add ( "Num 7" , "NUMPAD7" )
	$ODIC .Add ( "Num 8" , "NUMPAD8" )
	$ODIC .Add ( "Num 9" , "NUMPAD9" )
	$ODIC .Add ( "Num *" , "NUMPADMULT" )
	$ODIC .Add ( "Num +" , "NUMPADADD" )
	$ODIC .Add ( "Num -" , "NUMPADSUB" )
	$ODIC .Add ( "Num /" , "NUMPADDIV" )
	Return $ODIC
EndFunc
Func GUI_LANGSUPPORT ( )
	Local $LINK = IniRead ( $LANGFILE , "Lang" , "LangLink" , "" )
	If $LINK Then
		If StringLeft ( $LINK , 4 ) = "http" Then
			ShellExecute ( $LINK )
		Else
			MsgBox ( 64 , "MyBrowser" , $LINK )
		EndIf
	EndIf
EndFunc
Func GUI_LANGUAGEEVENT ( )
	GUI_SAVELANG ( )
	If $LANGUAGE = "zh-CN" Then
		$LANGSTR = "语言设置将在重启 MyBrowser 后生效！"
	ElseIf $LANGUAGE = "zh-TW" Then
		$LANGSTR = "語言設置將在重啟 MyBrowser 後生效！"
	Else
		$LANGSTR = "MyBrowser will restart to apply new language!"
	EndIf
	MsgBox ( 64 , "MyBrowser" , $LANGSTR )
	If $ISUPDATING Then Return
	GUIDelete ( $HSETTINGS )
	If @Compiled Then
		ShellExecute ( @ScriptName , "-Set" , @ScriptDir )
	Else
		ShellExecute ( @AutoItExe , """" & @ScriptFullPath & """ -Set" , @ScriptDir )
	EndIf
	Exit
EndFunc
Func GUI_SAVELANG ( )
	$SLANG = GUICtrlRead ( $HLANGUAGE )
	If $SLANG = "简体中文" Then
		$LANGUAGE = "zh-CN"
	ElseIf $SLANG = "繁體中文" Then
		$LANGUAGE = "zh-TW"
	ElseIf $SLANG = "English" Then
		$LANGUAGE = "en-US"
	Else
		$LANGUAGE = "Auto"
	EndIf
	IniWrite ( $INIFILE , "Settings" , "Language" , $LANGUAGE )
EndFunc
Func GUI_SETPROXY ( )
	Local $LANGPROXYDIRECT = LANG ( "GUI" , "ProxyDirect" , "直接连接" )
	Local $LANGPROXYIE = LANG ( "GUI" , "ProxyIE" , "跟随系统" )
	Local $PTYPE = GUICtrlRead ( $HPROXYTYPE )
	If $PTYPE = $LANGPROXYDIRECT Then
		$PROXYTYPE = "DIRECT"
	ElseIf $PTYPE = $LANGPROXYIE Then
		$PROXYTYPE = "SYSTEM"
	Else
		$PROXYTYPE = "HTTP"
	EndIf
	If $PROXYTYPE = "HTTP" Then
		GUICtrlSetState ( $HPROXYSEVER , $GUI_ENABLE )
		GUICtrlSetState ( $HPROXYPORT , $GUI_ENABLE )
		$PROXYSEVER = GUICtrlRead ( $HPROXYSEVER )
		$PROXYPORT = GUICtrlRead ( $HPROXYPORT )
	Else
		GUICtrlSetState ( $HPROXYSEVER , $GUI_DISABLE )
		GUICtrlSetState ( $HPROXYPORT , $GUI_DISABLE )
		If $PROXYTYPE = "SYSTEM" Then
			GETIEPROXY ( $PROXYSEVER , $PROXYPORT )
			_GUICTRLCOMBOBOX_SETEDITTEXT ( $HPROXYSEVER , $PROXYSEVER )
			_GUICTRLCOMBOBOX_SETEDITTEXT ( $HPROXYPORT , $PROXYPORT )
		EndIf
	EndIf
EndFunc
Func GUI_EVENTX86 ( )
	If GUICtrlRead ( $HX86 ) = "x86" Then
		$X86 = 1
	ElseIf GUICtrlRead ( $HX86 ) = "x64" Then
		$X86 = 0
	EndIf
	IniWrite ( $INIFILE , "Settings" , "x86" , $X86 )
	AdlibRegister ( "GUI_ShowLatestChromeVer" , 1000 )
EndFunc
Func GUI_ADDEXAPP ( )
	Local $PATH
	$PATH = FileOpenDialog ( LANG ( "GUI" , "ChooseExApp" , "选择外部程序" ) , @ScriptDir , "All files (*.*)" , 1 + 2 , "" , $HSETTINGS )
	If $PATH = "" Then Return
	$PATH = RELATIVEPATH ( $PATH )
	$EXAPP = GUICtrlRead ( $HEXAPP ) & $PATH & @CRLF
	GUICtrlSetData ( $HEXAPP , $EXAPP )
EndFunc
Func GUI_ADDEXAPP2 ( )
	Local $PATH
	$PATH = FileOpenDialog ( LANG ( "GUI" , "ChooseExApp" , "选择外部程序" ) , @ScriptDir , "All files (*.*)" , 1 + 2 , "" , $HSETTINGS )
	If $PATH = "" Then Return
	$PATH = RELATIVEPATH ( $PATH )
	$EXAPP2 = GUICtrlRead ( $HEXAPP2 ) & $PATH & @CRLF
	GUICtrlSetData ( $HEXAPP2 , $EXAPP2 )
EndFunc
Func GUI_RUNINBACKGROUND ( )
	If GUICtrlRead ( $HRUNINBACKGROUND ) = $GUI_CHECKED Then
		Return
	EndIf
	$LANGRUNBACKGROUNDTIPS = LANG ( "GUI" , "RunBackgroundTips" , "如果您不勾选该选项，请注意以下几点：\n\n1. 将浏览器锁定到任务栏或设为默认浏览器后，需再运行一次 MyBrowser 才能生效；\n2. MyBrowser 设置界面中带“*”符号的功能将无法实现。\n\n确定要取消此选项吗？" )
	$MSG = MsgBox ( 36 + 256 , "MyBrowser" , StringFormat ( $LANGRUNBACKGROUNDTIPS , 0 ) , 0 , $HSETTINGS )
	If $MSG <> 6 Then
		GUICtrlSetState ( $HRUNINBACKGROUND , $GUI_CHECKED )
	EndIf
EndFunc
Func GUI_GETCHROMEPATH ( )
	$SCHROMEPATH = FileOpenDialog ( LANG ( "GUI" , "ChooseChromeExe" , "选择浏览器主程序" ) , @ScriptDir , "Executable files (*.exe)|All files (*.*)" , 2 , "" , $HSETTINGS )
	If $SCHROMEPATH = "" Then Return
	Local $CHROMEDLL
	SPLITPATH ( $SCHROMEPATH , $CHROMEDIR , $CHROMEEXE )
	If FileExists ( $CHROMEDIR & "\chrome.dll" ) Then
		$CHROMEDLL = StringRegExpReplace ( $SCHROMEPATH , "[^\\]+$" , "chrome.dll" )
	ElseIf FileExists ( $CHROMEDIR & "\msedge.dll" ) Then
		$CHROMEDLL = StringRegExpReplace ( $SCHROMEPATH , "[^\\]+$" , "msedge.dll" )
	ElseIf FileExists ( $CHROMEDIR & "\vivaldi.dll" ) Then
		$CHROMEDLL = StringRegExpReplace ( $SCHROMEPATH , "[^\\]+$" , "vivaldi.dll" )
	ElseIf FileExists ( $CHROMEDIR & "\firefox.exe" ) Then
		$CHROMEDLL = StringRegExpReplace ( $SCHROMEPATH , "[^\\]+$" , "firefox.exe" )
	EndIf
	$CHROMEFILEVERSION = FileGetVersion ( $CHROMEDLL , "FileVersion" )
	GUICtrlSetData ( $HCURRENTVER , $CHROMEFILEVERSION )
	$CHROMEPATH = RELATIVEPATH ( $SCHROMEPATH )
	GUICtrlSetData ( $HCHROMEPATH , $CHROMEPATH )
EndFunc
Func GUI_GETUSERDATADIR ( )
	Local $SUSERDATADIR = FileSelectFolder ( LANG ( "GUI" , "ChooseDataDir" , "选择一个文件夹用来保存用户数据文件" ) , "" , 1 + 4 , @ScriptDir & "\Data" , $HSETTINGS )
	If $SUSERDATADIR <> "" Then
		$USERDATADIR = RELATIVEPATH ( $SUSERDATADIR )
		GUICtrlSetData ( $HUSERDATADIR , $USERDATADIR )
	EndIf
EndFunc
Func GUI_COPYCHROMEFROMSYSTEM ( )
	$CHROMEPATH = GUICtrlRead ( $HCHROMEPATH )
	SPLITPATH ( $CHROMEPATH , $CHROMEDIR , $CHROMEEXE )
	$LANGCLOSECHROMETIPS = LANG ( "GUI" , "CloseChromeTips" , "请关闭浏览器以便完成更新。\n是否强制关闭？" )
	$CHROMEISRUNNING = CHROMEISRUNNING ( $CHROMEPATH , StringFormat ( $LANGCLOSECHROMETIPS , 0 ) )
	If $CHROMEISRUNNING Then Return
	$LANGCOPYCHROMEFROMSYS = LANG ( "GUI" , "CopyChromeFromSys" , "正在复制浏览器程序文件..." )
	_GUICTRLSTATUSBAR_SETTEXT ( $HSTAUSBAR , $LANGCOPYCHROMEFROMSYS )
	SplashTextOn ( "MyBrowser" , $LANGCOPYCHROMEFROMSYS , 300 , 100 )
	FileCopy ( $DEFAULTCHROMEDIR & "\*.*" , $CHROMEDIR & "\" , 1 + 8 )
	DirCopy ( $DEFAULTCHROMEDIR & "\" & $DEFAULTCHROMEVER , $CHROMEDIR , 1 )
	SplashOff ( )
	If StringInStr ( $BROWSERTYPE , "Edge" ) Then
		Local $CHROMEDLL = StringRegExpReplace ( $CHROMEPATH , "[^\\]+$" , "msedge.dll" )
	ElseIf StringInStr ( $BROWSERTYPE , "Firefox" ) Then
		Local $CHROMEDLL = StringRegExpReplace ( $CHROMEPATH , "[^\\]+$" , "Firefox.exe" )
	ElseIf StringInStr ( $BROWSERTYPE , "Vivaldi" ) Then
		Local $CHROMEDLL = StringRegExpReplace ( $CHROMEPATH , "[^\\]+$" , "vivaldi.dll" )
	Else
		Local $CHROMEDLL = StringRegExpReplace ( $CHROMEPATH , "[^\\]+$" , "chrome.dll" )
	EndIf
	$CHROMEFILEVERSION = FileGetVersion ( $CHROMEDLL , "FileVersion" )
	GUICtrlSetData ( $HCURRENTVER , $CHROMEFILEVERSION )
	_GUICTRLSTATUSBAR_SETTEXT ( $HSTAUSBAR , LANG ( "GUI" , "CopyChromeSuccessful" , "提取浏览器程序文件成功！" ) )
EndFunc
Func GUI_SETTINGSOK ( )
	GUI_SETTINGSAPPLY ( )
	If $PLATFORM = "mac" Or $PLATFORM = "linux" Or $PLATFORM = "android" Then Return
	If @error Or $ISUPDATING Then Return
	If ProcessExists ( $ITHREADPID ) Then
		ProcessClose ( $ITHREADPID )
	EndIf
	$SETTINGSOK = 1
EndFunc
Func GUI_SETTINGSAPPLY ( )
	SPLITPATH ( $CHROMEPATH , $CHROMEDIR , $CHROMEEXE )
	Local $MSG , $VAR
	FileChangeDir ( @ScriptDir )
	Opt ( "ExpandEnvStrings" , 0 )
	$CHROMEPATH = RELATIVEPATH ( GUICtrlRead ( $HCHROMEPATH ) )
	Local $LANGINTVNEVER = LANG ( "GUI" , "IntvNever" , "从不" )
	Local $LANGINTVEVERYWEEK = LANG ( "GUI" , "IntvEveryWeek" , "每周" )
	Local $LANGINTVEVERYDAY = LANG ( "GUI" , "IntvEveryDay" , "每天" )
	Local $LANGINTVEVERYHOUR = LANG ( "GUI" , "IntvEveryHour" , "每小时" )
	Local $LANGINTVONSTARTUP = LANG ( "GUI" , "IntvOnStartup" , "每次启动时" )
	Switch GUICtrlRead ( $HUPDATEINTERVAL )
	Case $LANGINTVNEVER
		$UPDATEINTERVAL = - 1
	Case $LANGINTVEVERYWEEK
		$UPDATEINTERVAL = 168
	Case $LANGINTVEVERYDAY
		$UPDATEINTERVAL = 24
	Case $LANGINTVEVERYHOUR
		$UPDATEINTERVAL = 1
Case Else
		$UPDATEINTERVAL = 0
	EndSwitch
	$PLATFORM = GUICtrlRead ( $HPLATFORM )
	$BROWSERTYPE = GUICtrlRead ( $HBROWSERTYPE )
	$CHANNEL = GUICtrlRead ( $HCHANNEL )
	If GUICtrlRead ( $HX86 ) = "x86" Then
		$X86 = 1
	ElseIf GUICtrlRead ( $HX86 ) = "x64" Then
		$X86 = 0
	EndIf
	$CHROMESOURCE = GUICtrlRead ( $HCHROMESOURCE )
	$USERDATADIR = RELATIVEPATH ( GUICtrlRead ( $HUSERDATADIR ) )
	$PLUGINSDIR = RELATIVEPATH ( GUICtrlRead ( $HPLUGINSDIR ) )
	Local $COPYDATA = GUICtrlRead ( $HCOPYDATA )
	If GUICtrlRead ( $HAPPUPDATE ) = $GUI_CHECKED Then
		$APPUPDATE = 1
	Else
		$APPUPDATE = 0
	EndIf
	If GUICtrlRead ( $HRUNINBACKGROUND ) = $GUI_CHECKED Then
		$RUNINBACKGROUND = 1
	Else
		$RUNINBACKGROUND = 0
	EndIf
	$CACHEDIR = GUICtrlRead ( $HCACHEDIR )
	If $CACHEDIR <> "" Then
		$CACHEDIR = RELATIVEPATH ( $CACHEDIR )
	EndIf
	$CACHESIZE = GUICtrlRead ( $HCACHESIZE ) * 1024 * 1024
	If GUICtrlRead ( $HCACHESIZESMART ) = $GUI_CHECKED Then
		$CACHESIZESMART = 1
	Else
		$CACHESIZESMART = 0
	EndIf
	$VAR = GUICtrlRead ( $HPARAMS )
	$VAR = StringStripWS ( $VAR , 3 )
	$PARAMS = StringReplace ( $VAR , Chr ( 13 ) & Chr ( 10 ) , " " )
	$VAR = GUICtrlRead ( $HEXAPP )
	$VAR = StringStripWS ( $VAR , 3 )
	$VAR = StringReplace ( $VAR , @CRLF , "||" )
	$VAR = StringRegExpReplace ( $VAR , "\|+\s*\|+" , "\|\|" )
	$EXAPP = $VAR
	If GUICtrlRead ( $HEXAPPAUTOEXIT ) = $GUI_CHECKED Then
		$EXAPPAUTOEXIT = 1
	Else
		$EXAPPAUTOEXIT = 0
	EndIf
	$VAR = GUICtrlRead ( $HEXAPP2 )
	$VAR = StringStripWS ( $VAR , 3 )
	$VAR = StringReplace ( $VAR , @CRLF , "||" )
	$VAR = StringRegExpReplace ( $VAR , "\|+\s*\|+" , "\|\|" )
	$EXAPP2 = $VAR
	GUI_SETPROXY ( )
	GUI_SAVELANG ( )
	$DOWNLOADTHREADS = GUICtrlRead ( $HDOWNLOADTHREADS )
	IniWrite ( $INIFILE , "Settings" , "UserDataDir" , $USERDATADIR )
	IniWrite ( $INIFILE , "Settings" , "Params" , $PARAMS )
	IniWrite ( $INIFILE , "Settings" , "UpdateInterval" , $UPDATEINTERVAL )
	IniWrite ( $INIFILE , "Settings" , "Platform" , $PLATFORM )
	IniWrite ( $INIFILE , "Settings" , "BrowserType" , $BROWSERTYPE )
	IniWrite ( $INIFILE , "Settings" , "Channel" , $CHANNEL )
	IniWrite ( $INIFILE , "Settings" , "x86" , $X86 )
	IniWrite ( $INIFILE , "Settings" , "ChromeSource" , $CHROMESOURCE )
	IniWrite ( $INIFILE , "Settings" , "PluginsDir" , $PLUGINSDIR )
	IniWrite ( $INIFILE , "Settings" , "CacheDir" , $CACHEDIR )
	IniWrite ( $INIFILE , "Settings" , "CacheSize" , $CACHESIZE )
	IniWrite ( $INIFILE , "Settings" , "CacheSizeSmart" , $CACHESIZESMART )
	IniWrite ( $INIFILE , "Settings" , "RunInBackground" , $RUNINBACKGROUND )
	IniWrite ( $INIFILE , "Settings" , "AppUpdate" , $APPUPDATE )
	IniWrite ( $INIFILE , "Settings" , "ProxyType" , $PROXYTYPE )
	IniWrite ( $INIFILE , "Settings" , "UpdateProxy" , $PROXYSEVER )
	IniWrite ( $INIFILE , "Settings" , "UpdatePort" , $PROXYPORT )
	IniWrite ( $INIFILE , "Settings" , "DownloadThreads" , $DOWNLOADTHREADS )
	$VAR = $EXAPP
	If StringRegExp ( $VAR , "^"".*""$" ) Then $VAR = """" & $VAR & """"
	IniWrite ( $INIFILE , "Settings" , "ExApp" , $VAR )
	IniWrite ( $INIFILE , "Settings" , "ExAppAutoExit" , $EXAPPAUTOEXIT )
	$VAR = $EXAPP2
	If StringRegExp ( $VAR , "^"".*""$" ) Then $VAR = """" & $VAR & """"
	IniWrite ( $INIFILE , "Settings" , "ExApp2" , $VAR )
	$BOSSKEY = ""
	$KEY = GUICtrlRead ( $HBOSSKEY )
	If $KEY Then
		$BOSSKEY = StringStripWS ( $KEY , 8 )
		$BOSSKEY = StringReplace ( $BOSSKEY , "+" , "" )
		$BOSSKEY = StringReplace ( $BOSSKEY , "Shift" , "+" )
		$BOSSKEY = StringReplace ( $BOSSKEY , "Ctrl" , "^" )
		$BOSSKEY = StringReplace ( $BOSSKEY , "Alt" , "!" )
		$BOSSKEY = StringReplace ( $BOSSKEY , "Win" , "#" )
	EndIf
	If GUICtrlRead ( $HHIDE2TRAY ) = $GUI_CHECKED Then
		$HIDE2TRAY = 1
	Else
		$HIDE2TRAY = 0
	EndIf
	Local $MBUTTON = LANG ( "GUI" , "MiddleButton" , "中键" )
	Local $DBCLICK = LANG ( "GUI" , "DoubleClick" , "双击" )
	If GUICtrlRead ( $HBOSSKEYM ) <> $GUI_CHECKED Then
		$BOSSKEYM = ""
	Else
		If GUICtrlRead ( $HBOSSKEYM1 ) = $MBUTTON Then
			If GUICtrlRead ( $HBOSSKEYM2 ) = $DBCLICK Then
				$BOSSKEYM = $AU3_MDCLICK
			Else
				$BOSSKEYM = $AU3_MDROP
			EndIf
		Else
			If GUICtrlRead ( $HBOSSKEYM2 ) = $DBCLICK Then
				$BOSSKEYM = $AU3_RDCLICK
			Else
				$BOSSKEYM = $AU3_RDROP
			EndIf
		EndIf
	EndIf
	$INIFILE1 = $CHROMEDIR & "\TabPlus.ini"
	If GUICtrlRead ( $HTABPLUS ) = $GUI_CHECKED Then
		$TABPLUS = 1
		If Not FileExists ( $INIFILE1 ) Then FileInstall ( "TabPlus.ini" , $INIFILE1 , 1 )
		$MOUSECLICK2CLOSETAB1 = IniRead ( $INIFILE1 , "MouseSettings" , "doubleclick" , "Check" )
		$RIGHTCLICK2CLOSETAB1 = IniRead ( $INIFILE1 , "MouseSettings" , "rightclick" , "Check" )
		$MOUSE2SWITCHTAB1 = IniRead ( $INIFILE1 , "MouseSettings" , "scrolltab" , "Check" )
	Else
		$TABPLUS = 0
	EndIf
	$MOUSECLICK2CLOSETAB = ""
	If GUICtrlRead ( $HDOUBLECLICK2CLOSETAB ) = $GUI_CHECKED Then
		$MOUSECLICK2CLOSETAB &= "|" & $AU3_LDCLICK
		If GUICtrlRead ( $HTABPLUS ) = $GUI_CHECKED Then
			$MOUSECLICK2CLOSETAB1 = IniWrite ( $INIFILE1 , "MouseSettings" , "doubleclick" , "Check" )
		EndIf
	Else
		If GUICtrlRead ( $HTABPLUS ) = $GUI_CHECKED Then
			$MOUSECLICK2CLOSETAB1 = IniWrite ( $INIFILE1 , "MouseSettings" , "doubleclick" , "unCheck" )
		EndIf
	EndIf
	If GUICtrlRead ( $HRIGHTCLICK2CLOSETAB ) = $GUI_CHECKED Then
		$MOUSECLICK2CLOSETAB &= "|" & $AU3_RCLICK
		If GUICtrlRead ( $HTABPLUS ) = $GUI_CHECKED Then
			$RIGHTCLICK2CLOSETAB1 = IniWrite ( $INIFILE1 , "MouseSettings" , "rightclick" , "Check" )
		EndIf
	Else
		If GUICtrlRead ( $HTABPLUS ) = $GUI_CHECKED Then
			$RIGHTCLICK2CLOSETAB1 = IniWrite ( $INIFILE1 , "MouseSettings" , "rightclick" , "unCheck" )
		EndIf
	EndIf
	$MOUSECLICK2CLOSETAB = StringTrimLeft ( $MOUSECLICK2CLOSETAB , 1 )
	If GUICtrlRead ( $HMOUSE2SWITCHTAB ) = $GUI_CHECKED Then
		$MOUSE2SWITCHTAB = $AU3_WHEELDOWN & "|" & $AU3_WHEELUP
		If GUICtrlRead ( $HTABPLUS ) = $GUI_CHECKED Then
			$MOUSE2SWITCHTAB1 = IniWrite ( $INIFILE1 , "MouseSettings" , "scrolltab" , "Check" )
		EndIf
	Else
		$MOUSE2SWITCHTAB = ""
		If GUICtrlRead ( $HTABPLUS ) = $GUI_CHECKED Then
			$MOUSE2SWITCHTAB1 = IniWrite ( $INIFILE1 , "MouseSettings" , "scrolltab" , "unCheck" )
		EndIf
	EndIf
	If GUICtrlRead ( $HKEEPLASTTAB ) = $GUI_CHECKED Then
		$KEEPLASTTAB = 1
	Else
		$KEEPLASTTAB = 0
	EndIf
	If GUICtrlRead ( $AMOUSEINC ) = $GUI_CHECKED Then
		$MOUSEINCA = 1
		If ProcessExists ( $CHROMEEXE ) Then
			If Not FileExists ( $CHROMEDIR & "\MouseInc.exe" ) Then FileInstall ( "MouseInc.exe" , $CHROMEDIR & "\MouseInc.exe" , 1 )
			If Not FileExists ( $CHROMEDIR & "\MouseInc.Settings.zip" ) Then FileInstall ( "MouseInc.Settings.zip" , $CHROMEDIR & "\MouseInc.Settings.zip" , 1 )
			If Not FileExists ( $CHROMEDIR & "\MouseInc.json" ) Then FileInstall ( "MouseInc.json" , $CHROMEDIR & "\MouseInc.json" , 1 )
		EndIf
	Else
		$MOUSEINCA = 0
	EndIf
	If GUICtrlRead ( $BMOUSEINC ) = $GUI_CHECKED Then
		$MOUSEINCB = 1
	Else
		$MOUSEINCB = 0
	EndIf
	If GUICtrlRead ( $HHOOKBOX ) = $GUI_CHECKED Then
		$HOOKBOX = 1
		If ProcessExists ( $CHROMEEXE ) Then
			$HOOKDLL = $CHROMEDIR & "\hook.dll"
			If _WINAPI_GETBINARYTYPE ( $CHROMEPATH ) Then
				Switch @extended
				Case $SCS_32BIT_BINARY
					If Not FileExists ( $HOOKDLL ) Then FileInstall ( "hook.dll" , $HOOKDLL , 1 )
				Case $SCS_64BIT_BINARY
					If Not FileExists ( $HOOKDLL ) Then FileInstall ( "hook64.dll" , $HOOKDLL , 1 )
				EndSwitch
			EndIf
		EndIf
	Else
		$HOOKBOX = 0
	EndIf
	If $TABPLUS Then
		If GUICtrlRead ( $HDOUBLECLICK2CLOSETAB ) = $GUI_CHECKED Then $MOUSECLICK2CLOSETAB3 = "Check"
		If GUICtrlRead ( $HDOUBLECLICK2CLOSETAB ) = $GUI_UNCHECKED Then $MOUSECLICK2CLOSETAB3 = "unCheck"
		If GUICtrlRead ( $HRIGHTCLICK2CLOSETAB ) = $GUI_CHECKED Then $RIGHTCLICK2CLOSETAB3 = "Check"
		If GUICtrlRead ( $HRIGHTCLICK2CLOSETAB ) = $GUI_UNCHECKED Then $RIGHTCLICK2CLOSETAB3 = "unCheck"
		If GUICtrlRead ( $HMOUSE2SWITCHTAB ) = $GUI_CHECKED Then $MOUSE2SWITCHTAB3 = "Check"
		If GUICtrlRead ( $HMOUSE2SWITCHTAB ) = $GUI_UNCHECKED Then $MOUSE2SWITCHTAB3 = "unCheck"
		If $MOUSECLICK2CLOSETAB2 <> $MOUSECLICK2CLOSETAB3 Or $RIGHTCLICK2CLOSETAB2 <> $RIGHTCLICK2CLOSETAB3 Or $MOUSE2SWITCHTAB2 <> $MOUSE2SWITCHTAB3 Then
			If ProcessExists ( $CHROMEEXE ) Then
				If ProcessExists ( "TabPlus.exe" ) Then ProcessClose ( "TabPlus.exe" )
				$CMD = "cd /d """ & $CHROMEDIR & """ && start /b TabPlus.exe"
				Run ( @ComSpec & " /c " & $CMD , "" , @SW_HIDE )
			EndIf
		EndIf
	EndIf
	IniWrite ( $INIFILE , "Settings" , "Bosskey" , $BOSSKEY )
	IniWrite ( $INIFILE , "Settings" , "BosskeyM" , $BOSSKEYM )
	IniWrite ( $INIFILE , "Settings" , "Hide2Tray" , $HIDE2TRAY )
	IniWrite ( $INIFILE , "Settings" , "MouseClick2CloseTab" , $MOUSECLICK2CLOSETAB )
	IniWrite ( $INIFILE , "Settings" , "Mouse2SwitchTab" , $MOUSE2SWITCHTAB )
	IniWrite ( $INIFILE , "Settings" , "KeepLastTab" , $KEEPLASTTAB )
	IniWrite ( $INIFILE , "Settings" , "MouseIncA" , $MOUSEINCA )
	IniWrite ( $INIFILE , "Settings" , "MouseIncB" , $MOUSEINCB )
	IniWrite ( $INIFILE , "Settings" , "TabPlus" , $TABPLUS )
	IniWrite ( $INIFILE , "Settings" , "HookBox" , $HOOKBOX )
	If Not FileExists ( FULLPATH ( $CHROMEPATH ) ) Then
		If StringInStr ( $PLATFORM , "mac" ) Or StringInStr ( $PLATFORM , "linux" ) Or StringInStr ( $PLATFORM , "android" ) Then
		Else
			$LANGCHROMENOTEXISTSTIPS = LANG ( "GUI" , "ChromeNotExistsTips" , "找不到浏览器程序文件： \n%s\n\n请重新设置或者从网络下载！\n需要从网络下载浏览器的最新版本吗？" )
			Local $MSG = MsgBox ( 36 , "MyBrowser" , StringFormat ( $LANGCHROMENOTEXISTSTIPS , $CHROMEPATH ) , 0 , $HSETTINGS )
			If $MSG <> 6 Then
				GUICtrlSetState ( $HCHROMEPATH , $GUI_FOCUS )
				Return SetError ( 1 )
			Else
				GUI_START_END_CHROMEUPDATE ( )
			EndIf
		EndIf
	EndIf
	IniWrite ( $INIFILE , "Settings" , "ChromePath" , $CHROMEPATH )
	Opt ( "ExpandEnvStrings" , 1 )
	If StringInStr ( IniRead ( $INIFILE , "Settings" , "BrowserType" , "" ) , "Firefox" ) Then
		Local $CHANNEL = GUICtrlRead ( $HCHANNEL )
		Local $CHANNELPATH = StringRegExpReplace ( $CHROMEPATH , "\\?[^\\]+$" , "" ) & "\defaults\pref\channel-prefs.js"
		Local $VAR = FileRead ( $CHANNELPATH )
		If Not StringInStr ( $VAR , "pref(""app.update.channel"", """ & $CHANNEL & """);" ) Then
			FileDelete ( $CHANNELPATH )
			FileWrite ( $CHANNELPATH , "// Changed by MyFirefox" & @CRLF & "pref(""app.update.channel"", """ & $CHANNEL & """);" & @CRLF )
		EndIf
	EndIf
	If StringInStr ( $PLATFORM , "win" ) Then
		If StringInStr ( $BROWSERTYPE , "Chrome" ) Or StringInStr ( $BROWSERTYPE , "Chromium" ) Then
			If $COPYDATA = $GUI_CHECKED Then
				Local $LOCKFILE = $USERDATADIR & "\lockfile"
				While 1
					If FileExists ( $LOCKFILE ) And FileDelete ( $LOCKFILE ) = 0 Then
						$LANGCOPYDATATIPS = LANG ( "GUI" , "CopyDataTips" , "浏览器正在运行，无法提取用户数据文件！\n请关闭浏览器后继续。" )
						$MSG = MsgBox ( 17 , "MyBrowser" , StringFormat ( $LANGCOPYDATATIPS , 0 ) )
						If $MSG <> 1 Then ExitLoop
					Else
						$LANGCOPYINGUSERDATA = LANG ( "GUI" , "CopyingUserData" , "正在复制浏览器用户数据文件..." )
						_GUICTRLSTATUSBAR_SETTEXT ( $HSTAUSBAR , $LANGCOPYINGUSERDATA )
						SplashTextOn ( "MyBrowser" , $LANGCOPYINGUSERDATA , 300 , 100 )
						Local $VAR = DirCopy ( $DEFAULTUSERDATADIR , $USERDATADIR , 1 )
						SplashOff ( )
						If $VAR Then
							_GUICTRLSTATUSBAR_SETTEXT ( $HSTAUSBAR , LANG ( "GUI" , "CopyDataSuccess" , "提取配置文件成功！" ) )
						Else
							_GUICTRLSTATUSBAR_SETTEXT ( $HSTAUSBAR , LANG ( "GUI" , "CopyDataFail" , "提取配置文件失败！" ) )
						EndIf
						ExitLoop
					EndIf
				WEnd
				GUICtrlSetState ( $HCOPYDATA , $GUI_UNCHECKED )
			EndIf
		EndIf
	EndIf
	If Not FileExists ( $USERDATADIR ) Then
		DirCreate ( $USERDATADIR )
	EndIf
	If StringInStr ( IniRead ( $INIFILE , "Settings" , "BrowserType" , "" ) , "Firefox" ) Then
		If $PLUGINSDIR <> "" And Not FileExists ( $PLUGINSDIR ) Then
			DirCreate ( $PLUGINSDIR )
		EndIf
	EndIf
EndFunc
Func GUI_CHECKPLATFORM ( )
	$CHANNEL = GUICtrlRead ( $HCHANNEL )
	$BROWSERTYPE = GUICtrlRead ( $HBROWSERTYPE )
	$PLATFORM = GUICtrlRead ( $HPLATFORM )
	If $PLATFORM = "win" Then
		If $BROWSERTYPE <> "Firefox" Then
			GUICtrlSetData ( $HCHROMESOURCE , "|" & $GUANFANG & "|" & $LANGCHROMESOURCESYS & "|" & $LANGCHROMESOURCEINSTALLER , $CHROMESOURCE )
		EndIf
		GUICtrlSetData ( $HBROWSERTYPE , "|Chrome|Chromium|Edge|Brave|Firefox|Vivaldi|Cent" , $BROWSERTYPE )
		If $BROWSERTYPE = "Firefox" Then
			If $CHANNEL = "" Then
				GUICtrlSetState ( $HCHANNEL , $GUI_ENABLE )
				GUICtrlSetData ( $HCHANNEL , "|Release|ESR|Beta|Dev|Nightly" , "Release" )
			EndIf
		EndIf
		GUICtrlSetState ( $HX86 , $GUI_ENABLE )
		GUICtrlSetState ( $HCHECKUPDATE , $GUI_ENABLE )
	ElseIf $PLATFORM = "mac" Then
		GUICtrlSetData ( $HCHROMESOURCE , "|" & $GUANFANG , $GUANFANG )
		If $BROWSERTYPE = "Chrome" Or $BROWSERTYPE = "Chromium" Or $BROWSERTYPE = "Firefox" Or $BROWSERTYPE = "Vivaldi" Or $BROWSERTYPE = "Cent" Then
			If $BROWSERTYPE = "Chromium" Or $BROWSERTYPE = "Firefox" Then
				GUICtrlSetData ( $HCHANNEL , "" )
				GUICtrlSetState ( $HCHANNEL , $GUI_DISABLE )
			EndIf
			GUICtrlSetData ( $HBROWSERTYPE , "|Chrome|Chromium|Firefox" , $BROWSERTYPE )
		ElseIf $BROWSERTYPE = "Edge" Or $BROWSERTYPE = "Brave" Then
			GUICtrlSetData ( $HBROWSERTYPE , "|Chrome|Chromium|Firefox" , "Chrome" )
			$BROWSERTYPE = "Chrome"
		EndIf
		GUICtrlSetState ( $HX86 , $GUI_DISABLE )
		GUICtrlSetState ( $HCHECKUPDATE , $GUI_DISABLE )
	ElseIf $PLATFORM = "linux" Then
		GUICtrlSetData ( $HCHROMESOURCE , "|" & $GUANFANG , $GUANFANG )
		If $BROWSERTYPE = "Chrome" Or $BROWSERTYPE = "Edge" Or $BROWSERTYPE = "Brave" Or $BROWSERTYPE = "Vivaldi" Or $BROWSERTYPE = "Cent" Then
			GUICtrlSetData ( $HBROWSERTYPE , "|Chromium|Firefox" , "Chromium" )
		ElseIf $BROWSERTYPE = "Chromium" Or $BROWSERTYPE = "Firefox" Then
			GUICtrlSetData ( $HBROWSERTYPE , "|Chromium|Firefox" , $BROWSERTYPE )
		EndIf
		GUICtrlSetData ( $HCHANNEL , "" )
		GUICtrlSetState ( $HCHANNEL , $GUI_DISABLE )
		GUICtrlSetState ( $HX86 , $GUI_ENABLE )
		GUICtrlSetState ( $HCHECKUPDATE , $GUI_DISABLE )
	ElseIf $PLATFORM = "android" Then
		GUICtrlSetData ( $HCHROMESOURCE , "|" & $GUANFANG , $GUANFANG )
		GUICtrlSetData ( $HBROWSERTYPE , "|Chromium" , "Chromium" )
		GUICtrlSetData ( $HCHANNEL , "" )
		GUICtrlSetState ( $HCHANNEL , $GUI_DISABLE )
		GUICtrlSetState ( $HX86 , $GUI_DISABLE )
		GUICtrlSetState ( $HCHECKUPDATE , $GUI_DISABLE )
	EndIf
	AdlibRegister ( "GUI_ShowLatestChromeVer" , 1000 )
EndFunc
Func GUI_CHECKBROWSERTYPE ( )
	$CHANNEL = GUICtrlRead ( $HCHANNEL )
	$BROWSERTYPE = GUICtrlRead ( $HBROWSERTYPE )
	$PLATFORM = GUICtrlRead ( $HPLATFORM )
	If $BROWSERTYPE = "Chrome" Then
		IniWrite ( $INIFILE , "Settings" , "BrowserType" , "Chrome" )
		If $PLATFORM = "win" Then
			GUICtrlSetData ( $HCHROMESOURCE , "|" & $GUANFANG & "|" & $LANGCHROMESOURCESYS & "|" & $LANGCHROMESOURCEINSTALLER , $CHROMESOURCE )
		EndIf
		$CHROMEPATH = RELATIVEPATH ( $CHROMEPATH )
		GUICtrlSetState ( $HSETTINGSOK , $GUI_ENABLE )
		GUICtrlSetState ( $HX86 , $GUI_ENABLE )
		SPLITPATH ( $CHROMEPATH , $CHROMEDIR , $CHROMEEXE )
		$CHROMEEXE = "chrome.exe"
		IniWrite ( $INIFILE , "Settings" , "ChromePath" , ".\App\chrome.exe" )
		$CHROMEPATH = $CHROMEDIR & "\" & $CHROMEEXE
		GUICtrlSetData ( $HCHROMEPATH , $CHROMEPATH )
		If $CHANNEL = "Release" Or $CHANNEL = "ESR" Or $CHANNEL = "Nightly" Or $CHANNEL = "" Then
			If $CHANNEL = "" Then
				GUICtrlSetState ( $HCHANNEL , $GUI_ENABLE )
			EndIf
			GUICtrlSetData ( $HCHANNEL , "|Stable|Beta|Dev|Canary" , "Stable" )
			$CHANNEL = "Stable"
		ElseIf $CHANNEL = "Beta" Or $CHANNEL = "Dev" Then
			GUICtrlSetData ( $HCHANNEL , "|Stable|Beta|Dev|Canary" , $CHANNEL )
		EndIf
		IniWrite ( $INIFILE , "Settings" , "Channel" , $CHANNEL )
		GUICtrlSetState ( $HCHECKUPDATE , $GUI_ENABLE )
	ElseIf $BROWSERTYPE = "Chromium" Then
		IniWrite ( $INIFILE , "Settings" , "BrowserType" , "Chromium" )
		If $PLATFORM = "win" Then
			GUICtrlSetData ( $HCHROMESOURCE , "|" & $GUANFANG & "|" & $LANGCHROMESOURCESYS & "|" & $LANGCHROMESOURCEINSTALLER , $CHROMESOURCE )
		EndIf
		$CHROMEPATH = RELATIVEPATH ( $CHROMEPATH )
		GUICtrlSetState ( $HSETTINGSOK , $GUI_ENABLE )
		GUICtrlSetState ( $HX86 , $GUI_ENABLE )
		SPLITPATH ( $CHROMEPATH , $CHROMEDIR , $CHROMEEXE )
		$CHROMEEXE = "chrome.exe"
		IniWrite ( $INIFILE , "Settings" , "ChromePath" , ".\App\chrome.exe" )
		$CHROMEPATH = $CHROMEDIR & "\" & $CHROMEEXE
		GUICtrlSetData ( $HCHROMEPATH , $CHROMEPATH )
		If $PLATFORM = "win" Or $PLATFORM = "mac" Or $PLATFORM = "linux" Then
			GUICtrlSetData ( $HCHANNEL , "" )
			GUICtrlSetState ( $HCHANNEL , $GUI_DISABLE )
		EndIf
		IniWrite ( $INIFILE , "Settings" , "Channel" , "" )
		GUICtrlSetState ( $HCHECKUPDATE , $GUI_ENABLE )
	ElseIf $BROWSERTYPE = "Edge" Then
		IniWrite ( $INIFILE , "Settings" , "BrowserType" , "Edge" )
		GUICtrlSetData ( $HCHROMESOURCE , "|" & $GUANFANG & "|" & $LANGCHROMESOURCEINSTALLER , $CHROMESOURCE )
		$CHROMEPATH = RELATIVEPATH ( $CHROMEPATH )
		GUICtrlSetState ( $HSETTINGSOK , $GUI_ENABLE )
		SPLITPATH ( $CHROMEPATH , $CHROMEDIR , $CHROMEEXE )
		$CHROMEEXE = "msedge.exe"
		IniWrite ( $INIFILE , "Settings" , "ChromePath" , ".\App\msedge.exe" )
		$CHROMEPATH = $CHROMEDIR & "\" & $CHROMEEXE
		GUICtrlSetData ( $HCHROMEPATH , $CHROMEPATH )
		GUICtrlSetState ( $HX86 , $GUI_ENABLE )
		If $CHANNEL = "Release" Or $CHANNEL = "ESR" Or $CHANNEL = "Nightly" Or $CHANNEL = "" Then
			If $CHANNEL = "" Then
				GUICtrlSetState ( $HCHANNEL , $GUI_ENABLE )
			EndIf
			GUICtrlSetData ( $HCHANNEL , "|Stable|Beta|Dev|Canary" , "Stable" )
			$CHANNEL = "Stable"
		ElseIf $CHANNEL = "Beta" Or $CHANNEL = "Dev" Then
			GUICtrlSetData ( $HCHANNEL , "|Stable|Beta|Dev|Canary" , $CHANNEL )
		EndIf
		IniWrite ( $INIFILE , "Settings" , "Channel" , $CHANNEL )
		GUICtrlSetState ( $HCHECKUPDATE , $GUI_ENABLE )
	ElseIf $BROWSERTYPE = "Brave" Then
		IniWrite ( $INIFILE , "Settings" , "BrowserType" , "Brave" )
		GUICtrlSetData ( $HCHROMESOURCE , "|" & $GUANFANG & "|" & $LANGCHROMESOURCEINSTALLER , $CHROMESOURCE )
		$CHROMEPATH = RELATIVEPATH ( $CHROMEPATH )
		GUICtrlSetState ( $HSETTINGSOK , $GUI_ENABLE )
		GUICtrlSetState ( $HX86 , $GUI_ENABLE )
		SPLITPATH ( $CHROMEPATH , $CHROMEDIR , $CHROMEEXE )
		$CHROMEEXE = "brave.exe"
		IniWrite ( $INIFILE , "Settings" , "ChromePath" , ".\App\brave.exe" )
		$CHROMEPATH = $CHROMEDIR & "\" & $CHROMEEXE
		GUICtrlSetData ( $HCHROMEPATH , $CHROMEPATH )
		If $CHANNEL = "Stable" Or $CHANNEL = "ESR" Or $CHANNEL = "Canary" Or $CHANNEL = "" Then
			If $CHANNEL = "" Then
				GUICtrlSetState ( $HCHANNEL , $GUI_ENABLE )
			EndIf
			GUICtrlSetData ( $HCHANNEL , "|Release|Beta|Dev|Nightly" , "Release" )
			$CHANNEL = "Release"
		ElseIf $CHANNEL = "Beta" Or $CHANNEL = "Dev" Then
			GUICtrlSetData ( $HCHANNEL , "|Release|Beta|Dev|Nightly" , $CHANNEL )
		EndIf
		IniWrite ( $INIFILE , "Settings" , "Channel" , $CHANNEL )
		GUICtrlSetState ( $HCHECKUPDATE , $GUI_ENABLE )
	ElseIf $BROWSERTYPE = "Vivaldi" Then
		IniWrite ( $INIFILE , "Settings" , "BrowserType" , "Vivaldi" )
		GUICtrlSetData ( $HCHROMESOURCE , "|" & $GUANFANG & "|" & $LANGCHROMESOURCEINSTALLER , $CHROMESOURCE )
		$CHROMEPATH = RELATIVEPATH ( $CHROMEPATH )
		If Not FileExists ( $CHROMEPATH ) Then
			GUICtrlSetState ( $HSETTINGSOK , $GUI_DISABLE )
		Else
			GUICtrlSetState ( $HSETTINGSOK , $GUI_ENABLE )
		EndIf
		SPLITPATH ( $CHROMEPATH , $CHROMEDIR , $CHROMEEXE )
		$CHROMEEXE = "vivaldi.exe"
		IniWrite ( $INIFILE , "Settings" , "ChromePath" , ".\App\vivaldi.exe" )
		$CHROMEPATH = $CHROMEDIR & "\" & $CHROMEEXE
		GUICtrlSetData ( $HCHROMEPATH , $CHROMEPATH )
		GUICtrlSetData ( $HCHANNEL , "" )
		GUICtrlSetState ( $HCHANNEL , $GUI_DISABLE )
		IniWrite ( $INIFILE , "Settings" , "Channel" , "" )
		GUICtrlSetState ( $HX86 , $GUI_DISABLE )
		GUICtrlSetState ( $HCHECKUPDATE , $GUI_ENABLE )
	ElseIf $BROWSERTYPE = "Cent" Then
		IniWrite ( $INIFILE , "Settings" , "BrowserType" , "Cent" )
		GUICtrlSetData ( $HCHROMESOURCE , "|" & $GUANFANG & "|" & $LANGCHROMESOURCEINSTALLER , $CHROMESOURCE )
		$CHROMEPATH = RELATIVEPATH ( $CHROMEPATH )
		If Not FileExists ( $CHROMEPATH ) Then
			GUICtrlSetState ( $HSETTINGSOK , $GUI_DISABLE )
		Else
			GUICtrlSetState ( $HSETTINGSOK , $GUI_ENABLE )
		EndIf
		SPLITPATH ( $CHROMEPATH , $CHROMEDIR , $CHROMEEXE )
		$CHROMEEXE = "chrome.exe"
		IniWrite ( $INIFILE , "Settings" , "ChromePath" , ".\App\chrome.exe" )
		$CHROMEPATH = $CHROMEDIR & "\" & $CHROMEEXE
		GUICtrlSetData ( $HCHROMEPATH , $CHROMEPATH )
		GUICtrlSetData ( $HCHANNEL , "" )
		GUICtrlSetState ( $HCHANNEL , $GUI_DISABLE )
		IniWrite ( $INIFILE , "Settings" , "Channel" , "" )
		GUICtrlSetState ( $HX86 , $GUI_DISABLE )
		GUICtrlSetState ( $HCHECKUPDATE , $GUI_ENABLE )
	ElseIf $BROWSERTYPE = "Firefox" Then
		IniWrite ( $INIFILE , "Settings" , "BrowserType" , "Firefox" )
		If $PLATFORM = "win" Then
			GUICtrlSetData ( $HCHROMESOURCE , "|" & $GUANFANG & "|" & $LANGCHROMESOURCEINSTALLER , $CHROMESOURCE )
		EndIf
		$CHROMEPATH = RELATIVEPATH ( $CHROMEPATH )
		If Not FileExists ( $CHROMEPATH ) Then
			GUICtrlSetState ( $HSETTINGSOK , $GUI_DISABLE )
		Else
			GUICtrlSetState ( $HSETTINGSOK , $GUI_ENABLE )
		EndIf
		GUICtrlSetState ( $HX86 , $GUI_ENABLE )
		SPLITPATH ( $CHROMEPATH , $CHROMEDIR , $CHROMEEXE )
		$CHROMEEXE = "firefox.exe"
		IniWrite ( $INIFILE , "Settings" , "ChromePath" , ".\App\firefox.exe" )
		$CHROMEPATH = $CHROMEDIR & "\" & $CHROMEEXE
		GUICtrlSetData ( $HCHROMEPATH , $CHROMEPATH )
		If $PLATFORM = "mac" Or $PLATFORM = "linux" Then
			GUICtrlSetData ( $HCHANNEL , "" )
			GUICtrlSetState ( $HCHANNEL , $GUI_DISABLE )
		ElseIf $PLATFORM = "win" Then
			If $CHANNEL = "Stable" Or $CHANNEL = "Canary" Or $CHANNEL = "" Then
				If $CHANNEL = "" Then
					GUICtrlSetState ( $HCHANNEL , $GUI_ENABLE )
				EndIf
				GUICtrlSetData ( $HCHANNEL , "|Release|ESR|Beta|Dev|Nightly" , "Release" )
				$CHANNEL = "Release"
			ElseIf $CHANNEL = "Beta" Or $CHANNEL = "Dev" Then
				GUICtrlSetData ( $HCHANNEL , "|Release|ESR|Beta|Dev|Nightly" , $CHANNEL )
			EndIf
		EndIf
		IniWrite ( $INIFILE , "Settings" , "Channel" , $CHANNEL )
		GUICtrlSetState ( $HCHECKUPDATE , $GUI_ENABLE )
	EndIf
	AdlibRegister ( "GUI_ShowLatestChromeVer" , 1000 )
EndFunc
Func GUI_CHECKCHROME ( )
	$PLATFORM = GUICtrlRead ( $HPLATFORM )
	$BROWSERTYPE = GUICtrlRead ( $HBROWSERTYPE )
	$CHANNEL = GUICtrlRead ( $HCHANNEL )
	If $CHANNEL = "Stable" Then
		IniWrite ( $INIFILE , "Settings" , "Channel" , "Stable" )
	ElseIf $CHANNEL = "Beta" Then
		IniWrite ( $INIFILE , "Settings" , "Channel" , "Beta" )
	ElseIf $CHANNEL = "Dev" Then
		IniWrite ( $INIFILE , "Settings" , "Channel" , "Dev" )
	ElseIf $CHANNEL = "Canary" Then
		IniWrite ( $INIFILE , "Settings" , "Channel" , "Canary" )
	ElseIf $CHANNEL = "Release" Then
		IniWrite ( $INIFILE , "Settings" , "Channel" , "Release" )
	ElseIf $CHANNEL = "ESR" Then
		IniWrite ( $INIFILE , "Settings" , "Channel" , "ESR" )
	ElseIf $CHANNEL = "Nightly" Then
		IniWrite ( $INIFILE , "Settings" , "Channel" , "Nightly" )
	EndIf
	GUI_CHECKCHROMEINSYSTEM ( $PLATFORM , $BROWSERTYPE , $CHANNEL )
	AdlibRegister ( "GUI_ShowLatestChromeVer" , 1000 )
EndFunc
Func GUI_CHECKCHROMEINSYSTEM ( $PLATFORM , $BROWSERTYPE , $CHANNEL )
	Local $DIR , $SUBKEY , $VALUE = "version"
	If StringInStr ( $PLATFORM , "win" ) Then
		If StringInStr ( $BROWSERTYPE , "Chrome" ) Then
			If StringInStr ( $CHANNEL , "Canary" ) Then
				$DEFAULTUSERDATADIR = @LocalAppDataDir & "\Google\Chrome SxS\User Data"
				$DIR = "Google\Chrome SxS\Application"
			Else
				$DEFAULTUSERDATADIR = @LocalAppDataDir & "\Google\Chrome\User Data"
				$DIR = "Google\Chrome\Application"
			EndIf
		ElseIf StringInStr ( $BROWSERTYPE , "Chromium" ) Then
			$DEFAULTUSERDATADIR = @LocalAppDataDir & "\Chromium\User Data"
			$DIR = "Chromium\Application"
		EndIf
	EndIf
	If FileExists ( $DEFAULTUSERDATADIR & "\Local State" ) Then
		GUICtrlSetState ( $HCOPYDATA , $GUI_ENABLE )
	Else
		GUICtrlSetState ( $HCOPYDATA , $GUI_UNCHECKED )
		GUICtrlSetState ( $HCOPYDATA , $GUI_DISABLE )
	EndIf
	Local $PROGRAMFILESDIR , $PROGRAMFILESDIR32
	If @OSArch = "X86" Then
		$PROGRAMFILESDIR32 = @ProgramFilesDir
	Else
		$PROGRAMFILESDIR = RegRead ( "HKLM64\SOFTWARE\Microsoft\Windows\CurrentVersion" , "ProgramFilesDir" )
		$PROGRAMFILESDIR32 = RegRead ( "HKLM64\SOFTWARE\Microsoft\Windows\CurrentVersion" , "ProgramFilesDir (x86)" )
	EndIf
	If $PROGRAMFILESDIR Then
		$DEFAULTCHROMEDIR = $PROGRAMFILESDIR & "\" & $DIR
		If FileExists ( $DEFAULTCHROMEDIR & "\chrome.exe" ) Then
			$DEFAULTCHROMEVER = FINDCHROMEVER ( $DEFAULTCHROMEDIR )
			If $DEFAULTCHROMEVER Then Return 1
		EndIf
	EndIf
	If $PROGRAMFILESDIR32 Then
		$DEFAULTCHROMEDIR = $PROGRAMFILESDIR32 & "\" & $DIR
		If FileExists ( $DEFAULTCHROMEDIR & "\chrome.exe" ) Then
			$DEFAULTCHROMEVER = FINDCHROMEVER ( $DEFAULTCHROMEDIR )
			If $DEFAULTCHROMEVER Then Return 1
		EndIf
	EndIf
	$DEFAULTCHROMEDIR = @LocalAppDataDir & "\" & $DIR
	If FileExists ( $DEFAULTCHROMEDIR & "\chrome.exe" ) Then
		$DEFAULTCHROMEVER = FINDCHROMEVER ( $DEFAULTCHROMEDIR )
		If $DEFAULTCHROMEVER Then
			Return 1
		Else
			$DEFAULTCHROMEDIR = ""
		EndIf
	EndIf
EndFunc
Func FINDCHROMEVER ( $DIR )
	Local $HSEARCH = FileFindFirstFile ( $DIR & "\*.*" )
	If $HSEARCH = - 1 Then Return
	Local $DIRNAME , $VERSION = 0
	While 1
		$DIRNAME = FileFindNextFile ( $HSEARCH )
		If @error Then ExitLoop
		If StringInStr ( FileGetAttrib ( $DIR & "\" & $DIRNAME ) , "D" ) And FileExists ( $DIR & "\" & $DIRNAME & "\chrome.dll" ) Then
			If VERSIONCOMPARE ( $DIRNAME , $VERSION ) Then
				$VERSION = $DIRNAME
			EndIf
		EndIf
	WEnd
	FileClose ( $HSEARCH )
	Return $VERSION
EndFunc
Func GUI_SHOWLATESTCHROMEVER ( )
	AdlibUnRegister ( "GUI_ShowLatestChromeVer" )
	If $ISUPDATING Then Return
	If ProcessExists ( $ITHREADPID ) Then
		_KILLTHREAD ( $ITHREADPID )
	EndIf
	Local $ADLINFO [ 6 ]
	Local $RESPONSETIMER
	GUI_SETPROXY ( )
	$LATESTCHROMEVER = ""
	$LATESTCHROMEURLS = ""
	$ERROR = ""
	GUICtrlSetData ( $HLATESTCHROMEVER , "" )
	_SETVAR ( "DLInfo" , "|||||" )
	_SETVAR ( "ResponseTimer" , _NOWCALC ( ) )
	If $PROXYTYPE = "DIRECT" Or Not $PROXYSEVER Then
		$ITHREADPID = _STARTTHREAD ( @ScriptFullPath , $GET_LATEST_CHROME_VER , $PLATFORM , $BROWSERTYPE , $CHANNEL , $X86 , $INIFILE )
	Else
		$ITHREADPID = _STARTTHREAD ( @ScriptFullPath , $GET_LATEST_CHROME_VER , $PLATFORM , $BROWSERTYPE , $CHANNEL , $X86 , $INIFILE , "HTTP:" & $PROXYSEVER & ":" & $PROXYPORT )
	EndIf
	While 1
		$RESPONSETIMER = _GETVAR ( "ResponseTimer" )
		$ADLINFO = StringSplit ( _GETVAR ( "DLInfo" ) , "|" , 2 )
		If UBound ( $ADLINFO ) >= 6 Then
			_GUICTRLSTATUSBAR_SETTEXT ( $HSTAUSBAR , $ADLINFO [ 5 ] )
			If $ADLINFO [ 2 ] Then ExitLoop
		EndIf
		If Not ProcessExists ( $ITHREADPID ) Or _DATEDIFF ( "s" , $RESPONSETIMER , _NOWCALC ( ) ) > 30 Then
			$ERROR = LANG ( "GUI" , "NoResponse" , "进程意外中止或无响应" )
			ExitLoop
		EndIf
		Sleep ( 100 )
	WEnd
	_KILLTHREAD ( $ITHREADPID )
	If $ADLINFO [ 3 ] Then
		$LATESTCHROMEVER = $ADLINFO [ 0 ]
		$LATESTCHROMEURLS = $ADLINFO [ 1 ]
	Else
		If $ADLINFO [ 4 ] Then
			$ERROR = $ADLINFO [ 5 ]
		EndIf
		_GUICTRLSTATUSBAR_SETTEXT ( $HSTAUSBAR , LANG ( "GUI" , "GetUpdateInfoFailed" , "获取更新信息失败" ) & " " & $ERROR )
	EndIf
	If StringInStr ( $BROWSERTYPE , "Firefox" ) Then
		GUICtrlSetData ( $HLATESTCHROMEVER , StringFormat ( LANG ( "GUI" , "FirefoxDownloadUrl" , "Firefox下载地址" ) ) )
	ElseIf StringInStr ( $BROWSERTYPE , "Vivaldi" ) Then
		GUICtrlSetData ( $HLATESTCHROMEVER , StringFormat ( LANG ( "GUI" , "VivaldiDownloadUrl" , "Vivaldi下载地址" ) ) )
	ElseIf StringInStr ( $BROWSERTYPE , "Cent" ) Then
		GUICtrlSetData ( $HLATESTCHROMEVER , StringFormat ( LANG ( "GUI" , "CentDownloadUrl" , "Cent下载地址" ) ) )
	Else
		GUICtrlSetData ( $HLATESTCHROMEVER , $LATESTCHROMEVER )
	EndIf
EndFunc
Func OPENWEBSITE ( )
	Global $HMAINGUI = GUICreate ( LANG ( "GUI" , "About" , "关于" ) , 300 , 300 )
	$ABOUT1 = StringFormat ( LANG ( "GUI" , "About1" , "QQ:970852638" ) )
	Global $LABEL1 = GUICtrlCreateLabel ( $ABOUT1 , 90 , 30 , - 1 , - 1 )
	GUICtrlSetCursor ( - 1 , 0 )
	GUICtrlSetColor ( - 1 , 255 )
	GUICtrlSetOnEvent ( - 1 , "QQEvent" )
	$ABOUT2 = StringFormat ( LANG ( "GUI" , "About2" , "MyBrowser官网" ) )
	$LABEL2 = GUICtrlCreateLabel ( $ABOUT2 , 90 , 60 , - 1 , - 1 )
	GUICtrlSetCursor ( - 1 , 0 )
	GUICtrlSetColor ( - 1 , 255 )
	GUICtrlSetOnEvent ( - 1 , "Instructions" )
	$ABOUT3 = StringFormat ( LANG ( "GUI" , "About3" , "Chrome在线下载" ) )
	$LABEL3 = GUICtrlCreateLabel ( $ABOUT3 , 90 , 90 , - 1 , - 1 )
	GUICtrlSetCursor ( - 1 , 0 )
	GUICtrlSetColor ( - 1 , 255 )
	GUICtrlSetOnEvent ( - 1 , "ChromedownEvent" )
	$ABOUT4 = StringFormat ( LANG ( "GUI" , "About4" , "Edge在线下载" ) )
	$LABEL4 = GUICtrlCreateLabel ( $ABOUT4 , 90 , 120 , - 1 , - 1 )
	GUICtrlSetCursor ( - 1 , 0 )
	GUICtrlSetColor ( - 1 , 255 )
	GUICtrlSetOnEvent ( - 1 , "EdgedownEvent" )
	$ABOUT5 = StringFormat ( LANG ( "GUI" , "About5" , "Brave在线下载" ) )
	$LABEL5 = GUICtrlCreateLabel ( $ABOUT5 , 90 , 150 , - 1 , - 1 )
	GUICtrlSetCursor ( - 1 , 0 )
	GUICtrlSetColor ( - 1 , 255 )
	GUICtrlSetOnEvent ( - 1 , "BravedownEvent" )
	$ABOUT6 = StringFormat ( LANG ( "GUI" , "About6" , "Firefox在线下载" ) )
	$LABEL6 = GUICtrlCreateLabel ( $ABOUT6 , 90 , 180 , - 1 , - 1 )
	GUICtrlSetCursor ( - 1 , 0 )
	GUICtrlSetColor ( - 1 , 255 )
	GUICtrlSetOnEvent ( - 1 , "FirefoxdownEvent" )
	$ABOUT7 = StringFormat ( LANG ( "GUI" , "About7" , "Vivaldi在线下载" ) )
	$LABEL7 = GUICtrlCreateLabel ( $ABOUT7 , 90 , 210 , - 1 , - 1 )
	GUICtrlSetCursor ( - 1 , 0 )
	GUICtrlSetColor ( - 1 , 255 )
	GUICtrlSetOnEvent ( - 1 , "VivaldidownEvent" )
	$ABOUT8 = StringFormat ( LANG ( "GUI" , "About8" , "Cent在线下载" ) )
	$LABEL8 = GUICtrlCreateLabel ( $ABOUT8 , 90 , 240 , - 1 , - 1 )
	GUICtrlSetCursor ( - 1 , 0 )
	GUICtrlSetColor ( - 1 , 255 )
	GUICtrlSetOnEvent ( - 1 , "CentdownEvent" )
	GUISetOnEvent ( $GUI_EVENT_CLOSE , "CloseWindow" )
	GUISetState ( @SW_SHOW , $HMAINGUI )
EndFunc
Func CLOSEWINDOW ( )
	GUIDelete ( $HMAINGUI )
EndFunc
Func QQEVENT ( )
	Local $STEXT = GUICtrlRead ( $LABEL1 )
	ClipPut ( $STEXT )
	MsgBox ( 0 , "MyBrowser" , LANG ( "GUI" , "CopyAlready" , "文本已复制到剪贴板：" ) & @CRLF & $STEXT )
EndFunc
Func CHROMEDOWNEVENT ( )
	ShellExecute ( "https://xixiranran.github.io/tools/chrome/" )
EndFunc
Func EDGEDOWNEVENT ( )
	ShellExecute ( "https://xixiranran.github.io/tools/edge/" )
EndFunc
Func BRAVEDOWNEVENT ( )
	ShellExecute ( "https://xixiranran.github.io/tools/brave/" )
EndFunc
Func FIREFOXDOWNEVENT ( )
	ShellExecute ( "https://xixiranran.github.io/tools/firefox/" )
EndFunc
Func VIVALDIDOWNEVENT ( )
	ShellExecute ( "https://xixiranran.github.io/tools/vivaldi/" )
EndFunc
Func CENTDOWNEVENT ( )
	ShellExecute ( "https://xixiranran.github.io/tools/cent/" )
EndFunc
Func INSTRUCTIONS ( )
	ShellExecute ( "https://drsamonline.github.io/MyChrome/" )
EndFunc
Func GUI_SHOWURL ( )
	$PLATFORM = GUICtrlRead ( $HPLATFORM )
	$BROWSERTYPE = GUICtrlRead ( $HBROWSERTYPE )
	$CHANNEL = GUICtrlRead ( $HCHANNEL )
	If $BROWSERTYPE = "Vivaldi" Then
		$LATESTCHROMEURLS = "https://xixiranran.github.io/tools/vivaldi/"
	ElseIf $BROWSERTYPE = "Cent" Then
		$LATESTCHROMEURLS = "https://xixiranran.github.io/tools/cent/"
	EndIf
	If $LATESTCHROMEURLS <> "" Then
		Local $HGUI = GUICreate ( "MyBrowser" , 800 , 260 )
		GUISetOnEvent ( $GUI_EVENT_CLOSE , "GUI_ShowUrlExit" )
		GUICtrlCreateLabel ( LANG ( "GUI" , "UpdateUrlTips" , "选择链接可下载或复制到剪贴板" ) , 10 , 10 )
		$HURLLIST = GUICtrlCreateList ( "" , 10 , 40 , 780 , 170 , BitOR ( $WS_BORDER , $WS_VSCROLL ) )
		GUICtrlSetOnEvent ( - 1 , "GUI_ClickToCopyUrl" )
		GUICtrlSetData ( - 1 , StringReplace ( $LATESTCHROMEURLS , " " , "|" ) )
		If $PLATFORM = "win" Then
			If $BROWSERTYPE = "Chrome" Or $BROWSERTYPE = "Chromium" Or $BROWSERTYPE = "Edge" Or $BROWSERTYPE = "Brave" Then
				$HURLCOPY = GUICtrlCreateButton ( LANG ( "GUI" , "UrlCopy" , "复制" ) , 600 , 220 , 80 , 20 )
				GUICtrlSetOnEvent ( - 1 , "GUI_CopyUrl" )
				$HURLDOWNLOAD = GUICtrlCreateButton ( LANG ( "GUI" , "UrlDownload" , "下载" ) , 700 , 220 , 80 , 20 )
				GUICtrlSetOnEvent ( - 1 , "GUI_DownloadUrl" )
			ElseIf $BROWSERTYPE = "Firefox" Then
				$HURLCOPY = GUICtrlCreateButton ( LANG ( "GUI" , "UrlCopy" , "复制" ) , 600 , 220 , 80 , 20 )
				GUICtrlSetOnEvent ( - 1 , "GUI_CopyUrl" )
				$HURLDOWNLOAD = GUICtrlCreateButton ( LANG ( "GUI" , "OpenUrl" , "打开网页" ) , 700 , 220 , 80 , 20 )
				GUICtrlSetOnEvent ( - 1 , "FirefoxdownEvent" )
			ElseIf $BROWSERTYPE = "Vivaldi" Then
				$HURLCOPY = GUICtrlCreateButton ( LANG ( "GUI" , "UrlCopy" , "复制" ) , 600 , 220 , 80 , 20 )
				GUICtrlSetOnEvent ( - 1 , "GUI_CopyUrl" )
				$HURLDOWNLOAD = GUICtrlCreateButton ( LANG ( "GUI" , "OpenUrl" , "打开网页" ) , 700 , 220 , 80 , 20 )
				GUICtrlSetOnEvent ( - 1 , "VivaldidownEvent" )
			ElseIf $BROWSERTYPE = "Cent" Then
				$HURLCOPY = GUICtrlCreateButton ( LANG ( "GUI" , "UrlCopy" , "复制" ) , 600 , 220 , 80 , 20 )
				GUICtrlSetOnEvent ( - 1 , "GUI_CopyUrl" )
				$HURLDOWNLOAD = GUICtrlCreateButton ( LANG ( "GUI" , "OpenUrl" , "打开网页" ) , 700 , 220 , 80 , 20 )
				GUICtrlSetOnEvent ( - 1 , "CentdownEvent" )
			EndIf
		ElseIf $PLATFORM = "mac" Or $PLATFORM = "linux" Or $PLATFORM = "android" Then
			GUICtrlCreateButton ( LANG ( "GUI" , "UrlCopy" , "复制" ) , 700 , 220 , 80 , 20 )
			GUICtrlSetOnEvent ( - 1 , "GUI_CopyUrl" )
		EndIf
		$SELECTEDURL = GUICtrlRead ( $HURLLIST )
		If $SELECTEDURL = "" Then
			If $BROWSERTYPE = "Firefox" Or $BROWSERTYPE = "Vivaldi" Or $BROWSERTYPE = "Cent" Then
				GUICtrlSetState ( $HURLCOPY , $GUI_DISABLE )
			Else
				GUICtrlSetState ( $HURLDOWNLOAD , $GUI_DISABLE )
				GUICtrlSetState ( $HURLCOPY , $GUI_DISABLE )
			EndIf
		EndIf
		If $ISUPDATING Then
			GUICtrlSetState ( - 1 , $GUI_DISABLE )
		EndIf
		GUISetState ( @SW_SHOW , $HGUI )
	EndIf
EndFunc
Func GUI_SHOWURLEXIT ( )
	GUIDelete ( @GUI_WinHandle )
EndFunc
Func GUI_CLICKTOCOPYURL ( )
	Local $URL = GUICtrlRead ( $HURLLIST )
	If $URL = "" Then Return
	If MouseClick ( "left" ) Then
		GUICtrlSetState ( $HURLDOWNLOAD , $GUI_ENABLE )
		GUICtrlSetState ( $HURLCOPY , $GUI_ENABLE )
	EndIf
EndFunc
Func GUI_COPYURL ( )
	Local $URL = GUICtrlRead ( $HURLLIST )
	If $URL = "" Then Return
	ClipPut ( $URL )
	MsgBox ( 64 , "MyBrowser" , LANG ( "GUI" , "UrlCopySuccessful" , "下载地址已复制到剪贴板!" ) , 0 , @GUI_WinHandle )
EndFunc
Func GUI_DOWNLOADURL ( )
	$SELECTEDURL = GUICtrlRead ( $HURLLIST )
	If $SELECTEDURL = "" Then Return
	GUIDelete ( @GUI_WinHandle )
	GUI_START_END_CHROMEUPDATE ( )
EndFunc
Func GUI_EVENTCHROMESOURCE ( )
	$LANGCHROMESOURCESYS = LANG ( "GUI" , "ChromeSourceSys" , "从系统中提取" )
	$LANGCHROMESOURCEINSTALLER = LANG ( "GUI" , "ChromeSourceInstaller" , "从离线安装包提取" )
	Local $SOURCE = GUICtrlRead ( $HCHROMESOURCE )
	If $SOURCE = $LANGCHROMESOURCESYS Then
		If GUI_CHECKCHROMEINSYSTEM ( $PLATFORM , $BROWSERTYPE , $CHANNEL ) Then
			GUI_COPYCHROMEFROMSYSTEM ( )
		Else
			If $BROWSERTYPE = "Chrome" Then
				$LANGNOCHROMEFOUND = LANG ( "GUI" , "NoChromeFound" , "在您的系统中未找到 Chrome（%s）程序文件!" )
				MsgBox ( 64 , "MyBrowser" , StringFormat ( $LANGNOCHROMEFOUND , $CHANNEL ) , 0 , $HSETTINGS )
			ElseIf $BROWSERTYPE = "Chromium" Then
				$LANGNOCHROMEFOUND = LANG ( "GUI" , "NoChromiumFound" , "在您的系统中未找到 Chromium（%s）程序文件!" )
				MsgBox ( 64 , "MyBrowser" , $LANGNOCHROMEFOUND , 0 , $HSETTINGS )
			EndIf
		EndIf
		_GUICTRLCOMBOBOX_SELECTSTRING ( $HCHROMESOURCE , $CHROMESOURCE )
	ElseIf $SOURCE = $LANGCHROMESOURCEINSTALLER Then
		Local $INSTALLER = FileOpenDialog ( LANG ( "GUI" , "ChooseInstaller" , "选择离线安装文件" ) , @ScriptDir , "Executable files (*.exe)" , 1 + 2 , "" , $HSETTINGS )
		If $INSTALLER <> "" Then
			$CHROMEPATH = GUICtrlRead ( $HCHROMEPATH )
			$CHROMEPATH = FULLPATH ( $CHROMEPATH )
			SPLITPATH ( $CHROMEPATH , $CHROMEDIR , $CHROMEEXE )
			If FileExists ( $CHROMEDIR ) Then
				$CHROMEDIR = RELATIVEPATH ( $CHROMEDIR )
				If $CHROMEDIR = "." Then
					$FUGAI = MsgBox ( 64 + 4 , "MyBrowser" , $CHROMEEXE & $AND & @ScriptName & StringFormat ( LANG ( "GUI" , "fugaigengxin1" , "设置在同一目录(不推荐)，将会覆盖更新，是否继续？" ) ) , 0 , $HSETTINGS )
					If $FUGAI <> 6 Then
						ENDUPDATE ( )
						Return
					EndIf
				Else
					$FUGAI = MsgBox ( 64 + 3 , "MyBrowser" , StringFormat ( LANG ( "GUI" , "fugaigengxin2" , "是否覆盖更新？\n\n【是】:立即覆盖更新\n【否】:删除原程序目录后更新【危险：请注意备份重要文件】\n【取消】：取消本次操作" ) ) , 0 , $HSETTINGS )
					If $FUGAI = 7 Or $FUGAI = 6 Then
						If IniRead ( $INIFILE , "Settings" , "GreenChrome" , "" ) = 1 Then
							GUICtrlSetData ( $SETGC , LANG ( "GUI" , "setgcon" , "注入GreenChrome" ) )
							GUICtrlSetTip ( $SETGC , LANG ( "GUI" , "setgconTips" , "释放并注入GreenChrome" ) )
							GUICtrlSetState ( $GCSETTING , $GUI_DISABLE )
							GUICtrlSetState ( $SETGC , $GUI_ENABLE )
							IniWrite ( $INIFILE , "Settings" , "GreenChrome" , 0 )
						EndIf
						If ProcessExists ( $CHROMEEXE ) Then
							$FUGAI2 = MsgBox ( 64 + 1 , "MyBrowser" , StringFormat ( LANG ( "GUI" , "fugaigengxin3" , "检测到浏览器正在运行，是否关闭浏览器后更新？\n\n【确定】:关闭浏览后更新\n【取消】：不更新" ) ) , 0 , $HSETTINGS )
							If $FUGAI2 = 1 Then
								ProcessClose ( $CHROMEEXE )
								Sleep ( 2000 )
							EndIf
							If $FUGAI2 = 2 Then
								ENDUPDATE ( )
								Return
							EndIf
						EndIf
						If $FUGAI = 7 Then
							DirRemove ( FULLPATH ( $CHROMEDIR ) , 1 )
						EndIf
					ElseIf $FUGAI = 2 Then
						ENDUPDATE ( )
						Return
					EndIf
				EndIf
			EndIf
			INSTALLCHROME ( $INSTALLER )
			AdlibRegister ( "GUI_ShowLatestChromeVer" , 500 )
			ENDUPDATE ( )
		EndIf
		_GUICTRLCOMBOBOX_SELECTSTRING ( $HCHROMESOURCE , $CHROMESOURCE )
	Else
		$CHROMESOURCE = $SOURCE
		$GET_LATEST_CHROME_VER = "get_latest_chrome_ver"
		AdlibRegister ( "GUI_ShowLatestChromeVer" , 1000 )
	EndIf
EndFunc
Func GUI_CHECKTHREADSNUM ( )
	Local $THREADS = GUICtrlRead ( $HDOWNLOADTHREADS )
	If $THREADS > 10 Then
		GUICtrlSetData ( $HDOWNLOADTHREADS , 10 )
	ElseIf $THREADS < 1 Then
		GUICtrlSetData ( $HDOWNLOADTHREADS , 1 )
	EndIf
EndFunc
Func GUI_START_END_CHROMEUPDATE ( )
	If Not $ISUPDATING Then
		$ISUPDATING = 1
		_KILLTHREAD ( $ITHREADPID )
		GUICtrlSetState ( $SETGC , $GUI_DISABLE )
		Local $BROWSERTYPE = GUICtrlRead ( $HBROWSERTYPE )
		If $BROWSERTYPE = "Vivaldi" Then
			$MSG = MsgBox ( 32 + 4 , "MyBrowser" , StringFormat ( LANG ( "GUI" , "openvivaldidownload" , "是否打开Vivaldi网页下载链接？" ) ) , 0 , $HSETTINGS )
			If $MSG = 6 Then
				ShellExecute ( "https://xixiranran.github.io/tools/vivaldi/" )
			EndIf
			$ISUPDATING = 0
		ElseIf $BROWSERTYPE = "Cent" Then
			$MSG = MsgBox ( 32 + 4 , "MyBrowser" , StringFormat ( LANG ( "GUI" , "opencentdownload" , "是否打开Cent网页下载链接？" ) ) , 0 , $HSETTINGS )
			If $MSG = 6 Then
				ShellExecute ( "https://xixiranran.github.io/tools/cent/" )
			EndIf
			$ISUPDATING = 0
		ElseIf $BROWSERTYPE = "Firefox" Then
			$MSG = MsgBox ( 32 + 4 , "MyBrowser" , StringFormat ( LANG ( "GUI" , "openfirefoxdownload" , "是否打开Firefox网页下载链接？" ) ) , 0 , $HSETTINGS )
			If $MSG = 6 Then
				ShellExecute ( "https://xixiranran.github.io/tools/firefox/" )
			EndIf
			$ISUPDATING = 0
		Else
			AdlibRegister ( "GUI_CheckChromeUpdate" , 10 )
		EndIf
	ElseIf MsgBox ( 292 , "MyBrowser" , LANG ( "GUI" , "ConfirmUpdate" , "确定要取消浏览器更新吗？" ) , 0 , $HSETTINGS ) = 6 Then
		$ISUPDATING = 0
	EndIf
EndFunc
Func GUI_SELECTCACHEDIR ( )
	Local $SCACHEDIR = FileSelectFolder ( LANG ( "GUI" , "ChooseCacheDir" , "选择浏览器缓存文件夹" ) , "" , 1 + 4 , FULLPATH ( $USERDATADIR ) & "\Default" , $HSETTINGS )
	If $SCACHEDIR <> "" Then
		$CACHEDIR = RELATIVEPATH ( $SCACHEDIR )
		GUICtrlSetData ( $HCACHEDIR , $CACHEDIR )
	EndIf
EndFunc
Func GUI_CHECKCHROMEUPDATE ( )
	AdlibUnRegister ( "GUI_CheckChromeUpdate" )
	$CHROMEPATH = GUICtrlRead ( $HCHROMEPATH )
	$CHANNEL = GUICtrlRead ( $HCHANNEL )
	$DOWNLOADTHREADS = GUICtrlRead ( $HDOWNLOADTHREADS )
	GUI_SETPROXY ( )
	GUICtrlSetData ( $HCHECKUPDATE , LANG ( "GUI" , "CancelUpdate" , "取消更新" ) )
	GUICtrlSetState ( $HSETTINGSOK , $GUI_DISABLE )
	GUICtrlSetState ( $HSETTINGSAPPLY , $GUI_DISABLE )
	If $SELECTEDURL Then
		Local $STRURL = $SELECTEDURL
		$SELECTEDURL = ""
		UPDATECHROME ( $CHROMEPATH , $CHANNEL , $STRURL )
	Else
		UPDATECHROME ( $CHROMEPATH , $CHANNEL )
	EndIf
EndFunc
Func UPDATECHROME ( $CHROMEPATH , $CHANNEL , $STRURL = "" )
	$CHROMEPATH = FULLPATH ( $CHROMEPATH )
	SPLITPATH ( $CHROMEPATH , $CHROMEDIR , $CHROMEEXE )
	If CHROMEISUPDATING ( $CHROMEDIR ) Then
		If IsHWnd ( $HSETTINGS ) Then
			MsgBox ( 64 , "MyBrowser" , LANG ( "Update" , "UpdateInProgress" , "浏览器上次更新仍在进行中！" ) , 0 , $HSETTINGS )
		EndIf
		ENDUPDATE ( )
		Return
	EndIf
	If $PROXYTYPE = "SYSTEM" Then
		GETIEPROXY ( $PROXYSEVER , $PROXYPORT )
	EndIf
	$ISUPDATING = 1
	Local $MSG , $ERROR , $RESPONSETIMER , $ADLINFO [ 6 ]
	If Not $LATESTCHROMEVER Then
		Do
			$LATESTCHROMEVER = ""
			$LATESTCHROMEURLS = ""
			$ERROR = ""
			_SETVAR ( "DLInfo" , "|||||" )
			$RESPONSETIMER = _NOWCALC ( )
			_SETVAR ( "ResponseTimer" , $RESPONSETIMER )
			If $PROXYTYPE = "DIRECT" Or Not $PROXYSEVER Then
				$ITHREADPID = _STARTTHREAD ( @ScriptFullPath , $GET_LATEST_CHROME_VER , $PLATFORM , $BROWSERTYPE , $CHANNEL , $X86 , $INIFILE )
			Else
				$ITHREADPID = _STARTTHREAD ( @ScriptFullPath , $GET_LATEST_CHROME_VER , $PLATFORM , $BROWSERTYPE , $CHANNEL , $X86 , $INIFILE , "HTTP:" & $PROXYSEVER & ":" & $PROXYPORT )
			EndIf
			While 1
				$RESPONSETIMER = _GETVAR ( "ResponseTimer" )
				$ADLINFO = StringSplit ( _GETVAR ( "DLInfo" ) , "|" , 2 )
				If UBound ( $ADLINFO ) >= 6 Then
					If IsHWnd ( $HSETTINGS ) Then
						_GUICTRLSTATUSBAR_SETTEXT ( $HSTAUSBAR , $ADLINFO [ 5 ] )
					EndIf
					If $ADLINFO [ 2 ] Then ExitLoop
				EndIf
				If Not ProcessExists ( $ITHREADPID ) Or _DATEDIFF ( "s" , $RESPONSETIMER , _NOWCALC ( ) ) > 30 Then
					$ERROR = LANG ( "Update" , "NoResponse" , "进程意外中止或无响应" )
					ExitLoop
				EndIf
				If Not $ISUPDATING Then
					ExitLoop 2
				EndIf
				Sleep ( 100 )
			WEnd
			_KILLTHREAD ( $ITHREADPID )
			If $ADLINFO [ 3 ] Then
				$LATESTCHROMEVER = $ADLINFO [ 0 ]
				$LATESTCHROMEURLS = $ADLINFO [ 1 ]
			Else
				If $ADLINFO [ 4 ] Then
					$ERROR = $ADLINFO [ 5 ]
				EndIf
				If IsHWnd ( $HSETTINGS ) Then
					_GUICTRLSTATUSBAR_SETTEXT ( $HSTAUSBAR , LANG ( "GUI" , "GetUpdateInfoFailed" , "获取更新信息失败" ) & " " & $ERROR )
				EndIf
			EndIf
			If Not $LATESTCHROMEVER Then
				If Not IsHWnd ( $HSETTINGS ) Then ExitLoop
				$MSG = MsgBox ( 16 + 5 , "MyBrowser" , LANG ( "GUI" , "GetUpdateInfoFailed" , "获取更新信息失败" ) & "！" & @CRLF & $ERROR & @CRLF & @CRLF & LANG ( "GUI" , "LastKnownVersion" , "上次已知版本" ) & ": " & IniRead ( $INIFILE , "Settings" , "LastKnownVersion" , "-" ) , 0 , $HSETTINGS )
			EndIf
		Until $LATESTCHROMEVER Or $MSG = 2
		If $LATESTCHROMEVER And IsHWnd ( $HSETTINGS ) Then
			GUICtrlSetData ( $HLATESTCHROMEVER , $LATESTCHROMEVER )
		EndIf
	EndIf
	If Not $LATESTCHROMEVER Then
		ENDUPDATE ( )
		Return
	EndIf
	$LASTCHECKUPDATE = _NOWCALC ( )
	IniWrite ( $INIFILE , "Settings" , "LastCheckUpdate" , $LASTCHECKUPDATE )
	IniWrite ( $INIFILE , "Settings" , "LastKnownVersion" , $LATESTCHROMEVER )
	_LOG ( "update check: " & $BROWSERTYPE & " / " & $CHANNEL & " latest=" & $LATESTCHROMEVER & " installed=" & $CHROMEFILEVERSION )
	$CHROMEFILEVERSION = FileGetVersion ( $CHROMEDIR & "\chrome.dll" , "FileVersion" )
	$EDGEFILEVERSION = FileGetVersion ( $CHROMEDIR & "\msedge.dll" , "FileVersion" )
	If StringInStr ( IniRead ( $INIFILE , "Settings" , "BrowserType" , "" ) , "Edge" ) Then
		If $LATESTCHROMEVER = $EDGEFILEVERSION Then
			If Not IsHWnd ( $HSETTINGS ) Then
				ENDUPDATE ( )
				Return
			EndIf
		EndIf
	Else
		If $LATESTCHROMEVER = $CHROMEFILEVERSION Then
			If Not IsHWnd ( $HSETTINGS ) Then
				ENDUPDATE ( )
				Return
			EndIf
		EndIf
	EndIf
	If Not IsHWnd ( $HSETTINGS ) Then
		If $LATESTCHROMEVER = IniRead ( $INIFILE , "Settings" , "SkippedVersion" , "" ) Then
			ENDUPDATE ( )
			Return
		EndIf
	EndIf
	Local $LANGUPDATETIPS = LANG ( "Update" , "UpdateTips" , "浏览器可以更新，是否立即下载？\n\n最新版本：\t%s\n您的版本：\t%s  %s\n\n【是】:立即更新  【否】:不更新(下次不提示)  【取消】:不更新(下次会提示)" )
	If StringInStr ( IniRead ( $INIFILE , "Settings" , "BrowserType" , "" ) , "Edge" ) Then
		Local $INFO = StringFormat ( $LANGUPDATETIPS , $LATESTCHROMEVER , $EDGEFILEVERSION )
	Else
		Local $INFO = StringFormat ( $LANGUPDATETIPS , $LATESTCHROMEVER , $CHROMEFILEVERSION )
	EndIf
	$MSG = 6
	If Not IsHWnd ( $HSETTINGS ) Then
		$MSG = MsgBox ( 64 + 3 , "MyBrowser" , $INFO )
	EndIf
	If $MSG = 7 Then
		; Skip this release only. It used to write UpdateInterval=-1, which turned
		; update checks off permanently - one declined prompt, no more updates ever.
		IniWrite ( $INIFILE , "Settings" , "SkippedVersion" , $LATESTCHROMEVER )
		_LOG ( "user skipped " & $LATESTCHROMEVER )
		ENDUPDATE ( )
		Return
	EndIf
	If $MSG = 2 Then
		ENDUPDATE ( )
		Return
	EndIf
	If FileExists ( $CHROMEDIR ) Then
		$CHROMEDIR = RELATIVEPATH ( $CHROMEDIR )
		If $CHROMEDIR = "." Then
			$FUGAI = MsgBox ( 64 + 4 , "MyBrowser" , $CHROMEEXE & $AND & @ScriptName & StringFormat ( LANG ( "GUI" , "fugaigengxin1" , "设置在同一目录(不推荐)，将会覆盖更新，是否继续？" ) ) , 0 , $HSETTINGS )
			If $FUGAI <> 6 Then
				ENDUPDATE ( )
				Return
			EndIf
		Else
			$FUGAI = MsgBox ( 64 + 3 , "MyBrowser" , StringFormat ( LANG ( "GUI" , "fugaigengxin2" , "是否覆盖更新？\n\n【是】:立即覆盖更新\n【否】:删除原程序目录后更新【危险：请注意备份重要文件】\n【取消】：取消本次操作" ) ) , 0 , $HSETTINGS )
			If $FUGAI = 7 Or $FUGAI = 6 Then
				If IniRead ( $INIFILE , "Settings" , "GreenChrome" , "" ) = 1 Then
					GUICtrlSetData ( $SETGC , LANG ( "GUI" , "setgcon" , "注入GreenChrome" ) )
					GUICtrlSetTip ( $SETGC , LANG ( "GUI" , "setgconTips" , "释放并注入GreenChrome" ) )
					GUICtrlSetState ( $GCSETTING , $GUI_DISABLE )
					GUICtrlSetState ( $SETGC , $GUI_ENABLE )
					IniWrite ( $INIFILE , "Settings" , "GreenChrome" , 0 )
				EndIf
				If ProcessExists ( $CHROMEEXE ) Then
					$FUGAI2 = MsgBox ( 64 + 1 , "MyBrowser" , StringFormat ( LANG ( "GUI" , "fugaigengxin3" , "检测到浏览器正在运行，是否关闭浏览器后更新？\n\n【确定】:关闭浏览后更新\n【取消】：不更新" ) ) , 0 , $HSETTINGS )
					If $FUGAI2 = 1 Then
						ProcessClose ( $CHROMEEXE )
						Sleep ( 2000 )
					EndIf
					If $FUGAI2 = 2 Then
						ENDUPDATE ( )
						Return
					EndIf
				EndIf
				If $FUGAI = 7 Then
					DirRemove ( $CHROMEDIR , 1 )
				EndIf
			ElseIf $FUGAI = 2 Then
				ENDUPDATE ( )
				Return
			EndIf
		EndIf
	EndIf
	; A Chrome update needs roughly 1.5 GB free while the old build is still there.
	Local $SFREEMB = DriveSpaceFree ( $CHROMEDIR )
	If $SFREEMB > 0 And $SFREEMB < 2048 Then
		If MsgBox ( 64 + 4 , "MyBrowser" , LANG ( "Update" , "LowDiskSpace" , "可用磁盘空间不足 2GB，更新可能失败。是否继续？" ) , 0 , $HSETTINGS ) <> 6 Then
			ENDUPDATE ( )
			Return
		EndIf
	EndIf
	Local $UPDATED , $URLS , $ICANCEL
	Local $LANGDOWNLOADINGCHROME = LANG ( "Update" , "DownloadingChrome" , "下载中" )
	$ISUPDATING = $LATESTCHROMEURLS
	$TEMPDIR = $CHROMEDIR & "\~update"
	Local $LOCALFILE = $TEMPDIR & "\installer.exe"
	If Not FileExists ( $TEMPDIR ) Then
		DirCreate ( $TEMPDIR )
	EndIf
	If IsHWnd ( $HSETTINGS ) Then
		_GUICTRLSTATUSBAR_SETTEXT ( $HSTAUSBAR , $LANGDOWNLOADINGCHROME & " ..." )
	ElseIf Not @TrayIconVisible Then
		TraySetState ( 1 )
		TraySetClick ( 8 )
		TraySetToolTip ( "MyBrowser" )
		TraySetOnEvent ( $TRAY_EVENT_PRIMARYDOWN , "TrayTipProgress" )
		$ICANCEL = TrayCreateItem ( LANG ( "Update" , "CancelUpdate" , "取消更新" ) & " ..." )
		TrayItemSetOnEvent ( - 1 , "CancelUpdate" )
		TrayTip ( "MyBrowser" , StringFormat ( "%s ...\n%s" , $LANGDOWNLOADINGCHROME , LANG ( "Update" , "DownloadChromeTips" , "点击图标可查看下载进度" ) ) , 10 , 1 )
	EndIf
	Local $RESUMEDOWNLOAD = 0 , $ERROR , $ERRORMSG
	If $STRURL Then
		$URLS = $STRURL
	Else
		$URLS = $LATESTCHROMEURLS
	EndIf
	While 1
		_SETVAR ( "ResponseTimer" , _NOWCALC ( ) )
		_SETVAR ( "DLInfo" , StringFormat ( "|||||%s ..." , $LANGDOWNLOADINGCHROME ) )
		If Not $ISUPDATING Then
			ExitLoop
		EndIf
		If $RESUMEDOWNLOAD Then
			_SETVAR ( "ResumeDownload" , 1 )
			If IsHWnd ( $HSETTINGS ) Then
				_GUICTRLSTATUSBAR_SETTEXT ( $HSTAUSBAR , LANG ( "Update" , "RestoringDownload" , "尝试恢复下载" ) & " ..." )
			EndIf
		Else
			If $PROXYTYPE = "DIRECT" Or Not $PROXYSEVER Then
				$ITHREADPID = _STARTTHREAD ( @ScriptFullPath , "download_chrome" , $URLS , $LOCALFILE , $DOWNLOADTHREADS , $INIFILE )
			Else
				$ITHREADPID = _STARTTHREAD ( @ScriptFullPath , "download_chrome" , $URLS , $LOCALFILE , $DOWNLOADTHREADS , $INIFILE , "HTTP:" & $PROXYSEVER & ":" & $PROXYPORT )
			EndIf
			IniWrite ( $TEMPDIR & "\Update.ini" , "general" , "pid" , $ITHREADPID )
			IniWrite ( $TEMPDIR & "\Update.ini" , "general" , "exe" , StringRegExpReplace ( @AutoItExe , ".*\\" , "" ) )
			IniWrite ( $TEMPDIR & "\Update.ini" , "general" , "latest" , $LATESTCHROMEVER )
			IniWrite ( $TEMPDIR & "\Update.ini" , "general" , "url" , $URLS )
		EndIf
		Local $ADLINFO [ 6 ]
		While 1
			$ADLINFO = StringSplit ( _GETVAR ( "DLInfo" ) , "|" , 2 )
			If IsHWnd ( $HSETTINGS ) Then
				_GUICTRLSTATUSBAR_SETTEXT ( $HSTAUSBAR , $ADLINFO [ 5 ] )
			ElseIf $TRAYTIPPROGRESS Or TRAYTIPEXISTS ( $LANGDOWNLOADINGCHROME ) Then
				$TIPS = StringRegExpReplace ( $ADLINFO [ 5 ] , "\.\.\. *" , "..." & @CRLF )
				TrayTip ( "MyBrowser" , $TIPS , 10 , 1 )
				$TRAYTIPPROGRESS = 0
			EndIf
			$PROG = StringRegExp ( _GETVAR ( "DLInfo" ) , ".*\s(.*?)%" , 3 )
			If Not @error Then GUICtrlSetData ( $HPROGRESS1 , $PROG [ 0 ] + 1 )
			If $ADLINFO [ 2 ] Then ExitLoop
			If Not ProcessExists ( $ITHREADPID ) Or _DATEDIFF ( "s" , _GETVAR ( "ResponseTimer" ) , _NOWCALC ( ) ) > 30 Then
				$ERROR = LANG ( "Update" , "NoResponse" , "进程意外中止或无响应" )
				ExitLoop
			EndIf
			If Not $ISUPDATING Then
				ExitLoop 2
			EndIf
			Sleep ( 100 )
		WEnd
		If $ADLINFO [ 2 ] And $ADLINFO [ 3 ] Then
			FileSetAttrib ( $LOCALFILE , "+A" )
			$UPDATED = INSTALLCHROME ( )
			ExitLoop
		EndIf
		If $ADLINFO [ 4 ] Then
			$ERROR = $ADLINFO [ 5 ]
		EndIf
		If $ADLINFO [ 4 ] = 10 Then
			$RESUMEDOWNLOAD = 1
		Else
			$RESUMEDOWNLOAD = 0
			_KILLTHREAD ( $ITHREADPID )
		EndIf
		Local $LANGDOWNLOADFAILED = LANG ( "Update" , "DownloadFailed" , "下载浏览器失败" )
		If IsHWnd ( $HSETTINGS ) Then
			_GUICTRLSTATUSBAR_SETTEXT ( $HSTAUSBAR , $LANGDOWNLOADFAILED & " " & $ERROR )
		EndIf
		$MSG = MsgBox ( 16 + 5 , "MyBrowser" , $LANGDOWNLOADFAILED & "！" & @CRLF & $ERROR , 0 , $HSETTINGS )
		If $MSG <> 4 Then ExitLoop
	WEnd
	If @TrayIconVisible Then
		TrayItemDelete ( $ICANCEL )
		TraySetState ( 2 )
	EndIf
	ENDUPDATE ( )
	Return $UPDATED
EndFunc
Func CANCELUPDATE ( )
	Local $MSG = MsgBox ( 292 , "MyBrowser" , LANG ( "Update" , "CancelUpdateConfirm" , "浏览器正在更新，确定要取消吗？" ) )
	If $MSG = 6 Then
		$ISUPDATING = 0
	EndIf
EndFunc
Func _HASPARAM ( $SFLAG )
	Local $I
	For $I = 1 To $CMDLINE [ 0 ]
		If $CMDLINE [ $I ] = $SFLAG Then Return 1
	Next
	Return 0
EndFunc
Func _SELFTEST ( )
	; Probes every wired source through the same code the update path uses, then writes
	; a report next to the exe. Exit code is the number of required sources that failed.
	; Edge is left out on purpose: its MSXML2 request is synchronous and has no
	; timeout, so it can hang the probe. It is the one source that is not verified.
	Local $ABROWSER [ 5 ] [ 3 ] = [ _
		[ "Chrome" , "Stable" , 1 ] , _
		[ "Chromium" , "" , 1 ] , _
		[ "Brave" , "Release" , 1 ] , _
		[ "Firefox" , "Release" , 1 ] , _
		[ "Vivaldi" , "" , 1 ] ]
	Local $I , $SINFO , $AINFO , $SLINES = "" , $IFAIL = 0
	; Written after every probe, so a hung source still leaves evidence behind.
	Local $HREP = FileOpen ( @ScriptDir & "\MyBrowser.selftest.txt" , 2 )
	For $I = 0 To UBound ( $ABROWSER ) - 1
		If $HREP <> - 1 Then
			FileWrite ( $HREP , "PROBE " & $ABROWSER [ $I ] [ 0 ] & @CRLF )
			FileFlush ( $HREP )
		EndIf
		_SETVAR ( "DLInfo" , "" )
		GET_LATEST_CHROME_VER ( "win" , $ABROWSER [ $I ] [ 0 ] , $ABROWSER [ $I ] [ 1 ] , 0 , "MyBrowser.ini" )
		$SINFO = _GETVAR ( "DLInfo" )
		$AINFO = StringSplit ( $SINFO , "|" , 2 )
		If UBound ( $AINFO ) >= 2 And $AINFO [ 0 ] <> "" Then
			$SLINES &= "PASS  " & $ABROWSER [ $I ] [ 0 ] & "  " & $AINFO [ 0 ] & "  " & StringLeft ( $AINFO [ 1 ] , 90 ) & @CRLF
		ElseIf $ABROWSER [ $I ] [ 2 ] = 1 Then
			$IFAIL += 1
			$SLINES &= "FAIL  " & $ABROWSER [ $I ] [ 0 ] & "  " & StringReplace ( $SINFO , "|" , " " ) & @CRLF
		Else
			$SLINES &= "INFO  " & $ABROWSER [ $I ] [ 0 ] & "  not required: " & StringReplace ( $SINFO , "|" , " " ) & @CRLF
		EndIf
	Next
	If $HREP <> - 1 Then
		FileWrite ( $HREP , $SLINES )
		FileClose ( $HREP )
	EndIf
	Return $IFAIL
	Return $IFAIL
EndFunc
Func _LOG ( $SMSG )
	; Append-only support log next to the exe. Never let logging break an update.
	Local $SLOGFILE = @ScriptDir & "\MyBrowser.log"
	If FileExists ( $SLOGFILE ) Then
		If FileGetSize ( $SLOGFILE ) > 262144 Then FileDelete ( $SLOGFILE )
	EndIf
	Local $H = FileOpen ( $SLOGFILE , 1 )
	If $H = - 1 Then Return 0
	FileWriteLine ( $H , @YEAR & "-" & @MON & "-" & @MDAY & " " & @HOUR & ":" & @MIN & ":" & @SEC & "  " & $SMSG )
	FileClose ( $H )
	Return 1
EndFunc
Func _ZIPBROWSERDIR ( $SDIR , $SEXE )
	; Returns the single subfolder of $SDIR that holds $SEXE, or "" if there is none.
	Local $H = FileFindFirstFile ( $SDIR & "\*.*" )
	If $H = - 1 Then Return ""
	Local $SN
	While 1
		$SN = FileFindNextFile ( $H )
		If @error Then ExitLoop
		If $SN = "." Or $SN = ".." Then ContinueLoop
		If StringInStr ( FileGetAttrib ( $SDIR & "\" & $SN ) , "D" ) And FileExists ( $SDIR & "\" & $SN & "\" & $SEXE ) Then
			FileClose ( $H )
			Return $SN
		EndIf
	WEnd
	FileClose ( $H )
	Return ""
EndFunc
Func _MOVETEMPCONTENTS ( $SSRC , $SDST )
	; Moves every file and folder from $SSRC into $SDST, leaving the download tools behind.
	Local $H = FileFindFirstFile ( $SSRC & "\*.*" )
	If $H = - 1 Then Return 0
	Local $SN
	While 1
		$SN = FileFindNextFile ( $H )
		If @error Then ExitLoop
		If $SN = "." Or $SN = ".." Then ContinueLoop
		If $SN = "installer.exe" Or $SN = "7z.exe" Or $SN = "7z.dll" Or $SN = "Update.ini" Then ContinueLoop
		If StringInStr ( FileGetAttrib ( $SSRC & "\" & $SN ) , "D" ) Then
			DirMove ( $SSRC & "\" & $SN , $SDST & "\" & $SN , 1 )
		Else
			FileMove ( $SSRC & "\" & $SN , $SDST & "\" & $SN , 9 )
		EndIf
	WEnd
	FileClose ( $H )
	Return 1
EndFunc
Func _MOZILLA_FIREFOX_VER ( $HHTTPOPEN , $CHANNEL )
	; InetRead, not the inlined WinHTTP UDF: Mozilla answers with chunked encoding and the
	; bundled reader never returns on it. This call used to hang the version lookup.
	Local $SKEY = "LATEST_FIREFOX_VERSION"
	If $CHANNEL = "ESR" Then $SKEY = "FIREFOX_ESR"
	If $CHANNEL = "Beta" Then $SKEY = "LATEST_FIREFOX_DEVEL_VERSION"
	If $CHANNEL = "Dev" Then $SKEY = "LATEST_FIREFOX_DEVEL_VERSION"
	If $CHANNEL = "Nightly" Then $SKEY = "FIREFOX_NIGHTLY"
	Local $SBODY = BinaryToString ( InetRead ( "https://product-details.mozilla.org/1.0/firefox_versions.json" , 1 ) , 4 )
	If $SBODY = "" Then Return ""
	Local $AM = StringRegExp ( $SBODY , '"' & $SKEY & '"\s*:\s*"([^"]+)"' , 1 )
	If @error Then Return ""
	Return StringRegExpReplace ( $AM [ 0 ] , "(?i)(esr|a1|b\d+)$" , "" )
EndFunc
Func _BRAVE_GITHUB_LATEST ( $HHTTPOPEN , $NEED_X86 )
	; Brave publishes portable ZIPs per release; read the newest one from the GitHub API.
	Local $SPLAT = "x64"
	If $NEED_X86 Then $SPLAT = "ia32"
	Local $HCONNECT = _WINHTTPCONNECT ( $HHTTPOPEN , "api.github.com" )
	If @error Then Return ""
	Local $SBODY = _WINHTTPSIMPLESSLREQUEST ( $HCONNECT , "GET" , "/repos/brave/brave-browser/releases/latest" , Default , Default , "User-Agent: MyBrowser" )
	Local $IERR = @error
	_WINHTTPCLOSEHANDLE ( $HCONNECT )
	If $IERR Or $SBODY = "" Then Return ""
	Local $AM = StringRegExp ( $SBODY , '"name"\s*:\s*"(brave-v([\d.]+)-win32-' & $SPLAT & '\.zip)"' , 1 )
	If @error Then Return ""
	Return $AM [ 1 ] & "|https://github.com/brave/brave-browser/releases/download/v" & $AM [ 1 ] & "/" & $AM [ 0 ]
EndFunc
Func _VIVALDI_LATEST ( $HHTTPOPEN , $NEED_X86 )
	; Sparkle appcast: the newest enclosure is the full installer, deltas carry a .cab suffix.
	Local $SPATH = "/update/1.0/public/appcast.x64.xml"
	If $NEED_X86 Then $SPATH = "/update/1.0/public/appcast.xml"
	Local $HCONNECT = _WINHTTPCONNECT ( $HHTTPOPEN , "update.vivaldi.com" )
	If @error Then Return ""
	Local $SBODY = _WINHTTPSIMPLESSLREQUEST ( $HCONNECT , "GET" , $SPATH , Default , Default , "User-Agent: MyBrowser" )
	Local $IERR = @error
	_WINHTTPCLOSEHANDLE ( $HCONNECT )
	If $IERR Or $SBODY = "" Then Return ""
	Local $AURL = StringRegExp ( $SBODY , 'url="([^"]+\.exe)"' , 1 )
	If @error Then Return ""
	Local $SVER = ""
	Local $AVER = StringRegExp ( $SBODY , 'sparkle:version="([\d.]+)"' , 1 )
	If Not @error Then $SVER = $AVER [ 0 ]
	If $SVER = "" Then
		Local $AFROMFILE = StringRegExp ( $AURL [ 0 ] , 'Vivaldi\.([\d.]+)\.exe' , 1 )
		If Not @error Then $SVER = $AFROMFILE [ 0 ]
	EndIf
	Return $SVER & "|" & $AURL [ 0 ]
EndFunc
Func _CFT_GETLATEST ( $HHTTPOPEN , $CHANNEL , $NEED_X86 )
	; Returns "version|zip_url" for the requested Chrome channel, or "" on failure.
	Local $SCH = $CHANNEL
	If $SCH = "" Then $SCH = "Stable"
	If $SCH <> "Stable" And $SCH <> "Beta" And $SCH <> "Dev" And $SCH <> "Canary" Then Return ""
	Local $SPLAT = "win64"
	If $NEED_X86 Then $SPLAT = "win32"
	Local $SHOST = "googlechromelabs.github.io"
	Local $SPATH = "/chrome-for-testing/last-known-good-versions-with-downloads.json"
	Local $HCONNECT = _WINHTTPCONNECT ( $HHTTPOPEN , $SHOST )
	If @error Then Return ""
	Local $SBODY = _WINHTTPSIMPLESSLREQUEST ( $HCONNECT , "GET" , $SPATH , Default , Default , "User-Agent: MyBrowser" )
	Local $IERR = @error
	_WINHTTPCLOSEHANDLE ( $HCONNECT )
	If $IERR Or $SBODY = "" Then Return ""
	Local $IPOS = StringInStr ( $SBODY , '"' & $SCH & '"' )
	If Not $IPOS Then Return ""
	Local $SSUB = StringMid ( $SBODY , $IPOS , 8000 )
	Local $AVER = StringRegExp ( $SSUB , '(?s)"version"\s*:\s*"([\d.]+)"' , 1 )
	If @error Then Return ""
	Local $AURL = StringRegExp ( $SSUB , '(?s)"platform"\s*:\s*"' & $SPLAT & '"\s*,\s*"url"\s*:\s*"([^"]+)"' , 1 )
	If @error Then Return ""
	Return $AVER [ 0 ] & "|" & $AURL [ 0 ]
EndFunc
Func GET_LATEST_CHROME_VER ( $PLATFORM , $BROWSERTYPE , $CHANNEL , $X86 = 0 , $INIFILE = "MyBrowser.ini" , $PROXY = "" )
	Local $HOST , $URLBASE , $VAR , $LATESTVER , $LATESTURLS
	Local $HTTP = "https"
	Local $OSARCH = StringLower ( @OSArch )
	$X86 = $X86 * 1
	AdlibRegister ( "ResetTimer" , 1000 )
	Local $SPROXY
	If StringInStr ( $PROXY , "HTTP:" ) == 1 Then
		$ARR = StringSplit ( $PROXY , ":" , 2 )
		$PROXYSEVER = $ARR [ 1 ]
		$PROXYPORT = $ARR [ 2 ]
		$SPROXY = $PROXYSEVER & ":" & $PROXYPORT
	EndIf
	Local $HHTTPOPEN , $HCONNECT , $NAME , $A , $HREQUEST , $SHEADER , $ERROR
	If Not $SPROXY Then
		$HHTTPOPEN = _WINHTTPOPEN ( $USERAGENT )
	Else
		$HHTTPOPEN = _WINHTTPOPEN ( $USERAGENT , $WINHTTP_ACCESS_TYPE_NAMED_PROXY , $SPROXY , "localhost" )
	EndIf
	_WINHTTPSETTIMEOUTS ( $HHTTPOPEN , 0 , 3000 , 3000 , 3000 )
	$LANGGETCHROMECHANCES = LANG ( "Update" , "GetChromeChances" , "从服务器获取 %s 更新信息... 第 %d 次尝试" )
	$LANGNOSERVERRESP = LANG ( "Update" , "NoServerResp" , "服务器无响应" )
	$LANGPARSEINFOFAILED = LANG ( "Update" , "ParseInfoFailed" , "服务器返回的更新信息无法解析" )
	$LANGUPDATEGOT = LANG ( "Update" , "UpdateGot" , "已成功获取 %s 更新信息" )
	Local $NEED_X86 , $APPID , $AP , $DATA , $MATCH
	If $X86 Or $OSARCH = "x86" Then
		$NEED_X86 = True
	EndIf
	If $BROWSERTYPE = "Firefox" Then
		If $PLATFORM = "mac" Then $OSARCH = "osx"
		If $CHANNEL = "Release" Or $CHANNEL = "" Then $AP = "firefox-latest"
		If $CHANNEL = "ESR" Then $AP = "firefox-esr-latest"
		If $CHANNEL = "Beta" Then $AP = "firefox-beta-latest"
		If $CHANNEL = "Dev" Then $AP = "firefox-devedition-latest"
		If $CHANNEL = "Nightly" Then $AP = "firefox-nightly-latest"
		If $NEED_X86 Then
			If $PLATFORM = "win" Then
				$OSARCH = "Win"
			ElseIf $PLATFORM = "linux" Then
				$OSARCH = "Linux"
				$AP = "firefox-latest"
			EndIf
		Else
			If $PLATFORM = "win" Then
				$OSARCH = "Win64"
			ElseIf $PLATFORM = "linux" Then
				$OSARCH = "Linux64"
				$AP = "firefox-latest"
			EndIf
		EndIf
		_SETVAR ( "DLInfo" , "|||||" & StringFormat ( $LANGGETCHROMECHANCES , "Firefox" , $I ) )
		$LATESTURLS = "https://download.mozilla.org/?product=" & $AP & "&" & "os=" & $OSARCH & "&" & "lang=zh-CN"
		; The version has to be resolved separately: without it the caller treats the
		; lookup as failed and never starts the download.
		$LATESTVER = _MOZILLA_FIREFOX_VER ( $HHTTPOPEN , $CHANNEL )
		If $LATESTVER = "" Then $LATESTVER = "latest"
		_SETVAR ( "DLInfo" , $LATESTVER & "|" & $LATESTURLS & "|1|1||" & StringFormat ( $LANGUPDATEGOT , "Firefox" ) )
	EndIf
	If $BROWSERTYPE = "Chromium" Then
		If $PLATFORM = "mac" Then $OSARCH = "Mac"
		If $PLATFORM = "android" Then $OSARCH = "Android"
		If $NEED_X86 Then
			If $PLATFORM = "win" Then
				$OSARCH = "Win"
			ElseIf $PLATFORM = "linux" Then
				$OSARCH = "Linux"
			EndIf
		Else
			If $PLATFORM = "win" Then
				$OSARCH = "Win_x64"
			ElseIf $PLATFORM = "linux" Then
				$OSARCH = "Linux_x64"
			EndIf
		EndIf
		$HOST = $HTTP & "://storage.googleapis.com"
		$URLBASE = "chromium-browser-snapshots"
		For $I = 1 To 3
			_SETVAR ( "DLInfo" , "|||||" & StringFormat ( $LANGGETCHROMECHANCES , "Chromium" , $I ) )
			$HCONNECT = _WINHTTPCONNECT ( $HHTTPOPEN , $HOST )
			$VAR = _WINHTTPSIMPLESSLREQUEST ( $HCONNECT , "GET" , $URLBASE & "/" & $OSARCH & "/LAST_CHANGE" )
			$ERROR = @error
			_WINHTTPCLOSEHANDLE ( $HCONNECT )
			If $ERROR Then
				$ERROR = $LANGNOSERVERRESP
			Else
				If StringIsDigit ( $VAR ) And $VAR > 0 Then
					$LATESTVER = $VAR
					If StringInStr ( $PLATFORM , "win" ) Then
						$LATESTURLS = $HOST & "/" & $URLBASE & "/" & $OSARCH & "/" & $VAR & "/chrome-win.zip"
					ElseIf StringInStr ( $PLATFORM , "mac" ) Or StringInStr ( $PLATFORM , "linux" ) Or StringInStr ( $PLATFORM , "android" ) Then
						$LATESTURLS = $HOST & "/" & $URLBASE & "/" & $OSARCH & "/" & $VAR & "/chrome-" & $PLATFORM & ".zip"
					EndIf
					ExitLoop
				Else
					$ERROR = $LANGPARSEINFOFAILED
				EndIf
			EndIf
			_WINHTTPCLOSEHANDLE ( $HCONNECT )
		Next
		_WINHTTPCLOSEHANDLE ( $HHTTPOPEN )
		If $LATESTVER Then
			_SETVAR ( "DLInfo" , $LATESTVER & "|" & $LATESTURLS & "|1|1||" & StringFormat ( $LANGUPDATEGOT , "Chromium" ) )
		Else
			_SETVAR ( "DLInfo" , "||1||1|" & $ERROR )
		EndIf
		Return
	EndIf
	If $BROWSERTYPE = "Edge" Then
		Switch $CHANNEL
		Case "Stable"
			If $NEED_X86 Then
				$AP = "msedge-stable-win-x86"
				$OSARCH = "x86"
			Else
				$AP = "msedge-stable-win-x64"
				$OSARCH = "x64"
			EndIf
		Case "Beta"
			If $NEED_X86 Then
				$AP = "msedge-beta-win-x86"
				$OSARCH = "x86"
			Else
				$AP = "msedge-beta-win-x64"
				$OSARCH = "x64"
			EndIf
		Case "Dev"
			If $NEED_X86 Then
				$AP = "msedge-dev-win-x86"
				$OSARCH = "x86"
			Else
				$AP = "msedge-dev-win-x64"
				$OSARCH = "x64"
			EndIf
		Case "Canary"
			If $NEED_X86 Then
				$AP = "msedge-canary-win-x86"
				$OSARCH = "x86"
			Else
				$AP = "msedge-canary-win-x64"
				$OSARCH = "x64"
			EndIf
		EndSwitch
		For $I = 1 To 3
			$DATA = "{""targetingAttributes"":{""AppAp"":"""",""AppCohort"":"""",""AppLang"":""de-de"",""AppRollout"":""1.0"",""AppVersion"":"""",""IsMachine"":""0"",""OsArch"":""" & $OSARCH & """,""OsPlatform"":""win"",""OsVersion"":"""",""Updater"":""MicrosoftEdgeUpdate"",""UpdaterVersion"":""1.3.183.29""}}"
			$OHTTP = ObjCreate ( "MSXML2.XMLHTTP.6.0" )
			$OHTTP .open ( "POST" , "https://msedge.api.cdp.microsoft.com/api/v1.1/contents/Browser/namespaces/Default/names/" & $AP & "/versions/latest?action=select" , False )
			$OHTTP .setRequestHeader ( "User-Agent" , "Microsoft Edge Update/1.3.183.29;winhttp" )
			$OHTTP .setrequestheader ( "Content-Type" , "application/json" )
			$OHTTP .send ( $DATA )
			$ORECEIVED = $OHTTP .responsetext
			$POSITION = StringInStr ( $ORECEIVED , """Version"":""" )
			$URLTMP = StringMid ( $ORECEIVED , $POSITION + 11 , StringLen ( $ORECEIVED ) - $POSITION - 11 )
			$URL = StringSplit ( $URLTMP , """" )
			$EDGEVERSION = $URL [ 1 ]
			$VAR = $EDGEVERSION
			$DATA = "{}"
			$OHTTP = ObjCreate ( "MSXML2.XMLHTTP.6.0" )
			$OHTTP .open ( "Post" , "https://msedge.api.cdp.microsoft.com/api/v1.1/internal/contents/Browser/namespaces/Default/names/" & $AP & "/versions/" & $EDGEVERSION & "/files?action=GenerateDownloadInfo&foregroundPriority=true" , False )
			$OHTTP .setRequestHeader ( "User-Agent" , "Microsoft Edge Update/1.3.183.29;winhttp" )
			$OHTTP .setrequestheader ( "Content-Type" , "application/json" )
			$OHTTP .send ( $DATA )
			$ORECEIVED = $OHTTP .responsetext
			If $OSARCH == "x86" Then
				$POSITION = StringInStr ( $ORECEIVED , """Url"":""" )
				$POSITION2 = StringInStr ( $ORECEIVED , """,""FileId""" )
				$EDGELENGTH = $POSITION2 - $POSITION
				$URL4 = StringMid ( $ORECEIVED , $POSITION + 7 , $EDGELENGTH - 7 )
			ElseIf $OSARCH == "x64" Then
				$SJSON = StringTrimLeft ( $ORECEIVED , 1 )
				$SJSON = StringTrimRight ( $SJSON , 1 )
				Local $APARTS = StringSplit ( $SJSON , "},{" , 3 )
				Local $SCORRECTURL = ""
				For $I = 0 To UBound ( $APARTS ) - 1
					Local $SPART = $APARTS [ $I ]
					Local $SPATTERN = """FileId"":"""
					Local $IPOS = StringInStr ( $SPART , $SPATTERN )
					If $IPOS > 0 Then
						$SPART = StringTrimLeft ( $SPART , $IPOS + StringLen ( $SPATTERN ) - 1 )
						$IPOS = StringInStr ( $SPART , """," , 3 )
						If $IPOS > 0 Then
							Local $SFILEID = StringLeft ( $SPART , $IPOS - 1 )
							If COUNTUNDERSCORES ( $SFILEID ) = 2 Then
								$IPOS = StringInStr ( $APARTS [ $I ] , """Url"":""" )
								If $IPOS > 0 Then
									$SPATTERN = """Url"":"""
									$IPOS = StringInStr ( $APARTS [ $I ] , $SPATTERN )
									If $IPOS > 0 Then
										$APARTS [ $I ] = StringTrimLeft ( $APARTS [ $I ] , $IPOS + StringLen ( $SPATTERN ) - 1 )
										$IPOS = StringInStr ( $APARTS [ $I ] , """," )
										If $IPOS > 0 Then
											$SCORRECTURL = StringLeft ( $APARTS [ $I ] , $IPOS - 1 )
										EndIf
									Else
										$SCORRECTURL = ""
									EndIf
								EndIf
							EndIf
						EndIf
					EndIf
				Next
				If Not $SCORRECTURL = "" Then
					$URL4 = $SCORRECTURL
				Else
					EDGEDOWNLOAD ( )
					Exit
				EndIf
			EndIf
			_SETVAR ( "DLInfo" , "|||||" & StringFormat ( $LANGGETCHROMECHANCES , "Edge" , $I ) )
			$LATESTVER = $VAR
			$LATESTURLS = $URL4
			_WINHTTPCLOSEHANDLE ( $HCONNECT )
		Next
		_WINHTTPCLOSEHANDLE ( $HHTTPOPEN )
		If $LATESTVER Then
			_SETVAR ( "DLInfo" , $LATESTVER & "|" & $LATESTURLS & "|1|1||" & StringFormat ( $LANGUPDATEGOT , "Edge" ) )
		Else
			_SETVAR ( "DLInfo" , "||1||1|" & $ERROR )
		EndIf
		Return
	EndIf
	If $BROWSERTYPE = "Chrome" Then
		If $PLATFORM = "win" Then
			; Chrome for Testing is the primary source: official JSON API, direct ZIP,
			; no installer unpacking and no dependency on the Omaha update service.
			Local $CFT = ""
			For $CFTI = 1 To 3
				$CFT = _CFT_GETLATEST ( $HHTTPOPEN , $CHANNEL , $NEED_X86 )
				If $CFT <> "" Then ExitLoop
			Next
			If $CFT <> "" Then
				Local $ACFT = StringSplit ( $CFT , "|" , 2 )
				If UBound ( $ACFT ) = 2 Then
					_WINHTTPCLOSEHANDLE ( $HHTTPOPEN )
					_SETVAR ( "DLInfo" , $ACFT [ 0 ] & "|" & $ACFT [ 1 ] & "|1|1||" & StringFormat ( $LANGUPDATEGOT , "Chrome" ) )
					Return
				EndIf
			EndIf
			$VERSION1 = "10.0.26100.1742"
			Switch $CHANNEL
			Case "Stable"
				$APPID = "{8A69D345-D564-463C-AFF1-A69D9E530F96}"
				If $NEED_X86 Then
					$AP = ""
					$OSARCH = "x86"
				Else
					$AP = ""
				EndIf
			Case "Beta"
				$APPID = "{8A69D345-D564-463C-AFF1-A69D9E530F96}"
				If $NEED_X86 Then
					$AP = "1.1-beta"
					$OSARCH = "x86"
				Else
					$AP = "x64-beta-multi-chrome"
				EndIf
			Case "Dev"
				$APPID = "{8A69D345-D564-463C-AFF1-A69D9E530F96}"
				If $NEED_X86 Then
					$AP = "2.0-dev"
					$OSARCH = "x86"
				Else
					$AP = "x64-dev-multi-chrome"
				EndIf
			Case "Canary"
				$APPID = "{4EA16AC7-FD5A-47C3-875B-DBF4A2008C20}"
				If $NEED_X86 Then
					$AP = "x86-canary"
					$OSARCH = "x86"
				Else
					$AP = "x64-canary"
				EndIf
			EndSwitch
		ElseIf $PLATFORM = "mac" Then
			$VERSION1 = "46.0.2490.86"
			Switch $CHANNEL
			Case "Stable"
				$APPID = "com.google.Chrome"
				$AP = ""
			Case "Beta"
				$APPID = "com.google.Chrome.beta"
				$AP = "betachannel"
			Case "Dev"
				$APPID = "com.google.Chrome.dev"
				$AP = "devchannel"
			Case "Canary"
				$APPID = "com.google.Chrome.Canary"
				$AP = ""
			EndSwitch
		EndIf
		Local $A = MemGetStats ( )
		Local $PHYSMEMORY = Round ( $A [ 1 ] / 1024 / 1024 )
		$DATA = "<?xml version=""1.0"" encoding=""UTF-8""?><request protocol=""3.0"" version=""1.3.23.9"" shell_version=""1.3.21.103"" ismachine=""0"" sessionid=""{3597644B-2952-4F92-AE55-D315F45F80A5}"" installsource=""ondemandcheckforupdate"" requestid=""{CD7523AD-A40D-49F4-AEEF-8C114B804658}"" dedup=""cr"">" & "<hw physmemory=""12582912"" sse=""1"" sse2=""1"" sse3=""1"" ssse3=""1"" sse41=""1"" sse42=""1"" avx=""1""/>" & "<os platform=""" & $PLATFORM & """ version=""" & $VERSION1 & """ arch=""" & $OSARCH & """/>" & "<app appid=""" & $APPID & """ version="""" nextversion="""" ap=""" & $AP & """ lang=""zh-CN""><updatecheck/></app></request>"
		For $I = 1 To 3
			_SETVAR ( "DLInfo" , "|||||" & StringFormat ( $LANGGETCHROMECHANCES , "Chrome" , $I ) )
			$HCONNECT = _WINHTTPCONNECT ( $HHTTPOPEN , "https://tools.google.com" )
			$VAR = _WINHTTPSIMPLESSLREQUEST ( $HCONNECT , "POST" , "service/update2" , Default , $DATA , "User-Agent: Google Update/1.3.32.7;winhttp;cup-ecdsa" )
			$ERROR = @error
			_WINHTTPCLOSEHANDLE ( $HCONNECT )
			If $ERROR Then
				$ERROR = $LANGNOSERVERRESP
			Else
				$MATCH = StringRegExp ( $VAR , "(?i)<manifest +version=""(.+?)"".* name=""(.+?)""" , 1 )
				If @error Then
					$ERROR = $LANGPARSEINFOFAILED
				Else
					$ERROR = ""
					ExitLoop
				EndIf
			EndIf
			_WINHTTPCLOSEHANDLE ( $HCONNECT )
		Next
		If Not $ERROR Then
			$VERSION = $MATCH [ 0 ]
			$NAME = $MATCH [ 1 ]
			; https only: the manifest also lists plain-http mirrors, and they used to be tried first.
			$MATCH = StringRegExp ( $VAR , "(?i)<url +codebase=""(https://.+?)""" , 3 )
			If Not @error Then
				For $I = 0 To UBound ( $MATCH ) - 1
					$LATESTURLS &= " " & $MATCH [ $I ] & $NAME
				Next
				$LATESTVER = $VERSION
				$LATESTURLS = StringStripWS ( $LATESTURLS , 3 )
			EndIf
		EndIf
		_WINHTTPCLOSEHANDLE ( $HHTTPOPEN )
		If $LATESTVER Then
			_SETVAR ( "DLInfo" , $LATESTVER & "|" & $LATESTURLS & "|1|1||" & StringFormat ( $LANGUPDATEGOT , "Chrome" ) )
		Else
			_SETVAR ( "DLInfo" , "||1||1|" & $ERROR )
		EndIf
	EndIf
	If $BROWSERTYPE = "Brave" Then
		If $PLATFORM = "win" Then
			; Brave publishes a portable ZIP per release; prefer it over the Omaha
			; installer path, which has to be unpacked afterwards.
			Local $BG = _BRAVE_GITHUB_LATEST ( $HHTTPOPEN , $NEED_X86 )
			If $BG <> "" Then
				Local $ABG = StringSplit ( $BG , "|" , 2 )
				If UBound ( $ABG ) = 2 Then
					_WINHTTPCLOSEHANDLE ( $HHTTPOPEN )
					_SETVAR ( "DLInfo" , $ABG [ 0 ] & "|" & $ABG [ 1 ] & "|1|1||" & StringFormat ( $LANGUPDATEGOT , "Brave" ) )
					Return
				EndIf
			EndIf
			Switch $CHANNEL
			Case "Release"
				$APPID = "{AFE6A462-C574-4B8A-AF43-4CC60DF4563B}"
				If $NEED_X86 Then
					$AP = "x86-rel"
					$OSARCH = "x86"
				Else
					$AP = "x64-rel"
					$OSARCH = "x64"
				EndIf
			Case "Beta"
				$APPID = "{103BD053-949B-43A8-9120-2E424887DE11}"
				If $NEED_X86 Then
					$AP = "x86-be"
					$OSARCH = "x86"
				Else
					$AP = "x64-be"
					$OSARCH = "x64"
				EndIf
			Case "Dev"
				$APPID = "{CB2150F2-595F-4633-891A-E39720CE0531}"
				If $NEED_X86 Then
					$AP = "x86-dev"
					$OSARCH = "x86"
				Else
					$AP = "x64-dev"
					$OSARCH = "x64"
				EndIf
			Case "Nightly"
				$APPID = "{C6CB981E-DB30-4876-8639-109F8933582C}"
				If $NEED_X86 Then
					$AP = "x86-ni"
					$OSARCH = "x86"
				Else
					$AP = "x64-ni"
					$OSARCH = "x64"
				EndIf
			EndSwitch
		EndIf
		$DATA = "<?xml version=""1.0"" encoding=""UTF-8""?><request protocol=""3.0"" version=""1.3.99.0"" shell_version=""1.3.99.0"" ismachine=""1"" sessionid=""{11111111-1111-1111-1111-111111111111}"" installsource=""taggedmi"" testsource=""auto"" requestid=""{11111111-1111-1111-1111-111111111111}"" dedup=""cr""><os platform=""win"" version="""" sp="""" arch=""" & $OSARCH & """/><app appid=""" & $APPID & """ version="""" nextversion="""" ap=""" & $AP & """ lang=""en"" brand="""" client="""" installage=""-1"" installdate=""-1""><updatecheck/></app></request>"
		For $I = 1 To 3
			_SETVAR ( "DLInfo" , "|||||" & StringFormat ( $LANGGETCHROMECHANCES , "Brave" , $I ) )
			$HCONNECT = _WINHTTPCONNECT ( $HHTTPOPEN , "https://updates.bravesoftware.com" )
			$VAR = _WINHTTPSIMPLESSLREQUEST ( $HCONNECT , "POST" , "service/update2" , Default , $DATA , "User-Agent: Google Update/1.3.101.0;winhttp" )
			$ERROR = @error
			If $ERROR Then
				$ERROR = $LANGNOSERVERRESP
			Else
				$MANIFESTMATCH = StringRegExp ( $VAR , "(?i)<manifest version=""([^""]+)""" , 3 )
				$LATESTVER = $MANIFESTMATCH [ 0 ]
				$URLMATCH = StringRegExp ( $VAR , "(?i)<url codebase=""([^""]+)""" , 3 )
				$CODEBASEURLS = $URLMATCH [ 0 ]
				$PACKAGEMATCH = StringRegExp ( $VAR , "(?i)<package name=""(.+?)""" , 1 )
				$PACKAGEURL = $PACKAGEMATCH [ 0 ]
				$LATESTURLS = $CODEBASEURLS & $PACKAGEURL
			EndIf
			_WINHTTPCLOSEHANDLE ( $HCONNECT )
		Next
		_WINHTTPCLOSEHANDLE ( $HHTTPOPEN )
		If $LATESTVER Then
			_SETVAR ( "DLInfo" , $LATESTVER & "|" & $LATESTURLS & "|1|1||" & StringFormat ( $LANGUPDATEGOT , "Brave" ) )
		Else
			_SETVAR ( "DLInfo" , "||1||1|" & $ERROR )
		EndIf
	EndIf
	If $BROWSERTYPE = "Cent" Then
		$LATESTURLS = "https://xixiranran.github.io/tools/cent/"
		If $LATESTURLS Then
			_SETVAR ( "DLInfo" , $LATESTVER & "|" & $LATESTURLS & "|1|1||" & StringFormat ( $LANGUPDATEGOT , "Cent" ) )
		Else
			_SETVAR ( "DLInfo" , "||1||1|" & $ERROR )
		EndIf
		Return
	EndIf
	If StringInStr ( $BROWSERTYPE , "Vivaldi" ) Then
		; Vivaldi publishes a Sparkle appcast per architecture. It used to be a link
		; to a download page, which never downloaded anything.
		Local $SVIV = _VIVALDI_LATEST ( $HHTTPOPEN , $NEED_X86 )
		If $SVIV <> "" Then
			Local $AVIV = StringSplit ( $SVIV , "|" , 2 )
			If UBound ( $AVIV ) = 2 Then
				_WINHTTPCLOSEHANDLE ( $HHTTPOPEN )
				_SETVAR ( "DLInfo" , $AVIV [ 0 ] & "|" & $AVIV [ 1 ] & "|1|1||" & StringFormat ( $LANGUPDATEGOT , "Vivaldi" ) )
				Return
			EndIf
		EndIf
		$LATESTURLS = "https://xixiranran.github.io/tools/vivaldi/"
		If $LATESTURLS Then
			_SETVAR ( "DLInfo" , $LATESTVER & "|" & $LATESTURLS & "|1|1||" & StringFormat ( $LANGUPDATEGOT , "Vivaldi" ) )
		Else
			_SETVAR ( "DLInfo" , "||1||1|" & $ERROR )
		EndIf
		Return
	EndIf
EndFunc
Func RESETTIMER ( )
	_SETVAR ( "ResponseTimer" , _NOWCALC ( ) )
EndFunc
Func DOWNLOAD_CHROME ( $URLS , $LOCALFILE , $DOWNLOADTHREADS = 3 , $INIFILE = "MyBrowser.ini" , $PROXY = "" )
	Local $DOWNLOADINFO
	AdlibRegister ( "ResetTimer" , 1000 )
	If StringInStr ( $PROXY , "HTTP:" ) = 1 Then
		$ARR = StringSplit ( $PROXY , ":" , 2 )
		$PROXYSEVER = $ARR [ 1 ]
		$PROXYPORT = $ARR [ 2 ]
	EndIf
	Local $HHTTPOPEN , $RET , $ERROR
	If $PROXYSEVER = "" Or $PROXYPORT = "" Then
		$HHTTPOPEN = _WINHTTPOPEN ( $USERAGENT )
	Else
		$HHTTPOPEN = _WINHTTPOPEN ( $USERAGENT , $WINHTTP_ACCESS_TYPE_NAMED_PROXY , $PROXYSEVER & ":" & $PROXYPORT , "localhost" )
	EndIf
	_WINHTTPSETTIMEOUTS ( $HHTTPOPEN , 0 , 5000 , 5000 , 5000 )
	$CHROMESOURCE = IniRead ( $INIFILE , "Settings" , "ChromeSource" , $GUANFANG )
	Local $I , $J , $A , $HCONNECT , $HREQUEST , $SHEADER , $URL
	Local $AURL = StringSplit ( $URLS , " " )
	For $J = 1 To 2
		For $I = 1 To $AURL [ 0 ]
			_SETVAR ( "DLInfo" , "|||||" & LANG ( "Update" , "Connecting" , "尝试连接" ) & " " & $AURL [ $I ] )
			$A = HTTPPARSEURL ( $AURL [ $I ] )
			$HCONNECT = _WINHTTPCONNECT ( $HHTTPOPEN , $A [ 0 ] , $A [ 2 ] )
			If $A [ 2 ] = 443 Then
				$HREQUEST = _WINHTTPOPENREQUEST ( $HCONNECT , "GET" , $A [ 1 ] , Default , Default , Default , BitOR ( $WINHTTP_FLAG_SECURE , $WINHTTP_FLAG_ESCAPE_DISABLE ) )
			Else
				$HREQUEST = _WINHTTPOPENREQUEST ( $HCONNECT , "GET" , $A [ 1 ] )
			EndIf
			_WINHTTPSENDREQUEST ( $HREQUEST )
			_WINHTTPRECEIVERESPONSE ( $HREQUEST )
			$SHEADER = _WINHTTPQUERYHEADERS ( $HREQUEST , $WINHTTP_QUERY_STATUS_CODE )
			_WINHTTPCLOSEHANDLE ( $HREQUEST )
			_WINHTTPCLOSEHANDLE ( $HCONNECT )
			If $SHEADER = 200 Then
				$URL = $AURL [ $I ]
				ExitLoop 2
			EndIf
		Next
	Next
	If Not $URL Then
		_WINHTTPCLOSEHANDLE ( $HHTTPOPEN )
		_SETVAR ( "DLInfo" , "||1||1|" & LANG ( "Update" , "ConnectServerFailed" , "连接更新服务器失败" ) )
		Return
	Else
		Local $TEMPDIR = StringMid ( $LOCALFILE , 1 , StringInStr ( $LOCALFILE , "\" , 0 , - 1 ) - 1 )
		If Not FileExists ( $TEMPDIR ) Then DirCreate ( $TEMPDIR )
		If FileExists ( $LOCALFILE ) Then FileDelete ( $LOCALFILE )
		Local $HDLFILE = FileOpen ( $LOCALFILE , 25 )
		While 1
			$RET = __DOWNLOADCHROME ( $URL , $LOCALFILE , $HDLFILE , $DOWNLOADTHREADS , $HHTTPOPEN , $DOWNLOADINFO )
			$ERROR = @error
			_SETVAR ( "DLInfo" , $RET )
			For $I = 0 To UBound ( $DOWNLOADINFO ) - 1
				If Not $DOWNLOADINFO [ $I ] [ 3 ] Or $DOWNLOADINFO [ $I ] [ 3 ] = - 1 Then ContinueLoop
				_WINHTTPCLOSEHANDLE ( $DOWNLOADINFO [ $I ] [ 3 ] )
				_WINHTTPCLOSEHANDLE ( $DOWNLOADINFO [ $I ] [ 4 ] )
			Next
			If $ERROR <> 10 Then ExitLoop
			While 1
				Sleep ( 100 )
				If _GETVAR ( "ResumeDownload" ) = 1 Then
					_SETVAR ( "ResumeDownload" , 0 )
					ExitLoop 1
				EndIf
				If Not WinExists ( $__HWND_VARS ) Then ExitLoop 2
			WEnd
		WEnd
		FileClose ( $HDLFILE )
		If Not WinExists ( $__HWND_VARS ) Then
			DirRemove ( $TEMPDIR , 1 )
		EndIf
	EndIf
	_WINHTTPCLOSEHANDLE ( $HHTTPOPEN )
EndFunc
Func __DOWNLOADCHROME ( $URL , $LOCALFILE , $HDLFILE , $DOWNLOADTHREADS , $HHTTPOPEN , ByRef $DOWNLOADINFO )
	Local $I , $HEADER , $REMOTESIZE , $ATHREAD , $MATCH
	Local $TEMPDIR = StringMid ( $LOCALFILE , 1 , StringInStr ( $LOCALFILE , "\" , 0 , - 1 ) - 1 )
	Local $RESUME = IsArray ( $DOWNLOADINFO )
	Local $LANGDOWNLOADINGCHROME = LANG ( "Update" , "DownloadingChrome" , "下载中" )
	If Not $RESUME Then
		_SETVAR ( "DLInfo" , "|||||" & LANG ( "Update" , "ConnectingServer" , "正在连接服务器 ..." ) )
		For $I = 1 To 3
			$ATHREAD = CREATETHREAD ( $URL , $HHTTPOPEN , "10-20" )
			$HEADER = _WINHTTPQUERYHEADERS ( $ATHREAD [ 0 ] )
			_WINHTTPCLOSEHANDLE ( $ATHREAD [ 0 ] )
			_WINHTTPCLOSEHANDLE ( $ATHREAD [ 1 ] )
			If StringRegExp ( $HEADER , "(?is)^HTTP/[\d\.]+ +2" ) Then ExitLoop
			Sleep ( 500 )
			If Not WinExists ( $__HWND_VARS ) Then ExitLoop
		Next
		If Not $ATHREAD [ 0 ] Or $HEADER = "" Then
			Return SetError ( 1 , 0 , "||1||1|" & LANG ( "Update" , "ConnectServerFailed" , "连接更新服务器失败" ) )
		EndIf
		If StringRegExp ( $HEADER , "(?is)^HTTP/[\d\.]+ +200 " ) Then
			Dim $DOWNLOADINFO [ 1 ] [ 5 ] = [ [ 0 , 0 , 0 ] ]
			$MATCH = StringRegExp ( $HEADER , "(?im)Content-Length: *(\d+)" , 1 )
			If Not @error Then
				$REMOTESIZE = $MATCH [ 0 ]
				$DOWNLOADINFO [ 0 ] [ 2 ] = $REMOTESIZE - 1
			EndIf
		Else
			Dim $DOWNLOADINFO [ $DOWNLOADTHREADS ] [ 5 ]
			$MATCH = StringRegExp ( $HEADER , "(?im)^Content-Range: *bytes +\d+-\d+/(\d+)" , 1 )
			If Not @error Then
				$REMOTESIZE = $MATCH [ 0 ]
				Local $CHUNKS = UBound ( $DOWNLOADINFO )
				Local $CHUNKSIZE = Ceiling ( $REMOTESIZE / $CHUNKS )
				Local $POINTER = 0
				$DOWNLOADINFO [ $CHUNKS - 1 ] [ 2 ] = $REMOTESIZE - 1
				For $I = 0 To $CHUNKS - 1
					$DOWNLOADINFO [ $I ] [ 0 ] = $POINTER
					$DOWNLOADINFO [ $I ] [ 1 ] = $POINTER
					$POINTER += $CHUNKSIZE
					If $I <> $CHUNKS - 1 Then $DOWNLOADINFO [ $I ] [ 2 ] = $POINTER
					$POINTER += 1
				Next
			EndIf
		EndIf
		If Not $REMOTESIZE Then
			Dim $DOWNLOADINFO [ 1 ] [ 5 ] = [ [ 0 , 0 , 0 ] ]
		EndIf
		IniWrite ( $TEMPDIR & "\Update.ini" , "general" , "size" , $REMOTESIZE )
	EndIf
	_SETVAR ( "DLInfo" , StringFormat ( "|||||%s ..." , $LANGDOWNLOADINGCHROME ) )
	Local $RANGE , $J
	For $I = 0 To UBound ( $DOWNLOADINFO ) - 1
		If Not WinExists ( $__HWND_VARS ) Then ExitLoop
		If $DOWNLOADINFO [ $I ] [ 2 ] Then
			If $DOWNLOADINFO [ $I ] [ 1 ] > $DOWNLOADINFO [ $I ] [ 2 ] Then ContinueLoop
			$RANGE = $DOWNLOADINFO [ $I ] [ 1 ] & "-" & $DOWNLOADINFO [ $I ] [ 2 ]
		EndIf
		For $J = 1 To 2
			If Not WinExists ( $__HWND_VARS ) Then ExitLoop
			$ATHREAD = CREATETHREAD ( $URL , $HHTTPOPEN , $RANGE )
			If Not @error Then ExitLoop
			Sleep ( 200 )
		Next
		If $I = 0 And _WINHTTPQUERYHEADERS ( $ATHREAD [ 0 ] , $WINHTTP_QUERY_STATUS_CODE ) = 200 Then
			$DOWNLOADINFO [ $I ] [ 0 ] = 0
			$DOWNLOADINFO [ $I ] [ 1 ] = 0
		EndIf
		$DOWNLOADINFO [ $I ] [ 3 ] = $ATHREAD [ 0 ]
		$DOWNLOADINFO [ $I ] [ 4 ] = $ATHREAD [ 1 ]
	Next
	Local $N , $DATA , $RECVERROR , $RECVLEN , $MSG , $BYTES
	Local $THREADS = UBound ( $DOWNLOADINFO )
	Local $T = TimerInit ( )
	Local $TIMEDIFF , $TIMEINIT = $T
	Local $SPEED , $PROGRESS
	Local $ERRORTHREADS , $LIVETHREADS , $FILEERROR , $COMPLETE = 0
	Local $SIZE = 0 , $A
	Local $S [ 50 ]
	$REMOTESIZE = $DOWNLOADINFO [ $THREADS - 1 ] [ 2 ] + 1
	If $RESUME Then
		For $I = 0 To $THREADS - 1
			$SIZE += $DOWNLOADINFO [ $I ] [ 1 ] - $DOWNLOADINFO [ $I ] [ 0 ]
		Next
	EndIf
	For $I = 0 To UBound ( $S ) - 1
		$S [ $I ] = "0:" & $SIZE
	Next
	Do
		If Not WinExists ( $__HWND_VARS ) Then ExitLoop
		For $I = 0 To $THREADS - 1
			If Not WinExists ( $__HWND_VARS ) Then ExitLoop 2
			If Not $DOWNLOADINFO [ $I ] [ 3 ] Or $DOWNLOADINFO [ $I ] [ 3 ] = - 1 Then
				ContinueLoop
			EndIf
			If $COMPLETE Then
				$COMPLETE = 0
				$RECVERROR = - 1
				$RECVLEN = 0
			Else
				If _WINHTTPQUERYDATAAVAILABLE ( $DOWNLOADINFO [ $I ] [ 3 ] ) Then
					$BYTES = @extended
				Else
					$BYTES = Default
				EndIf
				$DATA = _WINHTTPREADDATA ( $DOWNLOADINFO [ $I ] [ 3 ] , 2 , $BYTES )
				$RECVERROR = @error
				$RECVLEN = @extended
			EndIf
			If $RECVERROR = - 1 Then
				_WINHTTPCLOSEHANDLE ( $DOWNLOADINFO [ $I ] [ 3 ] )
				_WINHTTPCLOSEHANDLE ( $DOWNLOADINFO [ $I ] [ 4 ] )
				$DOWNLOADINFO [ $I ] [ 3 ] = - 1
				$DOWNLOADINFO [ $I ] [ 4 ] = - 1
				$N = 0
				For $J = 0 To $THREADS - 1
					If Not $DOWNLOADINFO [ $J ] [ 3 ] Then
						$N = $J
						ExitLoop
					EndIf
				Next
				If $N Then
					For $J = 1 To 3
						Sleep ( 200 )
						$ATHREAD = CREATETHREAD ( $URL , $HHTTPOPEN , $DOWNLOADINFO [ $N ] [ 1 ] & "-" & $DOWNLOADINFO [ $N ] [ 2 ] )
						If Not @error Then
							$DOWNLOADINFO [ $N ] [ 3 ] = $ATHREAD [ 0 ]
							$DOWNLOADINFO [ $N ] [ 4 ] = $ATHREAD [ 1 ]
							ExitLoop
						EndIf
					Next
				EndIf
			ElseIf $RECVERROR Then
				_WINHTTPCLOSEHANDLE ( $DOWNLOADINFO [ $I ] [ 3 ] )
				_WINHTTPCLOSEHANDLE ( $DOWNLOADINFO [ $I ] [ 4 ] )
				$DOWNLOADINFO [ $I ] [ 3 ] = 0
				$DOWNLOADINFO [ $I ] [ 4 ] = 0
				For $J = 1 To 3
					Sleep ( 200 )
					$ATHREAD = CREATETHREAD ( $URL , $HHTTPOPEN , $DOWNLOADINFO [ $I ] [ 1 ] & "-" & $DOWNLOADINFO [ $I ] [ 2 ] )
					If Not @error Then
						$DOWNLOADINFO [ $I ] [ 3 ] = $ATHREAD [ 0 ]
						$DOWNLOADINFO [ $I ] [ 4 ] = $ATHREAD [ 1 ]
						ExitLoop
					EndIf
				Next
			ElseIf $RECVLEN Then
				FileSetPos ( $HDLFILE , $DOWNLOADINFO [ $I ] [ 1 ] , 0 )
				If Not FileWrite ( $HDLFILE , $DATA ) Then
					$FILEERROR = 1
					ExitLoop
				Else
					$DOWNLOADINFO [ $I ] [ 1 ] += $RECVLEN
					If $DOWNLOADINFO [ $I ] [ 1 ] > $DOWNLOADINFO [ $I ] [ 2 ] + 1 Then
						$DOWNLOADINFO [ $I ] [ 1 ] = $DOWNLOADINFO [ $I ] [ 2 ] + 1
						$COMPLETE = 1
						$I = $I - 1
					EndIf
				EndIf
			EndIf
		Next
		$SIZE = 0
		$ERRORTHREADS = 0
		$LIVETHREADS = 0
		For $I = 0 To $THREADS - 1
			$SIZE += $DOWNLOADINFO [ $I ] [ 1 ] - $DOWNLOADINFO [ $I ] [ 0 ]
			If $DOWNLOADINFO [ $I ] [ 3 ] = 0 Then
				$ERRORTHREADS += 1
			ElseIf $DOWNLOADINFO [ $I ] [ 3 ] <> - 1 Then
				$LIVETHREADS += 1
			EndIf
		Next
		If $FILEERROR Then
			Return SetError ( 2 , 0 , $SIZE & "|" & $REMOTESIZE & "|1||2|" & LANG ( "Update" , "SaveFileFailed" , "保存已下载的文件出错" ) )
		EndIf
		If Not $LIVETHREADS And $ERRORTHREADS Then
			Return SetError ( 10 , 0 , $SIZE & "|" & $REMOTESIZE & "|1||10|" )
		EndIf
		If TimerDiff ( $T ) > 200 Then
			$SPEED = 0
			$T = TimerInit ( )
			$TIMEDIFF = TimerDiff ( $TIMEINIT )
			_ARRAYPUSH ( $S , $TIMEDIFF & ":" & $SIZE )
			$A = StringSplit ( $S [ 0 ] , ":" )
			If $A [ 0 ] >= 2 Then
				$SPEED = ( $SIZE - $A [ 2 ] ) / ( $TIMEDIFF - $A [ 1 ] ) / 1.024
				If $SPEED < 1000 Then
					$SPEED = StringFormat ( "%.1fKB/s" , $SPEED )
				Else
					$SPEED = StringFormat ( "%.1fMB/s" , $SPEED / 1024 )
				EndIf
			EndIf
			$PROGRESS = StringFormat ( "%.1f% - %.1fMB / %.1fMB - %s" , $SIZE / $REMOTESIZE * 100 , $SIZE / 1024 / 1024 , $REMOTESIZE / 1024 / 1024 , $SPEED )
			_SETVAR ( "DLInfo" , StringFormat ( "%d|%d||||%s ...  %s" , $SIZE , $REMOTESIZE , $LANGDOWNLOADINGCHROME , $PROGRESS ) )
		EndIf
	Until Not $LIVETHREADS
	FileClose ( $HDLFILE )
	FileSetAttrib ( $LOCALFILE , "+A" )
	If $REMOTESIZE And $REMOTESIZE <> FileGetSize ( $LOCALFILE ) Then
		Return SetError ( 3 , 0 , $SIZE & "|" & $REMOTESIZE & "|1||3|" & LANG ( "Update" , "InstallerSizeError" , "已下载的浏览器安装包大小不正确" ) )
	Else
		Return SetError ( 0 , 0 , $SIZE & "|" & $REMOTESIZE & "|1|1||" & LANG ( "Update" , "ChromeDownloadFinished" , "浏览器下载完成" ) )
	EndIf
EndFunc
Func CREATETHREAD ( $URL , $HHTTPOPEN , $RANGE = "" )
	Local $HHTTPCONNECT , $HHTTPREQUEST , $AHANDLE
	Local $AURL = HTTPPARSEURL ( $URL )
	$HHTTPCONNECT = _WINHTTPCONNECT ( $HHTTPOPEN , $AURL [ 0 ] , $AURL [ 2 ] )
	If $AURL [ 2 ] = 443 Then
		$HHTTPREQUEST = _WINHTTPOPENREQUEST ( $HHTTPCONNECT , "GET" , $AURL [ 1 ] , Default , Default , Default , BitOR ( $WINHTTP_FLAG_SECURE , $WINHTTP_FLAG_ESCAPE_DISABLE ) )
	Else
		$HHTTPREQUEST = _WINHTTPOPENREQUEST ( $HHTTPCONNECT , "GET" , $AURL [ 1 ] )
	EndIf
	If $RANGE Then
		_WINHTTPSENDREQUEST ( $HHTTPREQUEST , "Range: bytes=" & $RANGE & @CRLF )
	Else
		_WINHTTPSENDREQUEST ( $HHTTPREQUEST )
	EndIf
	_WINHTTPRECEIVERESPONSE ( $HHTTPREQUEST )
	Local $HEADER = _WINHTTPQUERYHEADERS ( $HHTTPREQUEST , $WINHTTP_QUERY_STATUS_CODE )
	If StringLeft ( $HEADER , 1 ) <> "2" Or Not _WINHTTPQUERYDATAAVAILABLE ( $HHTTPREQUEST ) Then
		_WINHTTPCLOSEHANDLE ( $HHTTPREQUEST )
		_WINHTTPCLOSEHANDLE ( $HHTTPCONNECT )
		Dim $AHANDLE [ 2 ] = [ 0 , 0 ]
		Return SetError ( 1 , 0 , $AHANDLE )
	EndIf
	Dim $AHANDLE [ 2 ] = [ $HHTTPREQUEST , $HHTTPREQUEST ]
	Return SetError ( 0 , 0 , $AHANDLE )
EndFunc
Func INSTALLCHROME ( $CHROMEINSTALLER = "" )
	$CHANNEL = GUICtrlRead ( $HCHANNEL )
	$BROWSERTYPE = GUICtrlRead ( $HBROWSERTYPE )
	$CHROMEPATH = FULLPATH ( $CHROMEPATH )
	SPLITPATH ( $CHROMEPATH , $CHROMEDIR , $CHROMEEXE )
	Local $TEMPDIR = $CHROMEDIR & "\~update"
	If Not FileExists ( $TEMPDIR ) Then DirCreate ( $TEMPDIR )
	If $CHROMEINSTALLER = "" Then $CHROMEINSTALLER = $TEMPDIR & "\installer.exe"
	$LANGEXTRACTINGCHROME = LANG ( "Update" , "ExtractingChrome" , "正在提取程序文件" )
	If IsHWnd ( $HSETTINGS ) Then
		_GUICTRLSTATUSBAR_SETTEXT ( $HSTAUSBAR , $LANGEXTRACTINGCHROME & " ..." )
	Else
		TraySetState ( 1 )
		TraySetClick ( 0 )
		TraySetToolTip ( "MyBrowser" )
		TraySetOnEvent ( $TRAY_EVENT_PRIMARYDOWN , "" )
		TrayTip ( "MyBrowser" , $LANGEXTRACTINGCHROME & " ..." , 5 , 1 )
	EndIf
	FileInstall ( "7z.exe" , $TEMPDIR & "\7z.exe" , 1 )
	FileInstall ( "7z.dll" , $TEMPDIR & "\7z.dll" , 1 )
	; A truncated download or an HTML error page saved as .exe fails deep inside
	; extraction with a misleading message. Test the archive first.
	Local $IPACKETOK = 1
	If Not FileExists ( $CHROMEINSTALLER ) Then
		$IPACKETOK = 0
	ElseIf FileGetSize ( $CHROMEINSTALLER ) < 1048576 Then
		$IPACKETOK = 0
	ElseIf RunWait ( $TEMPDIR & "\7z.exe t """ & $CHROMEINSTALLER & """ -y" , $TEMPDIR , @SW_HIDE ) <> 0 Then
		$IPACKETOK = 0
	EndIf
	If Not $IPACKETOK Then
		_LOG ( "archive failed integrity test: " & $CHROMEINSTALLER )
		MsgBox ( 64 , "MyBrowser" , LANG ( "Update" , "ArchiveCorrupt" , "下载的更新包不完整或已损坏，请重试。" ) , 0 , $HSETTINGS )
		If FileExists ( $CHROMEINSTALLER ) Then FileDelete ( $CHROMEINSTALLER )
		DirRemove ( $TEMPDIR , 1 )
		Return SetError ( 1 , 0 , 0 )
	EndIf
	RunWait ( $TEMPDIR & "\7z.exe x """ & $CHROMEINSTALLER & """ -y" , $TEMPDIR , @SW_HIDE )
	If FileExists ( $TEMPDIR & "\Chrome-bin\" ) Then
		$CHROMEEXE = "chrome.exe"
		$CHROMEPATH = RELATIVEPATH ( $CHROMEDIR & "\" & $CHROMEEXE )
		GUICtrlSetData ( $HCHROMEPATH , $CHROMEPATH )
	ElseIf _ZIPBROWSERDIR ( $TEMPDIR , "chrome.exe" ) <> "" Then
		; Chrome for Testing (chrome-win64 / chrome-win32) and Chromium snapshots
		; (chrome-win) both ship a plain ZIP with the browser in one subfolder.
		Local $ZD = _ZIPBROWSERDIR ( $TEMPDIR , "chrome.exe" )
		$LATEST = FileGetVersion ( $TEMPDIR & "\" & $ZD & "\chrome.exe" )
		Local $ZCO = FileGetVersion ( $TEMPDIR & "\" & $ZD & "\chrome.exe" , "CompanyName" )
		If StringInStr ( $ZCO , "Chromium" , 2 ) Then
			$ISCHROMIUM = 1
		Else
			$ISCHROME = 1
		EndIf
		$CHROMEEXE = "chrome.exe"
		IniWrite ( $INIFILE , "Settings" , "ChromePath" , ".\App\chrome.exe" )
		IniWrite ( $INIFILE , "Settings" , "Params" , "--with-greenchrome --disable-features=RendererCodeIntegrity --test-type --no-first-run --no-default-browser-check" )
		GUICtrlSetData ( $HPARAMS , "--with-greenchrome --disable-features=RendererCodeIntegrity --test-type --no-first-run --no-default-browser-check" )
		$CHROMEPATH = RELATIVEPATH ( $CHROMEDIR & "\" & $CHROMEEXE )
		GUICtrlSetData ( $HCHROMEPATH , $CHROMEPATH )
	ElseIf FileExists ( $TEMPDIR & "\brave.exe" ) Then
		$ISBRAVEZIP = 1
		$LATEST = FileGetVersion ( $TEMPDIR & "\brave.exe" )
		GUICtrlSetData ( $HBROWSERTYPE , "|Chrome|Chromium|Edge|Brave|Firefox|Vivaldi|Cent" , "Brave" )
		IniWrite ( $INIFILE , "Settings" , "BrowserType" , "Brave" )
		If $CHANNEL = "Release" Or $CHANNEL = "Beta" Or $CHANNEL = "Dev" Or $CHANNEL = "Nightly" Then
			GUICtrlSetData ( $HCHANNEL , "|Release|Beta|Dev|Nightly" , $CHANNEL )
		Else
			GUICtrlSetData ( $HCHANNEL , "|Release|Beta|Dev|Nightly" , "Release" )
			IniWrite ( $INIFILE , "Settings" , "Channel" , "Release" )
		EndIf
		GUICtrlSetState ( $HX86 , $GUI_ENABLE )
		GUICtrlSetState ( $HCHANNEL , $GUI_ENABLE )
		$CHROMEEXE = "brave.exe"
		IniWrite ( $INIFILE , "Settings" , "ChromePath" , ".\App\brave.exe" )
		IniWrite ( $INIFILE , "Settings" , "Params" , "--with-greenchrome --disable-features=RendererCodeIntegrity --test-type --no-first-run --no-default-browser-check" )
		GUICtrlSetData ( $HPARAMS , "--with-greenchrome --disable-features=RendererCodeIntegrity --test-type --no-first-run --no-default-browser-check" )
		$CHROMEPATH = ".\App\" & $CHROMEEXE
		GUICtrlSetData ( $HCHROMEPATH , $CHROMEPATH )
	ElseIf FileExists ( $TEMPDIR & "\chrome.7z" ) Then
		$CHROMEEXE = "chrome.exe"
		$CHROMEPATH = RELATIVEPATH ( $CHROMEDIR & "\" & $CHROMEEXE )
		GUICtrlSetData ( $HCHROMEPATH , $CHROMEPATH )
		RunWait ( $TEMPDIR & "\7z.exe x """ & $TEMPDIR & "\chrome.7z"" -y" , $TEMPDIR , @SW_HIDE )
		If FileExists ( $TEMPDIR & "\Chrome-bin\safemode.bat" ) Then
			$ISCENT = 1
		EndIf
	ElseIf FileExists ( $TEMPDIR & "\MSEDGE.7z" ) Then
		$ISEDGE = 1
		$CHROMEEXE = "msedge.exe"
		$CHROMEPATH = RELATIVEPATH ( $CHROMEDIR & "\" & $CHROMEEXE )
		GUICtrlSetData ( $HCHROMEPATH , $CHROMEPATH )
		RunWait ( $TEMPDIR & "\7z.exe x """ & $TEMPDIR & "\MSEDGE.7z"" -y" , $TEMPDIR , @SW_HIDE )
	ElseIf FileExists ( $TEMPDIR & "\vivaldi.7z" ) Then
		$ISVIVALDI = 1
		$CHROMEEXE = "vivaldi.exe"
		$CHROMEPATH = RELATIVEPATH ( $CHROMEDIR & "\" & $CHROMEEXE )
		GUICtrlSetData ( $HCHROMEPATH , $CHROMEPATH )
		RunWait ( $TEMPDIR & "\7z.exe x """ & $TEMPDIR & "\vivaldi.7z"" -y" , $TEMPDIR , @SW_HIDE )
	ElseIf FileExists ( $TEMPDIR & "\core\" ) Then
		$ISFIREFOX = 1
		$CHROMEEXE = "firefox.exe"
		$CHROMEPATH = RELATIVEPATH ( $CHROMEDIR & "\" & $CHROMEEXE )
		GUICtrlSetData ( $HCHROMEPATH , $CHROMEPATH )
	ElseIf FileExists ( $TEMPDIR & "\safemode.bat" ) Then
		$ISCENTPRO = 1
		$CHROMEEXE = "chrome.exe"
		$CHROMEPATH = RELATIVEPATH ( $CHROMEDIR & "\" & $CHROMEEXE )
		GUICtrlSetData ( $HCHROMEPATH , $CHROMEPATH )
	Else
		MsgBox ( 64 , "MyBrowser" , LANG ( "Update" , "NotAdapted" , "未适配该程序，请手动解压安装！" ) , 0 , $HSETTINGS )
		DirRemove ( $TEMPDIR , 1 )
		Return SetError ( 1 , 0 , 0 )
	EndIf
	If $ISEDGE = 1 Then
		$LATEST = ""
		$SEARCH = FileFindFirstFile ( $TEMPDIR & "\Chrome-bin\" & "/*.*" )
		While 1
			$FILE = FileFindNextFile ( $SEARCH )
			If @error Then ExitLoop
			If $FILE = "." Or $FILE = ".." Then ContinueLoop
			If StringInStr ( FileGetAttrib ( $TEMPDIR & "\Chrome-bin\" & "/" & $FILE ) , "D" ) And StringRegExp ( $FILE , "^\d+(\.\d+)*$" ) Then
				$LATEST = $FILE
				ExitLoop
			EndIf
		WEnd
		FileClose ( $SEARCH )
		If $LATEST = "" Then
			MsgBox ( 64 , "MyBrowser" , LANG ( "Update" , "NotAdapted" , "未适配该程序，请手动解压安装！" ) , 0 , $HSETTINGS )
			DirRemove ( $TEMPDIR , 1 )
			Return SetError ( 1 , 0 , 0 )
		EndIf
		GUICtrlSetData ( $HBROWSERTYPE , "|Chrome|Chromium|Edge|Brave|Firefox|Vivaldi|Cent" , "Edge" )
		IniWrite ( $INIFILE , "Settings" , "BrowserType" , "Edge" )
		If $CHANNEL = "Stable" Or $CHANNEL = "Beta" Or $CHANNEL = "Dev" Or $CHANNEL = "Canary" Then
			GUICtrlSetData ( $HCHANNEL , "|Stable|Beta|Dev|Canary" , $CHANNEL )
		Else
			GUICtrlSetData ( $HCHANNEL , "|Stable|Beta|Dev|Canary" , "Stable" )
			IniWrite ( $INIFILE , "Settings" , "Channel" , "Stable" )
		EndIf
		GUICtrlSetState ( $HX86 , $GUI_ENABLE )
		GUICtrlSetState ( $HCHANNEL , $GUI_ENABLE )
		$CHROMEEXE = "msedge.exe"
		IniWrite ( $INIFILE , "Settings" , "ChromePath" , ".\App\msedge.exe" )
		IniWrite ( $INIFILE , "Settings" , "Params" , "--with-greenchrome --disable-features=RendererCodeIntegrity --test-type --no-first-run --no-default-browser-check" )
		GUICtrlSetData ( $HPARAMS , "--with-greenchrome --disable-features=RendererCodeIntegrity --test-type --no-first-run --no-default-browser-check" )
		$CHROMEPATH = ".\App\" & $CHROMEEXE
		GUICtrlSetData ( $HCHROMEPATH , $CHROMEPATH )
		GUICtrlSetData ( $HCHROMESOURCE , "|" & $GUANFANG & "|" & $LANGCHROMESOURCEINSTALLER , $CHROMESOURCE )
	ElseIf $ISFIREFOX = 1 Then
		$LATEST = FileGetVersion ( $TEMPDIR & "\core\firefox.exe" )
		GUICtrlSetData ( $HBROWSERTYPE , "|Chrome|Chromium|Edge|Brave|Firefox|Vivaldi|Cent" , "Firefox" )
		IniWrite ( $INIFILE , "Settings" , "BrowserType" , "Firefox" )
		If $CHANNEL = "Release" Or $CHANNEL = "Esr" Or $CHANNEL = "Beta" Or $CHANNEL = "Dev" Or $CHANNEL = "Nightly" Then
			GUICtrlSetData ( $HCHANNEL , "|Release|Esr|Beta|Dev|Nightly" , $CHANNEL )
		Else
			GUICtrlSetData ( $HCHANNEL , "|Release|Esr|Beta|Dev|Nightly" , "Release" )
			IniWrite ( $INIFILE , "Settings" , "Channel" , "Release" )
		EndIf
		GUICtrlSetState ( $HCHANNEL , $GUI_ENABLE )
		GUICtrlSetState ( $HX86 , $GUI_ENABLE )
		$CHROMEEXE = "firefox.exe"
		IniWrite ( $INIFILE , "Settings" , "ChromePath" , ".\App\firefox.exe" )
		IniWrite ( $INIFILE , "Settings" , "Params" , "" )
		GUICtrlSetData ( $HPARAMS , "" )
		GUICtrlSetState ( $GCAUTOSET , $GUI_UNCHECKED )
		IniWrite ( $INIFILE , "Settings" , "GreenChromeAuto" , 0 )
		$CHROMEPATH = ".\App\" & $CHROMEEXE
		GUICtrlSetData ( $HCHROMEPATH , $CHROMEPATH )
		GUICtrlSetData ( $HCHROMESOURCE , "|" & $GUANFANG & "|" & $LANGCHROMESOURCEINSTALLER , $CHROMESOURCE )
	ElseIf $ISCENT = 1 Then
		$LATEST = FileGetVersion ( $TEMPDIR & "\Chrome-bin\chrome.exe" )
		GUICtrlSetData ( $HBROWSERTYPE , "|Chrome|Chromium|Edge|Brave|Firefox|Vivaldi|Cent" , "Cent" )
		IniWrite ( $INIFILE , "Settings" , "BrowserType" , "Cent" )
		GUICtrlSetData ( $HCHANNEL , "" )
		IniWrite ( $INIFILE , "Settings" , "Channel" , "" )
		GUICtrlSetState ( $HCHANNEL , $GUI_DISABLE )
		GUICtrlSetState ( $HX86 , $GUI_DISABLE )
		$CHROMEEXE = "chrome.exe"
		IniWrite ( $INIFILE , "Settings" , "ChromePath" , ".\App\chrome.exe" )
		IniWrite ( $INIFILE , "Settings" , "Params" , "" )
		GUICtrlSetData ( $HPARAMS , "" )
		GUICtrlSetState ( $GCAUTOSET , $GUI_UNCHECKED )
		IniWrite ( $INIFILE , "Settings" , "GreenChromeAuto" , 0 )
		$CHROMEPATH = ".\App\" & $CHROMEEXE
		GUICtrlSetData ( $HCHROMEPATH , $CHROMEPATH )
		GUICtrlSetData ( $HCHROMESOURCE , "|" & $GUANFANG & "|" & $LANGCHROMESOURCEINSTALLER , $CHROMESOURCE )
	ElseIf $ISCENTPRO = 1 Then
		$LATEST = FileGetVersion ( $TEMPDIR & "\chrome.exe" )
		GUICtrlSetData ( $HBROWSERTYPE , "|Chrome|Chromium|Edge|Brave|Firefox|Vivaldi|Cent" , "Cent" )
		IniWrite ( $INIFILE , "Settings" , "BrowserType" , "Cent" )
		GUICtrlSetData ( $HCHANNEL , "" )
		IniWrite ( $INIFILE , "Settings" , "Channel" , "" )
		GUICtrlSetState ( $HCHANNEL , $GUI_DISABLE )
		GUICtrlSetState ( $HX86 , $GUI_DISABLE )
		$CHROMEEXE = "chrome.exe"
		IniWrite ( $INIFILE , "Settings" , "ChromePath" , ".\App\chrome.exe" )
		IniWrite ( $INIFILE , "Settings" , "Params" , "" )
		GUICtrlSetData ( $HPARAMS , "" )
		GUICtrlSetState ( $GCAUTOSET , $GUI_UNCHECKED )
		IniWrite ( $INIFILE , "Settings" , "GreenChromeAuto" , 0 )
		$CHROMEPATH = ".\App\" & $CHROMEEXE
		GUICtrlSetData ( $HCHROMEPATH , $CHROMEPATH )
		GUICtrlSetData ( $HCHROMESOURCE , "|" & $GUANFANG & "|" & $LANGCHROMESOURCEINSTALLER , $CHROMESOURCE )
	ElseIf $ISVIVALDI = 1 Then
		$LATEST = FileGetVersion ( $TEMPDIR & "\Vivaldi-bin\vivaldi.exe" )
		GUICtrlSetData ( $HBROWSERTYPE , "|Chrome|Chromium|Edge|Brave|Firefox|Vivaldi|Cent" , "Vivaldi" )
		IniWrite ( $INIFILE , "Settings" , "BrowserType" , "Vivaldi" )
		GUICtrlSetData ( $HCHANNEL , "" )
		IniWrite ( $INIFILE , "Settings" , "Channel" , "" )
		GUICtrlSetState ( $HCHANNEL , $GUI_DISABLE )
		GUICtrlSetState ( $HX86 , $GUI_DISABLE )
		$CHROMEEXE = "vivaldi.exe"
		IniWrite ( $INIFILE , "Settings" , "ChromePath" , ".\App\vivaldi.exe" )
		IniWrite ( $INIFILE , "Settings" , "Params" , "--with-greenchrome --disable-features=RendererCodeIntegrity --test-type --no-first-run --no-default-browser-check" )
		GUICtrlSetData ( $HPARAMS , "--with-greenchrome --disable-features=RendererCodeIntegrity --test-type --no-first-run --no-default-browser-check" )
		$CHROMEPATH = ".\App\" & $CHROMEEXE
		GUICtrlSetData ( $HCHROMEPATH , $CHROMEPATH )
		GUICtrlSetData ( $HCHROMESOURCE , "|" & $GUANFANG & "|" & $LANGCHROMESOURCEINSTALLER , $CHROMESOURCE )
	Else
		If FileExists ( $TEMPDIR & "\Chrome-bin\chrome.exe" ) Then
			$LATEST = FileGetVersion ( $TEMPDIR & "\Chrome-bin\chrome.exe" )
			Local $COMPANY = FileGetVersion ( $TEMPDIR & "\Chrome-bin\chrome.exe" , "CompanyName" )
			Local $DESCRIPTION = FileGetVersion ( $TEMPDIR & "\Chrome-bin\chrome.exe" , "FileDescription" )
			If StringInStr ( $COMPANY , "Google" , 2 ) Or StringInStr ( $DESCRIPTION , "Google" , 2 ) Then
				$ISCHROME = 1
				GUICtrlSetData ( $HBROWSERTYPE , "|Chrome|Chromium|Edge|Brave|Firefox|Vivaldi|Cent" , "Chrome" )
				IniWrite ( $INIFILE , "Settings" , "BrowserType" , "Chrome" )
				GUICtrlSetState ( $HCHANNEL , $GUI_ENABLE )
				If $CHANNEL = "Stable" Or $CHANNEL = "Beta" Or $CHANNEL = "Dev" Or $CHANNEL = "Canary" Then
					GUICtrlSetData ( $HCHANNEL , "|Stable|Beta|Dev|Canary" , $CHANNEL )
				Else
					GUICtrlSetData ( $HCHANNEL , "|Stable|Beta|Dev|Canary" , "Stable" )
					IniWrite ( $INIFILE , "Settings" , "Channel" , "Stable" )
				EndIf
			ElseIf StringInStr ( $COMPANY , "Chromium" , 2 ) Or StringInStr ( $DESCRIPTION , "Chromium" , 2 ) Then
				$ISCHROMIUM = 1
				GUICtrlSetData ( $HBROWSERTYPE , "|Chrome|Chromium|Edge|Brave|Firefox|Vivaldi|Cent" , "Chromium" )
				IniWrite ( $INIFILE , "Settings" , "BrowserType" , "Chromium" )
				GUICtrlSetData ( $HCHANNEL , "" )
				IniWrite ( $INIFILE , "Settings" , "Channel" , "" )
				GUICtrlSetState ( $HCHANNEL , $GUI_DISABLE )
			EndIf
			GUICtrlSetState ( $HX86 , $GUI_ENABLE )
			$CHROMEEXE = "chrome.exe"
			$CHROMEPATH = ".\App\" & $CHROMEEXE
			GUICtrlSetData ( $HCHROMEPATH , $CHROMEPATH )
			IniWrite ( $INIFILE , "Settings" , "ChromePath" , ".\App\chrome.exe" )
			GUICtrlSetData ( $HPARAMS , "--with-greenchrome --disable-features=RendererCodeIntegrity --test-type --no-first-run --no-default-browser-check" )
			IniWrite ( $INIFILE , "Settings" , "Params" , "--with-greenchrome --disable-features=RendererCodeIntegrity --test-type --no-first-run --no-default-browser-check" )
			GUICtrlSetData ( $HCHROMESOURCE , "|" & $GUANFANG & "|" & $LANGCHROMESOURCESYS & "|" & $LANGCHROMESOURCEINSTALLER , $CHROMESOURCE )
		ElseIf FileExists ( $TEMPDIR & "\Chrome-bin\brave.exe" ) Then
			$LATEST = FileGetVersion ( $TEMPDIR & "\Chrome-bin\brave.exe" )
			$ISBRAVE = 1
			GUICtrlSetData ( $HBROWSERTYPE , "|Chrome|Chromium|Edge|Brave|Firefox|Vivaldi|Cent" , "Brave" )
			IniWrite ( $INIFILE , "Settings" , "BrowserType" , "Brave" )
			If $CHANNEL = "Release" Or $CHANNEL = "Beta" Or $CHANNEL = "Dev" Or $CHANNEL = "Nightly" Then
				GUICtrlSetData ( $HCHANNEL , "|Release|Beta|Dev|Nightly" , $CHANNEL )
			Else
				GUICtrlSetData ( $HCHANNEL , "|Release|Beta|Dev|Nightly" , "Release" )
				IniWrite ( $INIFILE , "Settings" , "Channel" , "Release" )
			EndIf
			GUICtrlSetState ( $HX86 , $GUI_ENABLE )
			GUICtrlSetState ( $HCHANNEL , $GUI_ENABLE )
			$CHROMEEXE = "brave.exe"
			IniWrite ( $INIFILE , "Settings" , "ChromePath" , ".\App\brave.exe" )
			IniWrite ( $INIFILE , "Settings" , "Params" , "--with-greenchrome --disable-features=RendererCodeIntegrity --test-type --no-first-run --no-default-browser-check" )
			GUICtrlSetData ( $HPARAMS , "--with-greenchrome --disable-features=RendererCodeIntegrity --test-type --no-first-run --no-default-browser-check" )
			$CHROMEPATH = ".\App\" & $CHROMEEXE
			GUICtrlSetData ( $HCHROMEPATH , $CHROMEPATH )
			GUICtrlSetData ( $HCHROMESOURCE , "|" & $GUANFANG & "|" & $LANGCHROMESOURCEINSTALLER , $CHROMESOURCE )
		Else
			MsgBox ( 64 , "MyBrowser" , LANG ( "Update" , "NotAdapted" , "未适配该程序，请手动解压安装！" ) , 0 , $HSETTINGS )
			DirRemove ( $TEMPDIR , 1 )
			Return SetError ( 1 , 0 , 0 )
		EndIf
	EndIf
	If Not $LATEST Then
		Local $FILE
		Local $SEARCH = FileFindFirstFile ( "*.*" )
		While 1
			$FILE = FileFindNextFile ( $SEARCH )
			If @error Then ExitLoop
			If StringRegExp ( $FILE , "^[\d\.]+\.[\d\.]+$" ) Then
				$LATEST = $FILE
				ExitLoop
			EndIf
		WEnd
		FileClose ( $SEARCH )
	EndIf
	If $ISEDGE = 1 Then
		If Not FileExists ( $TEMPDIR & "\Chrome-bin\" & $LATEST & "\msedge.exe" ) Or Not FileExists ( $TEMPDIR & "\Chrome-bin\" & $LATEST & "\msedge.dll" ) Then
			MsgBox ( 64 , "MyBrowser" , LANG ( "Update" , "ExtractEdgeFailed" , "提取 MicroSoft Edge 程序文件失败！" ) , 0 , $HSETTINGS )
			DirRemove ( $TEMPDIR , 1 )
			Return SetError ( 1 , 0 , 0 )
		Else
			$BROWSERTYPE = "Edge"
			DirRemove ( $CHROMEDIR & "\~updated" , 1 )
			DirMove ( $TEMPDIR & "\Chrome-bin\" & $LATEST , $CHROMEDIR & "\~updated" , 1 )
		EndIf
	ElseIf $ISVIVALDI = 1 Then
		If Not FileExists ( $TEMPDIR & "\Vivaldi-bin\vivaldi.exe" ) Then
			MsgBox ( 64 , "MyBrowser" , LANG ( "Update" , "ExtractVivaldiFailed" , "提取 Vivaldi 程序文件失败！" ) , 0 , $HSETTINGS )
			DirRemove ( $TEMPDIR , 1 )
			Return SetError ( 1 , 0 , 0 )
		Else
			$BROWSERTYPE = "Vivaldi"
			FileMove ( $TEMPDIR & "\Vivaldi-bin\*.*" , $TEMPDIR & "\Vivaldi-bin\" & $LATEST & "\" , 9 )
			DirRemove ( $CHROMEDIR & "\~updated" , 1 )
			DirMove ( $TEMPDIR & "\Vivaldi-bin\" & $LATEST , $CHROMEDIR & "\~updated" , 1 )
		EndIf
	ElseIf $ISFIREFOX = 1 Then
		If Not FileExists ( $TEMPDIR & "\core\firefox.exe" ) Then
			MsgBox ( 64 , "MyBrowser" , LANG ( "Update" , "ExtractFirefoxFailed" , "提取 Firefox 程序文件失败！" ) , 0 , $HSETTINGS )
			DirRemove ( $TEMPDIR , 1 )
			Return SetError ( 1 , 0 , 0 )
		Else
			$BROWSERTYPE = "Firefox"
			DirRemove ( $CHROMEDIR & "\~updated" , 1 )
			DirMove ( $TEMPDIR & "\core\" , $CHROMEDIR & "\~updated" , 1 )
		EndIf
	ElseIf $ISCENT = 1 Then
		If Not FileExists ( $TEMPDIR & "\Chrome-bin\safemode.bat" ) Then
			MsgBox ( 64 , "MyBrowser" , LANG ( "Update" , "ExtractCentFailed" , "提取 Cent 程序文件失败！" ) , 0 , $HSETTINGS )
			DirRemove ( $TEMPDIR , 1 )
			Return SetError ( 1 , 0 , 0 )
		Else
			$BROWSERTYPE = "Cent"
			FileMove ( $TEMPDIR & "\Chrome-bin\*.*" , $TEMPDIR & "\Chrome-bin\" & $LATEST & "\" , 9 )
			DirRemove ( $CHROMEDIR & "\~updated" , 1 )
			DirMove ( $TEMPDIR & "\Chrome-bin\" & $LATEST , $CHROMEDIR & "\~updated" , 1 )
		EndIf
	ElseIf $ISCENTPRO = 1 Then
		If Not FileExists ( $TEMPDIR & "\safemode.bat" ) Then
			MsgBox ( 64 , "MyBrowser" , LANG ( "Update" , "ExtractCentFailed" , "提取 Cent 程序文件失败！" ) , 0 , $HSETTINGS )
			DirRemove ( $TEMPDIR , 1 )
			Return SetError ( 1 , 0 , 0 )
		Else
			$BROWSERTYPE = "Cent"
			FileMove ( $TEMPDIR & "\*.*" , $TEMPDIR & "\" & $LATEST & "\" , 9 )
			DirRemove ( $CHROMEDIR & "\~updated" , 1 )
			DirMove ( $TEMPDIR & "\" & $LATEST , $CHROMEDIR & "\~updated" , 1 )
		EndIf
	ElseIf $ISBRAVEZIP = 1 Then
		$BROWSERTYPE = "Brave"
		DirRemove ( $CHROMEDIR & "\~updated" , 1 )
		DirCreate ( $CHROMEDIR & "\~updated" )
		_MOVETEMPCONTENTS ( $TEMPDIR , $CHROMEDIR & "\~updated" )
	ElseIf $ISBRAVE = 1 Then
		If Not FileExists ( $TEMPDIR & "\Chrome-bin\brave.exe" ) Then
			MsgBox ( 64 , "MyBrowser" , LANG ( "Update" , "ExtractBraveFailed" , "提取 Brave 程序文件失败！" ) , 0 , $HSETTINGS )
			DirRemove ( $TEMPDIR , 1 )
			Return SetError ( 1 , 0 , 0 )
		Else
			$BROWSERTYPE = "Brave"
			FileMove ( $TEMPDIR & "\Chrome-bin\*.*" , $TEMPDIR & "\Chrome-bin\" & $LATEST & "\" , 9 )
			DirRemove ( $CHROMEDIR & "\~updated" , 1 )
			DirMove ( $TEMPDIR & "\Chrome-bin\" & $LATEST , $CHROMEDIR & "\~updated" , 1 )
		EndIf
	ElseIf _ZIPBROWSERDIR ( $TEMPDIR , "chrome.exe" ) <> "" Then
		Local $CFTDIR = _ZIPBROWSERDIR ( $TEMPDIR , "chrome.exe" )
		If $ISCHROMIUM = 1 Then
			$BROWSERTYPE = "Chromium"
		Else
			$BROWSERTYPE = "Chrome"
		EndIf
		DirRemove ( $CHROMEDIR & "\~updated" , 1 )
		DirMove ( $TEMPDIR & "\" & $CFTDIR , $CHROMEDIR & "\~updated" , 1 )
	Else
		If Not FileExists ( $TEMPDIR & "\Chrome-bin\chrome.exe" ) Then
			If $ISCHROME = 1 Then
				MsgBox ( 64 , "MyBrowser" , LANG ( "Update" , "ExtractChromeFailed" , "提取 Google Chrome 程序文件失败！" ) , 0 , $HSETTINGS )
			ElseIf $ISCHROMIUM = 1 Then
				MsgBox ( 64 , "MyBrowser" , LANG ( "Update" , "ExtractChromiumFailed" , "提取 Chromium 程序文件失败！" ) , 0 , $HSETTINGS )
			EndIf
			DirRemove ( $TEMPDIR , 1 )
			Return SetError ( 1 , 0 , 0 )
		Else
			If $ISCHROME = 1 Then
				$BROWSERTYPE = "Chrome"
			ElseIf $ISCHROMIUM = 1 Then
				$BROWSERTYPE = "Chromium"
			EndIf
			FileMove ( $TEMPDIR & "\Chrome-bin\*.*" , $TEMPDIR & "\Chrome-bin\" & $LATEST & "\" , 9 )
			DirRemove ( $CHROMEDIR & "\~updated" , 1 )
			DirMove ( $TEMPDIR & "\Chrome-bin\" & $LATEST , $CHROMEDIR & "\~updated" , 1 )
		EndIf
	EndIf
	$ISCHROME = 0
	$ISCHROMIUM = 0
	$ISEDGE = 0
	$ISVIVALDI = 0
	$ISBRAVE = 0
	$ISBRAVEZIP = 0
	$ISFIREFOX = 0
	$ISCENT = 0
	$ISCENTPRO = 0
	; A3: the vendor feed can serve a stale or wrong package. Compare and log,
	; but do not block - a mismatch is worth knowing about, not worth bricking on.
	If FileExists ( $CHROMEDIR & "\~updated\" & $CHROMEEXE ) Then
		Local $SUNPACKED = FileGetVersion ( $CHROMEDIR & "\~updated\" & $CHROMEEXE )
		If $SUNPACKED <> "" And $LATESTCHROMEVER <> "" And $SUNPACKED <> $LATESTCHROMEVER Then
			_LOG ( "version mismatch: requested " & $LATESTCHROMEVER & ", unpacked " & $SUNPACKED )
		Else
			_LOG ( "unpacked " & $SUNPACKED & " ok" )
		EndIf
	EndIf
	$LANGUPDATECLOSECHROME = LANG ( "Update" , "UpdateCloseChrome" , "是否关闭 Chrome 浏览器以完成更新？\n点击“是”强制关闭浏览器，点击“否”推迟到下次启动时应用更新。" )
	$CHROMEISRUNNING = CHROMEISRUNNING ( $CHROMEPATH , StringFormat ( $LANGUPDATECLOSECHROME , 0 ) )
	If $CHROMEISRUNNING Then Return
	Return APPLYUPDATE ( )
EndFunc
Func APPLYUPDATE ( )
	; Never copy a half-extracted tree over a working browser.
	Local $SAPPLYOK = FileExists ( $CHROMEDIR & "\~updated" )
	If $SAPPLYOK And $CHROMEEXE <> "" Then
		$SAPPLYOK = FileExists ( $CHROMEDIR & "\~updated\" & $CHROMEEXE )
	EndIf
	If Not $SAPPLYOK Then
		_LOG ( "apply refused: incomplete tree for " & $CHROMEEXE )
		MsgBox ( 64 , "MyBrowser" , LANG ( "Update" , "ApplyIncomplete" , "更新文件不完整，已取消本次更新，原浏览器未受影响。" ) , 0 , $HSETTINGS )
		If FileExists ( $CHROMEDIR & "\~updated" ) Then DirRemove ( $CHROMEDIR & "\~updated" , 1 )
		If FileExists ( $CHROMEDIR & "\~update" ) Then DirRemove ( $CHROMEDIR & "\~update" , 1 )
		ENDUPDATE ( )
		Return ""
	EndIf
	$LANGAPPLYUPDATE = LANG ( "Update" , "ApplyUpdate" , "正在应用浏览器更新" )
	If IsHWnd ( $HSETTINGS ) Then
		_GUICTRLSTATUSBAR_SETTEXT ( $HSTAUSBAR , $LANGAPPLYUPDATE & " ..." )
	ElseIf @TrayIconVisible Then
		TrayTip ( "MyBrowser" , $LANGAPPLYUPDATE & " ..." , 5 , 1 )
	EndIf
	; B1/B2: three renames instead of a copy over the live folder. Each step is
	; reversible, and the working build is not destroyed until the new one lands.
	Local $SNEWDIR = $CHROMEDIR & ".new"
	Local $SOLDDIR = $CHROMEDIR & ".old"
	Local $SBADDIR = $CHROMEDIR & ".bad"
	Local $SSWAPOK = 0
	Local $SAPPDIR = StringLower ( FULLPATH ( $CHROMEDIR ) )
	Local $SPROFABS = StringLower ( FULLPATH ( $USERDATADIR ) )
	If $SPROFABS <> "" And StringLeft ( $SPROFABS , StringLen ( $SAPPDIR ) ) = $SAPPDIR Then
		_LOG ( "atomic swap skipped: the profile folder is inside the browser folder" )
	ElseIf $SAPPDIR = StringLower ( @ScriptDir ) Then
		_LOG ( "atomic swap skipped: the browser folder is the app folder" )
	Else
		If FileExists ( $SNEWDIR ) Then DirRemove ( $SNEWDIR , 1 )
		If FileExists ( $SOLDDIR ) Then DirRemove ( $SOLDDIR , 1 )
		If DirMove ( $CHROMEDIR & "\~updated" , $SNEWDIR , 1 ) Then
			If DirMove ( $CHROMEDIR , $SOLDDIR , 1 ) Then
				If DirMove ( $SNEWDIR , $CHROMEDIR , 1 ) Then
					$SSWAPOK = 1
					_LOG ( "atomic swap applied" )
				Else
					DirMove ( $SOLDDIR , $CHROMEDIR , 1 )
					_LOG ( "atomic swap failed on step 3, old build restored" )
				EndIf
			Else
				DirMove ( $SNEWDIR , $CHROMEDIR & "\~updated" , 1 )
				_LOG ( "atomic swap failed on step 2" )
			EndIf
		Else
			_LOG ( "atomic swap failed on step 1" )
		EndIf
	EndIf
	If Not $SSWAPOK Then
		If FileExists ( $CHROMEDIR & "\~updated" ) Then
			FileMove ( $CHROMEDIR & "\~updated\*.*" , $CHROMEDIR , 9 )
			DirCopy ( $CHROMEDIR & "\~updated" , $CHROMEDIR , 1 )
		EndIf
	EndIf
	; B2: verify the build that actually landed, and put the old one back if not.
	If $SSWAPOK And $CHROMEEXE <> "" And $LATESTCHROMEVER <> "" Then
		Local $SPOSTVER = FileGetVersion ( $CHROMEDIR & "\" & $CHROMEEXE )
		If $SPOSTVER <> "" And $SPOSTVER <> $LATESTCHROMEVER Then
			_LOG ( "post-apply check failed: " & $SPOSTVER & " vs " & $LATESTCHROMEVER )
			If FileExists ( $SBADDIR ) Then DirRemove ( $SBADDIR , 1 )
			If DirMove ( $CHROMEDIR , $SBADDIR , 1 ) Then
				If DirMove ( $SOLDDIR , $CHROMEDIR , 1 ) Then
					_LOG ( "rolled back to the previous build" )
				Else
					_LOG ( "rollback move failed; previous build left at " & $SOLDDIR )
				EndIf
			EndIf
			If FileExists ( $SBADDIR ) Then DirRemove ( $SBADDIR , 1 )
		EndIf
	EndIf
	If FileExists ( $SOLDDIR ) Then DirRemove ( $SOLDDIR , 1 )
	Local $CHROMEDLL = $CHROMEDIR & "\chrome.dll"
	$CHROMEFILEVERSION = FileGetVersion ( $CHROMEDLL , "FileVersion" )
	Local $EDGEDLL = $CHROMEDIR & "\msedge.dll"
	$EDGEFILEVERSION = FileGetVersion ( $EDGEDLL , "FileVersion" )
	Local $VIVALDIDLL = $CHROMEDIR & "\vivaldi.dll"
	$VIVALDIFILEVERSION = FileGetVersion ( $VIVALDIDLL , "FileVersion" )
	Local $FIREFOXDLL = $CHROMEDIR & "\firefox.exe"
	$FIREFOXFILEVERSION = FileGetVersion ( $FIREFOXDLL , "FileVersion" )
	Local $BRAVEDLL = $CHROMEDIR & "\brave.exe"
	$BRAVEFILEVERSION = FileGetVersion ( $BRAVEDLL , "FileVersion" )
	If IsHWnd ( $HSETTINGS ) Then
		If StringInStr ( $BROWSERTYPE , "Edge" ) Then
			GUICtrlSetData ( $HCURRENTVER , $EDGEFILEVERSION )
		ElseIf StringInStr ( $BROWSERTYPE , "Vivaldi" ) Then
			GUICtrlSetData ( $HCURRENTVER , $VIVALDIFILEVERSION )
		ElseIf StringInStr ( $BROWSERTYPE , "Firefox" ) Then
			GUICtrlSetData ( $HCURRENTVER , $FIREFOXFILEVERSION )
		ElseIf StringInStr ( $BROWSERTYPE , "Brave" ) Then
			GUICtrlSetData ( $HCURRENTVER , $BRAVEFILEVERSION )
		Else
			GUICtrlSetData ( $HCURRENTVER , $CHROMEFILEVERSION )
		EndIf
	EndIf
	If StringInStr ( $BROWSERTYPE , "Edge" ) Then
		GUICtrlSetData ( $HLATESTCHROMEVER , $EDGEFILEVERSION )
	ElseIf StringInStr ( $BROWSERTYPE , "Vivaldi" ) Then
		GUICtrlSetData ( $HLATESTCHROMEVER , StringFormat ( LANG ( "GUI" , "VivaldiDownloadUrl" , "Vivaldi下载地址" ) ) )
	ElseIf StringInStr ( $BROWSERTYPE , "Firefox" ) Then
		GUICtrlSetData ( $HLATESTCHROMEVER , StringFormat ( LANG ( "GUI" , "FirefoxDownloadUrl" , "Firefox下载地址" ) ) )
	ElseIf StringInStr ( $BROWSERTYPE , "Brave" ) Then
		GUICtrlSetData ( $HLATESTCHROMEVER , $BRAVEFILEVERSION )
	ElseIf StringInStr ( $BROWSERTYPE , "Cent" ) Then
		GUICtrlSetData ( $HLATESTCHROMEVER , StringFormat ( LANG ( "GUI" , "CentDownloadUrl" , "Cent下载地址" ) ) )
	Else
		GUICtrlSetData ( $HLATESTCHROMEVER , $CHROMEFILEVERSION )
	EndIf
	If FileExists ( $CHROMEDIR & "\msedge.dll" ) Then
		$LANGUPDATEDTO = LANG ( "Update" , "EdgeUpdatedTo" , "MicroSoft Edge 浏览器已更新至 %s!" )
		MsgBox ( 64 , "MyBrowser" , StringFormat ( $LANGUPDATEDTO , $EDGEFILEVERSION ) , 0 , $HSETTINGS )
	ElseIf FileExists ( $CHROMEDIR & "\vivaldi.dll" ) Then
		$LANGUPDATEDTO = LANG ( "Update" , "VivaldiUpdatedTo" , "Vivaldi 浏览器已更新至 %s!" )
		MsgBox ( 64 , "MyBrowser" , StringFormat ( $LANGUPDATEDTO , $VIVALDIFILEVERSION ) , 0 , $HSETTINGS )
	ElseIf FileExists ( $CHROMEDIR & "\firefox.exe" ) Then
		$LANGUPDATEDTO = LANG ( "Update" , "FirefoxUpdatedTo" , "Firefox 浏览器已更新至 %s!" )
		MsgBox ( 64 , "MyBrowser" , StringFormat ( $LANGUPDATEDTO , $FIREFOXFILEVERSION ) , 0 , $HSETTINGS )
	ElseIf FileExists ( $CHROMEDIR & "\brave.exe" ) Then
		$LANGUPDATEDTO = LANG ( "Update" , "BraveUpdatedTo" , "Brave 浏览器已更新至 %s!" )
		MsgBox ( 64 , "MyBrowser" , StringFormat ( $LANGUPDATEDTO , $BRAVEFILEVERSION ) , 0 , $HSETTINGS )
	ElseIf FileExists ( $CHROMEDIR & "\safemode.bat" ) Then
		$LANGUPDATEDTO = LANG ( "Update" , "CentUpdatedTo" , "Cent 浏览器已更新至 %s!" )
		MsgBox ( 64 , "MyBrowser" , StringFormat ( $LANGUPDATEDTO , $CHROMEFILEVERSION ) , 0 , $HSETTINGS )
	Else
		Local $COMPANY = FileGetVersion ( $CHROMEDIR & "\" & $CHROMEEXE , "CompanyName" )
		Local $DESCRIPTION = FileGetVersion ( $CHROMEDIR & "\" & $CHROMEEXE , "FileDescription" )
		If StringInStr ( $COMPANY , "Google" , 2 ) Or StringInStr ( $DESCRIPTION , "Google" , 2 ) Then
			$LANGUPDATEDTO = LANG ( "Update" , "ChromeUpdatedTo" , "Google Chrome 浏览器已更新至 %s %s !" )
		ElseIf StringInStr ( $COMPANY , "Chromium" , 2 ) Or StringInStr ( $DESCRIPTION , "Chromium" , 2 ) Then
			$LANGUPDATEDTO = LANG ( "Update" , "ChromiumUpdatedTo" , "Chromium 浏览器已更新至 %s %s !" )
		Else
			$LANGUPDATEDTO = LANG ( "Update" , "ChromiumUpdatedTo" , "11Chromium 浏览器已更新至 %s %s !" )
		EndIf
		MsgBox ( 64 , "MyBrowser" , StringFormat ( $LANGUPDATEDTO , $CHROMEFILEVERSION ) , 0 , $HSETTINGS )
	EndIf
	DirRemove ( $CHROMEDIR & "\~updated" , 1 )
	If FileExists ( $CHROMEDIR & "\~update" ) Then DirRemove ( $CHROMEDIR & "\~update" , 1 )
	If FileExists ( $CHROMEDIR & "\7z.exe" ) Then FileDelete ( $CHROMEDIR & "\7z.exe" )
	If FileExists ( $CHROMEDIR & "\7z.dll" ) Then FileDelete ( $CHROMEDIR & "\7z.dll" )
	If IniRead ( $INIFILE , "Settings" , "GreenChromeAuto" , "" ) = 1 Then
		$GREENCHROMEDLL = $CHROMEDIR & "\GreenChrome.dll"
		$GREENCHROMEINI = $CHROMEDIR & "\GreenChrome.ini"
		$SETDLL = $CHROMEDIR & "\setdll.exe"
		If FileExists ( $GREENCHROMEDLL ) Then FileDelete ( $GREENCHROMEDLL )
		FileInstall ( "GreenChrome.dll" , $GREENCHROMEDLL , 1 )
		If Not FileExists ( $SETDLL ) Then FileInstall ( "setdll.exe" , $SETDLL , 1 )
		If Not FileExists ( $GREENCHROMEINI ) Then FileInstall ( "GreenChrome.ini" , $GREENCHROMEINI , 1 )
		$CMD = "cd /d """ & $CHROMEDIR & """ && setdll /d:GreenChrome.dll " & $CHROMEEXE
		Run ( @ComSpec & " /c " & $CMD , "" , @SW_HIDE )
		Sleep ( 1000 )
		If FileExists ( $CHROMEDIR & "\" & $CHROMEEXE & "~" ) Then
			If ProcessExists ( """" & $CHROMEEXE & """" ) Then
				MsgBox ( 0 , "MyBrowser" , $INJECTGC1 , 0 , $HSETTINGS )
			Else
				MsgBox ( 0 , "MyBrowser" , $INJECTGC2 , 0 , $HSETTINGS )
			EndIf
			FileDelete ( $CHROMEDIR & "\" & $CHROMEEXE & "~" )
			IniWrite ( $INIFILE , "Settings" , "GreenChrome" , 1 )
			GUICtrlSetData ( $SETGC , LANG ( "GUI" , "setgcoff" , "解除GreenChrome" ) )
			GUICtrlSetTip ( $SETGC , LANG ( "GUI" , "setgcoffTips" , "解除并删除GreenChrome" ) )
			GUICtrlSetState ( $GCSETTING , $GUI_ENABLE )
			GUICtrlSetState ( $SETCPP , $GUI_DISABLE )
			GUICtrlSetState ( $CPPAUTOSET , $GUI_DISABLE )
		ElseIf FileExists ( $CHROMEDIR & "\" & $CHROMEEXE & "#" ) Then
			If FileExists ( $GREENCHROMEDLL ) Then FileDelete ( $GREENCHROMEDLL )
			If FileExists ( $SETDLL ) Then FileDelete ( $SETDLL )
			FileInstall ( "GreenChrome64.dll" , $GREENCHROMEDLL , 1 )
			FileInstall ( "setdll64.exe" , $SETDLL , 1 )
			If Not FileExists ( $GREENCHROMEINI ) Then FileInstall ( "GreenChrome.ini" , $GREENCHROMEINI , 1 )
			$CMD = "cd /d """ & $CHROMEDIR & """ && setdll /d:GreenChrome.dll " & $CHROMEEXE
			Run ( @ComSpec & " /c " & $CMD , "" , @SW_HIDE )
			Sleep ( 1000 )
			If FileExists ( $CHROMEDIR & "\" & $CHROMEEXE & "~" ) Then
				If ProcessExists ( """" & $CHROMEEXE & """" ) Then
					MsgBox ( 0 , "MyBrowser" , $INJECTGC1 , 0 , $HSETTINGS )
				Else
					MsgBox ( 0 , "MyBrowser" , $INJECTGC2 , 0 , $HSETTINGS )
				EndIf
				FileDelete ( $CHROMEDIR & "\" & $CHROMEEXE & "~" )
				IniWrite ( $INIFILE , "Settings" , "GreenChrome" , 1 )
				GUICtrlSetData ( $SETGC , LANG ( "GUI" , "setgcoff" , "解除GreenChrome" ) )
				GUICtrlSetTip ( $SETGC , LANG ( "GUI" , "setgcoffTips" , "解除并删除GreenChrome" ) )
				GUICtrlSetState ( $GCSETTING , $GUI_ENABLE )
			ElseIf FileExists ( $CHROMEDIR & "\" & $CHROMEEXE & "#" ) Then
				If Not ProcessExists ( """" & $CHROMEEXE & """" ) Then FileDelete ( $CHROMEDIR & "\" & $CHROMEEXE & "#" )
			EndIf
		EndIf
		FileDelete ( $SETDLL )
	ElseIf IniRead ( $INIFILE , "Settings" , "ChromePlusPlusAuto" , "" ) = 1 Then
		$CHROMEPLUSPLUSDLL = $CHROMEDIR & "\Chrome++.dll"
		$CHROMEPLUSPLUSINI = $CHROMEDIR & "\Chrome++.ini"
		$SETDLL = $CHROMEDIR & "\setdll.exe"
		If IniRead ( $INIFILE , "Settings" , "x86" , "" ) = 1 Then
			If FileExists ( $CHROMEPLUSPLUSDLL ) Then FileDelete ( $CHROMEPLUSPLUSDLL )
			If Not FileExists ( $SETDLL ) Then FileInstall ( "setdll.exe" , $SETDLL , 1 )
		ElseIf IniRead ( $INIFILE , "Settings" , "x86" , "" ) = 0 Then
			If FileExists ( $CHROMEPLUSPLUSDLL ) Then FileDelete ( $CHROMEPLUSPLUSDLL )
			If Not FileExists ( $SETDLL ) Then FileInstall ( "setdll64.exe" , $SETDLL , 1 )
		EndIf
		$CMD = "cd /d """ & $CHROMEDIR & """ && setdll /d:Chrome++.dll " & $CHROMEEXE
		Run ( @ComSpec & " /c " & $CMD , "" , @SW_HIDE )
		Sleep ( 1000 )
		If FileExists ( $CHROMEDIR & "\" & $CHROMEEXE & "~" ) Then
			If ProcessExists ( """" & $CHROMEEXE & """" ) Then
				MsgBox ( 0 , "MyBrowser" , $INJECTCPP1 , 0 , $HSETTINGS )
			Else
				MsgBox ( 0 , "MyBrowser" , $INJECTCPP2 , 0 , $HSETTINGS )
			EndIf
			FileDelete ( $CHROMEDIR & "\" & $CHROMEEXE & "~" )
			IniWrite ( $INIFILE , "Settings" , "ChromePlusPlus" , 1 )
			GUICtrlSetState ( $CPPSETTINGTIPS , $GUI_ENABLE )
			GUICtrlSetState ( $SETGC , $GUI_DISABLE )
			GUICtrlSetState ( $GCAUTOSET , $GUI_DISABLE )
		EndIf
		If FileExists ( $CHROMEDIR & "\" & $CHROMEEXE & "#" ) Then
			If Not ProcessExists ( """" & $CHROMEEXE & """" ) Then FileDelete ( $CHROMEDIR & "\" & $CHROMEEXE & "#" )
			FileDelete ( $CHROMEPLUSPLUSDLL )
			FileDelete ( $CHROMEPLUSPLUSINI )
			MsgBox ( 64 , "MyBrowser" , $INJECTCPP3 , 0 , $HSETTINGS )
		EndIf
		FileDelete ( $SETDLL )
	EndIf
	$MSG = MsgBox ( 64 + 4 , "MyBrowser" , $BROWSERTYPE & LANG ( "Update" , "IfCreateChromeShortcut" , "是否创建快捷方式到桌面(不支持中文路径)" ) , 0 , $HSETTINGS )
	If $MSG = 6 Then
		CREATECHROMESHORTCUT ( )
	EndIf
	Return $CHROMEFILEVERSION
EndFunc
Func TRAYTIPPROGRESS ( )
	$TRAYTIPPROGRESS = 1
EndFunc
Func ENDUPDATE ( )
	If ProcessExists ( $ITHREADPID ) Then
		_KILLTHREAD ( $ITHREADPID )
	EndIf
	If Not CHROMEISUPDATING ( $CHROMEDIR ) Then
		Local $TEMPDIR = $CHROMEDIR & "\~update\"
		If FileExists ( $TEMPDIR ) Then
			$CMD = "del /s /f /q """ & $TEMPDIR & "*.*"" && rd /s /q """ & $TEMPDIR & """"
			If Not Run ( @ComSpec & " /c " & $CMD , "" , @SW_HIDE ) Then
				MsgBox ( 0 , "Error" , LANG ( "Update" , "DeleteFail" , "删除 ~update 文件夹失败。" ) )
			EndIf
		EndIf
	EndIf
	If IsHWnd ( $HSETTINGS ) Then
		GUICtrlSetData ( $HCHECKUPDATE , LANG ( "GUI" , "UpdateNow" , "立即更新" ) )
		GUICtrlSetState ( $HSETTINGSOK , $GUI_ENABLE )
		GUICtrlSetState ( $HSETTINGSAPPLY , $GUI_ENABLE )
		If GUICtrlRead ( $SETGC ) = StringFormat ( LANG ( "GUI" , "setgcoff" , "解除GreenChrome" ) ) Then
			GUICtrlSetState ( $SETGC , $GUI_ENABLE )
		EndIf
		$LANGSETTINGSTIPS = StringFormat ( LANG ( "GUI" , "SettingsTips" , "双击软件目录下的 ""%s.vbs"" 文件可显示此窗口" ) , $APPNAME )
		_GUICTRLSTATUSBAR_SETTEXT ( $HSTAUSBAR , $LANGSETTINGSTIPS )
	EndIf
	$ISUPDATING = 0
EndFunc
Func EXITAPP ( )
	If $ISUPDATING Then
		Local $MSG = MsgBox ( 292 , "MyBrowser" , StringFormat ( LANG ( "Update" , "ExitConfirm" , "浏览器正在更新，确定要取消更新并退出吗？" ) ) , 0 , $HSETTINGS )
		If $MSG = 7 Then Return
		ENDUPDATE ( )
	ElseIf ProcessExists ( $ITHREADPID ) Then
		_KILLTHREAD ( $ITHREADPID )
	EndIf
	Exit
EndFunc
Func SPLITPATH ( $PATH , ByRef $DIR , ByRef $FILE )
	Local $POS = StringInStr ( $PATH , "\" , 0 , - 1 )
	If $POS = 0 Then
		$DIR = "."
		$FILE = $PATH
	Else
		$DIR = StringLeft ( $PATH , $POS - 1 )
		$FILE = StringMid ( $PATH , $POS + 1 )
	EndIf
EndFunc
Func FIREFOXSPLITPATH ( $PATH , ByRef $DIR , ByRef $FILE , $SPLITER = "\" )
	Local $POS = StringInStr ( $PATH , $SPLITER , 0 , - 1 )
	If $POS = 0 Then
		$DIR = "."
		$FILE = $PATH
	Else
		$DIR = StringLeft ( $PATH , $POS - 1 )
		$FILE = StringMid ( $PATH , $POS + 1 )
	EndIf
EndFunc
Func RELATIVEPATH ( $PATH )
	If $PATH = "" Then Return $PATH
	If StringLeft ( $PATH , 1 ) = "%" Then Return $PATH
	If Not StringInStr ( $PATH , ":" ) And StringLeft ( $PATH , 2 ) <> "\\" Then Return $PATH
	If StringLeft ( @ScriptDir , 3 ) <> StringLeft ( $PATH , 3 ) Then Return $PATH
	If StringRight ( $PATH , 1 ) <> "\" Then $PATH &= "\"
	Local $R = ".\"
	Local $POS , $DIR = @ScriptDir & "\"
	While 1
		$PATH = StringReplace ( $PATH , $DIR , $R )
		If @extended Then ExitLoop
		$POS = StringInStr ( $DIR , "\" , 0 , - 2 )
		If $POS = 0 Then ExitLoop
		$DIR = StringLeft ( $DIR , $POS )
		If StringLeft ( $R , 2 ) = ".\" Then
			$R = "..\"
		Else
			$R = "..\" & $R
		EndIf
	WEnd
	If StringRight ( $PATH , 1 ) = "\" Then $PATH = StringTrimRight ( $PATH , 1 )
	Return $PATH
EndFunc
Func FULLPATH ( $PATH )
	If $PATH = "" Then Return $PATH
	If StringLeft ( $PATH , 1 ) = "%" Then Return $PATH
	If StringInStr ( $PATH , ":\" ) Or StringLeft ( $PATH , 2 ) = "\\" Then Return $PATH
	If StringRight ( $PATH , 1 ) <> "\" Then $PATH &= "\"
	Local $DIR = @ScriptDir
	If StringLeft ( $PATH , 2 ) = ".\" Then
		$PATH = StringReplace ( $PATH , "." , $DIR , 1 )
	ElseIf StringLeft ( $PATH , 3 ) <> "..\" Then
		$PATH = $DIR & "\" & $PATH
	Else
		Local $I , $N , $POS
		$PATH = StringReplace ( $PATH , "..\" , "" )
		$N = @extended
		For $I = 1 To $N
			$POS = StringInStr ( $DIR , "\" , 0 , - 1 )
			If $POS = 0 Then ExitLoop
			$DIR = StringLeft ( $DIR , $POS - 1 )
		Next
		$PATH = $DIR & "\" & $PATH
	EndIf
	If StringRight ( $PATH , 1 ) = "\" Then $PATH = StringTrimRight ( $PATH , 1 )
	Return $PATH
EndFunc
Func CHROMEISUPDATING ( $DIR )
	Local $UPDATEINI = $DIR & "\~update\Update.ini"
	If Not FileExists ( $UPDATEINI ) Then Return
	Local $PID = IniRead ( $UPDATEINI , "general" , "pid" , "" )
	Local $EXE = IniRead ( $UPDATEINI , "general" , "exe" , "" )
	If $PID <> $ITHREADPID And ProcessExists ( $PID ) And ProcessExists ( $EXE ) Then
		Return 1
	EndIf
EndFunc
Func APPISRUNNING ( $APPPATH )
	Local $EXE = StringRegExpReplace ( $APPPATH , ".*\\" , "" )
	Local $LIST = ProcessList ( $EXE )
	For $I = 1 To $LIST [ 0 ] [ 0 ]
		If StringInStr ( GETPROCPATH ( $LIST [ $I ] [ 1 ] ) , $APPPATH ) Then
			Return $LIST [ $I ] [ 1 ]
		EndIf
	Next
	Return 0
EndFunc
Func CHROMEISRUNNING ( $APPPATH = "chrome.exe" , $MSG = "Do you want to close Chrome？" )
	If Not APPISRUNNING ( $APPPATH ) Then Return 0
	$VAR = MsgBox ( 52 , "MyBrowser" , $MSG , 0 , $HSETTINGS )
	If $VAR <> 6 Then Return 1
	$EXE = StringRegExpReplace ( $APPPATH , ".*\\" , "" )
	For $J = 1 To 20
		$LIST = WinList ( "[REGEXPCLASS:(?i)Chrome; REGEXPTITLE:\S+]" )
		For $I = 1 To $LIST [ 0 ] [ 0 ]
			$PID = WinGetProcess ( $LIST [ $I ] [ 1 ] )
			If StringInStr ( GETPROCPATH ( $PID ) , $APPPATH ) Then
				WinClose ( $LIST [ $I ] [ 1 ] )
				WinWaitClose ( $LIST [ $I ] [ 1 ] , "" , 2 )
			EndIf
		Next
		Sleep ( 1000 )
		$LIST = ProcessList ( $EXE )
		For $I = 1 To $LIST [ 0 ] [ 0 ]
			If StringInStr ( GETPROCPATH ( $LIST [ $I ] [ 1 ] ) , $APPPATH ) Then
				ProcessClose ( $LIST [ $I ] [ 1 ] )
			EndIf
		Next
		If Not APPISRUNNING ( $APPPATH ) Then Return 0
	Next
	Return 1
EndFunc
Func HTTPPARSEURL ( $URL )
	Local $HOST , $PAGE , $PORT , $ARESULTS [ 3 ]
	Local $MATCH = StringRegExp ( $URL , "(?i)^https?://([^/]+)(/?.*)" , 1 )
	If @error Then Return SetError ( 1 , 0 , $ARESULTS )
	$ARESULTS [ 0 ] = $MATCH [ 0 ]
	$ARESULTS [ 1 ] = $MATCH [ 1 ]
	If $ARESULTS [ 1 ] = "" Then $ARESULTS [ 1 ] = "/"
	If StringLeft ( $URL , 5 ) = "https" Then
		$ARESULTS [ 2 ] = 443
	Else
		$ARESULTS [ 2 ] = 80
	EndIf
	Return SetError ( 0 , 0 , $ARESULTS )
EndFunc
Func TRAYTIPEXISTS ( $TRAYTEXT , $MATCHMODE = 0 )
	Local $AWINDOWS = WinList ( "[CLASS:tooltips_class32]" )
	Local $I , $HWND , $CLASS , $TEXT
	For $I = 1 To $AWINDOWS [ 0 ] [ 0 ]
		If Not BitAND ( WinGetState ( $AWINDOWS [ $I ] [ 1 ] ) , 2 ) Then ContinueLoop
		$HWND = DllCall ( "user32.dll" , "hwnd" , "GetParent" , "hwnd" , $AWINDOWS [ $I ] [ 1 ] )
		If @error Then Return SetError ( @error , @extended , 0 )
		$CLASS = DllCall ( "user32.dll" , "int" , "GetClassNameW" , "hwnd" , $HWND [ 0 ] , "wstr" , "" , "int" , 1024 )
		If @error Then Return SetError ( @error , @extended , 0 )
		If $CLASS [ 2 ] <> "Shell_TrayWnd" Then ContinueLoop
		$TEXT = WinGetTitle ( $AWINDOWS [ $I ] [ 1 ] )
		If $MATCHMODE = 1 Then
			If StringRegExp ( $TEXT , $TRAYTEXT ) Then Return $AWINDOWS [ $I ] [ 1 ]
		Else
			If StringInStr ( $TEXT , $TRAYTEXT ) Then Return $AWINDOWS [ $I ] [ 1 ]
		EndIf
	Next
EndFunc
Func REDUCEMEMORY ( )
	Local $AI_HANDLE = DllCall ( "kernel32.dll" , "int" , "OpenProcess" , "int" , 2035711 , "int" , False , "int" , @AutoItPID )
	Local $AI_RETURN = DllCall ( "psapi.dll" , "int" , "EmptyWorkingSet" , "long" , $AI_HANDLE [ 0 ] )
	DllCall ( "kernel32.dll" , "int" , "CloseHandle" , "int" , $AI_HANDLE [ 0 ] )
	Return $AI_RETURN [ 0 ]
EndFunc
Func GETPROCPATH ( $PID = @AutoItPID )
	If @OSArch <> "X86" And Not @AutoItX64 And Not _WINAPI_ISWOW64PROCESS ( $PID ) Then
		Local $COLITEMS = ""
		Local $OBJWMISERVICE = ObjGet ( "winmgmts:\\localhost\root\CIMV2" )
		$COLITEMS = $OBJWMISERVICE .ExecQuery ( "SELECT * FROM Win32_Process WHERE ProcessId = " & $PID , "WQL" , 16 + 32 )
		If IsObj ( $COLITEMS ) Then
			For $OBJITEM In $COLITEMS
				If $OBJITEM .ExecutablePath Then Return $OBJITEM .ExecutablePath
			Next
		EndIf
		Return ""
	Else
		Local $HPROCESS = DllCall ( "kernel32.dll" , "ptr" , "OpenProcess" , "dword" , BitOR ( 1024 , 16 ) , "int" , 0 , "dword" , $PID )
		If ( @error ) Or ( Not $HPROCESS [ 0 ] ) Then Return SetError ( 1 , 0 , "" )
		Local $RET = DllCall ( @SystemDir & "\psapi.dll" , "int" , "GetModuleFileNameExW" , "ptr" , $HPROCESS [ 0 ] , "ptr" , 0 , "wstr" , "" , "int" , 1024 )
		If ( @error ) Or ( Not $RET [ 0 ] ) Then Return SetError ( 1 , 0 , "" )
		Return $RET [ 3 ]
	EndIf
EndFunc
Func _ISUACADMIN ( )
	If StringRegExp ( @OSVersion , "_(XP|2003)" ) Or RegRead ( "HKLM64\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" , "EnableLUA" ) <> 1 Then
		Return SetExtended ( 0 , IsAdmin ( ) )
	EndIf
	Local $HTOKEN = _SECURITY__OPENPROCESSTOKEN ( _WINAPI_GETCURRENTPROCESS ( ) , $TOKEN_QUERY )
	Local $TTI = _SECURITY__GETTOKENINFORMATION ( $HTOKEN , $TOKENGROUPS )
	_WINAPI_CLOSEHANDLE ( $HTOKEN )
	Local $PTI = DllStructGetPtr ( $TTI )
	Local $CBSIDATTR = DllStructGetSize ( DllStructCreate ( "ptr;dword" ) )
	Local $COUNT = DllStructGetData ( DllStructCreate ( "dword" , $PTI ) , 1 )
	Local $PGROUP1 = DllStructGetPtr ( DllStructCreate ( "dword;STRUCT;ptr;dword;ENDSTRUCT" , $PTI ) , 2 )
	Local $TGROUP , $SGROUP = ""
	Local $INADMINGRP = False , $DENYADMIN = False , $ELEVATEDADMIN = False , $SSID
	For $I = 0 To $COUNT - 1
		$TGROUP = DllStructCreate ( "ptr;dword" , $PGROUP1 + ( $CBSIDATTR * $I ) )
		$SSID = _SECURITY__SIDTOSTRINGSID ( DllStructGetData ( $TGROUP , 1 ) )
		If StringInStr ( $SSID , "S-1-5-32-544" ) Then
			$INADMINGRP = True
			If ( BitAND ( DllStructGetData ( $TGROUP , 2 ) , 16 ) = 16 ) Then $DENYADMIN = True
		ElseIf StringInStr ( $SSID , "S-1-16-12288" ) Then
			$ELEVATEDADMIN = True
		EndIf
	Next
	If $INADMINGRP Then
		If $ELEVATEDADMIN Then
			If $DENYADMIN Then
				Return SetExtended ( 0 , 0 )
			Else
				Return SetExtended ( 1 , 1 )
			EndIf
		Else
			Return SetExtended ( 1 , 0 )
		EndIf
	Else
		Return SetExtended ( 0 , 0 )
	EndIf
EndFunc
Func VERSIONCOMPARE ( $V1 , $V2 )
	Local $I , $A1 , $A2 , $RET = 0
	$A1 = StringSplit ( $V1 , "." , 2 )
	$A2 = StringSplit ( $V2 , "." , 2 )
	If UBound ( $A1 ) > UBound ( $A2 ) Then
		ReDim $A2 [ UBound ( $A1 ) ]
	Else
		ReDim $A1 [ UBound ( $A2 ) ]
	EndIf
	For $I = 0 To UBound ( $A1 ) - 1
		$RET = $A1 [ $I ] - $A2 [ $I ]
		If $RET <> 0 Then ExitLoop
	Next
	Return $RET
EndFunc
Func CHECKPREFS ( )
	Local $VAR , $CFG
	Local $PREFS = FileRead ( $USERDATADIR & "\prefs.js" )
	If Not StringRegExp ( $PREFS , "(?i)(?m)^\Quser_pref(""browser.shell.checkDefaultBrowser"",\E *\Qfalse);\E" ) Then
		$CFG &= "pref(""browser.shell.checkDefaultBrowser"", false);" & @CRLF
	EndIf
	$CACHEDIR = FULLPATH ( $CACHEDIR )
	If $CACHEDIR = "" Or $CACHEDIR = $USERDATADIR Then
		If StringInStr ( $PREFS , "user_pref(""browser.cache.disk.parent_directory""," ) Then
			$CFG &= "clearPref(""browser.cache.disk.parent_directory"");" & @CRLF
		EndIf
	Else
		$VAR = StringReplace ( $CACHEDIR , "\" , "\\" )
		If Not StringRegExp ( $PREFS , "(?i)(?m)^\Quser_pref(""browser.cache.disk.parent_directory"",\E *\Q""" & $VAR & """);\E" ) Then
			$CFG &= "pref(""browser.cache.disk.parent_directory"", """ & $VAR & """);" & @CRLF
		EndIf
	EndIf
	If $CACHESIZE = "" Or $CACHESIZE = 250 Then
		If StringInStr ( $PREFS , "user_pref(""browser.cache.disk.capacity""," ) Then
			$CFG &= "clearPref(""browser.cache.disk.capacity"");" & @CRLF
		EndIf
	Else
		$VAR = $CACHESIZE * 1024
		If Not StringRegExp ( $PREFS , "(?i)(?m)^\Quser_pref(""browser.cache.disk.capacity"",\E *\Q" & $VAR & ");\E" ) Then
			$CFG &= "pref(""browser.cache.disk.capacity"", " & $VAR & ");" & @CRLF
		EndIf
	EndIf
	If $CACHESIZESMART = 1 Then
		If StringInStr ( $PREFS , "user_pref(""browser.cache.disk.smart_size.enabled""," ) Then
			$CFG &= "clearPref(""browser.cache.disk.smart_size.enabled"");" & @CRLF
		EndIf
	Else
		If Not StringRegExp ( $PREFS , "(?i)(?m)^\Quser_pref(""browser.cache.disk.smart_size.enabled"",\E *\Qfalse);\E" ) Then
			$CFG &= "pref(""browser.cache.disk.smart_size.enabled"", false);" & @CRLF
		EndIf
	EndIf
	If $CFG Then
		$CFG = "//" & @CRLF & $CFG
	EndIf
	$PREFS = ""
	Return $CFG
EndFunc
Func CHECKFIREFOXPINNEDPROGRAMS ( $BROWSER_PATH )
	If Not FileExists ( $TASKBARDIR ) Then
		Return
	EndIf
	Local $FTIME = FileGetTime ( $TASKBARDIR , 0 , 1 )
	If $FTIME = $TASKBARLASTCHANGE Then
		Return
	EndIf
	$TASKBARLASTCHANGE = $FTIME
	Local $SEARCH = FileFindFirstFile ( $TASKBARDIR & "\*.lnk" )
	If $SEARCH = - 1 Then Return
	Local $FILE , $SHELLOBJ , $OBJSHORTCUT , $SHORTCUT_APPID
	$SHELLOBJ = ObjCreate ( "WScript.Shell" )
	If Not @error Then
		While 1
			$FILE = $TASKBARDIR & "\" & FileFindNextFile ( $SEARCH )
			If @error Then ExitLoop
			$OBJSHORTCUT = $SHELLOBJ .CreateShortCut ( $FILE )
			$PATH = $OBJSHORTCUT .TargetPath
			If $PATH == $BROWSER_PATH Or $PATH == @ScriptFullPath Then
				If $PATH == $BROWSER_PATH Then
					$OBJSHORTCUT .TargetPath = @ScriptFullPath
					$OBJSHORTCUT .Save
					$TASKBARLASTCHANGE = FileGetTime ( $TASKBARDIR , 0 , 1 )
				EndIf
				$SHORTCUT_APPID = _SHORTCUTAPPID ( $FILE )
				If Not $APPUSERMODELID Then
					$APPUSERMODELID = _WINDOWAPPID ( $HWND_BROWSER )
					If Not $APPUSERMODELID Then
						$APPUSERMODELID = APPIDFROMREGISTRY ( )
						If Not $APPUSERMODELID Then
							Local $PID = Run ( $CHROMEDIR & "\uninstall\helper.exe /UpdateShortcutAppUserModelIds" )
							ProcessWaitClose ( $PID , 5 )
							$APPUSERMODELID = APPIDFROMREGISTRY ( )
						EndIf
						If Not $APPUSERMODELID Then
							If $SHORTCUT_APPID Then
								$APPUSERMODELID = $SHORTCUT_APPID
							Else
								$APPUSERMODELID = "MyFirefox." & StringTrimLeft ( _WINAPI_HASHSTRING ( @ScriptFullPath , 0 , 16 ) , 2 )
							EndIf
						EndIf
						_WINDOWAPPID ( $HWND_BROWSER , $APPUSERMODELID )
					EndIf
				EndIf
				If $SHORTCUT_APPID <> $APPUSERMODELID Then
					_SHORTCUTAPPID ( $FILE , $APPUSERMODELID )
					$TASKBARLASTCHANGE = FileGetTime ( $TASKBARDIR , 0 , 1 )
				EndIf
				ExitLoop
			EndIf
		WEnd
		$OBJSHORTCUT = ""
		$SHELLOBJ = ""
	EndIf
	FileClose ( $SEARCH )
EndFunc
Func APPIDFROMREGISTRY ( )
	Local $APPID
	If @OSArch = "X86" Then
		Local $AROOT [ 2 ] = [ "HKCU\SOFTWARE" , $HKLM_SOFTWARE_32 ]
	Else
		Local $AROOT [ 3 ] = [ "HKCU\SOFTWARE" , $HKLM_SOFTWARE_32 , $HKLM_SOFTWARE_64 ]
	EndIf
	For $I = 0 To UBound ( $AROOT ) - 1
		$APPID = RegRead ( $AROOT [ $I ] & "\Mozilla\Firefox\TaskBarIDs" , $CHROMEDIR )
		If $APPID Then ExitLoop
	Next
	Return $APPID
EndFunc
Func FIREFOXCHECKDEFAULTBROWSER ( $BROWSERPATH )
	Local $INTERNETCLIENT , $KEY , $I , $J , $VAR , $REGWRITEERROR = 0
	If Not $CLIENTKEY Then
		If @OSArch = "X86" Then
			Local $AROOT [ 2 ] = [ "HKCU\SOFTWARE" , $HKLM_SOFTWARE_32 ]
		Else
			Local $AROOT [ 3 ] = [ "HKCU\SOFTWARE" , $HKLM_SOFTWARE_32 , $HKLM_SOFTWARE_64 ]
		EndIf
		For $I = 0 To UBound ( $AROOT ) - 1
			$J = 1
			While 1
				$INTERNETCLIENT = RegEnumKey ( $AROOT [ $I ] & "\Clients\StartMenuInternet" , $J )
				If @error <> 0 Then ExitLoop
				$KEY = $AROOT [ $I ] & "\Clients\StartMenuInternet\" & $INTERNETCLIENT
				$VAR = RegRead ( $KEY & "\DefaultIcon" , "" )
				If StringInStr ( $VAR , $BROWSERPATH ) Then
					$CLIENTKEY = $KEY
					$FILEASSO = RegRead ( $CLIENTKEY & "\Capabilities\FileAssociations" , ".html" )
					$URLASSO = RegRead ( $CLIENTKEY & "\Capabilities\URLAssociations" , "http" )
					ExitLoop 2
				EndIf
				$J += 1
			WEnd
		Next
	EndIf
	If $CLIENTKEY Then
		$VAR = RegRead ( $CLIENTKEY & "\shell\open\command" , "" )
		If Not StringInStr ( $VAR , @ScriptFullPath ) Then
			$REGWRITEERROR += Not RegWrite ( $CLIENTKEY & "\shell\open\command" , "" , "REG_SZ" , """" & @ScriptFullPath & """" )
			RegWrite ( $CLIENTKEY & "\shell\properties\command" , "" , "REG_SZ" , """" & @ScriptFullPath & """ -preferences" )
			RegWrite ( $CLIENTKEY & "\shell\safemode\command" , "" , "REG_SZ" , """" & @ScriptFullPath & """ -safe-mode" )
		EndIf
	EndIf
	If Not $FILEASSO Then
		If StringInStr ( RegRead ( "HKCR\FirefoxHTML\DefaultIcon" , "" ) , $BROWSERPATH ) Then
			$FILEASSO = "FirefoxHTML"
		EndIf
	EndIf
	If Not $URLASSO Then
		If StringInStr ( RegRead ( "HKCR\FirefoxURL\DefaultIcon" , "" ) , $BROWSERPATH ) Then
			$URLASSO = "FirefoxURL"
		EndIf
	EndIf
	Local $AASSO [ 2 ] = [ $FILEASSO , $URLASSO ]
	For $I = 0 To 1
		If Not $AASSO [ $I ] Then ContinueLoop
		$VAR = RegRead ( "HKCR\" & $AASSO [ $I ] & "\shell\open\command" , "" )
		If Not StringInStr ( $VAR , @ScriptFullPath ) Then
			$REGWRITEERROR += Not RegWrite ( "HKCR\" & $AASSO [ $I ] & "\shell\open\command" , "" , "REG_SZ" , """" & @ScriptFullPath & """ -url ""%1""" )
			RegDelete ( "HKCR\" & $AASSO [ $I ] & "\shell\open\command" , "DelegateExecute" )
			RegWrite ( "HKCR\" & $AASSO [ $I ] & "\shell\open\ddeexec" , "" , "REG_SZ" , "" )
		EndIf
		If Not $AREG [ 5 + $I ] [ 1 ] Then
			$AREG [ 5 + $I ] [ 1 ] = $AASSO [ $I ]
			$AREG [ 5 + $I ] [ 2 ] = _WINAPI_REGOPENKEY ( $AREG [ 5 + $I ] [ 0 ] , $AREG [ 5 + $I ] [ 1 ] , $KEY_NOTIFY )
		EndIf
	Next
	Local $AURLASSO [ 3 ] = [ "ftp" , "http" , "https" ]
	For $I = 0 To 2
		$VAR = RegRead ( "HKCR\" & $AURLASSO [ $I ] & "\DefaultIcon" , "" )
		If StringInStr ( $VAR , $BROWSERPATH ) Then
			$VAR = RegRead ( "HKCR\" & $AURLASSO [ $I ] & "\shell\open\command" , "" )
			If Not StringInStr ( $VAR , @ScriptFullPath ) Then
				$REGWRITEERROR += Not RegWrite ( "HKCR\" & $AURLASSO [ $I ] & "\shell\open\command" , "" , "REG_SZ" , """" & @ScriptFullPath & """ -url ""%1""" )
				RegDelete ( "HKCR\" & $AURLASSO [ $I ] & "\shell\open\command" , "DelegateExecute" )
				RegWrite ( "HKCR\" & $AURLASSO [ $I ] & "\shell\open\ddeexec" , "" , "REG_SZ" , "" )
			EndIf
		EndIf
	Next
	If $REGWRITEERROR And Not _ISUACADMIN ( ) And @extended Then
		If @Compiled Then
			ShellExecute ( @ScriptName , "-SetDefaultGlobal" , @ScriptDir , "runas" )
		Else
			ShellExecute ( @AutoItExe , """" & @ScriptFullPath & """ -SetDefaultGlobal" , @ScriptDir , "runas" )
		EndIf
	EndIf
EndFunc
Func GETPLUGINSDIR ( )
	Local $DIR = FileSelectFolder ( LANG ( "GUI" , "SaveToPluginsDir" , "指定 Firefox 插件目录" ) , "" , 1 + 4 , @ScriptDir , $HSETTINGS )
	FileChangeDir ( @ScriptDir )
	If $DIR = "" Then Return
	$PLUGINSDIR = RELATIVEPATH ( $DIR )
	GUICtrlSetData ( $HPLUGINSDIR , $PLUGINSDIR )
EndFunc
Func PROFILEINUSE ( $PROFDIR )
	Return FileExists ( $PROFDIR & "\parent.lock" ) And Not FileDelete ( $PROFDIR & "\parent.lock" )
EndFunc
Func CREATECHROMESHORTCUT ( )
	If Not FileExists ( FULLPATH ( $CHROMEPATH ) ) Then
		If StringInStr ( $PLATFORM , "mac" ) Or StringInStr ( $PLATFORM , "linux" ) Or StringInStr ( $PLATFORM , "android" ) Then
		Else
			$LANGCHROMENOTEXISTSTIPS = LANG ( "GUI" , "ChromeNotExistsTips" , "找不到浏览器程序文件： \n%s\n\n请重新设置或者从网络下载！\n需要从网络下载浏览器的最新版本吗？" )
			Local $MSG = MsgBox ( 36 , "MyBrowser" , StringFormat ( $LANGCHROMENOTEXISTSTIPS , $CHROMEPATH ) , 0 , $HSETTINGS )
			If $MSG <> 6 Then
				GUICtrlSetState ( $HCHROMEPATH , $GUI_FOCUS )
				Return SetError ( 1 )
			Else
				GUI_START_END_CHROMEUPDATE ( )
			EndIf
		EndIf
		Return
	EndIf
	Local $TARGETPATH = @ScriptDir & "\" & $APPNAME & ".exe"
	Local $DESKTOPPATH = EnvGet ( "USERPROFILE" ) & "\Desktop\"
	$BROWSERTYPE1 = IniRead ( $INIFILE , "Settings" , "BrowserType" , "" )
	If StringInStr ( $BROWSERTYPE1 , "Chrome" ) Then
		$BROWSERTYPE = "Google Chrome"
	ElseIf StringInStr ( $BROWSERTYPE1 , "Edge" ) Then
		$BROWSERTYPE = "MicroSoft Edge"
	ElseIf StringInStr ( $BROWSERTYPE1 , "Cent" ) Then
		$BROWSERTYPE = "Cent Browser"
	ElseIf StringInStr ( $BROWSERTYPE1 , "Edge" ) Then
		$BROWSERTYPE = "MicroSoft Edge"
	Else
		$BROWSERTYPE = $BROWSERTYPE1
	EndIf
	Local $ICONPATH = FULLPATH ( $CHROMEPATH )
	Local $BATCONTENT = "@echo off" & @CRLF & "(echo Set WshShell=CreateObject(""WScript.Shell""^)" & @CRLF & "echo strDesKtop=WshShell.SpecialFolders(""Desktop""^)" & @CRLF & "echo Set oShellLink=WshShell.CreateShortcut(strDesKtop^&""\" & "" & $BROWSERTYPE & ".lnk""^)" & @CRLF & "echo oShellLink.TargetPath=""" & $TARGETPATH & """" & @CRLF & "echo oShellLink.IconLocation=""" & $ICONPATH & """" & @CRLF & "echo oShellLink.Save)>makelnk.vbs" & @CRLF & "makelnk.vbs" & @CRLF & "del /f /q makelnk.vbs"
	Local $BATFILE = @ScriptDir & "\createshortcut.bat"
	$BINARYDATA = StringToBinary ( $BATCONTENT , 1 )
	$FILEHANDLE = FileOpen ( $BATFILE , 2 )
	FileWrite ( $FILEHANDLE , $BINARYDATA )
	FileClose ( $FILEHANDLE )
	_RUNDOS ( "call " & $BATFILE )
	If @error Then
		MsgBox ( 0 , "Error" , "The batch file did not run successfully: Error code " & @error )
	Else
		FileDelete ( $BATFILE )
	EndIf
EndFunc
Func UPDATEADDONSTARUP ( )
	Local $MOZLZ4EXE , $ADDONSTARUP , $ADDONSTARUPLZ4
	If @OSArch = "X86" Then
		$MOZLZ4EXE = @ScriptDir & "\" & "mozlz4-win32.exe"
		FileInstall ( "mozlz4-win32.exe" , $MOZLZ4EXE )
	Else
		$MOZLZ4EXE = @ScriptDir & "\" & "mozlz4-win64.exe"
		FileInstall ( "mozlz4-win64.exe" , $MOZLZ4EXE )
	EndIf
	$ADDONSTARUPLZ4 = $USERDATADIR & "\addonStartup.json.lz4"
	$ADDONSTARUP = $USERDATADIR & "\addonStartup.json"
	If FileExists ( $ADDONSTARUPLZ4 ) Then
		FileDelete ( $ADDONSTARUP )
		RunWait ( $MOZLZ4EXE & " " & $ADDONSTARUPLZ4 & " " & $ADDONSTARUP , @ScriptDir , @SW_HIDE )
	EndIf
	If FileExists ( $ADDONSTARUP ) Then
		Local $FILEOPEN , $FILECONTENT , $MATCHES
		$FILEOPEN = FileOpen ( $ADDONSTARUP , $FO_READ )
		If $FILEOPEN <> - 1 Then
			$FILECONTENT = FileRead ( $FILEOPEN )
			FileClose ( $FILEOPEN )
			$FILECONTENT = REPLACEJARPATH ( $FILECONTENT )
			$FILEOPEN = FileOpen ( $ADDONSTARUP , $FO_OVERWRITE )
			If $FILEOPEN <> - 1 Then
				FileWrite ( $FILEOPEN , $FILECONTENT )
				FileClose ( $FILEOPEN )
				RunWait ( $MOZLZ4EXE & " -z " & $ADDONSTARUP & " " & $ADDONSTARUPLZ4 , @ScriptDir , @SW_HIDE )
			EndIf
		EndIf
		FileDelete ( $ADDONSTARUP )
	EndIf
	If FileExists ( @ScriptDir & "\" & "mozlz4-win32.exe" ) Then FileDelete ( @ScriptDir & "\" & "mozlz4-win32.exe" )
	If FileExists ( @ScriptDir & "\" & "mozlz4-win64.exe" ) Then FileDelete ( @ScriptDir & "\" & "mozlz4-win64.exe" )
EndFunc
Func REPLACEJARPATH ( $CONTENT )
	Local $MATCHES = StringRegExp ( $CONTENT , "jar:file[^""]+" , $STR_REGEXPARRAYGLOBALMATCH )
	For $I = 0 To UBound ( $MATCHES ) - 1
		Local $PREVPATH = $MATCHES [ $I ]
		Local $TEMPPATH = StringReplace ( $PREVPATH , "jar:file:///" , "" )
		$TEMPPATH = StringReplace ( $TEMPPATH , "!/" , "" )
		Local $DIR , $NAME , $NEWPATH = ""
		FIREFOXSPLITPATH ( $TEMPPATH , $DIR , $NAME , "/" )
		If ( _STRINGENDSWITH ( $DIR , "/browser/features" ) ) Then
			$NEWPATH = "jar:file:///" & $CHROMEPATH & "/browser/features/" & $NAME & "!/"
		EndIf
		If ( _STRINGENDSWITH ( $DIR , "/extensions" ) ) Then
			$NEWPATH = "jar:file:///" & $USERDATADIR & "/extensions/" & $NAME & "!/"
		EndIf
		If $NEWPATH <> "" Then
			$NEWPATH = StringReplace ( $NEWPATH , "\" , "/" )
			$CONTENT = StringReplace ( $CONTENT , $PREVPATH , $NEWPATH )
		EndIf
	Next
	Return $CONTENT
EndFunc
Func UPDATEEXTENSIONSJSON ( )
	Local $EXTENSIONS
	$EXTENSIONS = $USERDATADIR & "\extensions.json"
	If FileExists ( $EXTENSIONS ) Then
		Local $FILEOPEN , $FILECONTENT , $MATCHES
		$FILEOPEN = FileOpen ( $EXTENSIONS , $FO_READ )
		If $FILEOPEN <> - 1 Then
			$FILECONTENT = FileRead ( $FILEOPEN )
			FileClose ( $FILEOPEN )
			$FILECONTENT = REPLACELOCALPATH ( $FILECONTENT )
			$FILEOPEN = FileOpen ( $EXTENSIONS , $FO_OVERWRITE )
			If $FILEOPEN <> - 1 Then
				FileWrite ( $FILEOPEN , $FILECONTENT )
				FileClose ( $FILEOPEN )
			EndIf
		EndIf
	EndIf
EndFunc
Func REPLACELOCALPATH ( $CONTENT )
	Local $MATCHES = StringRegExp ( $CONTENT , """path"":""[^""]+" , $STR_REGEXPARRAYGLOBALMATCH )
	For $I = 0 To UBound ( $MATCHES ) - 1
		Local $PREVPATH = $MATCHES [ $I ]
		$PREVPATH = StringReplace ( $PREVPATH , """path"":""" , "" )
		$PREVPATH = StringReplace ( $PREVPATH , "\\" , "\" )
		Local $DIR , $NAME , $NEWPATH = ""
		FIREFOXSPLITPATH ( $PREVPATH , $DIR , $NAME , "\" )
		If ( _STRINGENDSWITH ( $DIR , "\browser\features" ) ) Then
			$NEWPATH = $CHROMEPATH & "\browser\features\" & $NAME
		EndIf
		If ( _STRINGENDSWITH ( $DIR , "\extensions" ) ) Then
			$NEWPATH = $USERDATADIR & "\extensions\" & $NAME
		EndIf
		If $NEWPATH <> "" Then
			$PREVPATH = StringReplace ( $PREVPATH , "\" , "\\" )
			$NEWPATH = StringReplace ( $NEWPATH , "\" , "\\" )
			$CONTENT = StringReplace ( $CONTENT , "\\\\" , "\\" )
			$CONTENT = StringReplace ( $CONTENT , $PREVPATH , $NEWPATH )
		EndIf
	Next
	Return $CONTENT
EndFunc
Func COUNTUNDERSCORES ( $SSTRING )
	Local $ICOUNT = 0
	Local $IPOS = StringInStr ( $SSTRING , "_" )
	While $IPOS > 0
		$ICOUNT += 1
		$SSTRING = StringTrimLeft ( $SSTRING , $IPOS + 1 )
		$IPOS = StringInStr ( $SSTRING , "_" )
	WEnd
	Return $ICOUNT
EndFunc
