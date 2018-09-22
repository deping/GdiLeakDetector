// GdiLeakDetector.cpp
//

#include "stdafx.h"
#include "GdiLeakDetector.h"
#include "GdiLeakDetectorDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CGdiLeakDetectorApp

BEGIN_MESSAGE_MAP(CGdiLeakDetectorApp, CWinApp)
	ON_COMMAND(ID_HELP, &CWinApp::OnHelp)
END_MESSAGE_MAP()


CGdiLeakDetectorApp::CGdiLeakDetectorApp()
{
}


CGdiLeakDetectorApp theApp;


#pragma data_seg(".share")
BOOL g_bFirstInstance = TRUE;
#pragma data_seg()
#pragma comment(linker, "-section:.share,rws")

BOOL EnableDebugPrivilege()
{
	HANDLE hToken;
	if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
		return FALSE;

	BOOL bSuccess = FALSE;
	TOKEN_PRIVILEGES tpOld;
	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (LookupPrivilegeValue(0, SE_DEBUG_NAME, &tp.Privileges[0].Luid))
	{
		DWORD cbOld = sizeof(tpOld);
		if (AdjustTokenPrivileges(hToken, FALSE, &tp, cbOld, &tpOld, &cbOld))
			bSuccess = (ERROR_NOT_ALL_ASSIGNED != GetLastError());
	}

	::CloseHandle(hToken);

	return bSuccess;
}

BOOL CGdiLeakDetectorApp::InitInstance()
{
	//Because the debugger will communicate with the debugged, We must ensure that at any time there
	//is at most only one debugger-debugged pair.
	if(g_bFirstInstance)
		g_bFirstInstance = FALSE;
	else
		return FALSE;

	if(!EnableDebugPrivilege())
	{
		AfxMessageBox(_T("You must have the debugging privilege to run the tool!"));
		return FALSE;
	}

	INITCOMMONCONTROLSEX InitCtrls;
	InitCtrls.dwSize = sizeof(InitCtrls);
	InitCtrls.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&InitCtrls);

	CWinApp::InitInstance();

	SetRegistryKey(_T("Tongji University"));

	CGdiLeakDetectorDlg dlg;
	m_pMainWnd = &dlg;
	INT_PTR nResponse = dlg.DoModal();
	return FALSE;
}
