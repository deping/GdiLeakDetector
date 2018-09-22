// GdiLeakDetectorDlg.cpp
//

#include "stdafx.h"
#include "GdiLeakDetector.h"
#include "GdiLeakDetectorDlg.h"
#include <atlconv.h>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")
#include <afxpriv.h>//#define WM_KICKIDLE         0x036A

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

HANDLE g_hMapFile = NULL;
LPVOID g_pBuf = NULL;
//These three constants must have the same values with those variables of same name in GdiSpy respectively.
const int PAGE_FILE_BUF_SIZE = 128 * 1024;
const int ONE_ENTRY_MAX_SPACE = 4 * 1024;
static const TCHAR g_szSectionObjectName[] = TEXT("CdpGdiLeaksList");

//CAboutDlg dialog

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);

protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
END_MESSAGE_MAP()


// CGdiLeakDetectorDlg




CGdiLeakDetectorDlg::CGdiLeakDetectorDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CGdiLeakDetectorDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CGdiLeakDetectorDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CGdiLeakDetectorDlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
	ON_BN_CLICKED(IDOK, &CGdiLeakDetectorDlg::OnBnClickedOk)
	ON_BN_CLICKED(IDC_BROWSEFILE, &CGdiLeakDetectorDlg::OnBnClickedBrowsefile)
	ON_NOTIFY(NM_CLICK, IDC_LEAKLIST, &CGdiLeakDetectorDlg::OnNMClickLeaklist)
	ON_LBN_DBLCLK(IDC_CALLSTACK, &CGdiLeakDetectorDlg::OnLbnDblclkCallstack)
	ON_BN_CLICKED(IDC_SAVE, &CGdiLeakDetectorDlg::OnBnClickedSave)
	ON_MESSAGE(WM_KICKIDLE, &CGdiLeakDetectorDlg::OnKickIdle)
	ON_MESSAGE(WM_GOLINE, &CGdiLeakDetectorDlg::OnGoLine)
END_MESSAGE_MAP()


// CGdiLeakDetectorDlg message handlers

BOOL CGdiLeakDetectorDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// Add "About..." command to the system menu.

	// IDM_ABOUTBOX must in the range of system command.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		CString strAboutMenu;
		strAboutMenu.LoadString(IDS_ABOUTBOX);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}
	SetIcon(m_hIcon, TRUE);			//set big icon
	SetIcon(m_hIcon, FALSE);		//set small icon

	// TODO: Add extra initialization code here...
	CListCtrl* pListCtrl = (CListCtrl*)GetDlgItem(IDC_LEAKLIST);
	pListCtrl->InsertColumn(0, _T("HANDLE"), LVCFMT_LEFT, 65);
	pListCtrl->InsertColumn(1, _T("TYPE"), LVCFMT_LEFT, 70);

	g_hMapFile = ::CreateFileMapping(
		INVALID_HANDLE_VALUE,    // use paging file
		NULL,                    // default security 
		PAGE_READWRITE,          // read/write access
		0,                       // 
		PAGE_FILE_BUF_SIZE,                // buffer size  
		g_szSectionObjectName);  // name of mapping object

	TCHAR message[256];
	if (g_hMapFile == NULL)
	{ 
		::wsprintf(message, _T("Debugger could not open file mapping object (error = %d)."),
			GetLastError());
		AfxMessageBox(message);
		PostQuitMessage(1);
		return TRUE;
	}

	g_pBuf = (LPTSTR)::MapViewOfFile(g_hMapFile, FILE_MAP_ALL_ACCESS,0,0,PAGE_FILE_BUF_SIZE);           
	if (g_pBuf == NULL)
	{
		CloseHandle(g_hMapFile);
		::wsprintf(message, _T("Debugger could not map view of file (error = %d)."),
			GetLastError());
		AfxMessageBox(message);
		PostQuitMessage(1);
		return TRUE;
	}
	m_ExeFileEdit.SubclassDlgItem(IDC_EXEFILE, this);
	m_LineNumEdit.SubclassDlgItem(IDC_CURRENTLINE, this);
	m_LineNumEdit.SetLimitText(5);
	CEdit* pEdit = (CEdit*)GetDlgItem(IDC_CONTENT);
	pEdit->SetLimitText(800000);

	return TRUE;  //return TRUE unless you set focus to a control.
}

void CGdiLeakDetectorDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

void CGdiLeakDetectorDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this);

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

HCURSOR CGdiLeakDetectorDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

BOOL GetProcessDllName(HANDLE hProcess, HMODULE hDll, LPSTR dllName, SIZE_T dllNameSize)
{
	_ASSERTE(dllName != NULL);
	_ASSERTE(dllNameSize >= 24);
	dllName[0] = 0;

	SIZE_T bytesRead;

	IMAGE_DOS_HEADER dosHdr;
	if (!ReadProcessMemory(hProcess, hDll, &dosHdr, sizeof(dosHdr), &bytesRead))
		return FALSE;

	IMAGE_NT_HEADERS        ntHdr;
	if (!ReadProcessMemory(hProcess, (PVOID)((char*)hDll+dosHdr.e_lfanew), &ntHdr, sizeof(ntHdr), &bytesRead))
		return FALSE;

	DWORD exportsRVA = ntHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	if (!exportsRVA)
		return FALSE;

	IMAGE_EXPORT_DIRECTORY  exportDir;
	if (!ReadProcessMemory(hProcess, (PVOID)((char*)hDll+exportsRVA), &exportDir, sizeof(exportDir), &bytesRead))
		return(FALSE);

	if (!ReadProcessMemory(hProcess, (PVOID)((char*)hDll+exportDir.Name), dllName, dllNameSize, &bytesRead))
		return(FALSE);

	return(TRUE);

}

void CGdiLeakDetectorDlg::OnBnClickedOk()
{
	USES_CONVERSION;

	CListCtrl* pLeakList = (CListCtrl*)GetDlgItem(IDC_LEAKLIST);
	pLeakList->DeleteAllItems();
	CListBox* pCallStack = (CListBox*)GetDlgItem(IDC_CALLSTACK);
	pCallStack->ResetContent();

	CString exeFileName;
	GetDlgItemText(IDC_EXEFILE, exeFileName);
	STARTUPINFO startupInfo;
	memset(&startupInfo, 0, sizeof(startupInfo));
	startupInfo.cb = sizeof(startupInfo);
	PROCESS_INFORMATION  processInformation;
	static BOOL bThreadStart = FALSE;

	BOOL bReturn = ::CreateProcess(
		exeFileName,				// lpszImageName
		NULL,						// lpszCommandLine
		NULL, NULL,					// lpsaProcess and lpsaThread
		FALSE,						// fInheritHandles
		DEBUG_ONLY_THIS_PROCESS,
		NULL, NULL,					// lpvEnvironment and lpszCurDir
		&startupInfo,
		&processInformation
		);
	if(bReturn == FALSE)
	{
		ShowDebugString(_T("CreateProcess failed"));
		return;
	}

	ShowWindow(SW_HIDE);
	TCHAR message[256];
	char dllName[64];
	DEBUG_EVENT DebugEv;
	BOOL bGdi32Loaded = FALSE;
	BOOL bKernel32Loaded = FALSE;
	BOOL bUser32Loaded = FALSE;
	while(TRUE)
	{
		DWORD dwContinueStatus = DBG_CONTINUE;
		::WaitForDebugEvent(&DebugEv, INFINITE);

		switch (DebugEv.dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:
			//For breakpoint exceptions£¬dwContinueStatus must be DBG_CONTINUE£¬otherwise the 
			//debuggee will terminate immediately.
			if(EXCEPTION_BREAKPOINT != DebugEv.u.Exception.ExceptionRecord.ExceptionCode)
			{
				dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
				ShowDebugString(_T("Exception occurred"));
			}
			break;

		case LOAD_DLL_DEBUG_EVENT:
			GetProcessDllName(processInformation.hProcess, (HMODULE)DebugEv.u.LoadDll.lpBaseOfDll, dllName, sizeof(dllName));
			strlwr(dllName);
			if(bKernel32Loaded && bGdi32Loaded && bUser32Loaded)
			{
				if(!bThreadStart)
				{
					bThreadStart = TRUE;
					//Create a remote thread to inject GdiSpy.dll to the debugged to intercept the
					//calls of creation and deletion of GDI objects.
					CreateRemoteThread(processInformation.hProcess);
				}
			}
			else
			{
				if(strcmp(dllName, "kernel32.dll") == 0)
					bKernel32Loaded = TRUE;
				else if(strcmp(dllName, "user32.dll") == 0)
					bUser32Loaded = TRUE;
				else if(strcmp(dllName, "gdi32.dll") == 0)
					bGdi32Loaded = TRUE;
			}
			if(dllName[0])
				dllName[0] += 'A' - 'a';//Capitalize the first letter.
			strcat(dllName, " loaded");
			ShowDebugString(CA2T(dllName));
			if (DebugEv.u.LoadDll.hFile)
				::CloseHandle(DebugEv.u.LoadDll.hFile);
			break;

		case OUTPUT_DEBUG_STRING_EVENT:
			{
				DWORD bufferSize = DebugEv.u.DebugString.nDebugStringLength;
				if(DebugEv.u.DebugString.fUnicode)
					bufferSize *= sizeof(wchar_t);
				bufferSize = min(bufferSize, sizeof(message));
				if(ReadProcessMemory(processInformation.hProcess, DebugEv.u.DebugString.lpDebugStringData,
					message, bufferSize, NULL) == FALSE)
				{
					wsprintf(message, _T("Read debuggee output failed (error = %d)."),
						GetLastError());
					
				}
				else
				{
					if(DebugEv.u.DebugString.fUnicode)
					{
#ifndef UNICODE
						strcpy(message, CW2A(message));
#endif
					}
					else
					{
#ifdef UNICODE
						wcscpy(message, CA2W((char*)message));
#endif
					}
				}
				ShowDebugString(message);
			}
			break;

		case CREATE_THREAD_DEBUG_EVENT:
			break;

		case CREATE_PROCESS_DEBUG_EVENT:
			ShowDebugString(_T("Process created"));

			if (DebugEv.u.CreateProcessInfo.hFile)
				::CloseHandle(DebugEv.u.CreateProcessInfo.hFile);
			if (DebugEv.u.CreateProcessInfo.hProcess)
				::CloseHandle(DebugEv.u.CreateProcessInfo.hProcess);
			if (DebugEv.u.CreateProcessInfo.hThread)
				::CloseHandle(DebugEv.u.CreateProcessInfo.hThread);
			break;

		case EXIT_PROCESS_DEBUG_EVENT:
			bThreadStart = FALSE;
			ShowDebugString(_T("Process exited"));
			break;

		default:
			break;
		}

		::ContinueDebugEvent(DebugEv.dwProcessId, DebugEv.dwThreadId, dwContinueStatus);
		//The sentence must be placed after the previous sentence, otherwis the debuggee won't be 
		//terminated.
		if(EXIT_PROCESS_DEBUG_EVENT == DebugEv.dwDebugEventCode)
			break;
	}

	::CloseHandle(processInformation.hProcess);
	::CloseHandle(processInformation.hThread);
	ShowWindow(SW_SHOW);
	GetLeakList();
	ShowLeakList();
}

void CGdiLeakDetectorDlg::ShowDebugString(LPCTSTR message)
{
	SendDlgItemMessage(IDC_CALLSTACK, LB_ADDSTRING, 0, (LPARAM)message);
}

void CGdiLeakDetectorDlg::OnBnClickedBrowsefile()
{
	CFileDialog dlg(TRUE);
	dlg.m_ofn.lpstrFilter = _T("*.exe\0*.exe\0");
	if(IDOK == dlg.DoModal())
	{
		SetDlgItemText(IDC_EXEFILE, dlg.GetPathName());
	}
}

BOOL CGdiLeakDetectorDlg::CreateRemoteThread(HANDLE hProcess)
{
	BOOL bSuccess = FALSE;
	TCHAR szFilename[_MAX_PATH];
	::GetModuleFileName(NULL, szFilename, _countof(szFilename));
	TCHAR* pPos = _tcsrchr(szFilename, _T('\\'));
	_tcscpy(pPos, _T("\\GdiSpy.dll"));
	PTSTR pRemoteDllPath = (PTSTR)VirtualAllocEx(hProcess, NULL, sizeof(szFilename), MEM_COMMIT,
		PAGE_READWRITE);
	if(pRemoteDllPath != NULL)
	{
		WriteProcessMemory(hProcess, pRemoteDllPath, szFilename, sizeof(szFilename), NULL);
		//The call to CreateRemoteThread assumes that Kernel32.dll is mapped to the same memory 
		//location in both the local and the remote processes' address spaces. Every application 
		//requires Kernel32.dll, and in my experience the system maps Kernel32.dll to the same 
		//address in every process.--Chapter: Injecting a DLL Using Remote Threads 
		//"Programming Applications for Microsoft Windows"(author: Jeffrey Richter)
		PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)GetProcAddress(
			GetModuleHandle(TEXT("Kernel32")),
	#ifdef UNICODE
			"LoadLibraryW"
	#else
			"LoadLibraryA"
	#endif
			);
		//The result proves: the Injected DLL by this way won't send notification to the debugger.
		HANDLE hThread = ::CreateRemoteThread(hProcess, NULL, 0, 
			pfnThreadRtn, pRemoteDllPath, 0, NULL);
		if (hThread != NULL)
		{
			bSuccess = TRUE;
			SetThreadPriority(hThread, THREAD_PRIORITY_HIGHEST);
			//WaitForSingleObject(hThread, INFINITE);
			CloseHandle(hThread);
		}
		//Mustn't free the memory, otherwise the remote thread maybe haven't done its work. 
		//Let it be, we are just debugging.
		//VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
	}
	if(!bSuccess)
		ShowDebugString(_T("CreateRemoteThread failed."));
	return bSuccess;
}

CGdiLeakDetectorDlg::~CGdiLeakDetectorDlg()
{
	if(g_pBuf)
	{
		::UnmapViewOfFile(g_pBuf);
		::CloseHandle(g_hMapFile);
	}
}

void CGdiLeakDetectorDlg::GetLeakList()
{
	m_HandleInfo.clear();
	//Deserialization here must have exactly coincidence with serialization in GdiSpy.dll, 
	//like writing a document to a file and reading a file to a document.
	char* pCur = (char*)g_pBuf;
	const char* pEnd = pCur + PAGE_FILE_BUF_SIZE;

	DWORD handleCount = *(DWORD*)pCur;
	pCur += sizeof(DWORD);

	for(int outer = 0; outer < handleCount; ++outer)
	{
		//If the free space in the named map file is not sufficient, then stop reading information.
		if(pEnd - pCur < ONE_ENTRY_MAX_SPACE)
			break;

		DWORD handleValue = *(DWORD*)pCur;
		pCur += sizeof(DWORD);

		DWORD stackFrameCount = *(DWORD*)pCur;
		pCur += sizeof(DWORD);
		std::vector<char*> callStacks(stackFrameCount);
		for(int inner=0; inner<stackFrameCount; ++inner)
		{
			DWORD len = *(DWORD*)pCur;
			pCur += sizeof(DWORD);

			callStacks[inner] = pCur;
			pCur += len;
		}

		m_HandleInfo.insert(std::make_pair(handleValue, callStacks));
	}
}

struct  
{
	DWORD type;
	LPCTSTR name;
} g_GDITypeName[] = 
{
	{0x30,		_T("Pen")},
	{0x10,		_T("Brush")},
	{0x0A,		_T("Font")},
	{0x05,		_T("Bitmap")},
	{0x01,		_T("DC")},//include _T("Memory DC")
	{0x50,		_T("ExtPen")},
	{0x04,		_T("Region")},
	{0x21,		_T("EnhMe DC")},
	{0x46,		_T("EnhMeta")},
	{0x26,		_T("Metafile")},
	{0x66,		_T("Meta DC")},
	{0x08,		_T("Palette")}
};

DWORD DecodeObjectType(DWORD handleValue)
{
	return (handleValue >> 16) & 0x7F;
}

LPCTSTR GetTypeName(DWORD objType)
{
	for(int i=0; i<_countof(g_GDITypeName); ++i)
	{
		if(g_GDITypeName[i].type == objType)
			return g_GDITypeName[i].name;
	}
	return _T("Unknown");
}

void CGdiLeakDetectorDlg::ShowLeakList()
{
	if(m_HandleInfo.empty())
		return;

	CListCtrl* pLeakList = (CListCtrl*)GetDlgItem(IDC_LEAKLIST);
	CListBox* pCallStack = (CListBox*)GetDlgItem(IDC_CALLSTACK);
	std::map<DWORD, std::vector<char*> >::iterator it;
	LVITEM lvItem;
	memset(&lvItem, 0, sizeof(lvItem));
	CString text;
	for(it = m_HandleInfo.begin(); it != m_HandleInfo.end(); ++it)
	{
		text.Format(_T("%08X"), it->first);
		lvItem.mask = LVIF_TEXT|LVIF_PARAM;
		lvItem.iSubItem = 0;
		lvItem.pszText = (LPTSTR)(LPCTSTR)text;
		lvItem.lParam = (LPARAM)it->first;
		pLeakList->InsertItem(&lvItem);
		//Can't use GetObjectType, as these handles belong to another process, thus its value are invalid.
		DWORD objType = DecodeObjectType(it->first);
		lvItem.mask = LVIF_TEXT;
		lvItem.iSubItem = 1;
		lvItem.pszText = (LPTSTR)GetTypeName(objType);
		pLeakList->SetItem(&lvItem);
		++lvItem.iItem;
	}
}

void CGdiLeakDetectorDlg::OnNMClickLeaklist(NMHDR *pNMHDR, LRESULT *pResult)
{
	*pResult = 0;
	CListBox* pCallStack = (CListBox*)GetDlgItem(IDC_CALLSTACK);
	pCallStack->ResetContent();
	LPNMITEMACTIVATE pStruc = (LPNMITEMACTIVATE)pNMHDR;
	if(pStruc->iItem != -1)
	{
		CSize sz;
		int dx = 0;
		TEXTMETRIC tm;
		CDC* pDC = pCallStack->GetDC();
		CFont* pFont = pCallStack->GetFont();
		CFont* pOldFont = pDC->SelectObject(pFont);
		pDC->GetTextMetrics(&tm);

		CListCtrl* pLeakList = (CListCtrl*)GetDlgItem(IDC_LEAKLIST);
		DWORD handleValue = (DWORD)pLeakList->GetItemData(pStruc->iItem);
		std::vector<char*>& callstacks = m_HandleInfo[handleValue];
		for(int i=0; i<callstacks.size(); ++i)
		{
			CString aline(callstacks[i]);
			pCallStack->AddString(aline);

			sz = pDC->GetTextExtent(aline);
			sz.cx += tm.tmAveCharWidth;
			if (sz.cx > dx)
				dx = sz.cx;
		}

		pDC->SelectObject(pOldFont);
		pCallStack->ReleaseDC(pDC);
		pCallStack->SetHorizontalExtent(dx);
	}
}

void CGdiLeakDetectorDlg::OnLbnDblclkCallstack()
{
	CListBox* pCallStack = (CListBox*)GetDlgItem(IDC_CALLSTACK);
	int index = pCallStack->GetCurSel();
	if(LB_ERR != index)
	{
		CString aline;
		pCallStack->GetText(index, aline);
		int pos = aline.Find(_T("):"));
		if(pos != -1)
		{
			aline = aline.Left(pos);
			int pos2 = aline.ReverseFind(_T('('));
			if(pos2 != -1)
			{
				CString fileName = aline.Left(pos2);
				CString lineNum = aline.Mid(pos2+1);
				if(PathFileExists(fileName))
				{
					ShowFile(fileName, _tstoi(lineNum));
				}
			}
		}
	}
}

void CGdiLeakDetectorDlg::ShowFile(const CString & fileName, int lineNum)
{
	CEdit* pEdit = (CEdit*)GetDlgItem(IDC_CONTENT);
	if(fileName != m_FileName)
	{
		HANDLE hFile = CreateFile(fileName, GENERIC_READ, FILE_SHARE_READ,
			NULL,                  // default security
			OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
			NULL);                 // no attr. template
		if (hFile == INVALID_HANDLE_VALUE) 
			return;
		DWORD fileLen = GetFileSize(hFile, NULL);
		char* text = (char*)VirtualAlloc(NULL, fileLen+1/*NULL*/, MEM_COMMIT, PAGE_READWRITE);
		if(text)
		{
			ReadFile(hFile, text, fileLen, &fileLen, NULL);
			text[fileLen] = 0;
			::SetWindowTextA(pEdit->GetSafeHwnd(), text);
			CString title(_T("GDI Leak Detector-"));
			title += fileName;
			SetWindowText(title);
			m_FileName = fileName;
			VirtualFree(text, 0, MEM_RELEASE);
			pEdit->SetModify(FALSE);
		}
		CloseHandle(hFile);
	}

	int selPos = pEdit->LineIndex(lineNum-1);
	if(selPos != -1)
	{
		int selPos2 = selPos + pEdit->LineLength(selPos);
		pEdit->SetSel(selPos, selPos2);
	}
	else
	{
		pEdit->SetSel(0, 0);
	}
	pEdit->SetFocus();
}
void CGdiLeakDetectorDlg::OnBnClickedSave()
{
	if(m_FileName.IsEmpty())
		return;

	CEdit* pEdit = (CEdit*)GetDlgItem(IDC_CONTENT);
	if(!pEdit->GetModify())
		return;

	HANDLE hFile; 
	hFile = CreateFile(m_FileName, GENERIC_WRITE,  0,//do not share                      
		NULL,                   // default security
		CREATE_ALWAYS,          // overwrite existing
		FILE_ATTRIBUTE_NORMAL,  // normal file
		NULL);                  // no attr. template

	if (hFile == INVALID_HANDLE_VALUE) 
	{
		AfxMessageBox(_T("Can't write the file!"));
		return;
	}

	int lineCount = pEdit->GetLineCount();
	int lastLineStart = pEdit->LineIndex(lineCount-1);
	int lastLineLength = pEdit->LineLength(lastLineStart);
	int enoughMemSize = (lastLineStart+lastLineLength+2/*CrLf*/+1/*NULL*/)*sizeof(TCHAR);
	char* text = (char*)VirtualAlloc(NULL, enoughMemSize, MEM_COMMIT, PAGE_READWRITE);
	if(text)
	{
		int readcount = ::GetWindowTextA(pEdit->GetSafeHwnd(), text, enoughMemSize);
		DWORD bytesWritten;
		WriteFile(hFile, text, readcount, &bytesWritten, NULL);
		VirtualFree(text, 0, MEM_RELEASE);
		pEdit->SetModify(FALSE);
		AfxMessageBox(_T("The modification has been saved!"));
	}
	else
	{
		AfxMessageBox(_T("Not enough memory!"));
	}
	CloseHandle(hFile);
}

LRESULT CGdiLeakDetectorDlg:: OnKickIdle(WPARAM wParam, LPARAM ICount)
{
	if(GetFocus() != &m_LineNumEdit)
	{
		CEdit* pEdit = (CEdit*)GetDlgItem(IDC_CONTENT);
		int lineNum = pEdit->LineFromChar();
		SetDlgItemInt(IDC_CURRENTLINE, lineNum+1);
	}
	return 0;
}

LRESULT CGdiLeakDetectorDlg::OnGoLine(WPARAM, LPARAM)
{
	int lineToGo = GetDlgItemInt(IDC_CURRENTLINE);
	if(lineToGo < 1)
		return 0;
	CEdit* pEdit = (CEdit*)GetDlgItem(IDC_CONTENT);
	int lineStart = pEdit->LineIndex(lineToGo-1);
	pEdit->SetSel(lineStart, lineStart);
	pEdit->SetFocus();
	return 0;
}
