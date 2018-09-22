/**********************************************************************
* 
* StackWalker.cpp
*
*
* History:
*  2005-07-27   v1    - First public release on http://www.codeproject.com/
*                       http://www.codeproject.com/threads/StackWalker.asp
*  2005-07-28   v2    - Changed the params of the constructor and ShowCallstack
*                       (to simplify the usage)
*  2005-08-01   v3    - Changed to use 'CONTEXT_FULL' instead of CONTEXT_ALL 
*                       (should also be enough)
*                     - Changed to compile correctly with the PSDK of VC7.0
*                       (GetFileVersionInfoSizeA and GetFileVersionInfoA is wrongly defined:
*                        it uses LPSTR instead of LPCSTR as first paremeter)
*                     - Added declarations to support VC5/6 without using 'dbghelp.h'
*                     - Added a 'pUserData' member to the ShowCallstack function and the 
*                       PReadProcessMemoryRoutine declaration (to pass some user-defined data, 
*                       which can be used in the readMemoryFunction-callback)
*  2005-08-02   v4    - OnSymInit now also outputs the OS-Version by default
*                     - Added example for doing an exception-callstack-walking in main.cpp
*                       (thanks to owillebo: http://www.codeproject.com/script/profile/whos_who.asp?id=536268)
*  2005-08-05   v5    - Removed most Link (http://www.gimpel.com/) errors... thanks to Okko Willeboordse!
*
**********************************************************************/
#include "StdAfx.h"
#include "StackWalker.h"
#include <tchar.h>
#include <stdio.h>
#include <malloc.h>
#include <dbghelp.h>
#include <shlwapi.h>
#include <ShlObj.h>
#pragma comment(lib, "shlwapi.lib")
#include <Tlhelp32.h>
#undef MODULEENTRY32
#undef PMODULEENTRY32
#undef LPMODULEENTRY32

BOOL GetProcessDllName(HANDLE hProcess, HMODULE hDll, LPSTR dllName, SIZE_T dllNameSize);

class StackWalkerInternal
{
public:
	StackWalkerInternal(CStackWalker *parent, HANDLE hProcess)
	{
		m_parent = parent;
		m_hProcess = hProcess;
		m_hDbhHelp = NULL;
		m_szSymPath = NULL;
		pSI = NULL;
		pSC = NULL;
		pSFTA = NULL;
		pSGLFA = NULL;
		pSGMB = NULL;
		pSGO = NULL;
		pSGSFA = NULL;
		pSLM = NULL;
		pSSO = NULL;
		pSW = NULL;
		pUDSN = NULL;
		pSGSP = NULL;
	}

	~StackWalkerInternal()
	{
		if (pSC != NULL)
			pSC(m_hProcess);  // SymCleanup
		if (m_hDbhHelp != NULL)
			FreeLibrary(m_hDbhHelp);
		m_hDbhHelp = NULL;
		m_parent = NULL;
		if(m_szSymPath != NULL)
			free(m_szSymPath);
		m_szSymPath = NULL;
	}

public:
	BOOL LoadModules(HANDLE hProcess, DWORD dwProcessId)
	{
		// first try toolhelp32
		if (LoadEnumModuleListByTH32(hProcess, dwProcessId))
			return TRUE;
		// then try psapi
		return LoadEnumModuleListByPSAPI(hProcess);
	}

	BOOL Init(LPCSTR szSymPath)
	{
		if (m_parent == NULL)
			return FALSE;
		// Dynamically load the Entry-Points for dbghelp.dll:
		// First try to load the newsest one from
		if(LoadDbgHelpDll() == NULL)
			return FALSE;
		pSI = (tSI) GetProcAddress(m_hDbhHelp, "SymInitialize" );
		pSC = (tSC) GetProcAddress(m_hDbhHelp, "SymCleanup" );

		pSW = (tSW) GetProcAddress(m_hDbhHelp, "StackWalk64" );
		pSGO = (tSGO) GetProcAddress(m_hDbhHelp, "SymGetOptions" );
		pSSO = (tSSO) GetProcAddress(m_hDbhHelp, "SymSetOptions" );

		pSFTA = (tSFTA) GetProcAddress(m_hDbhHelp, "SymFunctionTableAccess64" );
		pSGLFA = (tSGLFA) GetProcAddress(m_hDbhHelp, "SymGetLineFromAddr64" );
		pSGMB = (tSGMB) GetProcAddress(m_hDbhHelp, "SymGetModuleBase64" );
		pSGSFA = (tSGSFA) GetProcAddress(m_hDbhHelp, "SymGetSymFromAddr64" );
		pUDSN = (tUDSN) GetProcAddress(m_hDbhHelp, "UnDecorateSymbolName" );
		pSLM = (tSLM) GetProcAddress(m_hDbhHelp, "SymLoadModule64" );
		pSGSP =(tSGSP) GetProcAddress(m_hDbhHelp, "SymGetSearchPath" );

		if ( pSC == NULL || pSFTA == NULL || pSGMB == NULL ||
			pSGO == NULL || pSGSFA == NULL || pSI == NULL || pSSO == NULL ||
			pSW == NULL || pUDSN == NULL || pSLM == NULL )
		{
			FreeLibrary(m_hDbhHelp);
			m_hDbhHelp = NULL;
			pSC = NULL;
			return FALSE;
		}

		if (szSymPath != NULL)
			m_szSymPath = _strdup(szSymPath);
		//call SymInitialize
		if (pSI(m_hProcess, m_szSymPath, FALSE) == FALSE)
		{
			return FALSE;
		}

		// SymGetOptions
		DWORD symOptions = pSGO();
		symOptions |= SYMOPT_LOAD_LINES;//Loads line number information.
		symOptions |= SYMOPT_FAIL_CRITICAL_ERRORS;//the failure happens silently.
		// SymSetOptions
		symOptions = pSSO(symOptions);

		return TRUE;
	}

	HMODULE LoadDbgHelpDll()
	{
		TCHAR szTemp[1024];
		if(SUCCEEDED(SHGetFolderPath(NULL, CSIDL_PROGRAM_FILES, NULL, 0, szTemp))) 
		{
			_tcscat_s(szTemp, _T("\\Debugging Tools for Windows\\dbghelp.dll"));
			if (PathFileExists(szTemp))
			{
				m_hDbhHelp = LoadLibrary(szTemp);
			}
		}

		if (m_hDbhHelp == NULL)
			m_hDbhHelp = LoadLibrary( _T("dbghelp.dll") );
		return m_hDbhHelp;
	}

	CStackWalker *m_parent;

	HMODULE m_hDbhHelp;
	HANDLE m_hProcess;
	LPSTR m_szSymPath;

	// SymCleanup()
	typedef BOOL (__stdcall *tSC)( IN HANDLE hProcess );
	tSC pSC;

	// SymFunctionTableAccess64()
	typedef PVOID (__stdcall *tSFTA)( HANDLE hProcess, DWORD64 AddrBase );
	tSFTA pSFTA;

	// SymGetLineFromAddr64()
	typedef BOOL (__stdcall *tSGLFA)( IN HANDLE hProcess, IN DWORD64 dwAddr,
		OUT PDWORD pdwDisplacement, OUT PIMAGEHLP_LINE64 Line );
	tSGLFA pSGLFA;

	// SymGetModuleBase64()
	typedef DWORD64 (__stdcall *tSGMB)( IN HANDLE hProcess, IN DWORD64 dwAddr );
	tSGMB pSGMB;

	// SymGetOptions()
	typedef DWORD (__stdcall *tSGO)( VOID );
	tSGO pSGO;

	// SymGetSymFromAddr64()
	typedef BOOL (__stdcall *tSGSFA)( IN HANDLE hProcess, IN DWORD64 dwAddr,
		OUT PDWORD64 pdwDisplacement, OUT PIMAGEHLP_SYMBOL64 Symbol );
	tSGSFA pSGSFA;

	// SymInitialize()
	typedef BOOL (__stdcall *tSI)( IN HANDLE hProcess, IN PSTR UserSearchPath, IN BOOL fInvadeProcess );
	tSI pSI;

	// SymLoadModule64()
	typedef DWORD64 (__stdcall *tSLM)( IN HANDLE hProcess, IN HANDLE hFile,
		IN PSTR ImageName, IN PSTR ModuleName, IN DWORD64 BaseOfDll, IN DWORD SizeOfDll );
	tSLM pSLM;

	// SymSetOptions()
	typedef DWORD (__stdcall *tSSO)( IN DWORD SymOptions );
	tSSO pSSO;

	// StackWalk64()
	typedef BOOL (__stdcall *tSW)( 
		DWORD MachineType, 
		HANDLE hProcess,
		HANDLE hThread, 
		LPSTACKFRAME64 StackFrame, 
		PVOID ContextRecord,
		PREAD_PROCESS_MEMORY_ROUTINE64 ReadMemoryRoutine,
		PFUNCTION_TABLE_ACCESS_ROUTINE64 FunctionTableAccessRoutine,
		PGET_MODULE_BASE_ROUTINE64 GetModuleBaseRoutine,
		PTRANSLATE_ADDRESS_ROUTINE64 TranslateAddress );
	tSW pSW;

	// UnDecorateSymbolName()
	typedef DWORD (__stdcall WINAPI *tUDSN)( PCSTR DecoratedName, PSTR UnDecoratedName,
		DWORD UndecoratedLength, DWORD Flags );
	tUDSN pUDSN;

	typedef BOOL (__stdcall WINAPI *tSGSP)(HANDLE hProcess, PSTR SearchPath, DWORD SearchPathLength);
	tSGSP pSGSP;


private:
	// **************************************** ToolHelp32 ************************
	BOOL LoadEnumModuleListByTH32(HANDLE hProcess, DWORD pid)
	{
		// CreateToolhelp32Snapshot()
		typedef HANDLE (__stdcall *tCT32S)(DWORD dwFlags, DWORD th32ProcessID);
		// Module32First()
		typedef BOOL (__stdcall *tM32F)(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
		// Module32Next()
		typedef BOOL (__stdcall *tM32N)(HANDLE hSnapshot, LPMODULEENTRY32 lpme);

		HMODULE hToolhelp = NULL;
		tCT32S pCT32S = NULL;
		tM32F pM32F = NULL;
		tM32N pM32N = NULL;

		HANDLE hSnap;
		MODULEENTRY32 me;

		me.dwSize = sizeof(me);
		BOOL keepGoing;
		size_t i;

		// try both dlls.
		const TCHAR *dllname[] = { _T("kernel32.dll"), _T("tlhelp32.dll") };
		for (i = 0; i<(sizeof(dllname) / sizeof(dllname[0])); i++ )
		{
			hToolhelp = LoadLibrary( dllname[i] );
			if (hToolhelp == NULL)
				continue;
			pCT32S = (tCT32S) GetProcAddress(hToolhelp, "CreateToolhelp32Snapshot");
			pM32F = (tM32F) GetProcAddress(hToolhelp, "Module32First");
			pM32N = (tM32N) GetProcAddress(hToolhelp, "Module32Next");
			if ( (pCT32S != NULL) && (pM32F != NULL) && (pM32N != NULL) )
				break; // found all the functions!
			FreeLibrary(hToolhelp);
			hToolhelp = NULL;
		}

		if (hToolhelp == NULL)
			return FALSE;

		hSnap = pCT32S( TH32CS_SNAPMODULE, pid );
		if (hSnap == (HANDLE) -1)
			return FALSE;

		keepGoing = !!pM32F( hSnap, &me );
		int cnt = 0;
		while (keepGoing)
		{
			pSLM(hProcess, 0, me.szExePath, me.szModule, (DWORD64)me.modBaseAddr, me.modBaseSize);
			++cnt;
			keepGoing = !!pM32N( hSnap, &me );
		}
		CloseHandle(hSnap);
		FreeLibrary(hToolhelp);

		return cnt > 0;
	}  // GetModuleListTH32

	// **************************************** PSAPI ************************
	typedef struct _MODULEINFO {
		LPVOID lpBaseOfDll;
		DWORD SizeOfImage;
		LPVOID EntryPoint;
	} MODULEINFO, *LPMODULEINFO;

	BOOL LoadEnumModuleListByPSAPI(HANDLE hProcess)
	{
		// EnumProcessModules()
		typedef BOOL (__stdcall *tEPM)(HANDLE hProcess, HMODULE *lphModule, DWORD cb, LPDWORD lpcbNeeded );
		// GetModuleFileNameEx()
		typedef DWORD (__stdcall *tGMFNE)(HANDLE hProcess, HMODULE hModule, LPSTR lpFilename, DWORD nSize );
		// GetModuleBaseName()
		typedef DWORD (__stdcall *tGMBN)(HANDLE hProcess, HMODULE hModule, LPSTR lpFilename, DWORD nSize );
		// GetModuleInformation()
		typedef BOOL (__stdcall *tGMI)(HANDLE hProcess, HMODULE hModule, LPMODULEINFO pmi, DWORD nSize );

		HMODULE hPsapi = LoadLibrary( _T("psapi.dll") );
		if (hPsapi == NULL)
			return FALSE;
		tEPM pEPM = (tEPM) GetProcAddress( hPsapi, "EnumProcessModules" );
		tGMFNE pGMFNE = (tGMFNE) GetProcAddress( hPsapi, "GetModuleFileNameExA" );
		tGMBN pGMBN = (tGMFNE) GetProcAddress( hPsapi, "GetModuleBaseNameA" );
		tGMI pGMI = (tGMI) GetProcAddress( hPsapi, "GetModuleInformation" );
		if ( (pEPM == NULL) || (pGMFNE == NULL) || (pGMBN == NULL) || (pGMI == NULL) )
		{
			// we couldn't find all functions
			FreeLibrary(hPsapi);
			return FALSE;
		}

		const DWORD sizeOfhModuleHandles = 8*1024;
		HMODULE* hModuleHandles = (HMODULE*)VirtualAlloc(NULL, sizeOfhModuleHandles, MEM_COMMIT,
			PAGE_READWRITE);
		char* imageName = (char*) malloc(sizeof(char) * 512);
		char* moduleName = (char*) malloc(sizeof(char) * 512);
		if ( (hModuleHandles == NULL) || (imageName == NULL) || (moduleName == NULL) )
			goto cleanup;

		DWORD cbNeeded;
		if ( ! pEPM( hProcess, hModuleHandles, sizeOfhModuleHandles, &cbNeeded ) )
		{
			goto cleanup;
		}
		if ( cbNeeded >  sizeOfhModuleHandles)
		{
			goto cleanup;
		}

		MODULEINFO mi;
		DWORD i = 0;
		DWORD moduleCount = cbNeeded / sizeof(HMODULE);
		for ( ; i < moduleCount; ++i )
		{
			// get image size
			pGMI(hProcess, hModuleHandles[i], &mi, sizeof(mi) );
			// get image file name
			pGMFNE(hProcess, hModuleHandles[i], imageName,  sizeOfhModuleHandles);
			// get module name
			pGMBN(hProcess, hModuleHandles[i], moduleName,  sizeOfhModuleHandles);

			pSLM(hProcess, 0, imageName, moduleName, (DWORD64) mi.lpBaseOfDll, mi.SizeOfImage);
		}

cleanup:
		if (hPsapi != NULL) FreeLibrary(hPsapi);
		if (imageName != NULL) free(imageName);
		if (moduleName != NULL) free(moduleName);
		if (hModuleHandles != NULL)
			VirtualFree(hModuleHandles, 0, MEM_RELEASE);

		return i != 0;
	}  // GetModuleListPSAPI
};

//RtlCaptureContext API 的精简实现
#define GET_CURRENT_CONTEXT(c)\
	do { \
	memset(&c, 0, sizeof(CONTEXT)); \
	c.ContextFlags = CONTEXT_FULL; \
	__asm    call x \
	__asm x: pop eax \
	__asm    mov c.Eip, eax \
	__asm    mov c.Ebp, ebp \
	__asm    mov c.Esp, esp \
	} while(0)

CStackWalker::CStackWalker(LPCSTR szSymPath)
{
	m_hProcess = GetCurrentProcess();
	m_dwProcessId = GetCurrentProcessId();
	m_modulesLoaded = FALSE;
	m_sw = new StackWalkerInternal(this, m_hProcess);
	if (szSymPath != NULL)
		m_szSymPath = _strdup(szSymPath);
	else
		m_szSymPath = NULL;
}

CStackWalker::~CStackWalker(void)
{
	if (m_szSymPath != NULL)
	{
		free(m_szSymPath);
		m_szSymPath = NULL;
	}
	if (m_sw != NULL)
	{
		delete m_sw;
		m_sw = NULL;
	}
}

void CStackWalker::BuildSymPath(char* szSymPath, size_t nSymPathLen)
{
	_ASSERTE (szSymPath != NULL);

	szSymPath[0] = 0;

	if (m_szSymPath != NULL)
	{
		strcat_s(szSymPath, nSymPathLen, m_szSymPath);
		strcat_s(szSymPath, nSymPathLen, ";");
	}

	strcat_s(szSymPath, nSymPathLen, ".;");

	const size_t nTempLen = 1024;
	char szTemp[nTempLen];
	if (GetCurrentDirectoryA(nTempLen, szTemp) > 0)
	{
		szTemp[nTempLen-1] = 0;
		strcat_s(szSymPath, nSymPathLen, szTemp);
		strcat_s(szSymPath, nSymPathLen, ";");
	}

	if (GetModuleFileNameA(NULL, szTemp, nTempLen) > 0)
	{
		szTemp[nTempLen-1] = 0;
		char* pos = strrchr(szTemp, '\\');
		if(pos != NULL)
		{
			*pos = 0;
		}
		if (strlen(szTemp) > 0)
		{
			strcat_s(szSymPath, nSymPathLen, szTemp);
			strcat_s(szSymPath, nSymPathLen, ";");
		}
	}
	if (GetEnvironmentVariableA("_NT_SYMBOL_PATH", szTemp, nTempLen) > 0)
	{
		szTemp[nTempLen-1] = 0;
		strcat_s(szSymPath, nSymPathLen, szTemp);
		strcat_s(szSymPath, nSymPathLen, ";");
	}
	if (GetEnvironmentVariableA("_NT_ALTERNATE_SYMBOL_PATH", szTemp, nTempLen) > 0)
	{
		szTemp[nTempLen-1] = 0;
		strcat_s(szSymPath, nSymPathLen, szTemp);
		strcat_s(szSymPath, nSymPathLen, ";");
	}
}

void CStackWalker::OnCallstackEntry(const CallstackEntry &entry, /*out*/std::string& result)
{
	char buffer[STACKWALK_MAX_NAMELEN];
	char functionName[256];
	functionName[0] = 0;
	if(entry.name[0] != 0)
		strcpy_s(functionName, entry.name);
	else
		itoa(entry.offset, functionName, 16);

	if (entry.lineFileName[0] == 0)
		_snprintf_s(buffer, STACKWALK_MAX_NAMELEN, ": %s!%s\n", entry.moduleName, functionName);
	else
		_snprintf_s(buffer, STACKWALK_MAX_NAMELEN, "%s(%d): %s!%s\n", entry.lineFileName,
		entry.lineNumber, entry.moduleName, functionName);
	result = buffer;
}

BOOL __stdcall CdpReadProcMem(
	HANDLE      hProcess,
	DWORD64     qwBaseAddress,
	PVOID       lpBuffer,
	DWORD       nSize,
	LPDWORD     lpNumberOfBytesRead
	)
{
	SIZE_T st;
	BOOL bRet = ReadProcessMemory(hProcess, (LPVOID) qwBaseAddress, lpBuffer, nSize, &st);
	*lpNumberOfBytesRead = (DWORD) st;
	return bRet;
}

BOOL CStackWalker::LoadModulesSymbols()
{
	if (m_sw == NULL)
		return FALSE;
	if (m_modulesLoaded)
		return TRUE;

	char *szSymPath = NULL;
	const size_t nSymPathLen = 4096;
	szSymPath = (char*)VirtualAlloc(NULL, nSymPathLen, MEM_COMMIT, PAGE_READWRITE);
	BuildSymPath(szSymPath, nSymPathLen);
	BOOL bRet = m_sw->Init(szSymPath);
	if (szSymPath != NULL)
	{
		VirtualFree(szSymPath, 0, MEM_RELEASE);
	}
	if (bRet == FALSE)
	{
		return FALSE;
	}

	bRet = m_sw->LoadModules(m_hProcess, m_dwProcessId);
	if (bRet)
		m_modulesLoaded = TRUE;
	return bRet;
}

BOOL CStackWalker::GetCallstack(std::vector<std::string>& callStacks, int skipFrameCount, int maxFrameCount)
{
	if (m_modulesLoaded == FALSE)
		LoadModulesSymbols();

	if (m_sw->m_hDbhHelp == NULL)
		return FALSE;

	CONTEXT c;
	GET_CURRENT_CONTEXT(c);

	STACKFRAME64 s; // in/out stackframe
	memset(&s, 0, sizeof(s));
	DWORD imageType;
	imageType = IMAGE_FILE_MACHINE_I386;
	s.AddrPC.Offset = c.Eip;
	s.AddrPC.Mode = AddrModeFlat;
	s.AddrFrame.Offset = c.Ebp;
	s.AddrFrame.Mode = AddrModeFlat;
	s.AddrStack.Offset = c.Esp;
	s.AddrStack.Mode = AddrModeFlat;

	IMAGEHLP_SYMBOL64 *pSym = (IMAGEHLP_SYMBOL64 *) malloc(sizeof(IMAGEHLP_SYMBOL64) +
		STACKWALK_MAX_NAMELEN);
	if (!pSym)
		goto cleanup;
	memset(pSym, 0, sizeof(IMAGEHLP_SYMBOL64) + STACKWALK_MAX_NAMELEN);
	pSym->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
	pSym->MaxNameLength = STACKWALK_MAX_NAMELEN;

	IMAGEHLP_LINE64 Line;
	memset(&Line, 0, sizeof(Line));
	Line.SizeOfStruct = sizeof(Line);
	int frameNum;

	CallstackEntry csEntry;
	if(maxFrameCount == -1)
		maxFrameCount = INT_MAX;
	for (frameNum = 0; frameNum < maxFrameCount; ++frameNum )
	{
		if ( ! m_sw->pSW(imageType, m_hProcess, GetCurrentThread(), &s, &c, CdpReadProcMem,
			m_sw->pSFTA, m_sw->pSGMB, NULL) )
		{
			break;
		}

		csEntry.offset = s.AddrPC.Offset;
		csEntry.moduleName[0] = 0;
		csEntry.name[0] = 0;
		csEntry.lineFileName[0] = 0;
		csEntry.lineNumber = 0;
		if (s.AddrPC.Offset == s.AddrReturn.Offset)
		{
			//避免陷入无穷循环
			break;
		}
		if (s.AddrPC.Offset != 0 && frameNum >= skipFrameCount)
		{
			// get function name (SymGetSymFromAddr64())
			DWORD64 dwDisplacementFromFunc;
			if (m_sw->pSGSFA(m_hProcess, s.AddrPC.Offset, &dwDisplacementFromFunc, pSym))
			{
				// UnDecorateSymbolName()
				//a decorated C++ symbol name is always a question mark (?) 
				if(pSym->Name[0] == '?')
					m_sw->pUDSN(pSym->Name, csEntry.name, STACKWALK_MAX_NAMELEN, UNDNAME_NAME_ONLY);
				strcpy_s(csEntry.name, pSym->Name);
			}

			// get line number (SymGetLineFromAddr64())
			DWORD dwDisplacementFromLine;
			if (m_sw->pSGLFA(m_hProcess, s.AddrPC.Offset, &dwDisplacementFromLine, &Line))
			{
				csEntry.lineNumber = Line.LineNumber;
				strcpy_s(csEntry.lineFileName, Line.FileName);
			}

			// get module name
			DWORD moduleBase = m_sw->pSGMB(m_hProcess, s.AddrPC.Offset);
			GetProcessDllName(m_hProcess, (HMODULE)moduleBase, csEntry.moduleName,
				sizeof(csEntry.moduleName));

			std::string oneCallStack;
			OnCallstackEntry(csEntry, oneCallStack);
			callStacks.push_back(oneCallStack);
		}


		if (s.AddrReturn.Offset == 0)
		{
			break;
		}
	} // for ( frameNum )

cleanup:
	if (pSym)
		free( pSym );

	return TRUE;
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
