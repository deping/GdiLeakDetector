#include "StdAfx.h"
#include "GdiMonitor.h"
#include "pehack.h"
#include <Tlhelp32.h>
#include <tchar.h>
#include <algorithm>

//use named map file to communicate between GdiSpy and GdiLeakDetector
HANDLE g_hMapFile = NULL;
LPVOID g_pBuf = NULL;
//These three constants must have the same values with those variables of same name in GdiLeakDetector respectively.
const int PAGE_FILE_BUF_SIZE = 128 * 1024;
const int ONE_ENTRY_MAX_SPACE = 4 * 1024;
static const TCHAR szSectionObjectName[] = TEXT("CdpGdiLeaksList");

std::map<DWORD, std::vector<std::string> > g_HandleInfo;
CStackWalker g_StackWalker;
CGdiMonitor CGdiMonitor::g_GdiMonitor;

#define DEFINE_GDI_API(Name)\
	CGdiMonitor::Name##Proc CGdiMonitor::__##Name = NULL;
// device context
DEFINE_GDI_API(CreateDCA)
DEFINE_GDI_API(CreateDCW)
DEFINE_GDI_API(CreateCompatibleDC)
DEFINE_GDI_API(CreateICA)
DEFINE_GDI_API(CreateICW)
DEFINE_GDI_API(GetDC)
DEFINE_GDI_API(GetDCEx)
DEFINE_GDI_API(GetWindowDC)
// pen
DEFINE_GDI_API(CreatePen)
DEFINE_GDI_API(CreatePenIndirect)
DEFINE_GDI_API(ExtCreatePen)
// brush API
DEFINE_GDI_API(CreateSolidBrush)
DEFINE_GDI_API(CreateHatchBrush)
DEFINE_GDI_API(CreateBrushIndirect)
DEFINE_GDI_API(CreatePatternBrush)
DEFINE_GDI_API(CreateDIBPatternBrush)
DEFINE_GDI_API(CreateDIBPatternBrushPt)
// bitmap API
DEFINE_GDI_API(LoadBitmapA)
DEFINE_GDI_API(LoadBitmapW)
DEFINE_GDI_API(CreateBitmap)
DEFINE_GDI_API(CreateBitmapIndirect)
DEFINE_GDI_API(CreateCompatibleBitmap)
DEFINE_GDI_API(CreateDIBitmap)
DEFINE_GDI_API(CreateDIBSection)
// font
DEFINE_GDI_API(CreateFontA)
DEFINE_GDI_API(CreateFontW)
DEFINE_GDI_API(CreateFontIndirectA)
DEFINE_GDI_API(CreateFontIndirectW)
DEFINE_GDI_API(CreateFontIndirectExA)
DEFINE_GDI_API(CreateFontIndirectExW)
// region
DEFINE_GDI_API(CreateRectRgn)
DEFINE_GDI_API(CreateRectRgnIndirect)
DEFINE_GDI_API(CreateEllipticRgn)
DEFINE_GDI_API(CreateEllipticRgnIndirect)
DEFINE_GDI_API(CreatePolygonRgn)
DEFINE_GDI_API(CreatePolyPolygonRgn)
DEFINE_GDI_API(CreateRoundRectRgn)
DEFINE_GDI_API(PathToRegion)
DEFINE_GDI_API(ExtCreateRegion)
// metafile dc(released by CloseMetaFile/CloseEnhMetaFile)
DEFINE_GDI_API(CreateMetaFileA)
DEFINE_GDI_API(CreateMetaFileW)
DEFINE_GDI_API(CreateEnhMetaFileA)
DEFINE_GDI_API(CreateEnhMetaFileW)
// metafile
DEFINE_GDI_API(GetEnhMetaFileA)
DEFINE_GDI_API(GetEnhMetaFileW)
DEFINE_GDI_API(GetMetaFileA)
DEFINE_GDI_API(GetMetaFileW)
// palette
DEFINE_GDI_API(CreateHalftonePalette)
DEFINE_GDI_API(CreatePalette)
// object deletion
DEFINE_GDI_API(DeleteObject)
DEFINE_GDI_API(DeleteDC)
DEFINE_GDI_API(DeleteMetaFile)
DEFINE_GDI_API(DeleteEnhMetaFile)
// object release
DEFINE_GDI_API(ReleaseDC)
//delete metafile dc and generate metafile
DEFINE_GDI_API(CloseMetaFile)
DEFINE_GDI_API(CloseEnhMetaFile)

//All the dll has been sorted by alphabeta and capitalized.
const TCHAR* g_SystemDlls[] = 
{
	_T("ACTIVEDS.DLL"),
	_T("ADSLDPC.DLL"),
	_T("ADVAPI32.DLL"),
	_T("ADVPACK.DLL"),
	_T("APPHELP.DLL"),
	_T("ATL.DLL"),
	_T("AUTHZ.DLL"),
	_T("BROWSEUI.DLL"),
	_T("CABINET.DLL"),
	_T("CDFVIEW.DLL"),
	_T("CERTCLI.DLL"),
	_T("CFGMGR32.DLL"),
	_T("CLUSAPI.DLL"),
	_T("COMDLG32.DLL"),
	_T("CREDUI.DLL"),
	_T("CRYPT32.DLL"),
	_T("CRYPTUI.DLL"),
	_T("CSCDLL.DLL"),
	_T("DBGHELP.DLL"),
	_T("DEVMGR.DLL"),
	_T("DHCPCSVC.DLL"),
	_T("DNSAPI.DLL"),
	_T("DUSER.DLL"),
	_T("DWMAPI.DLL"),
	_T("EFSADU.DLL"),
	_T("ESENT.DLL"),
	_T("GDI32.DLL"),
	_T("HLINK.DLL"),
	_T("HNETCFG.DLL"),
	_T("IEFRAME.DLL"),
	_T("IERTUTIL.DLL"),
	_T("IEUI.DLL"),
	_T("IMAGEHLP.DLL"),
	_T("IMGUTIL.DLL"),
	_T("IMM32.DLL"),
	_T("INETCOMM.DLL"),
	_T("IPHLPAPI.DLL"),
	_T("KERNEL32.DLL"),
	_T("LINKINFO.DLL"),
	_T("LZ32.DLL"),
	_T("MLANG.DLL"),
	_T("MOBSYNC.DLL"),
	_T("MPR.DLL"),
	_T("MPRAPI.DLL"),
	_T("MPRUI.DLL"),
	_T("MSASN1.DLL"),
	//Microsoft Input Method
	_T("MSCTFIME.IME"),
	_T("MSGINA.DLL"),
	_T("MSHTML.DLL"),
	_T("MSI.DLL"),
	_T("MSIMG32.DLL"),
	_T("MSLS31.DLL"),
	_T("MSOERT2.DLL"),
	_T("MSRATING.DLL"),
	_T("MSSIGN32.DLL"),
	_T("MSVCP60.DLL"),
	_T("MSVCRT.DLL"),
	_T("MSWSOCK.DLL"),
	_T("NETAPI32.DLL"),
	_T("NETCFGX.DLL"),
	_T("NETMAN.DLL"),
	_T("NETPLWIZ.DLL"),
	_T("NETRAP.DLL"),
	_T("NETSHELL.DLL"),
	_T("NETUI0.DLL"),
	_T("NETUI1.DLL"),
	_T("NETUI2.DLL"),
	_T("NORMALIZ.DLL"),
	_T("NTDLL.DLL"),
	_T("NTDSAPI.DLL"),
	_T("NTLANMAN.DLL"),
	_T("ODBC32.DLL"),
	_T("OLE32.DLL"),
	_T("OLEACC.DLL"),
	_T("OLEAUT32.DLL"),
	_T("OLEDLG.DLL"),
	_T("OLEPRO32.DLL"),
	_T("POWRPROF.DLL"),
	_T("PRINTUI.DLL"),
	_T("PSAPI.DLL"),
	_T("QUERY.DLL"),
	_T("RASAPI32.DLL"),
	_T("RASDLG.DLL"),
	_T("RASMAN.DLL"),
	_T("REGAPI.DLL"),
	_T("RPCRT4.DLL"),
	_T("RTUTILS.DLL"),
	_T("SAMLIB.DLL"),
	_T("SCECLI.DLL"),
	_T("SECUR32.DLL"),
	_T("SETUPAPI.DLL"),
	_T("SHDOCVW.DLL"),
	_T("SHELL32.DLL"),
	_T("SHLWAPI.DLL"),
	_T("SHSVCS.DLL"),
	_T("TAPI32.DLL"),
	_T("URLMON.DLL"),
	_T("USER32.DLL"),
	_T("USERENV.DLL"),
	_T("USP10.DLL"),
	_T("UTILDLL.DLL"),
	_T("UXTHEME.DLL"),
	_T("VERSION.DLL"),
	_T("W32TOPL.DLL"),
	_T("WINHTTP.DLL"),
	_T("WININET.DLL"),
	_T("WINMM.DLL"),
	_T("WINSCARD.DLL"),
	_T("WINSPOOL.DRV"),
	_T("WINSTA.DLL"),
	_T("WINTRUST.DLL"),
	_T("WLDAP32.DLL"),
	_T("WMI.DLL"),
	_T("WS2_32.DLL"),
	_T("WS2HELP.DLL"),
	_T("WSOCK32.DLL"),
	_T("WTSAPI32.DLL"),
	_T("WZCDLG.DLL"),
	_T("WZCSAPI.DLL"),
	_T("WZCSVC.DLL")
};

bool Str1LessStr2(const TCHAR* str1, const TCHAR* str2)
{
	return _tcscmp(str1, str2) < 0;
}

BOOL IsSystemDll(TCHAR* dllName)
{
	_tcsupr(dllName);
	const TCHAR** pIndex = std::lower_bound(&g_SystemDlls[0], &g_SystemDlls[0]+_countof(g_SystemDlls),
		dllName, Str1LessStr2);
	if(pIndex != &g_SystemDlls[0]+_countof(g_SystemDlls))
		return _tcscmp(*pIndex, dllName) == 0;
	return FALSE;
}


CGdiMonitor::CGdiMonitor(void)
{
	g_hMapFile = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, szSectionObjectName);
	if (g_hMapFile == NULL) 
		return;

	g_pBuf = MapViewOfFile(g_hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, PAGE_FILE_BUF_SIZE);                   
	if (g_pBuf == NULL)
	{
		CloseHandle(g_hMapFile);
		return;
	}

	HMODULE hGDI32 = GetModuleHandle(TEXT("GDI32.DLL"));
	HMODULE hUSER32 = GetModuleHandle(TEXT("USER32.DLL"));
	// device context
	__CreateDCA = (CreateDCAProc)GetProcAddress(hGDI32, "CreateDCA");
	__CreateDCW = (CreateDCWProc)GetProcAddress(hGDI32, "CreateDCW");
	__CreateCompatibleDC = (CreateCompatibleDCProc)GetProcAddress(hGDI32, "CreateCompatibleDC");
	__CreateICA = (CreateICAProc)GetProcAddress(hGDI32, "CreateICA");
	__CreateICW = (CreateICWProc)GetProcAddress(hGDI32, "CreateICW");
	__GetDC = (GetDCProc)GetProcAddress(hUSER32, "GetDC");
	__GetDCEx = (GetDCExProc)GetProcAddress(hUSER32, "GetDCEx");
	__GetWindowDC = (GetWindowDCProc)GetProcAddress(hUSER32, "GetWindowDC");
	// pen
	__CreatePen = (CreatePenProc)GetProcAddress(hGDI32, "CreatePen");
	__CreatePenIndirect = (CreatePenIndirectProc)GetProcAddress(hGDI32, "CreatePenIndirect");
	__ExtCreatePen = (ExtCreatePenProc)GetProcAddress(hGDI32, "ExtCreatePen");
	// brush API
	__CreateSolidBrush = (CreateSolidBrushProc)GetProcAddress(hGDI32, "CreateSolidBrush");
	__CreateHatchBrush = (CreateHatchBrushProc)GetProcAddress(hGDI32, "CreateHatchBrush");
	__CreateBrushIndirect = (CreateBrushIndirectProc)GetProcAddress(hGDI32, "CreateBrushIndirect");
	__CreatePatternBrush = (CreatePatternBrushProc)GetProcAddress(hGDI32, "CreatePatternBrush");
	__CreateDIBPatternBrush = (CreateDIBPatternBrushProc)GetProcAddress(hGDI32, "CreateDIBPatternBrush");
	__CreateDIBPatternBrushPt = (CreateDIBPatternBrushPtProc)GetProcAddress(hGDI32, "CreateDIBPatternBrushPt");
	// bitmap API
	__LoadBitmapA = (LoadBitmapAProc)GetProcAddress(hUSER32, "LoadBitmapA");
	__LoadBitmapW = (LoadBitmapWProc)GetProcAddress(hUSER32, "LoadBitmapW");
	__CreateBitmap = (CreateBitmapProc)GetProcAddress(hGDI32, "CreateBitmap");
	__CreateBitmapIndirect = (CreateBitmapIndirectProc)GetProcAddress(hGDI32, "CreateBitmapIndirect");
	__CreateCompatibleBitmap = (CreateCompatibleBitmapProc)GetProcAddress(hGDI32, "CreateCompatibleBitmap");
	__CreateDIBitmap = (CreateDIBitmapProc)GetProcAddress(hGDI32, "CreateDIBitmap");
	__CreateDIBSection = (CreateDIBSectionProc)GetProcAddress(hGDI32, "CreateDIBSection");
	// font
	__CreateFontA = (CreateFontAProc)GetProcAddress(hGDI32, "CreateFontA");
	__CreateFontW = (CreateFontWProc)GetProcAddress(hGDI32, "CreateFontW");
	__CreateFontIndirectA = (CreateFontIndirectAProc)GetProcAddress(hGDI32, "CreateFontIndirectA");
	__CreateFontIndirectW = (CreateFontIndirectWProc)GetProcAddress(hGDI32, "CreateFontIndirectW");
	__CreateFontIndirectExA = (CreateFontIndirectExAProc)GetProcAddress(hGDI32, "CreateFontIndirectExA");
	__CreateFontIndirectExW = (CreateFontIndirectExWProc)GetProcAddress(hGDI32, "CreateFontIndirectExW");
	// region
	__CreateRectRgn = (CreateRectRgnProc)GetProcAddress(hGDI32, "CreateRectRgn");
	__CreateRectRgnIndirect = (CreateRectRgnIndirectProc)GetProcAddress(hGDI32, "CreateRectRgnIndirect");
	__CreateEllipticRgn = (CreateEllipticRgnProc)GetProcAddress(hGDI32, "CreateEllipticRgn");
	__CreateEllipticRgnIndirect = (CreateEllipticRgnIndirectProc)GetProcAddress(hGDI32, "CreateEllipticRgnIndirect");
	__CreatePolygonRgn = (CreatePolygonRgnProc)GetProcAddress(hGDI32, "CreatePolygonRgn");
	__CreatePolyPolygonRgn = (CreatePolyPolygonRgnProc)GetProcAddress(hGDI32, "CreatePolyPolygonRgn");
	__CreateRoundRectRgn = (CreateRoundRectRgnProc)GetProcAddress(hGDI32, "CreateRoundRectRgn");
	__PathToRegion = (PathToRegionProc)GetProcAddress(hGDI32, "PathToRegion");
	__ExtCreateRegion = (ExtCreateRegionProc)GetProcAddress(hGDI32, "ExtCreateRegion");
	// metafile dc(released by CloseMetaFile/CloseEnhMetaFile)
	__CreateMetaFileA = (CreateMetaFileAProc)GetProcAddress(hGDI32, "CreateMetaFileA");
	__CreateMetaFileW = (CreateMetaFileWProc)GetProcAddress(hGDI32, "CreateMetaFileW");
	__CreateEnhMetaFileA = (CreateEnhMetaFileAProc)GetProcAddress(hGDI32, "CreateEnhMetaFileA");
	__CreateEnhMetaFileW = (CreateEnhMetaFileWProc)GetProcAddress(hGDI32, "CreateEnhMetaFileW");
	__GetEnhMetaFileA = (GetEnhMetaFileAProc)GetProcAddress(hGDI32, "GetEnhMetaFileA");
	__GetEnhMetaFileW = (GetEnhMetaFileWProc)GetProcAddress(hGDI32, "GetEnhMetaFileW");
	__GetMetaFileA = (GetMetaFileAProc)GetProcAddress(hGDI32, "GetMetaFileA");
	__GetMetaFileW = (GetMetaFileWProc)GetProcAddress(hGDI32, "GetMetaFileW");
	// palette
	__CreateHalftonePalette = (CreateHalftonePaletteProc)GetProcAddress(hGDI32, "CreateHalftonePalette");
	__CreatePalette = (CreatePaletteProc)GetProcAddress(hGDI32, "CreatePalette");
	// object deletion
	__DeleteObject = (DeleteObjectProc)GetProcAddress(hGDI32, "DeleteObject");
	__DeleteDC = (DeleteDCProc)GetProcAddress(hGDI32, "DeleteDC");
	__DeleteMetaFile = (DeleteMetaFileProc)GetProcAddress(hGDI32, "DeleteMetaFile");
	__DeleteEnhMetaFile = (DeleteEnhMetaFileProc)GetProcAddress(hGDI32, "DeleteEnhMetaFile");
	// object release
	__ReleaseDC = (ReleaseDCProc)GetProcAddress(hUSER32, "ReleaseDC");
	//delete metafile dc and generate metafile
	__CloseMetaFile = (CloseMetaFileProc)GetProcAddress(hGDI32, "CloseMetaFile");
	__CloseEnhMetaFile = (CloseEnhMetaFileProc)GetProcAddress(hGDI32, "CloseEnhMetaFile");

	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;

	DWORD ProcessID = GetCurrentProcessId();
	// Take a snapshot of all modules in the specified process.
	hModuleSnap = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, ProcessID);
	if( INVALID_HANDLE_VALUE == hModuleSnap )
	{
		return;
	}

	// Set the size of the structure before using it.
	me32.dwSize = sizeof( MODULEENTRY32 );

	// Retrieve information about the first module,
	// and exit if unsuccessful
	if( !Module32First( hModuleSnap, &me32 ) )
	{
		CloseHandle( hModuleSnap );     // Must clean up the snapshot object!
		return;
	}

	// Now walk the module list of the process,
	do
	{
		if(IsSystemDll(me32.szModule))
			continue;

		//KPEFile can be found in the book "Windows Graphics Programming" (author: Feng Yuan). The
		//class can modify the addresses of imported functions and exported functions.
		//The parameter of constructor is the base address of a module.
		KPEFile module((HMODULE)me32.modBaseAddr);
		if(!module.IsPeFile())
			continue;
		__try
		{
			PIMAGE_IMPORT_DESCRIPTOR pImport1 = module.GetImportDescriptor("GDI32.dll");
			if(pImport1)
			{
				// device context
				module.SetImportAddress(pImport1, "CreateDCA", (FARPROC)_CreateDCA);
				module.SetImportAddress(pImport1, "CreateDCW", (FARPROC)_CreateDCW);
				module.SetImportAddress(pImport1, "CreateCompatibleDC", (FARPROC)_CreateCompatibleDC);
				module.SetImportAddress(pImport1, "CreateICA", (FARPROC)_CreateICA);
				module.SetImportAddress(pImport1, "CreateICW", (FARPROC)_CreateICW);
				// pen
				module.SetImportAddress(pImport1, "CreatePen", (FARPROC)_CreatePen);
				module.SetImportAddress(pImport1, "CreatePenIndirect", (FARPROC)_CreatePenIndirect);
				module.SetImportAddress(pImport1, "ExtCreatePen", (FARPROC)_ExtCreatePen);
				// brush API
				module.SetImportAddress(pImport1, "CreateSolidBrush", (FARPROC)_CreateSolidBrush);
				module.SetImportAddress(pImport1, "CreateHatchBrush", (FARPROC)_CreateHatchBrush);
				module.SetImportAddress(pImport1, "CreateBrushIndirect", (FARPROC)_CreateBrushIndirect);
				module.SetImportAddress(pImport1, "CreatePatternBrush", (FARPROC)_CreatePatternBrush);
				module.SetImportAddress(pImport1, "CreateDIBPatternBrush", (FARPROC)_CreateDIBPatternBrush);
				module.SetImportAddress(pImport1, "CreateDIBPatternBrushPt", (FARPROC)_CreateDIBPatternBrushPt);
				// bitmap API
				module.SetImportAddress(pImport1, "CreateBitmap", (FARPROC)_CreateBitmap);
				module.SetImportAddress(pImport1, "CreateBitmapIndirect", (FARPROC)_CreateBitmapIndirect);
				module.SetImportAddress(pImport1, "CreateCompatibleBitmap", (FARPROC)_CreateCompatibleBitmap);
				module.SetImportAddress(pImport1, "CreateDIBitmap", (FARPROC)_CreateDIBitmap);
				module.SetImportAddress(pImport1, "CreateDIBSection", (FARPROC)_CreateDIBSection);
				// font
				module.SetImportAddress(pImport1, "CreateFontA", (FARPROC)_CreateFontA);
				module.SetImportAddress(pImport1, "CreateFontW", (FARPROC)_CreateFontW);
				module.SetImportAddress(pImport1, "CreateFontIndirectA", (FARPROC)_CreateFontIndirectA);
				module.SetImportAddress(pImport1, "CreateFontIndirectW", (FARPROC)_CreateFontIndirectW);
				module.SetImportAddress(pImport1, "CreateFontIndirectExA", (FARPROC)_CreateFontIndirectExA);
				module.SetImportAddress(pImport1, "CreateFontIndirectExW", (FARPROC)_CreateFontIndirectExW);
				// region
				module.SetImportAddress(pImport1, "CreateRectRgn", (FARPROC)_CreateRectRgn);
				module.SetImportAddress(pImport1, "CreateRectRgnIndirect", (FARPROC)_CreateRectRgnIndirect);
				module.SetImportAddress(pImport1, "CreateEllipticRgn", (FARPROC)_CreateEllipticRgn);
				module.SetImportAddress(pImport1, "CreateEllipticRgnIndirect", (FARPROC)_CreateEllipticRgnIndirect);
				module.SetImportAddress(pImport1, "CreatePolygonRgn", (FARPROC)_CreatePolygonRgn);
				module.SetImportAddress(pImport1, "CreatePolyPolygonRgn", (FARPROC)_CreatePolyPolygonRgn);
				module.SetImportAddress(pImport1, "CreateRoundRectRgn", (FARPROC)_CreateRoundRectRgn);
				module.SetImportAddress(pImport1, "PathToRegion", (FARPROC)_PathToRegion);
				module.SetImportAddress(pImport1, "ExtCreateRegion", (FARPROC)_ExtCreateRegion);
				// metafile dc(released by CloseMetaFile/CloseEnhMetaFile)
				module.SetImportAddress(pImport1, "CreateMetaFileA", (FARPROC)_CreateMetaFileA);
				module.SetImportAddress(pImport1, "CreateMetaFileW", (FARPROC)_CreateMetaFileW);
				module.SetImportAddress(pImport1, "CreateEnhMetaFileA", (FARPROC)_CreateEnhMetaFileA);
				module.SetImportAddress(pImport1, "CreateEnhMetaFileW", (FARPROC)_CreateEnhMetaFileW);
				// metafile
				module.SetImportAddress(pImport1, "GetEnhMetaFileA", (FARPROC)_GetEnhMetaFileA);
				module.SetImportAddress(pImport1, "GetEnhMetaFileW", (FARPROC)_GetEnhMetaFileW);
				module.SetImportAddress(pImport1, "GetMetaFileA", (FARPROC)_GetMetaFileA);
				module.SetImportAddress(pImport1, "GetMetaFileW", (FARPROC)_GetMetaFileW);
				// palette
				module.SetImportAddress(pImport1, "CreateHalftonePalette", (FARPROC)_CreateHalftonePalette);
				module.SetImportAddress(pImport1, "CreatePalette", (FARPROC)_CreatePalette);
				// object deletion
				module.SetImportAddress(pImport1, "DeleteObject", (FARPROC)_DeleteObject);
				module.SetImportAddress(pImport1, "DeleteDC", (FARPROC)_DeleteDC);
				module.SetImportAddress(pImport1, "DeleteMetaFile", (FARPROC)_DeleteMetaFile);
				module.SetImportAddress(pImport1, "DeleteEnhMetaFile", (FARPROC)_DeleteEnhMetaFile);
				//delete metafile dc and generate metafile
				module.SetImportAddress(pImport1, "CloseMetaFile", (FARPROC)_CloseMetaFile);
				module.SetImportAddress(pImport1, "CloseEnhMetaFile", (FARPROC)_CloseEnhMetaFile);
			}

			PIMAGE_IMPORT_DESCRIPTOR pImport2 = module.GetImportDescriptor("USER32.dll");
			if(pImport2)
			{
				module.SetImportAddress(pImport2, "GetDC", (FARPROC)_GetDC);
				module.SetImportAddress(pImport2, "GetDCEx", (FARPROC)_GetDCEx);
				module.SetImportAddress(pImport2, "GetWindowDC", (FARPROC)_GetWindowDC);
				module.SetImportAddress(pImport2, "LoadBitmapA", (FARPROC)_LoadBitmapA);
				module.SetImportAddress(pImport2, "LoadBitmapW", (FARPROC)_LoadBitmapW);
				module.SetImportAddress(pImport2, "ReleaseDC", (FARPROC)_ReleaseDC);
			}
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
		}
	} while( /*FALSE*/Module32Next( hModuleSnap, &me32 ) );

	// Don't forget to clean up the snapshot object.
	CloseHandle( hModuleSnap );

	//for those DLLs which are loaded after GdiSpy.dll was loaded, we must modify addresses of 
	//the exported functions of GDI32.dll to hook the functions in the DLLs.
	KPEFile module(hGDI32);
	// device context
	module.SetExportAddress("CreateDCA", (FARPROC)_CreateDCA);
	module.SetExportAddress("CreateDCW", (FARPROC)_CreateDCW);
	module.SetExportAddress("CreateCompatibleDC", (FARPROC)_CreateCompatibleDC);
	module.SetExportAddress("CreateICA", (FARPROC)_CreateICA);
	module.SetExportAddress("CreateICW", (FARPROC)_CreateICW);
	// pen
	module.SetExportAddress("CreatePen", (FARPROC)_CreatePen);
	module.SetExportAddress("CreatePenIndirect", (FARPROC)_CreatePenIndirect);
	module.SetExportAddress("ExtCreatePen", (FARPROC)_ExtCreatePen);
	// brush API
	module.SetExportAddress("CreateSolidBrush", (FARPROC)_CreateSolidBrush);
	module.SetExportAddress("CreateHatchBrush", (FARPROC)_CreateHatchBrush);
	module.SetExportAddress("CreateBrushIndirect", (FARPROC)_CreateBrushIndirect);
	module.SetExportAddress("CreatePatternBrush", (FARPROC)_CreatePatternBrush);
	module.SetExportAddress("CreateDIBPatternBrush", (FARPROC)_CreateDIBPatternBrush);
	module.SetExportAddress("CreateDIBPatternBrushPt", (FARPROC)_CreateDIBPatternBrushPt);
	// bitmap API
	module.SetExportAddress("CreateBitmap", (FARPROC)_CreateBitmap);
	module.SetExportAddress("CreateBitmapIndirect", (FARPROC)_CreateBitmapIndirect);
	module.SetExportAddress("CreateCompatibleBitmap", (FARPROC)_CreateCompatibleBitmap);
	module.SetExportAddress("CreateDIBitmap", (FARPROC)_CreateDIBitmap);
	module.SetExportAddress("CreateDIBSection", (FARPROC)_CreateDIBSection);
	// font
	module.SetExportAddress("CreateFontA", (FARPROC)_CreateFontA);
	module.SetExportAddress("CreateFontW", (FARPROC)_CreateFontW);
	module.SetExportAddress("CreateFontIndirectA", (FARPROC)_CreateFontIndirectA);
	module.SetExportAddress("CreateFontIndirectW", (FARPROC)_CreateFontIndirectW);
	module.SetExportAddress("CreateFontIndirectExA", (FARPROC)_CreateFontIndirectExA);
	module.SetExportAddress("CreateFontIndirectExW", (FARPROC)_CreateFontIndirectExW);
	// region
	module.SetExportAddress("CreateRectRgn", (FARPROC)_CreateRectRgn);
	module.SetExportAddress("CreateRectRgnIndirect", (FARPROC)_CreateRectRgnIndirect);
	module.SetExportAddress("CreateEllipticRgn", (FARPROC)_CreateEllipticRgn);
	module.SetExportAddress("CreateEllipticRgnIndirect", (FARPROC)_CreateEllipticRgnIndirect);
	module.SetExportAddress("CreatePolygonRgn", (FARPROC)_CreatePolygonRgn);
	module.SetExportAddress("CreatePolyPolygonRgn", (FARPROC)_CreatePolyPolygonRgn);
	module.SetExportAddress("CreateRoundRectRgn", (FARPROC)_CreateRoundRectRgn);
	module.SetExportAddress("PathToRegion", (FARPROC)_PathToRegion);
	module.SetExportAddress("ExtCreateRegion", (FARPROC)_ExtCreateRegion);
	// metafile dc(released by CloseMetaFile/CloseEnhMetaFile)
	module.SetExportAddress("CreateMetaFileA", (FARPROC)_CreateMetaFileA);
	module.SetExportAddress("CreateMetaFileW", (FARPROC)_CreateMetaFileW);
	module.SetExportAddress("CreateEnhMetaFileA", (FARPROC)_CreateEnhMetaFileA);
	module.SetExportAddress("CreateEnhMetaFileW", (FARPROC)_CreateEnhMetaFileW);
	// metafile
	module.SetExportAddress("GetEnhMetaFileA", (FARPROC)_GetEnhMetaFileA);
	module.SetExportAddress("GetEnhMetaFileW", (FARPROC)_GetEnhMetaFileW);
	module.SetExportAddress("GetMetaFileA", (FARPROC)_GetMetaFileA);
	module.SetExportAddress("GetMetaFileW", (FARPROC)_GetMetaFileW);
	// palette
	module.SetExportAddress("CreateHalftonePalette", (FARPROC)_CreateHalftonePalette);
	module.SetExportAddress("CreatePalette", (FARPROC)_CreatePalette);
	// object deletion
	module.SetExportAddress("DeleteObject", (FARPROC)_DeleteObject);
	module.SetExportAddress("DeleteDC", (FARPROC)_DeleteDC);
	module.SetExportAddress("DeleteMetaFile", (FARPROC)_DeleteMetaFile);
	module.SetExportAddress("DeleteEnhMetaFile", (FARPROC)_DeleteEnhMetaFile);
	//delete metafile dc and generate metafile
	module.SetExportAddress("CloseMetaFile", (FARPROC)_CloseMetaFile);
	module.SetExportAddress("CloseEnhMetaFile", (FARPROC)_CloseEnhMetaFile);

	KPEFile user32module(hUSER32);
	user32module.SetExportAddress("GetDC", (FARPROC)_GetDC);
	user32module.SetExportAddress("GetDCEx", (FARPROC)_GetDCEx);
	user32module.SetExportAddress("GetWindowDC", (FARPROC)_GetWindowDC);
	user32module.SetExportAddress("LoadBitmapA", (FARPROC)_LoadBitmapA);
	user32module.SetExportAddress("LoadBitmapW", (FARPROC)_LoadBitmapW);
	user32module.SetExportAddress("ReleaseDC", (FARPROC)_ReleaseDC);
}

using namespace std;
CGdiMonitor::~CGdiMonitor(void)
{
	if(g_pBuf == NULL)
		return;

	//Serialization here must have exactly coincidence with deserialization in GdiLeakDetector.exe, 
	//like writing a document to a file and reading a file to a document.
	char* pCur = (char*)g_pBuf;
	const char* pEnd = pCur + PAGE_FILE_BUF_SIZE;

	//Serialize handle value and call stack of each leaked GDI object in the named map file.
	DWORD handleCount = g_HandleInfo.size();
	*(DWORD*)pCur = handleCount;
	pCur += sizeof(DWORD);

	map<DWORD, vector<string> >::iterator it;
	for(it = g_HandleInfo.begin(); it != g_HandleInfo.end(); ++it)
	{
		//If the free space in the named map file is not sufficient, then stop dumping information.
		if(pEnd - pCur < ONE_ENTRY_MAX_SPACE)
			break;
		*(DWORD*)pCur = it->first;//handle value
		pCur += sizeof(DWORD);

		DWORD stackFrameCount = it->second.size();
		*(DWORD*)pCur = stackFrameCount;
		pCur += sizeof(DWORD);

		for(int i=0; i<stackFrameCount; ++i)
		{
			DWORD len = it->second[i].length() + 1;
			*(DWORD*)pCur = len;
			pCur += sizeof(DWORD);

			memcpy(pCur, it->second[i].c_str(), len);
			pCur += len;
		}
	}
	UnmapViewOfFile(g_pBuf);
	CloseHandle(g_hMapFile);
}
