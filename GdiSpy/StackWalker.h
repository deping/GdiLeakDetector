/**********************************************************************
* 
* StackWalker.h
*
*
* History:
*  2005-07-27   v1    - First public release on http://www.codeproject.com/
*  (for additional changes see History in 'StackWalker.cpp'!
**********************************************************************
*  2005-08-25		-refined and refactored by chen deping for more
*					 convenient usage
**********************************************************************/
#pragma once

#include <windows.h>
#include <vector>

class StackWalkerInternal;
class CStackWalker
{
public:
	CStackWalker(LPCSTR szSymPath = NULL);
	~CStackWalker(void);
	BOOL GetCallstack(/*out*/std::vector<std::string>& callStacks, int skipFrameCount, int maxFrameCount=10);

private:
	enum { STACKWALK_MAX_NAMELEN = 512 }; // max name length for found symbols

	typedef struct CallstackEntry
	{
		DWORD64 offset;  // if 0, we have no valid entry
		CHAR moduleName[STACKWALK_MAX_NAMELEN];
		CHAR name[STACKWALK_MAX_NAMELEN];
		CHAR lineFileName[STACKWALK_MAX_NAMELEN];
		DWORD lineNumber;
	} CallstackEntry;

	void OnCallstackEntry(const CallstackEntry &entry, /*out*/std::string& result);
	void BuildSymPath(char* szSymPath, size_t nSymPathLen);
	BOOL LoadModulesSymbols();


	StackWalkerInternal *m_sw;
	HANDLE m_hProcess;
	DWORD m_dwProcessId;
	BOOL m_modulesLoaded;
	LPSTR m_szSymPath;

	friend StackWalkerInternal;
};
