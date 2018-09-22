// GdiLeakDetector.h
//

#pragma once


#include "resource.h"


class CGdiLeakDetectorApp : public CWinApp
{
public:
	CGdiLeakDetectorApp();

	public:
	virtual BOOL InitInstance();

	DECLARE_MESSAGE_MAP()
};

extern CGdiLeakDetectorApp theApp;