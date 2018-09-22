#pragma once


// CLineNumEdit
#define WM_GOLINE WM_USER+1

class CLineNumEdit : public CEdit
{
	DECLARE_DYNAMIC(CLineNumEdit)

public:

protected:
	afx_msg void OnKeyDown(UINT nChar, UINT nRepCnt, UINT nFlags);
	DECLARE_MESSAGE_MAP()
};


