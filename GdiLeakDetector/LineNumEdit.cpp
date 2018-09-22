// LineNumEdit.cpp : implementation file
//

#include "stdafx.h"
#include "GdiLeakDetector.h"
#include "LineNumEdit.h"


// CLineNumEdit

IMPLEMENT_DYNAMIC(CLineNumEdit, CEdit)


BEGIN_MESSAGE_MAP(CLineNumEdit, CEdit)
	ON_WM_KEYDOWN()
END_MESSAGE_MAP()



// CLineNumEdit message handlers



void CLineNumEdit::OnKeyDown(UINT nChar, UINT nRepCnt, UINT nFlags)
{
	if(VK_RETURN == nChar)
		GetOwner()->SendNotifyMessage(WM_GOLINE, 0, 0);
	else
		CEdit::OnKeyDown(nChar, nRepCnt, nFlags);
}
