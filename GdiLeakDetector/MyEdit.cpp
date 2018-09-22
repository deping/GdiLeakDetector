// MyEdit.cpp : implementation file
//

#include "stdafx.h"
#include "GdiLeakDetector.h"
#include "MyEdit.h"


// CMyEdit

IMPLEMENT_DYNAMIC(CMyEdit, CEdit)

CMyEdit::CMyEdit()
{
	m_NotFocus = TRUE;
}

BEGIN_MESSAGE_MAP(CMyEdit, CEdit)
//	ON_CONTROL_REFLECT(EN_SETFOCUS, &CMyEdit::OnEnSetfocus)
ON_WM_LBUTTONDOWN()
ON_WM_SETFOCUS()
ON_WM_KILLFOCUS()
END_MESSAGE_MAP()

// CMyEdit message handlers

void CMyEdit::OnLButtonDown(UINT nFlags, CPoint point)
{
	BOOL bNotFocus = m_NotFocus;
	CEdit::OnLButtonDown(nFlags, point);
	if(bNotFocus)
	{
		SetSel(0, -1);
	}
}

void CMyEdit::OnSetFocus(CWnd* pOldWnd)
{
	CEdit::OnSetFocus(pOldWnd);

	m_NotFocus = FALSE;
}

void CMyEdit::OnKillFocus(CWnd* pNewWnd)
{
	CEdit::OnKillFocus(pNewWnd);

	m_NotFocus = TRUE;
}
