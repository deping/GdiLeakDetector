// GdiLeakDetectorDlg.h
//

#pragma once

#include <map>
#include <vector>
#include "MyEdit.h"
#include "LineNumEdit.h"

// CGdiLeakDetectorDlg
class CGdiLeakDetectorDlg : public CDialog
{
public:
	CGdiLeakDetectorDlg(CWnd* pParent = NULL);
	~CGdiLeakDetectorDlg();

	enum { IDD = IDD_GDILEAKDETECTOR_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);


protected:
	HICON m_hIcon;
	std::map<DWORD, std::vector<char*> > m_HandleInfo;
	CString m_FileName;
	CMyEdit m_ExeFileEdit;
	CLineNumEdit m_LineNumEdit;

	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedBrowsefile();
	afx_msg void OnNMClickLeaklist(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnLbnDblclkCallstack();
	afx_msg void OnBnClickedSave();
	afx_msg LRESULT OnKickIdle(WPARAM wParam, LPARAM ICount);
	afx_msg LRESULT OnGoLine(WPARAM, LPARAM);
	DECLARE_MESSAGE_MAP()
private:
	void ShowDebugString(LPCTSTR message);
	BOOL CreateRemoteThread(HANDLE hProcess);
	void GetLeakList();
	void ShowLeakList();
	void ShowFile(const CString & fileName, int lineNum);
};
