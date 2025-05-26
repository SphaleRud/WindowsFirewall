#pragma once
#include "rule_manager.h"
#include "rule.h"
#include <Windows.h>
#include <memory>

class RuleWizard {
public:
    enum WizardPage {
        PAGE_TYPE,
        PAGE_PARAMS_APP,
        PAGE_PARAMS_PORT,
        PAGE_PARAMS_PROTO,
        PAGE_PARAMS_ADVANCED,
        PAGE_ACTION,
        PAGE_NAME,
        PAGE_COUNT
    };

    RuleWizard(HWND hParent, Rule& rule);
    ~RuleWizard();

    bool Show();

private:
    HWND m_hwndParent;
    HWND m_hwndMain;
    HWND m_hwndCurrent;
    WizardPage m_currentPage;
    Rule& m_ruleDraft;
    int m_selectedType;

    void ShowPage(WizardPage page);
    void GoToNextPage();
    void GoToPrevPage();
    bool ValidateCurrentPage();
    bool ApplyPageData();
    bool SaveRule(HWND hwnd);
    void BrowseForProgram(HWND hwnd, int editId);
    int GetPageDialogId(WizardPage page);
    void UpdateButtons();

    static INT_PTR CALLBACK DialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static INT_PTR CALLBACK PageDlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
};