#pragma once
#include "rule.h"
#include "rule_manager.h"
#include <Windows.h>
#include <memory>

class RuleWizard {
public:
    static bool ShowWizard(HWND hParent, Rule& rule);

private:
    enum WizardPage {
        PAGE_TYPE = 0,
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
    void ShowPage(WizardPage page);
    void UpdateButtons();
    bool SavePageData();
    bool ValidateCurrentPage();

    static INT_PTR CALLBACK MainDlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static INT_PTR CALLBACK PageDlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

private:
    HWND m_hwndMain;
    HWND m_hwndCurrent;
    HWND m_hwndParent;
    WizardPage m_currentPage;
    Rule& m_rule;
    int m_selectedType;
    static RuleWizard* s_instance;
};