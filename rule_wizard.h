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
    static bool EditRule(HWND parent, Rule& rule);
    void ShowPage(WizardPage page);
    void UpdateButtons();
    bool SavePageData();
    bool ValidateCurrentPage();

    static INT_PTR CALLBACK MainDlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static INT_PTR CALLBACK PageDlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

private:
    static Rule* currentRule;
    static bool isEditMode;

    static INT_PTR CALLBACK DialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static void InitDialog(HWND hwnd);
    static void LoadRule(HWND hwnd);
    static bool SaveRule(HWND hwnd);

    static void BrowseForProgram(HWND hwnd);

    HWND m_hwndMain;
    HWND m_hwndCurrent;
    HWND m_hwndParent;
    WizardPage m_currentPage;
    Rule& m_rule;
    int m_selectedType;
    static RuleWizard* s_instance;
};