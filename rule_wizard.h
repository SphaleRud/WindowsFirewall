#pragma once
#include "rule.h"
#include "rule_manager.h"
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
    static bool ShowWizard(HWND hParent, Rule& rule);
    static bool EditRule(HWND parent, Rule& rule);

private:
    RuleWizard(HWND hParent, Rule& rule);
    ~RuleWizard();
    
    static void ShowPage(WizardPage page);
    static void UpdateButtons();
    static void SetupPageControls();

    static Rule* currentRule;
    static bool isEditMode;
    static WizardPage currentPage;
    static int selectedType;
    static HWND currentPageHwnd;

    static INT_PTR CALLBACK DialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static void InitDialog();
    static void LoadRule();
    static bool SaveRule();
    static bool ValidateCurrentPage();
    static void BrowseForProgram();
    static bool SavePageData();
    static int GetPageDialogId(WizardPage page);
    static INT_PTR CALLBACK PageDlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

    static RuleWizard* s_instance;

    HWND m_hwndParent;
    HWND m_hwndMain;
    HWND m_hwndCurrent;
    WizardPage m_currentPage;
    Rule& m_rule;
    int m_selectedType;
};