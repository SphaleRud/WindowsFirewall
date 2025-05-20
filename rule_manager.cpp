#include "rule_manager.h"
#include <algorithm>
#include <optional>
#include "Resource.h"
#include <commctrl.h>
#include <string>

RuleManager& RuleManager::Instance() {
    static RuleManager instance;
    return instance;
}

static std::wstring s2ws(const std::string& str) {
    int sz = MultiByteToWideChar(CP_UTF8, 0, str.data(), str.size(), nullptr, 0);
    std::wstring wstr(sz, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.data(), str.size(), &wstr[0], sz);
    return wstr;
}

void RuleManager::ShowRulesDialog(HWND hParent) {
    DialogBoxParam(
        GetModuleHandle(nullptr),
        MAKEINTRESOURCE(IDD_RULES_DIALOG),
        hParent,
        RulesDialogProc,
        reinterpret_cast<LPARAM>(this)
    );
}

// Функция для заполнения ListView правилами
static void FillRulesList(HWND hList) {
    ListView_DeleteAllItems(hList);
    auto& rules = RuleManager::Instance().GetRules();

    for (const Rule& rule : rules) {
        LVITEM lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = ListView_GetItemCount(hList);

        std::wstring proto = (rule.protocol == Protocol::TCP) ? L"TCP" :
            (rule.protocol == Protocol::UDP) ? L"UDP" :
            (rule.protocol == Protocol::ICMP) ? L"ICMP" :
            (rule.protocol == Protocol::ANY) ? L"ANY" : L"?";
        std::wstring src = s2ws(rule.sourceIp);
        std::wstring dst = s2ws(rule.destIp);
        std::wstring act = (rule.action == RuleAction::ALLOW) ? L"Allow" : L"Block";
        std::wstring name = s2ws(rule.name);
        std::wstring descr = s2ws(rule.description);
        std::wstring enabled = rule.enabled ? L"Yes" : L"No";

        lvi.iSubItem = 0;
        lvi.pszText = const_cast<LPWSTR>(proto.c_str());
        int idx = ListView_InsertItem(hList, &lvi);

        ListView_SetItemText(hList, idx, 1, const_cast<LPWSTR>(src.c_str()));
        ListView_SetItemText(hList, idx, 2, const_cast<LPWSTR>(dst.c_str()));
        ListView_SetItemText(hList, idx, 3, const_cast<LPWSTR>(act.c_str()));
        ListView_SetItemText(hList, idx, 4, const_cast<LPWSTR>(name.c_str()));
        ListView_SetItemText(hList, idx, 5, const_cast<LPWSTR>(descr.c_str()));
        ListView_SetItemText(hList, idx, 6, const_cast<LPWSTR>(enabled.c_str()));
    }
}


static void AddRuleSimple() {
    Rule rule;
    rule.name = "New Rule";
    rule.description = "Custom rule";
    rule.protocol = Protocol::ANY;
    rule.sourceIp = "";
    rule.destIp = "";
    rule.sourcePort = 0;
    rule.destPort = 0;
    rule.action = RuleAction::ALLOW;
    rule.enabled = true;
    RuleManager::Instance().AddRule(rule);
}

static void DeleteSelectedRule(HWND hList) {
    int sel = ListView_GetNextItem(hList, -1, LVNI_SELECTED);
    if (sel == -1) return;
    auto rules = RuleManager::Instance().GetRules();
    if (sel >= 0 && sel < (int)rules.size()) {
        int ruleId = rules[sel].id;
        RuleManager::Instance().RemoveRule(ruleId);
    }
}


bool RuleManager::UpdateRule(const Rule& rule) {
    std::lock_guard<std::mutex> lock(ruleMutex);
    auto it = std::find_if(rules.begin(), rules.end(),
        [&rule](const Rule& r) { return r.id == rule.id; });

    if (it != rules.end()) {
        *it = rule;
        return true;
    }
    return false;
}

std::vector<Rule> RuleManager::GetRules() const {
    std::lock_guard<std::mutex> lock(ruleMutex);
    return rules;
}

std::optional<Rule> RuleManager::GetRuleById(int ruleId) const {
    std::lock_guard<std::mutex> lock(ruleMutex);
    auto it = std::find_if(rules.begin(), rules.end(),
        [ruleId](const Rule& rule) { return rule.id == ruleId; });
    if (it != rules.end())
        return *it;
    return std::nullopt;
}

bool RuleManager::IsAllowed(const Connection& connection, int& matchedRuleId) {
    std::lock_guard<std::mutex> lock(ruleMutex);
    matchedRuleId = -1;

    for (const auto& rule : rules) {
        if (!rule.enabled) continue;

        bool sourceMatch = (rule.sourceIp.empty() || rule.sourceIp == connection.sourceIp);
        bool destMatch = (rule.destIp.empty() || rule.destIp == connection.destIp);
        bool protocolMatch = (rule.protocol == Protocol::ANY || rule.protocol == connection.protocol);
        bool sourcePortMatch = (rule.sourcePort == 0 || rule.sourcePort == connection.sourcePort);
        bool destPortMatch = (rule.destPort == 0 || rule.destPort == connection.destPort);

        if (sourceMatch && destMatch && protocolMatch && sourcePortMatch && destPortMatch) {
            matchedRuleId = rule.id;
            return rule.action == RuleAction::ALLOW;
        }
    }

    return true; // По умолчанию разрешено, если нет подходящих правил
}

void RuleManager::Clear() {
    std::lock_guard<std::mutex> lock(ruleMutex);
    rules.clear();
    nextRuleId = 1;
}

void RuleManager::ResetRuleIdCounter(int newNextId) {
    std::lock_guard<std::mutex> lock(ruleMutex);
    nextRuleId = newNextId;
}

static INT_PTR CALLBACK RulesDialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    static HWND hList = nullptr;
    switch (uMsg) {
    case WM_INITDIALOG: {
        hList = GetDlgItem(hwndDlg, IDC_RULES_LIST);

        LVCOLUMN lvc = { 0 };
        lvc.mask = LVCF_TEXT | LVCF_WIDTH;
        lvc.cx = 80; lvc.pszText = L"Протокол"; ListView_InsertColumn(hList, 0, &lvc);
        lvc.cx = 110; lvc.pszText = L"Источник"; ListView_InsertColumn(hList, 1, &lvc);
        lvc.cx = 110; lvc.pszText = L"Назначение"; ListView_InsertColumn(hList, 2, &lvc);
        lvc.cx = 70; lvc.pszText = L"Действие"; ListView_InsertColumn(hList, 3, &lvc);
        lvc.cx = 110; lvc.pszText = L"Имя"; ListView_InsertColumn(hList, 4, &lvc);
        lvc.cx = 180; lvc.pszText = L"Описание"; ListView_InsertColumn(hList, 5, &lvc);
        lvc.cx = 60; lvc.pszText = L"Вкл"; ListView_InsertColumn(hList, 6, &lvc);

        FillRulesList(hList);
        return TRUE;
    }
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case ID_ADD_RULE:
            AddRuleSimple();
            FillRulesList(hList);
            return TRUE;
        case ID_DELETE_RULE:
            DeleteSelectedRule(hList);
            FillRulesList(hList);
            return TRUE;
        case IDOK:
        case IDCANCEL:
            EndDialog(hwndDlg, LOWORD(wParam));
            return TRUE;
        }
        break;
    }
    return FALSE;
}