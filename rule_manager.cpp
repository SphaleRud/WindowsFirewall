#include "rule_manager.h"
#include "Resource.h"
#include <commctrl.h>
#include <algorithm>
#include <shobjidl.h>
#include <string>
#include <codecvt>
#include <locale>
#include "rule.h"
#include "string_utils.h" 
#include "validator.h"
#include "rule_wizard.h"

RuleManager::RuleManager() = default;
RuleManager::~RuleManager() = default;

RuleManager& RuleManager::Instance() {
    static RuleManager instance;
    return instance;
}

void RuleManager::SetDirection(RuleDirection direction) {
    std::lock_guard<std::mutex> lock(ruleMutex);
    currentDirection = direction;
}

RuleDirection RuleManager::GetCurrentDirection() const {
    std::lock_guard<std::mutex> lock(ruleMutex);
    return currentDirection;
}

bool RuleManager::AddRule(const Rule& rule) {
    std::lock_guard<std::mutex> lock(ruleMutex);
    Rule newRule = rule;
    newRule.id = nextRuleId++;
    rules.push_back(newRule);
    return true;
}

bool RuleManager::RemoveRule(int ruleId) {
    std::lock_guard<std::mutex> lock(ruleMutex);
    auto it = std::find_if(rules.begin(), rules.end(), [ruleId](const Rule& r) { return r.id == ruleId; });
    if (it != rules.end()) {
        rules.erase(it);
        return true;
    }
    return false;
}

bool RuleManager::UpdateRule(const Rule& rule) {
    std::lock_guard<std::mutex> lock(ruleMutex);
    auto it = std::find_if(rules.begin(), rules.end(), [&rule](const Rule& r) { return r.id == rule.id; });
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
    auto it = std::find_if(rules.begin(), rules.end(), [ruleId](const Rule& r) { return r.id == ruleId; });
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

    return true; // Разрешить по умолчанию, если не найдено подходящее правило
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

// --- Диалог всех правил ---
void RuleManager::ShowRulesDialog(HWND hParent) {
    DialogBoxParam(
        GetModuleHandle(nullptr),
        MAKEINTRESOURCE(IDD_RULES_DIALOG),
        hParent,
        RuleManager::RulesDialogProc,
        reinterpret_cast<LPARAM>(this)
    );
}

void FillRulesList(HWND hList) {
    ListView_DeleteAllItems(hList);

    // Удаляем все колонки
    while (ListView_DeleteColumn(hList, 0)) {}

    // Добавляем колонки
    LVCOLUMN lvc = { 0 };
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

    const struct {
        const wchar_t* text;
        int width;
    } columns[] = {
        { L"Название", 150 },
        { L"Состояние", 70 },
        { L"Действие", 70 },
        { L"Программа", 150 },
        { L"Локальный адрес", 120 },
        { L"Адрес назначения", 120 },
        { L"Протокол", 70 },
        { L"Локальный порт", 100 },
        { L"Порт назначения", 100 }
    };

    for (int i = 0; i < _countof(columns); i++) {
        lvc.iSubItem = i;
        lvc.pszText = const_cast<LPWSTR>(columns[i].text);
        lvc.cx = columns[i].width;
        ListView_InsertColumn(hList, i, &lvc);
    }

    // Получаем правила и текущее направление
    auto rules = RuleManager::Instance().GetRules();
    auto currentDirection = RuleManager::Instance().GetCurrentDirection();

    int itemIndex = 0;
    for (const auto& rule : rules) {
        if (rule.direction != currentDirection)
            continue;

        LVITEM lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = itemIndex;

        // Название
        lvi.iSubItem = 0;
        lvi.pszText = const_cast<LPWSTR>(Utf8ToWide(rule.name).c_str());
        ListView_InsertItem(hList, &lvi);

        // Состояние
        lvi.iSubItem = 1;
        lvi.pszText = const_cast<LPWSTR>(rule.enabled ? L"Вкл" : L"Выкл");
        ListView_SetItem(hList, &lvi);

        // Действие
        lvi.iSubItem = 2;
        lvi.pszText = const_cast<LPWSTR>(rule.action == RuleAction::ALLOW ? L"Разрешить" : L"Запретить");
        ListView_SetItem(hList, &lvi);

        // Программа
        lvi.iSubItem = 3;
        lvi.pszText = const_cast<LPWSTR>(Utf8ToWide(rule.appPath).c_str());
        ListView_SetItem(hList, &lvi);

        // Локальный адрес
        lvi.iSubItem = 4;
        lvi.pszText = const_cast<LPWSTR>(Utf8ToWide(rule.sourceIp).c_str());
        ListView_SetItem(hList, &lvi);

        // Адрес назначения
        lvi.iSubItem = 5;
        lvi.pszText = const_cast<LPWSTR>(Utf8ToWide(rule.destIp).c_str());
        ListView_SetItem(hList, &lvi);

        // Протокол
        lvi.iSubItem = 6;
        std::wstring protocolStr;
        switch (rule.protocol) {
        case Protocol::TCP: protocolStr = L"TCP"; break;
        case Protocol::UDP: protocolStr = L"UDP"; break;
        case Protocol::ICMP: protocolStr = L"ICMP"; break;
        default: protocolStr = L"Любой"; break;
        }
        lvi.pszText = const_cast<LPWSTR>(protocolStr.c_str());
        ListView_SetItem(hList, &lvi);

        // Локальный порт
        lvi.iSubItem = 7;
        lvi.pszText = const_cast<LPWSTR>(std::to_wstring(rule.sourcePort).c_str());
        ListView_SetItem(hList, &lvi);

        // Порт назначения
        lvi.iSubItem = 8;
        lvi.pszText = const_cast<LPWSTR>(std::to_wstring(rule.destPort).c_str());
        ListView_SetItem(hList, &lvi);

        itemIndex++;
    }
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




bool RuleManager::ShowAddRuleWizard(HWND hParent) {
    Rule newRule;
    newRule.direction = GetCurrentDirection();
    if (RuleWizard::ShowWizard(hParent, newRule)) {
        AddRule(newRule);
        return true;
    }
    return false;
}

// Остальные методы класса RuleManager (AddRule, RemoveRule и т.д.) остаются без изменений

// --- Диалог списка правил ---
INT_PTR CALLBACK RuleManager::RulesDialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    static HWND hList = nullptr;
    switch (uMsg) {
    case WM_INITDIALOG: {
        hList = GetDlgItem(hwndDlg, IDC_RULES_LIST);

        // Устанавливаем начальное состояние переключателей
        CheckRadioButton(hwndDlg, IDC_RADIO_INBOUND, IDC_RADIO_OUTBOUND,
            RuleManager::Instance().GetCurrentDirection() == RuleDirection::Inbound ?
            IDC_RADIO_INBOUND : IDC_RADIO_OUTBOUND);

        hList = GetDlgItem(hwndDlg, IDC_RULES_LIST);

        LVCOLUMN lvc = { 0 };
        lvc.mask = LVCF_TEXT | LVCF_WIDTH;
        lvc.cx = 80;  lvc.pszText = const_cast<LPWSTR>(L"Протокол");   ListView_InsertColumn(hList, 0, &lvc);
        lvc.cx = 110; lvc.pszText = const_cast<LPWSTR>(L"Источник");   ListView_InsertColumn(hList, 1, &lvc);
        lvc.cx = 110; lvc.pszText = const_cast<LPWSTR>(L"Назначение"); ListView_InsertColumn(hList, 2, &lvc);
        lvc.cx = 70;  lvc.pszText = const_cast<LPWSTR>(L"Действие");   ListView_InsertColumn(hList, 3, &lvc);
        lvc.cx = 110; lvc.pszText = const_cast<LPWSTR>(L"Имя");        ListView_InsertColumn(hList, 4, &lvc);
        lvc.cx = 180; lvc.pszText = const_cast<LPWSTR>(L"Описание");   ListView_InsertColumn(hList, 5, &lvc);
        lvc.cx = 60;  lvc.pszText = const_cast<LPWSTR>(L"Вкл");        ListView_InsertColumn(hList, 6, &lvc);

        FillRulesList(hList);
        return TRUE;
    }
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_RADIO_INBOUND:
        case IDC_RADIO_OUTBOUND:
            if (HIWORD(wParam) == BN_CLICKED) {
                RuleManager::Instance().SetDirection(
                    LOWORD(wParam) == IDC_RADIO_INBOUND ?
                    RuleDirection::Inbound : RuleDirection::Outbound
                );
                FillRulesList(hList);
            }
            return TRUE;
        case ID_ADD_RULE:
            if (RuleManager::Instance().ShowAddRuleWizard(hwndDlg)) {
                FillRulesList(hList);
            }
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