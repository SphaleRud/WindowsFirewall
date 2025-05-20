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

// В RuleManager добавим метод для валидации ввода
bool RuleValidator::ValidatePortInput(const std::wstring& input, std::vector<std::pair<int, int>>& portRanges) {
    std::wstring port = input;
    std::vector<std::wstring> parts;

    // Разделяем по запятой
    size_t pos = 0;
    while ((pos = port.find(L',')) != std::wstring::npos) {
        parts.push_back(port.substr(0, pos));
        port = port.substr(pos + 1);
    }
    parts.push_back(port);

    for (const auto& part : parts) {
        // Проверяем на диапазон
        if (part.find(L'-') != std::wstring::npos) {
            size_t dashPos = part.find(L'-');
            int start = _wtoi(part.substr(0, dashPos).c_str());
            int end = _wtoi(part.substr(dashPos + 1).c_str());

            if (start <= 0 || end <= 0 || start > 65535 || end > 65535 || start > end)
                return false;

            portRanges.push_back({ start, end });
        }
        else {
            // Одиночный порт
            int singlePort = _wtoi(part.c_str());
            if (singlePort <= 0 || singlePort > 65535)
                return false;

            portRanges.push_back({ singlePort, singlePort });
        }
    }
    return true;
}

bool RuleValidator::ValidateIpInput(const std::wstring& input, std::vector<std::pair<std::string, std::string>>& ipRanges) {
    std::wstring ip = input;
    std::vector<std::wstring> parts;

    // Разделяем по запятой
    size_t pos = 0;
    while ((pos = ip.find(L',')) != std::wstring::npos) {
        parts.push_back(ip.substr(0, pos));
        ip = ip.substr(pos + 1);
    }
    parts.push_back(ip);

    for (const auto& part : parts) {
        // Проверяем на CIDR нотацию
        if (part.find(L'/') != std::wstring::npos) {
            // Реализовать проверку CIDR
            continue;
        }

        // Проверяем на диапазон
        if (part.find(L'-') != std::wstring::npos) {
            size_t dashPos = part.find(L'-');
            std::string start = WideToUtf8(part.substr(0, dashPos).c_str());
            std::string end = WideToUtf8(part.substr(dashPos + 1).c_str());

            // Здесь нужно добавить проверку корректности IP адресов
            ipRanges.push_back({ start, end });
        }
        else {
            std::string single = WideToUtf8(part.c_str());
            // Здесь нужно добавить проверку корректности IP адреса
            ipRanges.push_back({ single, single });
        }
    }
    return true;
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

static void FillRulesList(HWND hList) {
    ListView_DeleteAllItems(hList);
    auto rules = RuleManager::Instance().GetRules();
    auto currentDirection = RuleManager::Instance().GetCurrentDirection();

    for (const Rule& rule : rules) {
        if (rule.direction != currentDirection)
            continue;

        LVITEM lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = ListView_GetItemCount(hList);

        std::wstring proto = (rule.protocol == Protocol::TCP) ? L"TCP" :
            (rule.protocol == Protocol::UDP) ? L"UDP" :
            (rule.protocol == Protocol::ICMP) ? L"ICMP" :
            (rule.protocol == Protocol::ANY) ? L"ANY" : L"?";
        std::wstring src = Utf8ToWide(rule.sourceIp);
        std::wstring dst = Utf8ToWide(rule.destIp);
        std::wstring act = (rule.action == RuleAction::ALLOW) ? L"Allow" : L"Block";
        std::wstring name = Utf8ToWide(rule.name);
        std::wstring descr = Utf8ToWide(rule.description);
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