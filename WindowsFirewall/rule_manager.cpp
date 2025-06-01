#include <windows.h>
#include "rule_manager.h"
#include "Resource.h"
#include <algorithm>
#include <shobjidl.h>
#include <string>
#include <codecvt>
#include <locale>
#include <fstream>
#include <nlohmann/json.hpp>
#include "rule.h"
#include "string_utils.h" 
#include "validator.h"
#include "rule_wizard.h"
#include <commctrl.h>

#pragma comment(lib, "comctl32.lib")

#ifndef LVS_FULLROWSELECT
#define LVS_FULLROWSELECT 0x00000020
#endif

RuleManager::RuleManager() {
    LoadRulesFromFile();
}
RuleManager::~RuleManager() = default;

using nlohmann::json;

// Сериализация Rule в json
static std::string ProtocolToString(Protocol proto) {
    switch (proto) {
    case Protocol::ANY: return "ANY";
    case Protocol::TCP: return "TCP";
    case Protocol::UDP: return "UDP";
    case Protocol::ICMP: return "ICMP";
    default: return "UNKNOWN";
    }
}
static Protocol ProtocolFromString(const std::string& str) {
    if (str == "TCP") return Protocol::TCP;
    if (str == "UDP") return Protocol::UDP;
    if (str == "ICMP") return Protocol::ICMP;
    return Protocol::ANY;
}
static std::string ActionToString(RuleAction act) { return act == RuleAction::ALLOW ? "ALLOW" : "BLOCK"; }
static RuleAction ActionFromString(const std::string& str) { return str == "ALLOW" ? RuleAction::ALLOW : RuleAction::BLOCK; }
static std::string DirectionToString(RuleDirection dir) { return dir == RuleDirection::Inbound ? "Inbound" : "Outbound"; }
static RuleDirection DirectionFromString(const std::string& str) { return str == "Outbound" ? RuleDirection::Outbound : RuleDirection::Inbound; }

std::wstring GetExecutableDir()
{
    wchar_t buf[MAX_PATH];
    GetModuleFileNameW(NULL, buf, MAX_PATH);
    std::wstring path(buf);
    size_t pos = path.find_last_of(L"\\/");
    if (pos != std::wstring::npos)
        return path.substr(0, pos);
    return L".";
}

std::wstring rulesPath = GetExecutableDir() + L"\\rules.json";

bool RuleManager::SaveRulesToFile(const std::wstring& path) const {
    std::ofstream f(rulesPath, std::ios::out | std::ios::trunc);
    if (!f) {
        OutputDebugStringA("Не удалось создать rules.json!\n");
        return false;
    }
    OutputDebugStringA("rules.json успешно открыт для записи.\n");
    json arr = json::array();
    for (const auto& r : rules) {
        arr.push_back({
            {"id", r.id},
            {"name", r.name},
            {"description", r.description},
            {"protocol", ProtocolToString(r.protocol)},
            {"sourceIp", r.sourceIp},
            {"destIp", r.destIp},
            {"sourcePort", r.sourcePort},
            {"destPort", r.destPort},
            {"sourcePortStr", r.sourcePortStr},
            {"destPortStr", r.destPortStr},
            {"appPath", r.appPath},
            {"action", ActionToString(r.action)},
            {"enabled", r.enabled},
            {"direction", DirectionToString(r.direction)}
            });
    }
    f << arr.dump(2);
    return true;
}

bool RuleManager::LoadRulesFromFile(const std::wstring& path) {
    std::lock_guard<std::mutex> lock(ruleMutex);
    std::ifstream f(path);
    if (!f) return false;
    json arr;
    f >> arr;
    rules.clear();
    nextRuleId = 1;
    for (const auto& j : arr) {
        Rule r;
        r.id = j.value("id", 0);
        r.name = j.value("name", "");
        r.description = j.value("description", "");
        r.protocol = ProtocolFromString(j.value("protocol", "ANY"));
        r.sourceIp = j.value("sourceIp", "");
        r.destIp = j.value("destIp", "");
        r.sourcePort = j.value("sourcePort", 0);
        r.destPort = j.value("destPort", 0);
        r.sourcePortStr = j.value("sourcePortStr", "");
        r.destPortStr = j.value("destPortStr", "");
        r.appPath = j.value("appPath", "");
        r.action = ActionFromString(j.value("action", "ALLOW"));
        r.enabled = j.value("enabled", true);
        r.direction = DirectionFromString(j.value("direction", "Inbound"));
        rules.push_back(r);
        if (r.id >= nextRuleId) nextRuleId = r.id + 1;
    }
    return true;
}

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
    SaveRulesToFile();
    return true;
}
bool RuleManager::RemoveRule(int ruleId) {
    std::lock_guard<std::mutex> lock(ruleMutex);
    auto it = std::find_if(rules.begin(), rules.end(), [ruleId](const Rule& r) { return r.id == ruleId; });
    if (it != rules.end()) {
        rules.erase(it);
        SaveRulesToFile();
        return true;
    }
    return false;
}
bool RuleManager::UpdateRule(const Rule& rule) {
    std::lock_guard<std::mutex> lock(ruleMutex);
    auto it = std::find_if(rules.begin(), rules.end(), [&rule](const Rule& r) { return r.id == rule.id; });
    if (it != rules.end()) {
        *it = rule;
        SaveRulesToFile();
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

    auto rules = RuleManager::Instance().GetRules();
    auto currentDirection = RuleManager::Instance().GetCurrentDirection();

    // Фильтрация
    std::vector<Rule> filteredRules;
    for (const auto& rule : rules) {
        if (rule.direction == currentDirection)
            filteredRules.push_back(rule);
    }

    // Сортировка!
    std::sort(filteredRules.begin(), filteredRules.end(), [](const Rule& a, const Rule& b) {
        return a.id < b.id; // по возрастанию id
        });

    int itemIndex = 0;
    for (const auto& rule : filteredRules) {
        std::wstring values[9];
        values[0] = Utf8ToWide(rule.name);
        values[1] = rule.enabled ? L"Вкл" : L"Выкл";
        values[2] = rule.action == RuleAction::ALLOW ? L"Разрешить" : L"Блокировать";
        values[3] = Utf8ToWide(rule.appPath);
        values[4] = Utf8ToWide(rule.sourceIp);
        values[5] = Utf8ToWide(rule.destIp);
        values[6] = Utf8ToWide(ProtocolToString(rule.protocol));

        // Для исходного порта
        if (!rule.sourcePortStr.empty()) {
            values[7] = Utf8ToWide(rule.sourcePortStr);
        }
        else {
            values[7] = rule.sourcePort == 0 ? L"Любой" : std::to_wstring(rule.sourcePort);
        }

        // Для порта назначения
        if (!rule.destPortStr.empty()) {
            values[8] = Utf8ToWide(rule.destPortStr);
        }
        else {
            values[8] = rule.destPort == 0 ? L"Любой" : std::to_wstring(rule.destPort);
        }

        LVITEM lvi = { 0 };
        lvi.mask = LVIF_TEXT | LVIF_PARAM;
        lvi.iItem = itemIndex;
        lvi.iSubItem = 0;
        lvi.pszText = (LPWSTR)values[0].c_str();
        lvi.lParam = rule.id;
        ListView_InsertItem(hList, &lvi);

        for (int i = 1; i < 9; ++i) {
            LVITEM subLvi = { 0 };
            subLvi.mask = LVIF_TEXT;
            subLvi.iItem = itemIndex;
            subLvi.iSubItem = i;
            subLvi.pszText = (LPWSTR)values[i].c_str();
            ListView_SetItem(hList, &subLvi);
        }
        itemIndex++;
    }
}

// Удаление выбранных правил по lParam (id)
static void DeleteSelectedRule(HWND hList) {
    std::vector<int> ruleIdsToDelete;
    int sel = -1;
    while ((sel = ListView_GetNextItem(hList, sel, LVNI_SELECTED)) != -1) {
        LVITEM lvi = { 0 };
        lvi.iItem = sel;
        lvi.mask = LVIF_PARAM;
        if (ListView_GetItem(hList, &lvi)) {
            ruleIdsToDelete.push_back((int)lvi.lParam);
        }
    }
    for (int ruleId : ruleIdsToDelete) {
        RuleManager::Instance().RemoveRule(ruleId);
    }
}

bool RuleManager::ShowAddRuleWizard(HWND hParent) {
    Rule rule;
    rule.direction = GetCurrentDirection();
    RuleWizard wizard(hParent, rule);
    if (wizard.Show()) {
        OutputDebugStringA(("Added rule: name=" + rule.name + " srcIP=" + rule.sourceIp + " appPath=" + rule.appPath + "\n").c_str());
        return AddRule(rule);
    }
    return false;
}

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


        // Устанавливаем стиль выделения всей строки и разрешаем множественный выбор
        LONG_PTR style = GetWindowLongPtr(hList, GWL_STYLE);
        style |= LVS_FULLROWSELECT;
        style &= ~LVS_SINGLESEL; // разрешить множественный выбор
        style |= LVS_REPORT | LVS_SHOWSELALWAYS;
        style &= ~(LVS_SORTASCENDING | LVS_SORTDESCENDING);
        SetWindowLongPtr(hList, GWL_STYLE, style);

        ListView_SetExtendedListViewStyle(hList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

        // Включаем расширенный стиль выделения всей строки
        SendMessage(hList, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);
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
    case WM_CONTEXTMENU: {
        HWND hwndFrom = (HWND)wParam;
        if (hwndFrom == hList) {
            POINT pt;
            pt.x = LOWORD(lParam);
            pt.y = HIWORD(lParam);

            if (pt.x == -1 && pt.y == -1) {
                int sel = ListView_GetNextItem(hList, -1, LVNI_SELECTED);
                if (sel != -1) {
                    RECT rc;
                    ListView_GetItemRect(hList, sel, &rc, LVIR_BOUNDS);
                    pt.x = rc.left;
                    pt.y = rc.bottom;
                    ClientToScreen(hList, &pt);
                }
            }

            HMENU hMenu = LoadMenu(GetModuleHandle(NULL), MAKEINTRESOURCE(IDR_RULE_CONTEXT_MENU));
            HMENU hSubMenu = GetSubMenu(hMenu, 0);

            int cmd = TrackPopupMenu(hSubMenu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwndDlg, NULL);

            DestroyMenu(hMenu);

            switch (cmd) {
            case ID_CONTEXT_EDIT:
                PostMessage(hwndDlg, WM_COMMAND, ID_EDIT_RULE, 0);
                break;
            case ID_CONTEXT_TOGGLE:
                PostMessage(hwndDlg, WM_COMMAND, ID_TOGGLE_RULE, 0);
                break;
            case ID_CONTEXT_DELETE:
                PostMessage(hwndDlg, WM_COMMAND, ID_DELETE_RULE, 0);
                break;
            }
        }
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
        case ID_DELETE_RULE: {
            if (MessageBox(hwndDlg, L"Удалить выбранные правила?", L"Подтверждение", MB_YESNO | MB_ICONQUESTION) == IDYES) {
                DeleteSelectedRule(hList);
                FillRulesList(hList);
            }
            break;
        }
        case ID_EDIT_RULE: {
            int sel = ListView_GetNextItem(hList, -1, LVNI_SELECTED);
            if (sel == -1) break;

            LVITEM lvi = { 0 };
            lvi.iItem = sel;
            lvi.mask = LVIF_PARAM;
            if (!ListView_GetItem(hList, &lvi))
                break;
            int ruleId = (int)lvi.lParam;

            auto ruleOpt = RuleManager::Instance().GetRuleById(ruleId);
            if (ruleOpt) {
                Rule rule = *ruleOpt;
                RuleWizard wizard(hwndDlg, rule);
                if (wizard.Show()) {
                    RuleManager::Instance().UpdateRule(rule);
                    FillRulesList(hList);
                }
            }
            break;
        }
        case ID_TOGGLE_RULE: {
            int sel = ListView_GetNextItem(hList, -1, LVNI_SELECTED);
            if (sel == -1) break;
            LVITEM lvi = { 0 };
            lvi.iItem = sel;
            lvi.mask = LVIF_PARAM;
            if (!ListView_GetItem(hList, &lvi))
                break;
            int ruleId = (int)lvi.lParam;

            auto ruleOpt = RuleManager::Instance().GetRuleById(ruleId);
            if (ruleOpt) {
                Rule rule = *ruleOpt;
                rule.enabled = !rule.enabled;
                RuleManager::Instance().UpdateRule(rule);
                FillRulesList(hList);
            }
            break;
        }
        case IDOK:
        case IDCANCEL:
            EndDialog(hwndDlg, LOWORD(wParam));
            return TRUE;
        }
        break;
    }
    return FALSE;
}