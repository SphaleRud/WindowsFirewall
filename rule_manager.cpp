#include "rule_manager.h"
#include "Resource.h"
#include <commctrl.h>
#include <algorithm>
#include <shobjidl.h>
#include <string>
#include <codecvt>
#include <locale>
#include "rule.h"
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

// --- Вспомогательные функции для строк ---
inline std::wstring s2ws(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), nullptr, 0);
    std::wstring result(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), &result[0], size_needed);
    return result;
}

inline std::string ws2s(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), nullptr, 0, nullptr, nullptr);
    std::string result(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), &result[0], size_needed, nullptr, nullptr);
    return result;
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

static void DeleteSelectedRule(HWND hList) {
    int sel = ListView_GetNextItem(hList, -1, LVNI_SELECTED);
    if (sel == -1) return;
    auto rules = RuleManager::Instance().GetRules();
    if (sel >= 0 && sel < (int)rules.size()) {
        int ruleId = rules[sel].id;
        RuleManager::Instance().RemoveRule(ruleId);
    }
}

// ---- Мастер добавления правила ----
// Функция для переключения видимости групп параметров
static void ShowParamGroups(HWND hwndDlg, int sel) {
    // Сначала скрываем ВСЕ группы параметров
    HWND hParamsGroup = GetDlgItem(hwndDlg, IDC_WIZARD_STEP_PARAMS);
    if (hParamsGroup) {
        ShowWindow(hParamsGroup, SW_SHOW);  // Показываем контейнер

        // Скрываем все группы параметров
        ShowWindow(GetDlgItem(hwndDlg, IDC_RULE_PARAM_APP), SW_HIDE);
        ShowWindow(GetDlgItem(hwndDlg, IDC_RULE_PARAM_PORT), SW_HIDE);
        ShowWindow(GetDlgItem(hwndDlg, IDC_RULE_PARAM_PROTO), SW_HIDE);
        ShowWindow(GetDlgItem(hwndDlg, IDC_RULE_PARAM_ADVANCED), SW_HIDE);

        // Показываем только нужную группу
        switch (sel) {
        case 0: // По приложению
            ShowWindow(GetDlgItem(hwndDlg, IDC_RULE_PARAM_APP), SW_SHOW);
            break;
        case 1: // По порту
            ShowWindow(GetDlgItem(hwndDlg, IDC_RULE_PARAM_PORT), SW_SHOW);
            break;
        case 2: // По протоколу
            ShowWindow(GetDlgItem(hwndDlg, IDC_RULE_PARAM_PROTO), SW_SHOW);
            break;
        case 3: // Пользовательское
            ShowWindow(GetDlgItem(hwndDlg, IDC_RULE_PARAM_ADVANCED), SW_SHOW);
            break;
        }
    }
}

bool RuleManager::ShowAddRuleWizard(HWND hParent) {
    Rule newRule; // Создаем новое правило
    if (RuleWizard::ShowWizard(hParent, newRule)) {
        // Если пользователь нажал "Готово", добавляем правило
        AddRule(newRule);
        return true;
    }
    return false;
}

static void ShowWizardStep(HWND hwndDlg, int step) {
    // Сначала скрываем все шаги
    ShowWindow(GetDlgItem(hwndDlg, IDC_WIZARD_STEP_TYPE), SW_HIDE);
    ShowWindow(GetDlgItem(hwndDlg, IDC_WIZARD_STEP_PARAMS), SW_HIDE);
    ShowWindow(GetDlgItem(hwndDlg, IDC_WIZARD_STEP_ACTION), SW_HIDE);
    ShowWindow(GetDlgItem(hwndDlg, IDC_WIZARD_STEP_NAME), SW_HIDE);

    // Показываем нужный шаг
    switch (step) {
    case 0: // Тип
        ShowWindow(GetDlgItem(hwndDlg, IDC_WIZARD_STEP_TYPE), SW_SHOW);
        break;
    case 1: // Параметры
        ShowWindow(GetDlgItem(hwndDlg, IDC_WIZARD_STEP_PARAMS), SW_SHOW);
        break;
    case 2: // Действие
        ShowWindow(GetDlgItem(hwndDlg, IDC_WIZARD_STEP_ACTION), SW_SHOW);
        break;
    case 3: // Имя/описание
        ShowWindow(GetDlgItem(hwndDlg, IDC_WIZARD_STEP_NAME), SW_SHOW);
        break;
    }
}

// Мастер добавления правила
// Процедура диалога мастера создания правила
INT_PTR CALLBACK RuleManager::FirewallRuleWizardProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    static Rule* rule = nullptr;
    static int wizardStep = 0;

    switch (uMsg) {
    case WM_INITDIALOG: {
        rule = reinterpret_cast<Rule*>(lParam);
        wizardStep = 0;

        // Заполняем комбобоксы
        HWND typeCombo = GetDlgItem(hwndDlg, IDC_RULE_TYPE_COMBO);
        SendMessage(typeCombo, CB_ADDSTRING, 0, (LPARAM)L"По приложению");
        SendMessage(typeCombo, CB_ADDSTRING, 0, (LPARAM)L"По порту");
        SendMessage(typeCombo, CB_ADDSTRING, 0, (LPARAM)L"По протоколу");
        SendMessage(typeCombo, CB_ADDSTRING, 0, (LPARAM)L"Пользовательское");
        SendMessage(typeCombo, CB_SETCURSEL, 0, 0);

        auto fillProtoCombo = [](HWND combo) {
            SendMessage(combo, CB_ADDSTRING, 0, (LPARAM)L"ANY");
            SendMessage(combo, CB_ADDSTRING, 0, (LPARAM)L"TCP");
            SendMessage(combo, CB_ADDSTRING, 0, (LPARAM)L"UDP");
            SendMessage(combo, CB_ADDSTRING, 0, (LPARAM)L"ICMP");
            SendMessage(combo, CB_SETCURSEL, 0, 0);
            };

        fillProtoCombo(GetDlgItem(hwndDlg, IDC_PROTOCOL_COMBO));
        fillProtoCombo(GetDlgItem(hwndDlg, IDC_ADV_PROTO_COMBO));

        // По умолчанию "Разрешить"
        CheckRadioButton(hwndDlg, IDC_RULE_ALLOW_RADIO, IDC_RULE_BLOCK_RADIO, IDC_RULE_ALLOW_RADIO);

        // Показываем первый шаг
        ShowWizardStep(hwndDlg, wizardStep);
        ShowParamGroups(hwndDlg, 0);

        return TRUE;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_RULE_TYPE_COMBO:
            if (HIWORD(wParam) == CBN_SELCHANGE) {
                // При изменении типа правила
                int sel = (int)SendMessage(GetDlgItem(hwndDlg, IDC_RULE_TYPE_COMBO),
                    CB_GETCURSEL, 0, 0);
                ShowParamGroups(hwndDlg, sel); // Обновляем видимость групп
            }
            break;

        case IDC_WIZARD_NEXT: {
            if (wizardStep < 3) {
                wizardStep++;
                ShowWizardStep(hwndDlg, wizardStep);

                // Если перешли на шаг параметров, показываем нужную группу
                if (wizardStep == 1) {
                    int sel = (int)SendMessage(GetDlgItem(hwndDlg, IDC_RULE_TYPE_COMBO), CB_GETCURSEL, 0, 0);
                    ShowParamGroups(hwndDlg, sel);
                }
            }
            else {
                // Завершение мастера - сбор данных
                int ruleType = (int)SendMessage(GetDlgItem(hwndDlg, IDC_RULE_TYPE_COMBO), CB_GETCURSEL, 0, 0);
                wchar_t buf[256];
                int port = 0;
                int protoSel = 0;

                // Заполняем правило в зависимости от типа
                switch (ruleType) {
                case 0: // По приложению
                    GetDlgItemText(hwndDlg, IDC_APP_PATH_EDIT, buf, 255);
                    rule->appPath = ws2s(buf);
                    rule->protocol = Protocol::ANY;
                    rule->sourcePort = rule->destPort = 0;
                    rule->sourceIp = "";
                    rule->destIp = "";
                    break;

                case 1: // По порту
                    GetDlgItemText(hwndDlg, IDC_PORT_EDIT, buf, 255);
                    port = _wtoi(buf);
                    rule->sourcePort = rule->destPort = port;
                    rule->appPath = "";
                    rule->protocol = Protocol::ANY;
                    rule->sourceIp = "";
                    rule->destIp = "";
                    break;

                case 2: // По протоколу
                    protoSel = (int)SendMessage(GetDlgItem(hwndDlg, IDC_PROTOCOL_COMBO), CB_GETCURSEL, 0, 0);
                    rule->protocol = (protoSel == 1) ? Protocol::TCP :
                        (protoSel == 2) ? Protocol::UDP :
                        (protoSel == 3) ? Protocol::ICMP : Protocol::ANY;
                    rule->sourcePort = rule->destPort = 0;
                    rule->appPath = "";
                    rule->sourceIp = "";
                    rule->destIp = "";
                    break;

                case 3: // Пользовательское
                    // Протокол
                    protoSel = (int)SendMessage(GetDlgItem(hwndDlg, IDC_ADV_PROTO_COMBO), CB_GETCURSEL, 0, 0);
                    rule->protocol = (protoSel == 1) ? Protocol::TCP :
                        (protoSel == 2) ? Protocol::UDP :
                        (protoSel == 3) ? Protocol::ICMP : Protocol::ANY;

                    // Порты
                    GetDlgItemText(hwndDlg, IDC_ADV_SRC_PORT_EDIT, buf, 255);
                    rule->sourcePort = _wtoi(buf);
                    GetDlgItemText(hwndDlg, IDC_ADV_DST_PORT_EDIT, buf, 255);
                    rule->destPort = _wtoi(buf);

                    // IP-адреса
                    GetDlgItemText(hwndDlg, IDC_ADV_SRC_IP_EDIT, buf, 255);
                    rule->sourceIp = ws2s(buf);
                    GetDlgItemText(hwndDlg, IDC_ADV_DST_IP_EDIT, buf, 255);
                    rule->destIp = ws2s(buf);

                    // Приложение
                    GetDlgItemText(hwndDlg, IDC_ADV_APP_PATH_EDIT, buf, 255);
                    rule->appPath = ws2s(buf);
                    break;
                }

                // Общие параметры для всех типов
                rule->action = IsDlgButtonChecked(hwndDlg, IDC_RULE_ALLOW_RADIO) == BST_CHECKED
                    ? RuleAction::ALLOW : RuleAction::BLOCK;
                rule->enabled = true;

                GetDlgItemText(hwndDlg, IDC_RULE_NAME_EDIT, buf, 255);
                rule->name = ws2s(buf);
                GetDlgItemText(hwndDlg, IDC_RULE_DESC_EDIT, buf, 255);
                rule->description = ws2s(buf);

                EndDialog(hwndDlg, IDOK);
            }
            return TRUE;
        }

        case IDC_WIZARD_BACK: {
            if (wizardStep > 0) {
                wizardStep--;
                ShowWizardStep(hwndDlg, wizardStep);

                // Если вернулись на шаг параметров, показываем нужную группу
                if (wizardStep == 1) {
                    int sel = (int)SendMessage(GetDlgItem(hwndDlg, IDC_RULE_TYPE_COMBO), CB_GETCURSEL, 0, 0);
                    ShowParamGroups(hwndDlg, sel);
                }
            }
            return TRUE;
        }

        case IDC_BROWSE_APP:
        case IDC_ADV_BROWSE_APP: {
            int editId = (LOWORD(wParam) == IDC_BROWSE_APP) ?
                IDC_APP_PATH_EDIT : IDC_ADV_APP_PATH_EDIT;

            IFileOpenDialog* pFileOpen = nullptr;
            HRESULT hr = CoCreateInstance(CLSID_FileOpenDialog, NULL, CLSCTX_ALL,
                IID_IFileOpenDialog, (void**)&pFileOpen);
            if (SUCCEEDED(hr)) {
                hr = pFileOpen->Show(hwndDlg);
                if (SUCCEEDED(hr)) {
                    IShellItem* pItem;
                    hr = pFileOpen->GetResult(&pItem);
                    if (SUCCEEDED(hr)) {
                        PWSTR pszFilePath = nullptr;
                        pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath);
                        if (pszFilePath) {
                            SetDlgItemText(hwndDlg, editId, pszFilePath);
                            CoTaskMemFree(pszFilePath);
                        }
                        pItem->Release();
                    }
                }
                pFileOpen->Release();
            }
            return TRUE;
        }

        case IDCANCEL:
            EndDialog(hwndDlg, IDCANCEL);
            return TRUE;
        }
        break;
    }
    return FALSE;
}

// Остальные методы класса RuleManager (AddRule, RemoveRule и т.д.) остаются без изменений

// --- Диалог списка правил ---
INT_PTR CALLBACK RuleManager::RulesDialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    static HWND hList = nullptr;
    switch (uMsg) {
    case WM_INITDIALOG: {
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