#include "rule_wizard.h"
#include "resource.h"
#include <shobjidl.h>
#include <CommCtrl.h>
#include "string_utils.h" 
#include <vector>
#include "validator.h"
#include <windowsx.h>
#include <shlwapi.h>


RuleWizard::RuleWizard(HWND hParent, Rule& rule)
    : m_hwndParent(hParent)
    , m_hwndMain(NULL)
    , m_hwndCurrent(NULL)
    , m_currentPage(PAGE_TYPE)
    , m_ruleDraft(rule)
    , m_selectedType(0)
{
    if (!rule.appPath.empty() && rule.sourcePort == 0 && rule.destPort == 0 && rule.protocol == Protocol::ANY
        && rule.sourceIp.empty() && rule.destIp.empty()) {
        m_selectedType = 0; // По приложению
    }
    else if (rule.appPath.empty() && rule.protocol == Protocol::ANY
        && (rule.sourcePort != 0 || rule.destPort != 0)
        && rule.sourceIp.empty() && rule.destIp.empty()) {
        m_selectedType = 1; // По порту
    }
    else if (rule.appPath.empty() && rule.sourcePort == 0 && rule.destPort == 0
        && rule.protocol != Protocol::ANY
        && rule.sourceIp.empty() && rule.destIp.empty()) {
        m_selectedType = 2; // По протоколу
    }
    else {
        m_selectedType = 3; // Пользовательские
    }
}

RuleWizard::~RuleWizard() {}

bool RuleWizard::Show() {
    // Запускаем диалог мастера
    INT_PTR res = DialogBoxParam(
        GetModuleHandle(NULL),
        MAKEINTRESOURCE(IDD_RULE_WIZARD),
        m_hwndParent,
        DialogProc,
        reinterpret_cast<LPARAM>(this)
    );
    if (res == IDOK) {
        // Копируем данные из черновика в исходную Rule
        //m_ruleDraft = m_ruleDraft;
        return true;
    }
    return false;
}

/*
bool RuleWizard::SaveRule(HWND hwnd) {
    if (!hwnd) return false;

    wchar_t buffer[MAX_PATH];

    // Название
    GetDlgItemText(hwnd, IDC_RULE_NAME_EDIT, buffer, MAX_PATH);
    m_ruleDraft.name = WideToUtf8(buffer);

    // Состояние (enabled) — если есть чекбокс, иначе по умолчанию true
    // currentRule->enabled = (IsDlgButtonChecked(hwnd, IDC_RULE_ENABLED_CHECK) == BST_CHECKED);
    m_ruleDraft.enabled = true;

    // Действие
    m_ruleDraft.action = IsDlgButtonChecked(hwnd, IDC_RULE_ALLOW_RADIO) == BST_CHECKED
        ? RuleAction::ALLOW : RuleAction::BLOCK;

    // Программа
    GetDlgItemText(hwnd, IDC_APP_PATH_EDIT, buffer, MAX_PATH);
    m_ruleDraft.appPath = WideToUtf8(buffer);

    // Локальный адрес
    if (IsDlgButtonChecked(hwnd, IDC_CHECK_ANY_LOCAL_IP) == BST_CHECKED) {
        m_ruleDraft.sourceIp = "0.0.0.0";
    }
    else {
        GetDlgItemText(hwnd, IDC_EDIT_LOCAL_IP, buffer, MAX_PATH);
        m_ruleDraft.sourceIp = WideToUtf8(buffer);
    }

    // Адрес назначения
    if (IsDlgButtonChecked(hwnd, IDC_CHECK_ANY_REMOTE_IP) == BST_CHECKED) {
        m_ruleDraft.destIp = "0.0.0.0";
    }
    else {
        GetDlgItemText(hwnd, IDC_EDIT_REMOTE_IP, buffer, MAX_PATH);
        m_ruleDraft.destIp = WideToUtf8(buffer);
    }

    // Протокол (ищем текущий протокол в любом из возможных комбобоксов)
    int protoIdx = CB_ERR;
    HWND protoCombo = GetDlgItem(hwnd, IDC_PROTOCOL_COMBO);
    if (protoCombo)
        protoIdx = ComboBox_GetCurSel(protoCombo);
    else {
        protoCombo = GetDlgItem(hwnd, IDC_COMBO_PROTOCOL);
        if (protoCombo)
            protoIdx = ComboBox_GetCurSel(protoCombo);
        else {
            protoCombo = GetDlgItem(hwnd, IDC_ADV_PROTO_COMBO);
            if (protoCombo)
                protoIdx = ComboBox_GetCurSel(protoCombo);
        }
    }
    if (protoIdx == CB_ERR)
        m_ruleDraft.protocol = Protocol::ANY;
    else
        m_ruleDraft.protocol = static_cast<Protocol>(protoIdx);

    // Локальный порт
    if (IsDlgButtonChecked(hwnd, IDC_CHECK_ANY_LOCAL_PORT) == BST_CHECKED) {
        m_ruleDraft.sourcePort = 0;
    }
    else {
        GetDlgItemText(hwnd, IDC_EDIT_LOCAL_PORT, buffer, MAX_PATH);
        if (wcslen(buffer) == 0)
            m_ruleDraft.sourcePort = 0;
        else
            m_ruleDraft.sourcePort = _wtoi(buffer);
    }

    // Порт назначения
    if (IsDlgButtonChecked(hwnd, IDC_CHECK_ANY_REMOTE_PORT) == BST_CHECKED) {
        m_ruleDraft.destPort = 0;
    }
    else {
        GetDlgItemText(hwnd, IDC_EDIT_REMOTE_PORT, buffer, MAX_PATH);
        if (wcslen(buffer) == 0)
            m_ruleDraft.destPort = 0;
        else
            m_ruleDraft.destPort = _wtoi(buffer);
    }

    // Если есть описание, сохраняем
    GetDlgItemText(hwnd, IDC_RULE_DESC_EDIT, buffer, MAX_PATH);
    m_ruleDraft.description = WideToUtf8(buffer);

    // creator, creationTime — можно заполнить как раньше

    return true;
}
*/

void RuleWizard::BrowseForProgram(HWND hwnd, int editId) {
    wchar_t oldDir[MAX_PATH];
    GetCurrentDirectoryW(MAX_PATH, oldDir);
    wchar_t filePath[MAX_PATH] = { 0 };
    OPENFILENAME ofn = { 0 };
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = L"Executable Files (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = filePath;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
    ofn.lpstrDefExt = L"exe";
    if (GetOpenFileName(&ofn)) {
        SetDlgItemText(hwnd, editId, filePath);
    }
    SetCurrentDirectoryW(oldDir);
}


INT_PTR CALLBACK RuleWizard::DialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    RuleWizard* self = nullptr;
    if (msg == WM_INITDIALOG) {
        self = reinterpret_cast<RuleWizard*>(lParam);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        self->m_hwndMain = hwnd;
        self->ShowPage(PAGE_TYPE);
        return TRUE;
    }
    else {
        self = reinterpret_cast<RuleWizard*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    }
    if (!self) return FALSE;

    switch (msg) {
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_WIZARD_NEXT:
            if (!self->ValidateCurrentPage())
                return TRUE;
            if (!self->ApplyPageData())
                return TRUE;
            if (self->m_currentPage == PAGE_NAME) {
                // На последней странице данные уже сохранены через ApplyPageData
                EndDialog(hwnd, IDOK);
            }
            else {
                self->GoToNextPage();
            }
            return TRUE;
        case IDC_WIZARD_BACK:
            self->GoToPrevPage();
            return TRUE;
        case IDCANCEL:
            EndDialog(hwnd, IDCANCEL);
            return TRUE;
        }
        break;
    }
    return FALSE;
}

bool RuleWizard::ValidateCurrentPage() {
    wchar_t buffer[MAX_PATH];
    switch (m_currentPage) {
    case PAGE_TYPE:
        m_selectedType = static_cast<int>(SendDlgItemMessage(m_hwndCurrent, IDC_RULE_TYPE_COMBO, CB_GETCURSEL, 0, 0));
        if (m_selectedType == CB_ERR) {
            MessageBox(m_hwndCurrent, L"Выберите тип правила", L"Ошибка", MB_OK | MB_ICONWARNING);
            return false;
        }
        return true;
    case PAGE_PARAMS_APP:
        GetDlgItemText(m_hwndCurrent, IDC_APP_PATH_EDIT, buffer, MAX_PATH);
        if (buffer[0] == L'\0') {
            MessageBox(m_hwndCurrent, L"Укажите путь к приложению", L"Ошибка", MB_OK | MB_ICONWARNING);
            return false;
        }
        if (GetFileAttributes(buffer) == INVALID_FILE_ATTRIBUTES) {
            MessageBox(m_hwndCurrent, L"Указан некорректный путь к файлу", L"Ошибка", MB_OK | MB_ICONWARNING);
            return false;
        }
        return true;
    case PAGE_PARAMS_PORT:
        GetDlgItemText(m_hwndCurrent, IDC_PORT_EDIT, buffer, MAX_PATH);
        if (buffer[0] == L'\0' || _wtoi(buffer) <= 0 || _wtoi(buffer) > 65535) {
            MessageBox(m_hwndCurrent, L"Введите корректный номер порта (1-65535)", L"Ошибка", MB_OK | MB_ICONWARNING);
            return false;
        }
        return true;
    case PAGE_NAME:
        GetDlgItemText(m_hwndCurrent, IDC_RULE_NAME_EDIT, buffer, MAX_PATH);
        if (buffer[0] == L'\0') {
            MessageBox(m_hwndCurrent, L"Введите имя правила", L"Ошибка", MB_OK | MB_ICONWARNING);
            return false;
        }
        return true;
    default:
        return true;
    }
}



void RuleWizard::ShowPage(WizardPage page) {
    if (m_hwndCurrent) {
        DestroyWindow(m_hwndCurrent);
        m_hwndCurrent = NULL;
    }
    m_currentPage = page;
    m_hwndCurrent = CreateDialogParam(
        GetModuleHandle(NULL),
        MAKEINTRESOURCE(GetPageDialogId(page)),
        m_hwndMain,
        PageDlgProc,
        reinterpret_cast<LPARAM>(this)
    );
    if (!m_hwndCurrent) {
        MessageBox(m_hwndMain, L"Не удалось создать страницу мастера.", L"Ошибка", MB_OK | MB_ICONERROR);
        return;
    }
    HWND container = GetDlgItem(m_hwndMain, IDC_PAGE_CONTAINER);
    RECT rc;
    GetClientRect(container, &rc);
    SetWindowPos(m_hwndCurrent, NULL, rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, SWP_NOZORDER);
    ShowWindow(m_hwndCurrent, SW_SHOW);
    UpdateButtons();
}

void RuleWizard::GoToNextPage() {
    WizardPage next = m_currentPage;
    switch (m_currentPage) {
    case PAGE_TYPE:
        next = static_cast<WizardPage>(m_selectedType + 1); // PAGE_PARAMS_APP и т.д.
        break;
    case PAGE_PARAMS_APP:
    case PAGE_PARAMS_PORT:
    case PAGE_PARAMS_PROTO:
    case PAGE_PARAMS_ADVANCED:
        next = PAGE_ACTION;
        break;
    case PAGE_ACTION:
        next = PAGE_NAME;
        break;
    default:
        break;
    }
    ShowPage(next);
}

void RuleWizard::GoToPrevPage() {
    WizardPage prev = m_currentPage;
    switch (m_currentPage) {
    case PAGE_NAME:
        prev = PAGE_ACTION;
        break;
    case PAGE_ACTION:
        prev = static_cast<WizardPage>(m_selectedType + 1);
        break;
    case PAGE_PARAMS_APP:
    case PAGE_PARAMS_PORT:
    case PAGE_PARAMS_PROTO:
    case PAGE_PARAMS_ADVANCED:
        prev = PAGE_TYPE;
        break;
    default:
        break;
    }
    ShowPage(prev);
}

bool RuleWizard::ApplyPageData() {
    wchar_t buffer[MAX_PATH];
    switch (m_currentPage) {
    case PAGE_TYPE:
        m_selectedType = static_cast<int>(SendDlgItemMessage(m_hwndCurrent, IDC_RULE_TYPE_COMBO, CB_GETCURSEL, 0, 0));
        break;
    case PAGE_PARAMS_APP:
        GetDlgItemText(m_hwndCurrent, IDC_APP_PATH_EDIT, buffer, MAX_PATH);
        m_ruleDraft.appPath = WideToUtf8(buffer);
        break;
    case PAGE_PARAMS_PORT:
        GetDlgItemText(m_hwndCurrent, IDC_PORT_EDIT, buffer, MAX_PATH);
        m_ruleDraft.sourcePort = _wtoi(buffer);
        break;
    case PAGE_PARAMS_PROTO: {
        // Протокол
        int protoIdx = ComboBox_GetCurSel(GetDlgItem(m_hwndCurrent, IDC_PROTOCOL_COMBO));
        m_ruleDraft.protocol = protoIdx == CB_ERR ? Protocol::ANY : static_cast<Protocol>(protoIdx);

        // Локальный порт
        if (IsDlgButtonChecked(m_hwndCurrent, IDC_CHECK_ANY_LOCAL_PORT) == BST_CHECKED) {
            m_ruleDraft.sourcePort = 0;
        }
        else {
            GetDlgItemText(m_hwndCurrent, IDC_EDIT_LOCAL_PORT, buffer, MAX_PATH);
            m_ruleDraft.sourcePort = wcslen(buffer) ? _wtoi(buffer) : 0;
        }

        // Порт назначения
        if (IsDlgButtonChecked(m_hwndCurrent, IDC_CHECK_ANY_REMOTE_PORT) == BST_CHECKED) {
            m_ruleDraft.destPort = 0;
        }
        else {
            GetDlgItemText(m_hwndCurrent, IDC_EDIT_REMOTE_PORT, buffer, MAX_PATH);
            m_ruleDraft.destPort = wcslen(buffer) ? _wtoi(buffer) : 0;
        }

        // Локальный IP
        if (IsDlgButtonChecked(m_hwndCurrent, IDC_CHECK_ANY_LOCAL_IP) == BST_CHECKED) {
            m_ruleDraft.sourceIp = "Любые";
        }
        else {
            GetDlgItemText(m_hwndCurrent, IDC_EDIT_LOCAL_IP, buffer, MAX_PATH);
            m_ruleDraft.sourceIp = WideToUtf8(buffer);
        }

        // IP назначения
        if (IsDlgButtonChecked(m_hwndCurrent, IDC_CHECK_ANY_REMOTE_IP) == BST_CHECKED) {
            m_ruleDraft.destIp = "Любые";
        }
        else {
            GetDlgItemText(m_hwndCurrent, IDC_EDIT_REMOTE_IP, buffer, MAX_PATH);
            m_ruleDraft.destIp = WideToUtf8(buffer);
        }
        break;
    }
    case PAGE_PARAMS_ADVANCED: {
        // Аналогично PAGE_PARAMS_PROTO, только используйте свои контролы, например, IDC_ADV_PROTO_COMBO, IDC_ADV_SRC_PORT_EDIT и т.д.
        int protoIdx = ComboBox_GetCurSel(GetDlgItem(m_hwndCurrent, IDC_ADV_PROTO_COMBO));
        m_ruleDraft.protocol = protoIdx == CB_ERR ? Protocol::ANY : static_cast<Protocol>(protoIdx);

        if (IsDlgButtonChecked(m_hwndCurrent, IDC_CHECK_ANY_LOCAL_PORT) == BST_CHECKED) {
            m_ruleDraft.sourcePort = 0;
        }
        else {
            GetDlgItemText(m_hwndCurrent, IDC_ADV_SRC_PORT_EDIT, buffer, MAX_PATH);
            m_ruleDraft.sourcePort = wcslen(buffer) ? _wtoi(buffer) : 0;
        }
        if (IsDlgButtonChecked(m_hwndCurrent, IDC_CHECK_ANY_REMOTE_PORT) == BST_CHECKED) {
            m_ruleDraft.destPort = 0;
        }
        else {
            GetDlgItemText(m_hwndCurrent, IDC_ADV_DST_PORT_EDIT, buffer, MAX_PATH);
            m_ruleDraft.destPort = wcslen(buffer) ? _wtoi(buffer) : 0;
        }
        if (IsDlgButtonChecked(m_hwndCurrent, IDC_CHECK_ANY_LOCAL_IP) == BST_CHECKED) {
            m_ruleDraft.sourceIp = "0.0.0.0";
        }
        else {
            GetDlgItemText(m_hwndCurrent, IDC_ADV_SRC_IP_EDIT, buffer, MAX_PATH);
            m_ruleDraft.sourceIp = WideToUtf8(buffer);
        }
        if (IsDlgButtonChecked(m_hwndCurrent, IDC_CHECK_ANY_REMOTE_IP) == BST_CHECKED) {
            m_ruleDraft.destIp = "0.0.0.0";
        }
        else {
            GetDlgItemText(m_hwndCurrent, IDC_ADV_DST_IP_EDIT, buffer, MAX_PATH);
            m_ruleDraft.destIp = WideToUtf8(buffer);
        }
        // Программа
        GetDlgItemText(m_hwndCurrent, IDC_ADV_APP_PATH_EDIT, buffer, MAX_PATH);
        m_ruleDraft.appPath = WideToUtf8(buffer);
        break;
    }
    case PAGE_ACTION:
        m_ruleDraft.action = IsDlgButtonChecked(m_hwndCurrent, IDC_RULE_ALLOW_RADIO) == BST_CHECKED
            ? RuleAction::ALLOW : RuleAction::BLOCK;
        break;
    case PAGE_NAME:
        GetDlgItemText(m_hwndCurrent, IDC_RULE_NAME_EDIT, buffer, MAX_PATH);
        m_ruleDraft.name = WideToUtf8(buffer);
        GetDlgItemText(m_hwndCurrent, IDC_RULE_DESC_EDIT, buffer, MAX_PATH);
        m_ruleDraft.description = WideToUtf8(buffer);
        break;
    }
    return true;
}

// Вспомогательный метод для получения ID диалога страницы
int RuleWizard::GetPageDialogId(WizardPage page) {
    switch (page) {
    case PAGE_TYPE: return IDD_RULE_PAGE_TYPE;
    case PAGE_PARAMS_APP: return IDD_RULE_PAGE_APP;
    case PAGE_PARAMS_PORT: return IDD_RULE_PAGE_PORT;
    case PAGE_PARAMS_PROTO: return IDD_RULE_PARAM_PROTO;
    case PAGE_PARAMS_ADVANCED: return IDD_RULE_PARAM_ADVANCED;
    case PAGE_ACTION: return IDD_RULE_PAGE_ACTION;
    case PAGE_NAME: return IDD_RULE_PAGE_NAME;
    default: return 0;
    }
}



void RuleWizard::UpdateButtons() {
    EnableWindow(GetDlgItem(m_hwndMain, IDC_WIZARD_BACK), m_currentPage > PAGE_TYPE);
    SetDlgItemText(m_hwndMain, IDC_WIZARD_NEXT, m_currentPage == PAGE_NAME ? L"Готово" : L"Далее >");
}

INT_PTR CALLBACK RuleWizard::PageDlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    RuleWizard* self = reinterpret_cast<RuleWizard*>(GetWindowLongPtr(GetParent(hwnd), GWLP_USERDATA));
    if (msg == WM_INITDIALOG) {
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));

        // --- Комбобокс типа правила ---
        HWND ruleTypeCombo = GetDlgItem(hwnd, IDC_RULE_TYPE_COMBO);
        if (ruleTypeCombo) {
            ComboBox_ResetContent(ruleTypeCombo);
            ComboBox_AddString(ruleTypeCombo, L"По приложению");
            ComboBox_AddString(ruleTypeCombo, L"По порту");
            ComboBox_AddString(ruleTypeCombo, L"По протоколу");
            ComboBox_AddString(ruleTypeCombo, L"Пользовательские");
            if (self) ComboBox_SetCurSel(ruleTypeCombo, self->m_selectedType);
        }

        // --- Имя и описание (PAGE_NAME) ---
        HWND nameEdit = GetDlgItem(hwnd, IDC_RULE_NAME_EDIT);
        if (nameEdit) {
            SetDlgItemText(hwnd, IDC_RULE_NAME_EDIT, Utf8ToWide(self->m_ruleDraft.name).c_str());
        }
        HWND descEdit = GetDlgItem(hwnd, IDC_RULE_DESC_EDIT);
        if (descEdit) {
            SetDlgItemText(hwnd, IDC_RULE_DESC_EDIT, Utf8ToWide(self->m_ruleDraft.description).c_str());
        }

        // --- Поля приложения (PAGE_PARAMS_APP, PAGE_PARAMS_ADVANCED) ---
        HWND appPathEdit = GetDlgItem(hwnd, IDC_APP_PATH_EDIT);
        if (appPathEdit) {
            SetDlgItemText(hwnd, IDC_APP_PATH_EDIT, Utf8ToWide(self->m_ruleDraft.appPath).c_str());
        }
        HWND advAppPathEdit = GetDlgItem(hwnd, IDC_ADV_APP_PATH_EDIT);
        if (advAppPathEdit) {
            SetDlgItemText(hwnd, IDC_ADV_APP_PATH_EDIT, Utf8ToWide(self->m_ruleDraft.appPath).c_str());
        }

        HWND portEdit = GetDlgItem(hwnd, IDC_PORT_EDIT);
        if (portEdit) {
            if (self->m_ruleDraft.sourcePort != 0)
                SetDlgItemText(hwnd, IDC_PORT_EDIT, std::to_wstring(self->m_ruleDraft.sourcePort).c_str());
            else
                SetDlgItemText(hwnd, IDC_PORT_EDIT, L"");
        }

        // --- Адреса и порты (PAGE_PARAMS_PROTO, PAGE_PARAMS_ADVANCED) ---
        HWND editLocalIp = GetDlgItem(hwnd, IDC_EDIT_LOCAL_IP);
        if (editLocalIp) {
            SetDlgItemText(hwnd, IDC_EDIT_LOCAL_IP, Utf8ToWide(self->m_ruleDraft.sourceIp).c_str());
            CheckDlgButton(hwnd, IDC_CHECK_ANY_LOCAL_IP, (self->m_ruleDraft.sourceIp.empty() || self->m_ruleDraft.sourceIp == "0.0.0.0") ? BST_CHECKED : BST_UNCHECKED);
            EnableWindow(editLocalIp, !(self->m_ruleDraft.sourceIp.empty() || self->m_ruleDraft.sourceIp == "0.0.0.0"));
        }
        HWND editRemoteIp = GetDlgItem(hwnd, IDC_EDIT_REMOTE_IP);
        if (editRemoteIp) {
            SetDlgItemText(hwnd, IDC_EDIT_REMOTE_IP, Utf8ToWide(self->m_ruleDraft.destIp).c_str());
            CheckDlgButton(hwnd, IDC_CHECK_ANY_REMOTE_IP, (self->m_ruleDraft.destIp.empty() || self->m_ruleDraft.destIp == "0.0.0.0") ? BST_CHECKED : BST_UNCHECKED);
            EnableWindow(editRemoteIp, !(self->m_ruleDraft.destIp.empty() || self->m_ruleDraft.destIp == "0.0.0.0"));
        }
        HWND advSrcIpEdit = GetDlgItem(hwnd, IDC_ADV_SRC_IP_EDIT);
        if (advSrcIpEdit) {
            SetDlgItemText(hwnd, IDC_ADV_SRC_IP_EDIT, Utf8ToWide(self->m_ruleDraft.sourceIp).c_str());
            CheckDlgButton(hwnd, IDC_CHECK_ANY_LOCAL_IP, (self->m_ruleDraft.sourceIp.empty() || self->m_ruleDraft.sourceIp == "0.0.0.0") ? BST_CHECKED : BST_UNCHECKED);
            EnableWindow(advSrcIpEdit, !(self->m_ruleDraft.sourceIp.empty() || self->m_ruleDraft.sourceIp == "0.0.0.0"));
        }
        HWND advDstIpEdit = GetDlgItem(hwnd, IDC_ADV_DST_IP_EDIT);
        if (advDstIpEdit) {
            SetDlgItemText(hwnd, IDC_ADV_DST_IP_EDIT, Utf8ToWide(self->m_ruleDraft.destIp).c_str());
            CheckDlgButton(hwnd, IDC_CHECK_ANY_REMOTE_IP, (self->m_ruleDraft.destIp.empty() || self->m_ruleDraft.destIp == "0.0.0.0") ? BST_CHECKED : BST_UNCHECKED);
            EnableWindow(advDstIpEdit, !(self->m_ruleDraft.destIp.empty() || self->m_ruleDraft.destIp == "0.0.0.0"));
        }

        HWND editLocalPort = GetDlgItem(hwnd, IDC_EDIT_LOCAL_PORT);
        if (editLocalPort) {
            if (self->m_ruleDraft.sourcePort != 0)
                SetDlgItemText(hwnd, IDC_EDIT_LOCAL_PORT, std::to_wstring(self->m_ruleDraft.sourcePort).c_str());
            else
                SetDlgItemText(hwnd, IDC_EDIT_LOCAL_PORT, L"");
            CheckDlgButton(hwnd, IDC_CHECK_ANY_LOCAL_PORT, self->m_ruleDraft.sourcePort == 0 ? BST_CHECKED : BST_UNCHECKED);
            EnableWindow(editLocalPort, self->m_ruleDraft.sourcePort != 0);
        }
        HWND editRemotePort = GetDlgItem(hwnd, IDC_EDIT_REMOTE_PORT);
        if (editRemotePort) {
            if (self->m_ruleDraft.destPort != 0)
                SetDlgItemText(hwnd, IDC_EDIT_REMOTE_PORT, std::to_wstring(self->m_ruleDraft.destPort).c_str());
            else
                SetDlgItemText(hwnd, IDC_EDIT_REMOTE_PORT, L"");
            CheckDlgButton(hwnd, IDC_CHECK_ANY_REMOTE_PORT, self->m_ruleDraft.destPort == 0 ? BST_CHECKED : BST_UNCHECKED);
            EnableWindow(editRemotePort, self->m_ruleDraft.destPort != 0);
        }
        HWND advSrcPortEdit = GetDlgItem(hwnd, IDC_ADV_SRC_PORT_EDIT);
        if (advSrcPortEdit) {
            if (self->m_ruleDraft.sourcePort != 0)
                SetDlgItemText(hwnd, IDC_ADV_SRC_PORT_EDIT, std::to_wstring(self->m_ruleDraft.sourcePort).c_str());
            else
                SetDlgItemText(hwnd, IDC_ADV_SRC_PORT_EDIT, L"");
            CheckDlgButton(hwnd, IDC_CHECK_ANY_LOCAL_PORT, self->m_ruleDraft.sourcePort == 0 ? BST_CHECKED : BST_UNCHECKED);
            EnableWindow(advSrcPortEdit, self->m_ruleDraft.sourcePort != 0);
        }
        HWND advDstPortEdit = GetDlgItem(hwnd, IDC_ADV_DST_PORT_EDIT);
        if (advDstPortEdit) {
            if (self->m_ruleDraft.destPort != 0)
                SetDlgItemText(hwnd, IDC_ADV_DST_PORT_EDIT, std::to_wstring(self->m_ruleDraft.destPort).c_str());
            else
                SetDlgItemText(hwnd, IDC_ADV_DST_PORT_EDIT, L"");
            CheckDlgButton(hwnd, IDC_CHECK_ANY_REMOTE_PORT, self->m_ruleDraft.destPort == 0 ? BST_CHECKED : BST_UNCHECKED);
            EnableWindow(advDstPortEdit, self->m_ruleDraft.destPort != 0);
        }

        // --- Протоколы (PAGE_PARAMS_PROTO, PAGE_PARAMS_ADVANCED) ---
        HWND protoCombo = GetDlgItem(hwnd, IDC_PROTOCOL_COMBO);
        if (protoCombo) {
            ComboBox_ResetContent(protoCombo);
            ComboBox_AddString(protoCombo, L"Любой");
            ComboBox_AddString(protoCombo, L"TCP");
            ComboBox_AddString(protoCombo, L"UDP");
            ComboBox_AddString(protoCombo, L"ICMP");
            ComboBox_SetCurSel(protoCombo, static_cast<int>(self->m_ruleDraft.protocol));
        }
        HWND comboProto = GetDlgItem(hwnd, IDC_COMBO_PROTOCOL);
        if (comboProto) {
            ComboBox_ResetContent(comboProto);
            ComboBox_AddString(comboProto, L"Любой");
            ComboBox_AddString(comboProto, L"TCP");
            ComboBox_AddString(comboProto, L"UDP");
            ComboBox_AddString(comboProto, L"ICMP");
            ComboBox_SetCurSel(comboProto, static_cast<int>(self->m_ruleDraft.protocol));
        }
        HWND advProtoCombo = GetDlgItem(hwnd, IDC_ADV_PROTO_COMBO);
        if (advProtoCombo) {
            ComboBox_ResetContent(advProtoCombo);
            ComboBox_AddString(advProtoCombo, L"Любой");
            ComboBox_AddString(advProtoCombo, L"TCP");
            ComboBox_AddString(advProtoCombo, L"UDP");
            ComboBox_AddString(advProtoCombo, L"ICMP");
            ComboBox_SetCurSel(advProtoCombo, static_cast<int>(self->m_ruleDraft.protocol));
        }

        // --- Действие (разрешить/запретить) (PAGE_ACTION) ---
        HWND allowRadio = GetDlgItem(hwnd, IDC_RULE_ALLOW_RADIO);
        HWND blockRadio = GetDlgItem(hwnd, IDC_RULE_BLOCK_RADIO);
        if (allowRadio && blockRadio) {
            CheckRadioButton(hwnd, IDC_RULE_ALLOW_RADIO, IDC_RULE_BLOCK_RADIO,
                self->m_ruleDraft.action == RuleAction::ALLOW ? IDC_RULE_ALLOW_RADIO : IDC_RULE_BLOCK_RADIO);
        }

        return TRUE;
    }
    if (msg == WM_COMMAND) {
        switch (LOWORD(wParam)) {
        case IDC_CHECK_ANY_LOCAL_PORT:
        case IDC_CHECK_ANY_REMOTE_PORT:
        case IDC_CHECK_ANY_LOCAL_IP:
        case IDC_CHECK_ANY_REMOTE_IP: {
            int editId = 0;
            if (LOWORD(wParam) == IDC_CHECK_ANY_LOCAL_PORT)
                editId = (GetDlgItem(hwnd, IDC_EDIT_LOCAL_PORT) ? IDC_EDIT_LOCAL_PORT : IDC_ADV_SRC_PORT_EDIT);
            if (LOWORD(wParam) == IDC_CHECK_ANY_REMOTE_PORT)
                editId = (GetDlgItem(hwnd, IDC_EDIT_REMOTE_PORT) ? IDC_EDIT_REMOTE_PORT : IDC_ADV_DST_PORT_EDIT);
            if (LOWORD(wParam) == IDC_CHECK_ANY_LOCAL_IP)
                editId = (GetDlgItem(hwnd, IDC_EDIT_LOCAL_IP) ? IDC_EDIT_LOCAL_IP : IDC_ADV_SRC_IP_EDIT);
            if (LOWORD(wParam) == IDC_CHECK_ANY_REMOTE_IP)
                editId = (GetDlgItem(hwnd, IDC_EDIT_REMOTE_IP) ? IDC_EDIT_REMOTE_IP : IDC_ADV_DST_IP_EDIT);
            if (HIWORD(wParam) == BN_CLICKED && editId) {
                BOOL checked = IsDlgButtonChecked(hwnd, LOWORD(wParam)) == BST_CHECKED;
                HWND edit = GetDlgItem(hwnd, editId);
                if (edit) EnableWindow(edit, !checked);
            }
            break;
        }
        case IDC_BROWSE_APP:
            if (HIWORD(wParam) == BN_CLICKED) self->BrowseForProgram(hwnd, IDC_APP_PATH_EDIT);
            break;
        case IDC_ADV_BROWSE_APP:
            if (HIWORD(wParam) == BN_CLICKED) self->BrowseForProgram(hwnd, IDC_ADV_APP_PATH_EDIT);
            break;
        }
    }
    return FALSE;
}