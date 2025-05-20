#include "rule_wizard.h"
#include "resource.h"
#include <shobjidl.h>
#include <CommCtrl.h>
#include "string_utils.h" 
#include <vector>
#include "validator.h"

RuleWizard* RuleWizard::s_instance = nullptr;

RuleWizard::RuleWizard(HWND hParent, Rule& rule)
    : m_hwndParent(hParent)
    , m_hwndMain(NULL)
    , m_hwndCurrent(NULL)
    , m_currentPage(PAGE_TYPE)
    , m_rule(rule)
    , m_selectedType(0)
{
    s_instance = this;
}

RuleWizard::~RuleWizard()
{
    s_instance = nullptr;
}

bool RuleWizard::ShowWizard(HWND hParent, Rule& rule)
{
    RuleWizard wizard(hParent, rule);
    return wizard.Show();
}

bool RuleWizard::Show()
{
    return DialogBoxParam(GetModuleHandle(NULL),
        MAKEINTRESOURCE(IDD_RULE_WIZARD_DIALOG),
        m_hwndParent,
        MainDlgProc,
        reinterpret_cast<LPARAM>(this)) == IDOK;
}

void RuleWizard::ShowPage(WizardPage page)
{
    // Сохраняем данные текущей страницы перед переключением
    if (m_hwndCurrent) {
        SavePageData();
        DestroyWindow(m_hwndCurrent);
        m_hwndCurrent = NULL;
    }

    // Определяем ID диалога для новой страницы
    int dialogId = 0;
    switch (page) {
    case PAGE_TYPE: dialogId = IDD_RULE_PAGE_TYPE; break;
    case PAGE_PARAMS_APP: dialogId = IDD_RULE_PAGE_APP; break;
    case PAGE_PARAMS_PORT: dialogId = IDD_RULE_PAGE_PORT; break;
    case PAGE_PARAMS_PROTO: dialogId = IDD_RULE_PARAM_PROTO; break;
    case PAGE_PARAMS_ADVANCED: dialogId = IDD_RULE_PARAM_ADVANCED; break;
    case PAGE_ACTION: dialogId = IDD_RULE_PAGE_ACTION; break;
    case PAGE_NAME: dialogId = IDD_RULE_PAGE_NAME; break;
    }

    // Создаем новую страницу
    m_hwndCurrent = CreateDialog(GetModuleHandle(NULL),
        MAKEINTRESOURCE(dialogId),
        m_hwndMain,
        PageDlgProc);

    if (m_hwndCurrent) {
        // Размещаем страницу в контейнере
        HWND container = GetDlgItem(m_hwndMain, IDC_WIZARD_CONTAINER);
        RECT rc;
        GetClientRect(container, &rc);
        SetWindowPos(m_hwndCurrent, NULL,
            rc.left, rc.top,
            rc.right - rc.left, rc.bottom - rc.top,
            SWP_NOZORDER);

        // Инициализация страницы
        switch (page) {
        case PAGE_TYPE: {
            HWND combo = GetDlgItem(m_hwndCurrent, IDC_RULE_TYPE_COMBO);
            SendMessage(combo, CB_ADDSTRING, 0, (LPARAM)L"По приложению");
            SendMessage(combo, CB_ADDSTRING, 0, (LPARAM)L"По порту");
            SendMessage(combo, CB_ADDSTRING, 0, (LPARAM)L"По протоколу");
            SendMessage(combo, CB_ADDSTRING, 0, (LPARAM)L"Пользовательское");
            SendMessage(combo, CB_SETCURSEL, m_selectedType, 0);
            break;
        }
        case PAGE_PARAMS_PROTO:
        case PAGE_PARAMS_ADVANCED: {
            HWND combo = GetDlgItem(m_hwndCurrent,
                page == PAGE_PARAMS_PROTO ? IDC_PROTOCOL_COMBO : IDC_ADV_PROTO_COMBO);
            SendMessage(combo, CB_ADDSTRING, 0, (LPARAM)L"ANY");
            SendMessage(combo, CB_ADDSTRING, 0, (LPARAM)L"TCP");
            SendMessage(combo, CB_ADDSTRING, 0, (LPARAM)L"UDP");
            SendMessage(combo, CB_ADDSTRING, 0, (LPARAM)L"ICMP");
            SendMessage(combo, CB_SETCURSEL, 0, 0);
            break;
        }
        case PAGE_ACTION: {
            CheckRadioButton(m_hwndCurrent,
                IDC_RULE_ALLOW_RADIO, IDC_RULE_BLOCK_RADIO,
                m_rule.action == RuleAction::ALLOW ?
                IDC_RULE_ALLOW_RADIO : IDC_RULE_BLOCK_RADIO);
            break;
        }
        }

        ShowWindow(m_hwndCurrent, SW_SHOW);
    }

    m_currentPage = page;
    UpdateButtons();
}

bool RuleWizard::ValidateCurrentPage()
{
    if (!SavePageData())
        return false;

    switch (m_currentPage) {
    case PAGE_TYPE: {
        // Проверяем, что тип правила выбран
        if (m_selectedType < 0 || m_selectedType > 3) {
            MessageBox(m_hwndCurrent,
                L"Пожалуйста, выберите тип правила.",
                L"Проверка данных", MB_OK | MB_ICONWARNING);
            return false;
        }
        return true;
    }

    case PAGE_PARAMS_APP: {
        // Проверяем путь к приложению
        wchar_t buf[MAX_PATH];
        GetDlgItemText(m_hwndCurrent, IDC_APP_PATH_EDIT, buf, MAX_PATH);
        if (wcslen(buf) == 0) {
            MessageBox(m_hwndCurrent,
                L"Пожалуйста, укажите путь к приложению.",
                L"Проверка данных", MB_OK | MB_ICONWARNING);
            return false;
        }
        // Проверяем существование файла
        if (GetFileAttributes(buf) == INVALID_FILE_ATTRIBUTES) {
            MessageBox(m_hwndCurrent,
                L"Указанный файл не существует.\nПожалуйста, проверьте путь к приложению.",
                L"Проверка данных", MB_OK | MB_ICONWARNING);
            return false;
        }
        return true;
    }

    case PAGE_PARAMS_PORT: {
        wchar_t buf[256];
        GetDlgItemText(m_hwndCurrent, IDC_PORT_EDIT, buf, 255);
        if (wcslen(buf) == 0) {
            MessageBox(m_hwndCurrent,
                L"Пожалуйста, укажите порт или диапазон портов.",
                L"Проверка данных", MB_OK | MB_ICONWARNING);
            return false;
        }

        std::vector<std::pair<int, int>> portRanges;
        if (!RuleValidator::ValidatePortInput(buf, portRanges)) {
            MessageBox(m_hwndCurrent,
                L"Неверный формат порта. Используйте:\n\n"
                L"• Одиночный порт: 80\n"
                L"• Диапазон портов: 1000-2000\n"
                L"• Список портов: 80,443,3389\n\n"
                L"Допустимые значения: 1-65535",
                L"Проверка данных", MB_OK | MB_ICONWARNING);
            return false;
        }
        return true;
    }

    case PAGE_PARAMS_PROTO: {
        // Проверяем, что протокол выбран
        int protoSel = SendDlgItemMessage(m_hwndCurrent, IDC_PROTOCOL_COMBO, CB_GETCURSEL, 0, 0);
        if (protoSel == CB_ERR) {
            MessageBox(m_hwndCurrent,
                L"Пожалуйста, выберите протокол.",
                L"Проверка данных", MB_OK | MB_ICONWARNING);
            return false;
        }
        return true;
    }

    case PAGE_PARAMS_ADVANCED: {
        wchar_t buf[256];
        bool hasAtLeastOne = false;

        // Проверка протокола
        int protoSel = SendDlgItemMessage(m_hwndCurrent, IDC_ADV_PROTO_COMBO, CB_GETCURSEL, 0, 0);
        if (protoSel == CB_ERR) {
            MessageBox(m_hwndCurrent,
                L"Пожалуйста, выберите протокол.",
                L"Проверка данных", MB_OK | MB_ICONWARNING);
            return false;
        }

        // Проверка IP адреса источника
        GetDlgItemText(m_hwndCurrent, IDC_ADV_SRC_IP_EDIT, buf, 255);
        if (buf[0] != '\0') {
            std::vector<std::pair<std::string, std::string>> ipRanges;
            if (!RuleValidator::ValidateIpInput(buf, ipRanges)) {
                MessageBox(m_hwndCurrent,
                    L"Неверный формат IP адреса источника. Используйте:\n\n"
                    L"• Одиночный IP: 192.168.1.1\n"
                    L"• Диапазон IP: 192.168.1.1-192.168.1.10\n"
                    L"• Подсеть: 192.168.1.0/24\n"
                    L"• Список IP: 192.168.1.1,192.168.1.2",
                    L"Проверка данных", MB_OK | MB_ICONWARNING);
                return false;
            }
            hasAtLeastOne = true;
        }

        // Проверка порта источника
        GetDlgItemText(m_hwndCurrent, IDC_ADV_SRC_PORT_EDIT, buf, 255);
        if (buf[0] != '\0') {
            std::vector<std::pair<int, int>> portRanges;
            if (!RuleValidator::ValidatePortInput(buf, portRanges)) {
                MessageBox(m_hwndCurrent,
                    L"Неверный формат порта источника. Используйте:\n\n"
                    L"• Одиночный порт: 80\n"
                    L"• Диапазон портов: 1000-2000\n"
                    L"• Список портов: 80,443,3389\n\n"
                    L"Допустимые значения: 1-65535",
                    L"Проверка данных", MB_OK | MB_ICONWARNING);
                return false;
            }
            hasAtLeastOne = true;
        }

        // Проверка IP адреса назначения
        GetDlgItemText(m_hwndCurrent, IDC_ADV_DST_IP_EDIT, buf, 255);
        if (buf[0] != '\0') {
            std::vector<std::pair<std::string, std::string>> ipRanges;
            if (!RuleValidator::ValidateIpInput(buf, ipRanges)) {
                MessageBox(m_hwndCurrent,
                    L"Неверный формат IP адреса назначения. Используйте:\n\n"
                    L"• Одиночный IP: 192.168.1.1\n"
                    L"• Диапазон IP: 192.168.1.1-192.168.1.10\n"
                    L"• Подсеть: 192.168.1.0/24\n"
                    L"• Список IP: 192.168.1.1,192.168.1.2",
                    L"Проверка данных", MB_OK | MB_ICONWARNING);
                return false;
            }
            hasAtLeastOne = true;
        }

        // Проверка порта назначения
        GetDlgItemText(m_hwndCurrent, IDC_ADV_DST_PORT_EDIT, buf, 255);
        if (buf[0] != '\0') {
            std::vector<std::pair<int, int>> portRanges;
            if (!RuleValidator::ValidatePortInput(buf, portRanges)) {
                MessageBox(m_hwndCurrent,
                    L"Неверный формат порта назначения. Используйте:\n\n"
                    L"• Одиночный порт: 80\n"
                    L"• Диапазон портов: 1000-2000\n"
                    L"• Список портов: 80,443,3389\n\n"
                    L"Допустимые значения: 1-65535",
                    L"Проверка данных", MB_OK | MB_ICONWARNING);
                return false;
            }
            hasAtLeastOne = true;
        }

        // Проверка пути к приложению
        GetDlgItemText(m_hwndCurrent, IDC_ADV_APP_PATH_EDIT, buf, MAX_PATH);
        if (buf[0] != '\0') {
            if (GetFileAttributes(buf) == INVALID_FILE_ATTRIBUTES) {
                MessageBox(m_hwndCurrent,
                    L"Указанный файл не существует.\nПожалуйста, проверьте путь к приложению.",
                    L"Проверка данных", MB_OK | MB_ICONWARNING);
                return false;
            }
            hasAtLeastOne = true;
        }

        // Проверяем, что хотя бы одно поле заполнено
        if (!hasAtLeastOne) {
            MessageBox(m_hwndCurrent,
                L"Пожалуйста, заполните хотя бы одно поле:\n\n"
                L"• IP адрес источника или назначения\n"
                L"• Порт источника или назначения\n"
                L"• Путь к приложению",
                L"Проверка данных", MB_OK | MB_ICONWARNING);
            return false;
        }
        return true;
    }

    case PAGE_ACTION: {
        // Проверка не требуется, так как всегда выбран один из вариантов
        return true;
    }

    case PAGE_NAME: {
        wchar_t buf[256];

        // Проверяем имя правила
        GetDlgItemText(m_hwndCurrent, IDC_RULE_NAME_EDIT, buf, 255);
        if (wcslen(buf) == 0) {
            MessageBox(m_hwndCurrent,
                L"Пожалуйста, введите имя правила.",
                L"Проверка данных", MB_OK | MB_ICONWARNING);
            return false;
        }

        // Описание может быть пустым
        return true;
    }
    }

    return true;
}

void RuleWizard::UpdateButtons()
{
    EnableWindow(GetDlgItem(m_hwndMain, IDC_WIZARD_BACK), m_currentPage > PAGE_TYPE);

    SetDlgItemText(m_hwndMain, IDC_WIZARD_NEXT,
        m_currentPage == PAGE_NAME ? L"Готово" : L"Далее >");
}

bool RuleWizard::SavePageData()
{
    if (!m_hwndCurrent)
        return true;

    wchar_t buf[256];
    switch (m_currentPage) {
    case PAGE_TYPE:
        m_selectedType = SendDlgItemMessage(m_hwndCurrent,
            IDC_RULE_TYPE_COMBO, CB_GETCURSEL, 0, 0);
        return true;

    case PAGE_PARAMS_APP:
        GetDlgItemText(m_hwndCurrent, IDC_APP_PATH_EDIT, buf, 255);
        m_rule.appPath = WideToUtf8(buf);
        return true;

    case PAGE_PARAMS_PORT:
        GetDlgItemText(m_hwndCurrent, IDC_PORT_EDIT, buf, 255);
        m_rule.destPort = _wtoi(buf);
        return m_rule.destPort > 0 && m_rule.destPort <= 65535;

    case PAGE_PARAMS_PROTO:
        m_rule.protocol = (Protocol)SendDlgItemMessage(m_hwndCurrent,
            IDC_PROTOCOL_COMBO, CB_GETCURSEL, 0, 0);
        return true;

    case PAGE_PARAMS_ADVANCED:
        m_rule.protocol = (Protocol)SendDlgItemMessage(m_hwndCurrent,
            IDC_ADV_PROTO_COMBO, CB_GETCURSEL, 0, 0);

        GetDlgItemText(m_hwndCurrent, IDC_ADV_SRC_PORT_EDIT, buf, 255);
        m_rule.sourcePort = _wtoi(buf);

        GetDlgItemText(m_hwndCurrent, IDC_ADV_DST_PORT_EDIT, buf, 255);
        m_rule.destPort = _wtoi(buf);

        GetDlgItemText(m_hwndCurrent, IDC_ADV_SRC_IP_EDIT, buf, 255);
        m_rule.sourceIp = WideToUtf8(buf);

        GetDlgItemText(m_hwndCurrent, IDC_ADV_DST_IP_EDIT, buf, 255);
        m_rule.destIp = WideToUtf8(buf);

        GetDlgItemText(m_hwndCurrent, IDC_ADV_APP_PATH_EDIT, buf, 255);
        m_rule.appPath = WideToUtf8(buf);
        return true;

    case PAGE_ACTION:
        m_rule.action = IsDlgButtonChecked(m_hwndCurrent, IDC_RULE_ALLOW_RADIO) == BST_CHECKED
            ? RuleAction::ALLOW : RuleAction::BLOCK;
        return true;

    case PAGE_NAME:
        GetDlgItemText(m_hwndCurrent, IDC_RULE_NAME_EDIT, buf, 255);
        m_rule.name = WideToUtf8(buf);
        GetDlgItemText(m_hwndCurrent, IDC_RULE_DESC_EDIT, buf, 255);
        m_rule.description = WideToUtf8(buf);
        return !m_rule.name.empty();
    }
    return true;
}

INT_PTR CALLBACK RuleWizard::MainDlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_INITDIALOG:
        s_instance->m_hwndMain = hwnd;
        s_instance->ShowPage(PAGE_TYPE);
        return TRUE;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_WIZARD_NEXT:
            if (!s_instance->ValidateCurrentPage())
                return TRUE;

            if (s_instance->m_currentPage == PAGE_NAME) {
                EndDialog(hwnd, IDOK);
            }
            else {
                WizardPage nextPage;
                if (s_instance->m_currentPage == PAGE_TYPE) {
                    switch (s_instance->m_selectedType) {
                    case 0: nextPage = PAGE_PARAMS_APP; break;
                    case 1: nextPage = PAGE_PARAMS_PORT; break;
                    case 2: nextPage = PAGE_PARAMS_PROTO; break;
                    case 3: nextPage = PAGE_PARAMS_ADVANCED; break;
                    }
                }
                else if (s_instance->m_currentPage == PAGE_PARAMS_APP ||
                    s_instance->m_currentPage == PAGE_PARAMS_PORT ||
                    s_instance->m_currentPage == PAGE_PARAMS_PROTO ||
                    s_instance->m_currentPage == PAGE_PARAMS_ADVANCED) {
                    nextPage = PAGE_ACTION;
                }
                else if (s_instance->m_currentPage == PAGE_ACTION) {
                    nextPage = PAGE_NAME;
                }
                s_instance->ShowPage(nextPage);
            }
            return TRUE;

        case IDC_WIZARD_BACK:
            if (s_instance->m_currentPage > PAGE_TYPE) {
                WizardPage prevPage;
                if (s_instance->m_currentPage == PAGE_NAME) {
                    prevPage = PAGE_ACTION;
                }
                else if (s_instance->m_currentPage == PAGE_ACTION) {
                    switch (s_instance->m_selectedType) {
                    case 0: prevPage = PAGE_PARAMS_APP; break;
                    case 1: prevPage = PAGE_PARAMS_PORT; break;
                    case 2: prevPage = PAGE_PARAMS_PROTO; break;
                    case 3: prevPage = PAGE_PARAMS_ADVANCED; break;
                    }
                }
                else {
                    prevPage = PAGE_TYPE;
                }
                s_instance->ShowPage(prevPage);
            }
            return TRUE;

        case IDCANCEL:
            EndDialog(hwnd, IDCANCEL);
            return TRUE;
        }
        break;
    }
    return FALSE;
}

INT_PTR CALLBACK RuleWizard::PageDlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_BROWSE_APP:
        case IDC_ADV_BROWSE_APP: {
            IFileOpenDialog* pFileOpen = nullptr;
            HRESULT hr = CoCreateInstance(CLSID_FileOpenDialog, NULL,
                CLSCTX_ALL, IID_IFileOpenDialog, (void**)&pFileOpen);

            if (SUCCEEDED(hr)) {
                hr = pFileOpen->Show(hwnd);
                if (SUCCEEDED(hr)) {
                    IShellItem* pItem;
                    hr = pFileOpen->GetResult(&pItem);
                    if (SUCCEEDED(hr)) {
                        PWSTR pszFilePath;
                        hr = pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath);
                        if (SUCCEEDED(hr)) {
                            SetDlgItemText(hwnd,
                                LOWORD(wParam) == IDC_BROWSE_APP ?
                                IDC_APP_PATH_EDIT : IDC_ADV_APP_PATH_EDIT,
                                pszFilePath);
                            CoTaskMemFree(pszFilePath);
                        }
                        pItem->Release();
                    }
                }
                pFileOpen->Release();
            }
            return TRUE;
        }
        }
        break;
    }
    return FALSE;
}