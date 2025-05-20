#include "rule_wizard.h"
#include "resource.h"
#include <shobjidl.h>
#include <CommCtrl.h>
#include "string_utils.h" 
#include <vector>
#include "validator.h"
#include <windowsx.h>
#include <shlwapi.h>

RuleWizard::WizardPage RuleWizard::currentPage = PAGE_TYPE;
int RuleWizard::selectedType = 0;

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

Rule* RuleWizard::currentRule = nullptr;
bool RuleWizard::isEditMode = false;

bool RuleWizard::ShowWizard(HWND parent, Rule& rule) {
    currentRule = &rule;
    isEditMode = false;
    return DialogBox(
        GetModuleHandle(NULL),
        MAKEINTRESOURCE(IDD_RULE_EDIT),
        parent,
        DialogProc
    ) == IDOK;
}

bool RuleWizard::EditRule(HWND parent, Rule& rule) {
    currentRule = &rule;
    isEditMode = true;
    return DialogBox(
        GetModuleHandle(NULL),
        MAKEINTRESOURCE(IDD_RULE_EDIT),
        parent,
        DialogProc
    ) == IDOK;
}

void RuleWizard::InitDialog(HWND hwnd) {
    // Инициализация комбобокса протоколов
    HWND hProtocol = GetDlgItem(hwnd, IDC_COMBO_PROTOCOL);
    ComboBox_AddString(hProtocol, L"Любой");
    ComboBox_AddString(hProtocol, L"TCP");
    ComboBox_AddString(hProtocol, L"UDP");
    ComboBox_AddString(hProtocol, L"ICMP");
    ComboBox_SetCurSel(hProtocol, 0);

    // Установка текущего времени UTC в формате YYYY-MM-DD HH:MM:SS
    time_t now;
    time(&now);
    tm utc_tm;
    gmtime_s(&utc_tm, &now);
    wchar_t timeStr[64];
    swprintf_s(timeStr, L"%04d-%02d-%02d %02d:%02d:%02d",
        utc_tm.tm_year + 1900, utc_tm.tm_mon + 1, utc_tm.tm_mday,
        utc_tm.tm_hour, utc_tm.tm_min, utc_tm.tm_sec);
    SetDlgItemText(hwnd, IDC_EDIT_NAME, timeStr);

    // Инициализация чекбоксов
    Button_SetCheck(GetDlgItem(hwnd, IDC_CHECK_ANY_LOCAL_IP), BST_CHECKED);
    Button_SetCheck(GetDlgItem(hwnd, IDC_CHECK_ANY_REMOTE_IP), BST_CHECKED);
    Button_SetCheck(GetDlgItem(hwnd, IDC_CHECK_ANY_LOCAL_PORT), BST_CHECKED);
    Button_SetCheck(GetDlgItem(hwnd, IDC_CHECK_ANY_REMOTE_PORT), BST_CHECKED);

    // Отключаем поля ввода по умолчанию
    EnableWindow(GetDlgItem(hwnd, IDC_EDIT_LOCAL_IP), FALSE);
    EnableWindow(GetDlgItem(hwnd, IDC_EDIT_REMOTE_IP), FALSE);
    EnableWindow(GetDlgItem(hwnd, IDC_EDIT_LOCAL_PORT), FALSE);
    EnableWindow(GetDlgItem(hwnd, IDC_EDIT_REMOTE_PORT), FALSE);

    // По умолчанию выбираем "Разрешить"
    CheckRadioButton(hwnd, IDC_RADIO_ALLOW, IDC_RADIO_BLOCK, IDC_RADIO_ALLOW);

    if (isEditMode && currentRule) {
        LoadRule(hwnd);
    }
}

void RuleWizard::LoadRule(HWND hwnd) {
    if (!currentRule) return;

    // Загружаем данные правила
    SetDlgItemText(hwnd, IDC_EDIT_NAME, Utf8ToWide(currentRule->name).c_str());
    SetDlgItemText(hwnd, IDC_EDIT_PROGRAM, Utf8ToWide(currentRule->appPath).c_str());

    // Действие
    CheckRadioButton(hwnd, IDC_RADIO_ALLOW, IDC_RADIO_BLOCK,
        currentRule->action == RuleAction::ALLOW ? IDC_RADIO_ALLOW : IDC_RADIO_BLOCK);

    // Протокол
    HWND hProtocol = GetDlgItem(hwnd, IDC_COMBO_PROTOCOL);
    int protocolIndex = static_cast<int>(currentRule->protocol);
    ComboBox_SetCurSel(hProtocol, protocolIndex);

    // IP адреса
    bool anyLocalIp = (currentRule->sourceIp == "0.0.0.0" || currentRule->sourceIp.empty());
    bool anyRemoteIp = (currentRule->destIp == "0.0.0.0" || currentRule->destIp.empty());

    Button_SetCheck(GetDlgItem(hwnd, IDC_CHECK_ANY_LOCAL_IP), anyLocalIp ? BST_CHECKED : BST_UNCHECKED);
    Button_SetCheck(GetDlgItem(hwnd, IDC_CHECK_ANY_REMOTE_IP), anyRemoteIp ? BST_CHECKED : BST_UNCHECKED);

    EnableWindow(GetDlgItem(hwnd, IDC_EDIT_LOCAL_IP), !anyLocalIp);
    EnableWindow(GetDlgItem(hwnd, IDC_EDIT_REMOTE_IP), !anyRemoteIp);

    if (!anyLocalIp) {
        SetDlgItemText(hwnd, IDC_EDIT_LOCAL_IP, Utf8ToWide(currentRule->sourceIp).c_str());
    }
    if (!anyRemoteIp) {
        SetDlgItemText(hwnd, IDC_EDIT_REMOTE_IP, Utf8ToWide(currentRule->destIp).c_str());
    }

    // Порты
    bool anyLocalPort = (currentRule->sourcePort == 0);
    bool anyRemotePort = (currentRule->destPort == 0);

    Button_SetCheck(GetDlgItem(hwnd, IDC_CHECK_ANY_LOCAL_PORT), anyLocalPort ? BST_CHECKED : BST_UNCHECKED);
    Button_SetCheck(GetDlgItem(hwnd, IDC_CHECK_ANY_REMOTE_PORT), anyRemotePort ? BST_CHECKED : BST_UNCHECKED);

    EnableWindow(GetDlgItem(hwnd, IDC_EDIT_LOCAL_PORT), !anyLocalPort);
    EnableWindow(GetDlgItem(hwnd, IDC_EDIT_REMOTE_PORT), !anyRemotePort);

    if (!anyLocalPort) {
        SetDlgItemText(hwnd, IDC_EDIT_LOCAL_PORT, std::to_wstring(currentRule->sourcePort).c_str());
    }
    if (!anyRemotePort) {
        SetDlgItemText(hwnd, IDC_EDIT_REMOTE_PORT, std::to_wstring(currentRule->destPort).c_str());
    }
}

bool RuleWizard::SaveRule(HWND hwnd) {
    if (!currentRule) return false;

    std::wstring errorMsg;
    if (!RuleValidator::ValidateInputs(hwnd, errorMsg)) {
        MessageBox(hwnd, errorMsg.c_str(), L"Ошибка", MB_OK | MB_ICONERROR);
        return false;
    }

    wchar_t buffer[MAX_PATH];

    // Название
    GetDlgItemText(hwnd, IDC_EDIT_NAME, buffer, MAX_PATH);
    currentRule->name = WideToUtf8(buffer);

    // Путь к программе
    GetDlgItemText(hwnd, IDC_EDIT_PROGRAM, buffer, MAX_PATH);
    currentRule->appPath = WideToUtf8(buffer);

    // Действие
    currentRule->action = IsDlgButtonChecked(hwnd, IDC_RADIO_ALLOW) == BST_CHECKED ?
        RuleAction::ALLOW : RuleAction::BLOCK;

    // Протокол
    int protocolIndex = ComboBox_GetCurSel(GetDlgItem(hwnd, IDC_COMBO_PROTOCOL));
    currentRule->protocol = static_cast<Protocol>(protocolIndex);

    // IP адреса
    if (IsDlgButtonChecked(hwnd, IDC_CHECK_ANY_LOCAL_IP) == BST_CHECKED) {
        currentRule->sourceIp = "0.0.0.0";
    }
    else {
        GetDlgItemText(hwnd, IDC_EDIT_LOCAL_IP, buffer, MAX_PATH);
        currentRule->sourceIp = WideToUtf8(buffer);
    }

    if (IsDlgButtonChecked(hwnd, IDC_CHECK_ANY_REMOTE_IP) == BST_CHECKED) {
        currentRule->destIp = "0.0.0.0";
    }
    else {
        GetDlgItemText(hwnd, IDC_EDIT_REMOTE_IP, buffer, MAX_PATH);
        currentRule->destIp = WideToUtf8(buffer);
    }

    // Порты
    if (IsDlgButtonChecked(hwnd, IDC_CHECK_ANY_LOCAL_PORT) == BST_CHECKED) {
        currentRule->sourcePort = 0;
    }
    else {
        GetDlgItemText(hwnd, IDC_EDIT_LOCAL_PORT, buffer, MAX_PATH);
        currentRule->sourcePort = _wtoi(buffer);
    }

    if (IsDlgButtonChecked(hwnd, IDC_CHECK_ANY_REMOTE_PORT) == BST_CHECKED) {
        currentRule->destPort = 0;
    }
    else {
        GetDlgItemText(hwnd, IDC_EDIT_REMOTE_PORT, buffer, MAX_PATH);
        currentRule->destPort = _wtoi(buffer);
    }

    // Создатель правила
    currentRule->creator = "BlackBruceLee576"; // текущий пользователь

    // Время создания
    time_t now;
    time(&now);
    tm utc_tm;
    gmtime_s(&utc_tm, &now);
    char timeStr[64];
    sprintf_s(timeStr, "%04d-%02d-%02d %02d:%02d:%02d",
        utc_tm.tm_year + 1900, utc_tm.tm_mon + 1, utc_tm.tm_mday,
        utc_tm.tm_hour, utc_tm.tm_min, utc_tm.tm_sec);
    currentRule->creationTime = timeStr;

    return true;
}

void RuleWizard::BrowseForProgram(HWND hwnd) {
    wchar_t filePath[MAX_PATH] = { 0 };

    // Настраиваем диалог выбора файла
    OPENFILENAME ofn = { 0 };
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = L"Executable Files (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = filePath;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
    ofn.lpstrDefExt = L"exe";

    if (GetOpenFileName(&ofn)) {
        SetDlgItemText(hwnd, IDC_EDIT_PROGRAM, filePath);
    }
}

INT_PTR CALLBACK RuleWizard::DialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_INITDIALOG:
        InitDialog(hwnd);
        ShowPage(hwnd, IDD_RULE_PAGE_TYPE);
        return TRUE;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_WIZARD_NEXT:
            if (!ValidateCurrentPage())
                return TRUE;

            if (currentPage == PAGE_NAME) {
                if (SaveRule(hwnd)) {
                    EndDialog(hwnd, IDOK);
                }
            }
            else {
                WizardPage nextPage;
                if (currentPage == PAGE_TYPE) {
                    switch (selectedType) {
                    case 0: nextPage = PAGE_PARAMS_APP; break;
                    case 1: nextPage = PAGE_PARAMS_PORT; break;
                    case 2: nextPage = PAGE_PARAMS_PROTO; break;
                    case 3: nextPage = PAGE_PARAMS_ADVANCED; break;
                    default: nextPage = PAGE_PARAMS_APP; break;
                    }
                }
                else if (currentPage == PAGE_PARAMS_APP ||
                    currentPage == PAGE_PARAMS_PORT ||
                    currentPage == PAGE_PARAMS_PROTO ||
                    currentPage == PAGE_PARAMS_ADVANCED) {
                    nextPage = PAGE_ACTION;
                }
                else if (currentPage == PAGE_ACTION) {
                    nextPage = PAGE_NAME;
                }
                ShowPage(hwnd, nextPage);
            }
            return TRUE;

        case IDC_WIZARD_BACK:
            if (currentPage > PAGE_TYPE) {
                WizardPage prevPage;
                if (currentPage == PAGE_NAME) {
                    prevPage = PAGE_ACTION;
                }
                else if (currentPage == PAGE_ACTION) {
                    switch (selectedType) {
                    case 0: prevPage = PAGE_PARAMS_APP; break;
                    case 1: prevPage = PAGE_PARAMS_PORT; break;
                    case 2: prevPage = PAGE_PARAMS_PROTO; break;
                    case 3: prevPage = PAGE_PARAMS_ADVANCED; break;
                    default: prevPage = PAGE_PARAMS_APP; break;
                    }
                }
                else {
                    prevPage = PAGE_TYPE;
                }
                ShowPage(hwnd, prevPage);
            }
            return TRUE;

        case IDC_BROWSE_PROGRAM:
            if (HIWORD(wParam) == BN_CLICKED) {
                BrowseForProgram(hwnd);
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

bool RuleWizard::ValidateCurrentPage() {
    if (!s_instance || !s_instance->m_hwndCurrent)
        return false;

    wchar_t buffer[MAX_PATH];

    switch (s_instance->m_currentPage) {
    case PAGE_TYPE:
        s_instance->m_selectedType = SendDlgItemMessage(s_instance->m_hwndCurrent,
            IDC_RULE_TYPE_COMBO, CB_GETCURSEL, 0, 0);
        if (s_instance->m_selectedType == CB_ERR) {
            MessageBox(s_instance->m_hwndCurrent,
                L"Пожалуйста, выберите тип правила.",
                L"Ошибка", MB_OK | MB_ICONWARNING);
            return false;
        }
        return true;

    case PAGE_PARAMS_APP:
        GetDlgItemText(s_instance->m_hwndCurrent, IDC_APP_PATH_EDIT, buffer, MAX_PATH);
        if (buffer[0] != '\0' && GetFileAttributes(buffer) == INVALID_FILE_ATTRIBUTES) {
            MessageBox(s_instance->m_hwndCurrent,
                L"Указанный файл не существует.",
                L"Ошибка", MB_OK | MB_ICONWARNING);
            return false;
        }
        return true;

    case PAGE_PARAMS_PORT:
        GetDlgItemText(s_instance->m_hwndCurrent, IDC_PORT_EDIT, buffer, MAX_PATH);
        if (buffer[0] == '\0') {
            MessageBox(s_instance->m_hwndCurrent,
                L"Введите номер порта или диапазон портов.",
                L"Ошибка", MB_OK | MB_ICONWARNING);
            return false;
        }
        // Здесь должна быть валидация формата порта
        return true;

    case PAGE_NAME:
        GetDlgItemText(s_instance->m_hwndCurrent, IDC_RULE_NAME_EDIT, buffer, MAX_PATH);
        if (buffer[0] == '\0') {
            MessageBox(s_instance->m_hwndCurrent,
                L"Введите название правила.",
                L"Ошибка", MB_OK | MB_ICONWARNING);
            return false;
        }
        return true;

    default:
        return true;
    }
}

void RuleWizard::SetupPageControls(HWND hwnd) {
    switch (currentPage) {
    case PAGE_TYPE:
        // Показываем выбор типа правила
        EnableWindow(GetDlgItem(hwnd, IDC_COMBO_PROTOCOL), TRUE);
        break;

    case PAGE_PARAMS_APP:
        // Показываем выбор программы
        EnableWindow(GetDlgItem(hwnd, IDC_EDIT_PROGRAM), TRUE);
        EnableWindow(GetDlgItem(hwnd, IDC_BROWSE_PROGRAM), TRUE);
        break;

    case PAGE_PARAMS_PORT:
        // Показываем настройки портов
        EnableWindow(GetDlgItem(hwnd, IDC_CHECK_ANY_LOCAL_PORT), TRUE);
        EnableWindow(GetDlgItem(hwnd, IDC_EDIT_LOCAL_PORT),
            IsDlgButtonChecked(hwnd, IDC_CHECK_ANY_LOCAL_PORT) != BST_CHECKED);
        EnableWindow(GetDlgItem(hwnd, IDC_CHECK_ANY_REMOTE_PORT), TRUE);
        EnableWindow(GetDlgItem(hwnd, IDC_EDIT_REMOTE_PORT),
            IsDlgButtonChecked(hwnd, IDC_CHECK_ANY_REMOTE_PORT) != BST_CHECKED);
        break;

    case PAGE_PARAMS_PROTO:
        // Показываем выбор протокола
        EnableWindow(GetDlgItem(hwnd, IDC_COMBO_PROTOCOL), TRUE);
        break;

    case PAGE_PARAMS_ADVANCED:
        // Показываем все параметры
        EnableWindow(GetDlgItem(hwnd, IDC_EDIT_PROGRAM), TRUE);
        EnableWindow(GetDlgItem(hwnd, IDC_BROWSE_PROGRAM), TRUE);
        EnableWindow(GetDlgItem(hwnd, IDC_CHECK_ANY_LOCAL_IP), TRUE);
        EnableWindow(GetDlgItem(hwnd, IDC_CHECK_ANY_REMOTE_IP), TRUE);
        EnableWindow(GetDlgItem(hwnd, IDC_CHECK_ANY_LOCAL_PORT), TRUE);
        EnableWindow(GetDlgItem(hwnd, IDC_CHECK_ANY_REMOTE_PORT), TRUE);
        EnableWindow(GetDlgItem(hwnd, IDC_COMBO_PROTOCOL), TRUE);
        break;

    case PAGE_ACTION:
        // Показываем выбор действия
        EnableWindow(GetDlgItem(hwnd, IDC_RADIO_ALLOW), TRUE);
        EnableWindow(GetDlgItem(hwnd, IDC_RADIO_BLOCK), TRUE);
        break;

    case PAGE_NAME:
        // Показываем поля имени и описания
        EnableWindow(GetDlgItem(hwnd, IDC_EDIT_NAME), TRUE);
        break;
    }
}

bool RuleWizard::SavePageData() {
    if (!s_instance || !s_instance->m_hwndCurrent)
        return false;

    wchar_t buffer[MAX_PATH];

    switch (s_instance->m_currentPage) {
    case PAGE_TYPE:
        s_instance->m_selectedType = SendDlgItemMessage(s_instance->m_hwndCurrent,
            IDC_RULE_TYPE_COMBO, CB_GETCURSEL, 0, 0);
        return true;

    case PAGE_PARAMS_APP:
        GetDlgItemText(s_instance->m_hwndCurrent, IDC_APP_PATH_EDIT, buffer, MAX_PATH);
        s_instance->m_rule.appPath = WideToUtf8(buffer);
        return true;

    case PAGE_PARAMS_PORT:
        GetDlgItemText(s_instance->m_hwndCurrent, IDC_PORT_EDIT, buffer, MAX_PATH);
        // Здесь должна быть обработка порта и сохранение в правило
        return true;

    case PAGE_PARAMS_PROTO:
        s_instance->m_rule.protocol = static_cast<Protocol>(
            SendDlgItemMessage(s_instance->m_hwndCurrent,
                IDC_PROTOCOL_COMBO, CB_GETCURSEL, 0, 0));
        return true;

    case PAGE_ACTION:
        s_instance->m_rule.action =
            (IsDlgButtonChecked(s_instance->m_hwndCurrent, IDC_RULE_ALLOW_RADIO) == BST_CHECKED) ?
            RuleAction::ALLOW : RuleAction::BLOCK;
        return true;

    case PAGE_NAME:
        GetDlgItemText(s_instance->m_hwndCurrent, IDC_RULE_NAME_EDIT, buffer, MAX_PATH);
        s_instance->m_rule.name = WideToUtf8(buffer);
        GetDlgItemText(s_instance->m_hwndCurrent, IDC_RULE_DESC_EDIT, buffer, MAX_PATH);
        s_instance->m_rule.description = WideToUtf8(buffer);
        return true;

    default:
        return true;
    }
}

void RuleWizard::ShowPage(HWND hwnd, WizardPage page) {
    // Сохраняем данные текущей страницы
    if (!SavePageData()) {
        return;
    }

    currentPage = page;

    // Скрываем все элементы управления
    EnableWindow(GetDlgItem(hwnd, IDC_EDIT_NAME), FALSE);
    EnableWindow(GetDlgItem(hwnd, IDC_EDIT_PROGRAM), FALSE);
    EnableWindow(GetDlgItem(hwnd, IDC_BROWSE_PROGRAM), FALSE);
    EnableWindow(GetDlgItem(hwnd, IDC_RADIO_ALLOW), FALSE);
    EnableWindow(GetDlgItem(hwnd, IDC_RADIO_BLOCK), FALSE);
    EnableWindow(GetDlgItem(hwnd, IDC_CHECK_ANY_LOCAL_IP), FALSE);
    EnableWindow(GetDlgItem(hwnd, IDC_EDIT_LOCAL_IP), FALSE);
    EnableWindow(GetDlgItem(hwnd, IDC_CHECK_ANY_REMOTE_IP), FALSE);
    EnableWindow(GetDlgItem(hwnd, IDC_EDIT_REMOTE_IP), FALSE);
    EnableWindow(GetDlgItem(hwnd, IDC_COMBO_PROTOCOL), FALSE);
    EnableWindow(GetDlgItem(hwnd, IDC_CHECK_ANY_LOCAL_PORT), FALSE);
    EnableWindow(GetDlgItem(hwnd, IDC_EDIT_LOCAL_PORT), FALSE);
    EnableWindow(GetDlgItem(hwnd, IDC_CHECK_ANY_REMOTE_PORT), FALSE);
    EnableWindow(GetDlgItem(hwnd, IDC_EDIT_REMOTE_PORT), FALSE);

    // Показываем элементы в зависимости от страницы
    SetupPageControls(hwnd);

    // Обновляем кнопки Назад/Далее
    UpdateButtons(hwnd);
}



void RuleWizard::UpdateButtons(HWND hwnd) {
    // Кнопка "Назад" активна везде, кроме первой страницы
    EnableWindow(GetDlgItem(hwnd, IDC_WIZARD_BACK), currentPage > PAGE_TYPE);

    // На последней странице меняем текст кнопки "Далее" на "Готово"
    SetDlgItemText(hwnd, IDC_WIZARD_NEXT,
        currentPage == PAGE_NAME ? L"Готово" : L"Далее >");
}

