#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <commctrl.h>
#include <windowsx.h>
#include <ctime>
#include "main_window.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#define ID_RULES_LIST 1001
#define ID_CONNECTIONS_LIST 1002
#define ID_ADD_RULE 1003
#define ID_DELETE_RULE 1004
#define ID_START_CAPTURE 1005
#define ID_STOP_CAPTURE 1006

MainWindow::MainWindow() :
    hwnd(NULL),
    hInstance(NULL),
    rulesListView(NULL),
    connectionsListView(NULL),
    packetInterceptor(nullptr) {
}

MainWindow::~MainWindow() {
    if (packetInterceptor) {
        packetInterceptor->StopCapture();
    }
}

MainWindow& MainWindow::Instance() {
    static MainWindow instance;
    return instance;
}

void MainWindow::SetPacketInterceptor(std::shared_ptr<PacketInterceptor> interceptor) {
    packetInterceptor = interceptor;
}

void MainWindow::OnPacketReceived(const PacketInfo& info) {
    {
        std::lock_guard<std::mutex> lock(packetMutex);
        packetQueue.push(info);
    }
    PostMessage(hwnd, WM_UPDATE_PACKET, 0, 0);
}

void MainWindow::InitializeConnectionsList() {
    LVCOLUMN lvc;
    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;

    wchar_t timeText[] = L"Time";
    wchar_t sourceText[] = L"Source IP";
    wchar_t destText[] = L"Destination IP";
    wchar_t protoText[] = L"Protocol";
    wchar_t descText[] = L"Description";

    lvc.iSubItem = 0;
    lvc.cx = 150;
    lvc.pszText = timeText;
    ListView_InsertColumn(connectionsListView, 0, &lvc);

    lvc.iSubItem = 1;
    lvc.cx = 120;
    lvc.pszText = sourceText;
    ListView_InsertColumn(connectionsListView, 1, &lvc);

    lvc.iSubItem = 2;
    lvc.cx = 120;
    lvc.pszText = destText;
    ListView_InsertColumn(connectionsListView, 2, &lvc);

    lvc.iSubItem = 3;
    lvc.cx = 80;
    lvc.pszText = protoText;
    ListView_InsertColumn(connectionsListView, 3, &lvc);

    lvc.iSubItem = 4;
    lvc.cx = 150;
    lvc.pszText = descText;
    ListView_InsertColumn(connectionsListView, 4, &lvc);
}

void MainWindow::AddPacketToList(const PacketInfo& info) {
    if (!packetInterceptor) return;

    LVITEM lvi = { 0 };
    lvi.mask = LVIF_TEXT;
    lvi.iItem = 0;

    lvi.pszText = const_cast<LPWSTR>(info.time.c_str());
    int index = ListView_InsertItem(connectionsListView, &lvi);

    lvi.iSubItem = 1;
    lvi.pszText = const_cast<LPWSTR>(info.sourceIP.c_str());
    ListView_SetItem(connectionsListView, &lvi);

    lvi.iSubItem = 2;
    lvi.pszText = const_cast<LPWSTR>(info.destIP.c_str());
    ListView_SetItem(connectionsListView, &lvi);

    lvi.iSubItem = 3;
    lvi.pszText = const_cast<LPWSTR>(info.protocol.c_str());
    ListView_SetItem(connectionsListView, &lvi);

    lvi.iSubItem = 4;
    std::wstring desc = packetInterceptor->GetConnectionDescription(info);
    lvi.pszText = const_cast<LPWSTR>(desc.c_str());
    ListView_SetItem(connectionsListView, &lvi);

    // Прокручиваем список к новому элементу
    ListView_EnsureVisible(connectionsListView, index, FALSE);
}


bool MainWindow::Initialize(HINSTANCE hInstance, int nCmdShow) {
    this->hInstance = hInstance;

    // Регистрируем класс окна
    WNDCLASSEX wc = { 0 };
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.lpfnWndProc = MainWindow::WndProc;
    wc.hInstance = hInstance;
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"FirewallWindowClass";

    if (!RegisterClassEx(&wc)) {
        return false;
    }

    // Создаем главное окно
    hwnd = CreateWindowEx(
        0,
        L"FirewallWindowClass",
        L"Windows Firewall",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        800, 600,
        NULL,
        NULL,
        hInstance,
        this  // Важно: передаем указатель на текущий объект
    );

    if (!hwnd) {
        return false;
    }

    SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));

    // Инициализируем элементы управления
    InitCommonControls();
    InitializeRulesList();
    InitializeConnectionsList();

    // Создаем список правил
    rulesListView = CreateWindowEx(
        0, WC_LISTVIEW, L"",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | WS_BORDER,
        10, 40, 760, 200,
        hwnd, (HMENU)ID_RULES_LIST,
        hInstance, NULL
    );

    // Добавляем колонки в список правил
    LVCOLUMN lvc = { 0 };
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

    lvc.iSubItem = 0;
    lvc.cx = 50;
    lvc.pszText = (LPWSTR)L"ID";
    ListView_InsertColumn(rulesListView, 0, &lvc);

    lvc.iSubItem = 1;
    lvc.cx = 100;
    lvc.pszText = (LPWSTR)L"Protocol";
    ListView_InsertColumn(rulesListView, 1, &lvc);

    lvc.iSubItem = 2;
    lvc.cx = 150;
    lvc.pszText = (LPWSTR)L"Source IP";
    ListView_InsertColumn(rulesListView, 2, &lvc);

    lvc.iSubItem = 3;
    lvc.cx = 150;
    lvc.pszText = (LPWSTR)L"Destination IP";
    ListView_InsertColumn(rulesListView, 3, &lvc);

    lvc.iSubItem = 4;
    lvc.cx = 100;
    lvc.pszText = (LPWSTR)L"Action";
    ListView_InsertColumn(rulesListView, 4, &lvc);

    // Создаем список соединений
    connectionsListView = CreateWindowEx(
        0, WC_LISTVIEW, L"",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | WS_BORDER,
        10, 280, 760, 200,
        hwnd, (HMENU)ID_CONNECTIONS_LIST,
        hInstance, NULL
    );

    // Добавляем колонки в список соединений
    lvc.iSubItem = 0;
    lvc.cx = 150;
    lvc.pszText = (LPWSTR)L"Time";
    ListView_InsertColumn(connectionsListView, 0, &lvc);

    lvc.iSubItem = 1;
    lvc.cx = 200;
    lvc.pszText = (LPWSTR)L"Source";
    ListView_InsertColumn(connectionsListView, 1, &lvc);

    lvc.iSubItem = 2;
    lvc.cx = 200;
    lvc.pszText = (LPWSTR)L"Destination";
    ListView_InsertColumn(connectionsListView, 2, &lvc);

    lvc.iSubItem = 3;
    lvc.cx = 100;
    lvc.pszText = (LPWSTR)L"Protocol";
    ListView_InsertColumn(connectionsListView, 3, &lvc);

    lvc.iSubItem = 4;
    lvc.cx = 100;
    lvc.pszText = (LPWSTR)L"Action";
    ListView_InsertColumn(connectionsListView, 4, &lvc);

    // Создаем кнопки управления
    CreateWindow(
        L"BUTTON", L"Add Rule",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        10, 10, 80, 25,
        hwnd, (HMENU)ID_ADD_RULE,
        hInstance, NULL
    );

    CreateWindow(
        L"BUTTON", L"Delete Rule",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        100, 10, 80, 25,
        hwnd, (HMENU)ID_DELETE_RULE,
        hInstance, NULL
    );

    CreateWindow(
        L"BUTTON", L"Start Capture",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        190, 10, 90, 25,
        hwnd, (HMENU)ID_START_CAPTURE,
        hInstance, NULL
    );

    CreateWindow(
        L"BUTTON", L"Stop Capture",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        290, 10, 90, 25,
        hwnd, (HMENU)ID_STOP_CAPTURE,
        hInstance, NULL
    );

    return true;
}

void MainWindow::Show() {
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);
}

LRESULT CALLBACK MainWindow::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    MainWindow* window = reinterpret_cast<MainWindow*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));

    if (msg == WM_CREATE) {
        CREATESTRUCT* createStruct = reinterpret_cast<CREATESTRUCT*>(lParam);
        window = reinterpret_cast<MainWindow*>(createStruct->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(window));
    }
    else {
        window = reinterpret_cast<MainWindow*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    }
    if (window) {
        switch (msg) {
        case WM_UPDATE_PACKET:
        {
            PacketInfo info;
            bool hasPacket = false;
            {
                std::lock_guard<std::mutex> lock(window->packetMutex);
                if (!window->packetQueue.empty()) {
                    info = window->packetQueue.front();
                    window->packetQueue.pop();
                    hasPacket = true;
                }
            }
            if (hasPacket) {
                window->AddPacketToList(info);
            }
            return 0;
        }
        case WM_COMMAND:
        {
            if (!window) return 0;
            switch (LOWORD(wParam)) {
            case ID_ADD_RULE:
                window->AddRule();
                break;

            case ID_DELETE_RULE:
                window->DeleteRule();
                break;

            case ID_START_CAPTURE:
                window->StartCapture();
                break;

            case ID_STOP_CAPTURE:
                window->StopCapture();
                break;
            case ID_SELECT_ADAPTER:
                window->ShowAdapterSelectionDialog();
                break;
            }
            break;
        }

        case WM_DESTROY:
            if (window) {
                window->StopCapture();
            }
            PostQuitMessage(0);
            return 0;
        }
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

void MainWindow::ShowAdapterSelectionDialog() {
    if (!packetInterceptor) return;

    auto adapters = packetInterceptor->GetNetworkAdapters();
    if (adapters.empty()) {
        MessageBox(hwnd, L"No network adapters found", L"Error", MB_OK | MB_ICONERROR);
        return;
    }

    // Создаем диалог
    HWND hDlg = CreateDialog(hInstance, MAKEINTRESOURCE(IDD_ADAPTER_DIALOG), hwnd,
        [](HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) -> INT_PTR {
            MainWindow* window = reinterpret_cast<MainWindow*>(GetWindowLongPtr(GetParent(hDlg), GWLP_USERDATA));

            switch (msg) {
            case WM_INITDIALOG: {
                HWND hCombo = GetDlgItem(hDlg, IDC_ADAPTER_COMBO);
                auto adapters = window->packetInterceptor->GetNetworkAdapters();
                for (const auto& adapter : adapters) {
                    std::wstring displayText = adapter.name + L" (" +
                        std::wstring(adapter.ipAddress.begin(), adapter.ipAddress.end()) + L")";
                    SendMessage(hCombo, CB_ADDSTRING, 0, (LPARAM)displayText.c_str());
                }
                return TRUE;
            }

            case WM_COMMAND:
                if (LOWORD(wParam) == IDOK) {
                    HWND hCombo = GetDlgItem(hDlg, IDC_ADAPTER_COMBO);
                    int idx = SendMessage(hCombo, CB_GETCURSEL, 0, 0);
                    if (idx != CB_ERR && window) {
                        auto adapters = window->packetInterceptor->GetNetworkAdapters();
                        window->selectedAdapterIp = adapters[idx].ipAddress;

                        if (window->isCapturing) {
                            window->StopCapture();
                            window->StartCapture();
                        }
                    }
                    EndDialog(hDlg, IDOK);
                    return TRUE;
                }
                else if (LOWORD(wParam) == IDCANCEL) {
                    EndDialog(hDlg, IDCANCEL);
                    return TRUE;
                }
                break;
            }
            return FALSE;
        });

    ShowWindow(hDlg, SW_SHOW);
}

void MainWindow::StartCapture() {
    if (packetInterceptor) {
        // Устанавливаем callback перед запуском
        packetInterceptor->SetPacketCallback([this](const PacketInfo& info) {
            OnPacketReceived(info);
            });
        if (packetInterceptor->StartCapture()) {
            isCapturing = true;
            // Отключаем кнопку Start и включаем Stop
            EnableWindow(GetDlgItem(hwnd, ID_START_CAPTURE), FALSE);
            EnableWindow(GetDlgItem(hwnd, ID_STOP_CAPTURE), TRUE);

            // Добавляем сообщение в список соединений
            LVITEM lvi = { 0 };
            lvi.mask = LVIF_TEXT;
            lvi.iItem = 0;

            // Получаем текущее время
            time_t now = time(nullptr);
            struct tm timeinfo;
            localtime_s(&timeinfo, &now);

            // Форматируем время
            wchar_t timeStr[64];
            swprintf_s(timeStr, L"%04d-%02d-%02d %02d:%02d:%02d",
                timeinfo.tm_year + 1900,
                timeinfo.tm_mon + 1,
                timeinfo.tm_mday,
                timeinfo.tm_hour,
                timeinfo.tm_min,
                timeinfo.tm_sec);

            // Добавляем время
            lvi.pszText = timeStr;
            ListView_InsertItem(connectionsListView, &lvi);

            // Добавляем остальные колонки
            static const wchar_t* texts[] = {
                L"System",
                L"All",
                L"---",
                L"Capture Started"
            };

            for (int i = 1; i <= 4; i++) {
                lvi.iSubItem = i;
                lvi.pszText = const_cast<LPWSTR>(texts[i - 1]);
                ListView_SetItem(connectionsListView, &lvi);
            }
        }
        else {
            MessageBox(hwnd, L"Failed to start packet capture", L"Error", MB_OK | MB_ICONERROR);
        }
    }
}

void MainWindow::StopCapture() {
    if (packetInterceptor) {
        packetInterceptor->StopCapture();

        // Включаем кнопку Start и отключаем Stop
        EnableWindow(GetDlgItem(hwnd, ID_START_CAPTURE), TRUE);
        EnableWindow(GetDlgItem(hwnd, ID_STOP_CAPTURE), FALSE);

        // Добавляем сообщение в список соединений
        LVITEM lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = 0;

        // Получаем текущее время
        time_t now = time(nullptr);
        struct tm timeinfo;
        localtime_s(&timeinfo, &now);

        // Форматируем время
        wchar_t timeStr[64];
        swprintf_s(timeStr, L"%04d-%02d-%02d %02d:%02d:%02d",
            timeinfo.tm_year + 1900,
            timeinfo.tm_mon + 1,
            timeinfo.tm_mday,
            timeinfo.tm_hour,
            timeinfo.tm_min,
            timeinfo.tm_sec);

        // Добавляем время
        lvi.pszText = timeStr;
        ListView_InsertItem(connectionsListView, &lvi);

        // Добавляем остальные колонки
        static const wchar_t* texts[] = {
            L"System",
            L"All",
            L"---",
            L"Capture Stopped"
        };

        for (int i = 1; i <= 4; i++) {
            lvi.iSubItem = i;
            lvi.pszText = const_cast<LPWSTR>(texts[i - 1]);
            ListView_SetItem(connectionsListView, &lvi);
        }
    }
}
void MainWindow::InitializeRulesList() {
    // Создаем список правил
    rulesListView = CreateWindowEx(
        0, WC_LISTVIEW, L"",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | WS_BORDER,
        10, 40, 760, 200,
        hwnd, (HMENU)ID_RULES_LIST,
        hInstance, NULL
    );

    // Добавляем колонки в список правил
    LVCOLUMN lvc = { 0 };
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

    const struct {
        const wchar_t* text;
        int width;
    } columns[] = {
        {L"ID", 50},
        {L"Protocol", 100},
        {L"Source IP", 150},
        {L"Destination IP", 150},
        {L"Action", 100}
    };

    for (int i = 0; i < _countof(columns); i++) {
        lvc.iSubItem = i;
        lvc.cx = columns[i].width;
        lvc.pszText = const_cast<LPWSTR>(columns[i].text);
        ListView_InsertColumn(rulesListView, i, &lvc);
    }
}


void MainWindow::AddRule() {
    // TODO: Добавить диалоговое окно для создания правила
    MessageBox(hwnd, L"Add Rule functionality will be implemented soon",
        L"Not Implemented", MB_OK | MB_ICONINFORMATION);
}

void MainWindow::DeleteRule() {
    // Получаем выбранный элемент
    int selectedIndex = ListView_GetNextItem(rulesListView, -1, LVNI_SELECTED);
    if (selectedIndex == -1) {
        MessageBox(hwnd, L"Please select a rule to delete",
            L"No Rule Selected", MB_OK | MB_ICONINFORMATION);
        return;
    }

    // Запрашиваем подтверждение
    if (MessageBox(hwnd, L"Are you sure you want to delete this rule?",
        L"Confirm Delete", MB_YESNO | MB_ICONQUESTION) == IDYES) {
        ListView_DeleteItem(rulesListView, selectedIndex);
    }
}

// Добавляем реализации методов UpdateRulesList и UpdateConnectionsList, 
// хотя они пока не используются
void MainWindow::UpdateRulesList() {
    // TODO: Обновить список правил
}

void MainWindow::UpdateConnectionsList() {
    // TODO: Обновить список соединений
}