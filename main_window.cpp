#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <commctrl.h>
#include <windowsx.h>
#include "resource.h"
#include <ctime>
#include "main_window.h"
#include "connection_tracker.h"

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

MainWindow::MainWindow(HINSTANCE hInst) :
    hwnd(nullptr),
    hInstance(hInst),
    rulesListView(nullptr),
    connectionsListView(nullptr),
    packetInterceptor(std::make_shared<PacketInterceptor>()),
    isCapturing(false)
{
}

MainWindow::~MainWindow() {
    if (hwnd) {
        DestroyWindow(hwnd);
    }
}

void MainWindow::LogError(const wchar_t* message) {
    OutputDebugString(L"[WindowsFirewall Error] ");
    OutputDebugString(message);
    OutputDebugString(L"\n");
}

void MainWindow::ShowErrorMessage(const wchar_t* message) {
    MessageBox(hwnd, message, L"Error", MB_OK | MB_ICONERROR);
}

bool MainWindow::RegisterWindowClass() {
    WNDCLASSEX wc = { 0 };
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.lpfnWndProc = MainWindow::WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"WindowsFirewallClass";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.style = CS_HREDRAW | CS_VREDRAW;

    return RegisterClassEx(&wc) != 0;
}

bool MainWindow::Create() {
    hwnd = CreateWindow(
        L"WindowsFirewallClass",
        L"Windows Firewall",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        800, 600,
        nullptr,
        LoadMenu(hInstance, MAKEINTRESOURCE(IDM_MAIN_MENU)), // Добавляем меню
        hInstance,
        nullptr
    );

    if (!hwnd) {
        return false;
    }

    // Создаем панель инструментов
    CreateToolbar();

    // Создаем элементы управления
    InitializeRulesList();
    InitializeConnectionsList();

    // Обновляем размеры элементов управления
    UpdateLayout();

    return true;
}

void MainWindow::CreateToolbar() {
    toolBar = CreateWindowEx(0, TOOLBARCLASSNAME, NULL,
        WS_CHILD | WS_VISIBLE | TBSTYLE_FLAT | TBSTYLE_TOOLTIPS,
        0, 0, 0, 0,
        hwnd, nullptr, hInstance, nullptr);

    if (!toolBar) {
        return;
    }

    SendMessage(toolBar, TB_BUTTONSTRUCTSIZE, (WPARAM)sizeof(TBBUTTON), 0);

    TBADDBITMAP tbab;
    tbab.hInst = HINST_COMMCTRL;
    tbab.nID = IDB_STD_SMALL_COLOR;
    SendMessage(toolBar, TB_ADDBITMAP, 0, (LPARAM)&tbab);

    // Используем другие стандартные иконки
    TBBUTTON tbb[5] = {
        {MAKELONG(STD_FILEOPEN, 0), ID_SELECT_ADAPTER,  TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, (INT_PTR)L"Select Adapter"},
        {0, 0, TBSTATE_ENABLED, BTNS_SEP, {0}, 0, 0},
        {MAKELONG(STD_FIND, 0),    IDM_START_CAPTURE,  TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, (INT_PTR)L"Start Capture"},
        {MAKELONG(STD_DELETE, 0),   IDM_STOP_CAPTURE,   TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, (INT_PTR)L"Stop Capture"},
        {MAKELONG(STD_FILESAVE, 0), IDM_ADD_RULE,       TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, (INT_PTR)L"Add Rule"}
    };

    SendMessage(toolBar, TB_ADDBUTTONS, 5, (LPARAM)&tbb);
}


void MainWindow::UpdateLayout() {
    if (!hwnd) return;

    RECT clientRect;
    GetClientRect(hwnd, &clientRect);

    // Получаем размер панели инструментов
    RECT tbRect;
    GetWindowRect(toolBar, &tbRect);
    int toolBarHeight = tbRect.bottom - tbRect.top;

    // Вычисляем оставшуюся высоту
    int remainingHeight = clientRect.bottom - toolBarHeight;
    int halfHeight = remainingHeight / 2;

    // Обновляем позиции списков
    SetWindowPos(rulesListView, nullptr,
        0, toolBarHeight,
        clientRect.right,
        halfHeight,
        SWP_NOZORDER
    );

    SetWindowPos(connectionsListView, nullptr,
        0, toolBarHeight + halfHeight,
        clientRect.right,
        halfHeight,
        SWP_NOZORDER
    );
}

void MainWindow::Show(int nCmdShow) {
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);
}

void MainWindow::SetPacketInterceptor(std::shared_ptr<PacketInterceptor> interceptor) {
    packetInterceptor = interceptor;
    if (packetInterceptor) {
        packetInterceptor->SetPacketCallback([this](const PacketInfo& info) {
            OnPacketReceived(info);
            });
    }
}

INT_PTR CALLBACK MainWindow::AdapterDialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static MainWindow* window = nullptr;
    static PacketInterceptor* interceptor = nullptr;

    try {
        switch (msg) {
        case WM_INITDIALOG: {
            window = &MainWindow::Instance();
            interceptor = reinterpret_cast<PacketInterceptor*>(lParam);

            if (!interceptor) {
                MessageBox(hwnd, L"Invalid adapter data", L"Error", MB_OK | MB_ICONERROR);
                EndDialog(hwnd, IDCANCEL);
                return TRUE;
            }

            HWND combo = GetDlgItem(hwnd, IDC_ADAPTER_COMBO);
            if (!combo) {
                MessageBox(hwnd, L"Failed to create dialog controls", L"Error", MB_OK | MB_ICONERROR);
                EndDialog(hwnd, IDCANCEL);
                return TRUE;
            }

            try {
                auto adapters = interceptor->GetNetworkAdapters();
                if (adapters.empty()) {
                    MessageBox(hwnd, L"No network adapters found", L"Error", MB_OK | MB_ICONERROR);
                    EndDialog(hwnd, IDCANCEL);
                    return TRUE;
                }

                SendMessage(combo, CB_RESETCONTENT, 0, 0);

                for (const auto& adapter : adapters) {
                    std::wstring displayText = adapter.name;
                    if (!adapter.description.empty()) {
                        displayText += L" - " + adapter.description;
                    }

                    AdapterData* data = new AdapterData{
                        adapter.name,
                        adapter.ipAddress
                    };

                    int idx = (int)SendMessage(combo, CB_ADDSTRING, 0, (LPARAM)displayText.c_str());
                    if (idx != CB_ERR) {
                        if (SendMessage(combo, CB_SETITEMDATA, idx, (LPARAM)data) == CB_ERR) {
                            delete data;
                        }
                    }
                    else {
                        delete data;
                    }
                }

                SendMessage(combo, CB_SETCURSEL, 0, 0);
            }
            catch (const std::exception& e) {
                MessageBox(hwnd, L"Error loading adapters", L"Error", MB_OK | MB_ICONERROR);
                EndDialog(hwnd, IDCANCEL);
                return TRUE;
            }

            return TRUE;
        }

        case WM_COMMAND: {
            if (LOWORD(wParam) == IDOK) {
                if (!interceptor) {
                    MessageBox(hwnd, L"Invalid adapter data", L"Error", MB_OK | MB_ICONERROR);
                    EndDialog(hwnd, IDCANCEL);
                    return TRUE;
                }

                HWND combo = GetDlgItem(hwnd, IDC_ADAPTER_COMBO);
                if (!combo) {
                    EndDialog(hwnd, IDCANCEL);
                    return TRUE;
                }

                int idx = (int)SendMessage(combo, CB_GETCURSEL, 0, 0);
                if (idx == CB_ERR) {
                    MessageBox(hwnd, L"Please select an adapter", L"Error", MB_OK | MB_ICONERROR);
                    return TRUE;
                }

                AdapterData* data = (AdapterData*)SendMessage(combo, CB_GETITEMDATA, idx, 0);
                if (!data) {
                    MessageBox(hwnd, L"Failed to get adapter data", L"Error", MB_OK | MB_ICONERROR);
                    EndDialog(hwnd, IDCANCEL);
                    return TRUE;
                }

                try {
                    interceptor->StopCapture();

                    if (!interceptor->SwitchAdapter(data->ipAddress)) {
                        MessageBox(hwnd, L"Failed to switch adapter", L"Error", MB_OK | MB_ICONERROR);
                        return TRUE;
                    }

                    EndDialog(hwnd, IDOK);
                }
                catch (const std::exception&) {
                    MessageBox(hwnd, L"Error switching adapter", L"Error", MB_OK | MB_ICONERROR);
                    EndDialog(hwnd, IDCANCEL);
                }
                return TRUE;
            }
            else if (LOWORD(wParam) == IDCANCEL) {
                EndDialog(hwnd, IDCANCEL);
                return TRUE;
            }
            break;
        }

        case WM_DESTROY: {
            HWND combo = GetDlgItem(hwnd, IDC_ADAPTER_COMBO);
            if (combo) {
                int count = (int)SendMessage(combo, CB_GETCOUNT, 0, 0);
                for (int i = 0; i < count; i++) {
                    AdapterData* data = (AdapterData*)SendMessage(combo, CB_GETITEMDATA, i, 0);
                    delete data;
                }
            }
            window = nullptr;
            interceptor = nullptr;
            break;
        }
        }
    }
    catch (const std::exception&) {
        MessageBox(hwnd, L"Unexpected error occurred", L"Error", MB_OK | MB_ICONERROR);
        EndDialog(hwnd, IDCANCEL);
        return TRUE;
    }

    return FALSE;
}

void MainWindow::OnPacketReceived(const PacketInfo& info) {
    {
        std::lock_guard<std::mutex> lock(packetMutex);
        packetQueue.push(info);
    }
    PostMessage(hwnd, WM_UPDATE_PACKET, 0, 0);
}

void MainWindow::InitializeConnectionsList() {
    connectionsListView = CreateWindowEx(
        0, WC_LISTVIEW, L"",
        WS_CHILD | WS_VISIBLE | LVS_REPORT,
        0, 0, 0, 0,
        hwnd, nullptr, hInstance, nullptr
    );

    ListView_SetExtendedListViewStyle(connectionsListView,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

    LVCOLUMN lvc = { 0 };
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

    const struct {
        const wchar_t* text;
        int width;
    } columns[] = {
        {L"Time", 140},
        {L"Application", 120},
        {L"Service", 100},
        {L"Source", 150},
        {L"Destination", 150},
        {L"Protocol", 70},
        {L"Direction", 70},
        {L"Packets", 70},
        {L"Bytes", 80}
    };

    int i = 0;
    for (const auto& col : columns) {
        lvc.iSubItem = i;
        lvc.pszText = const_cast<LPWSTR>(col.text);
        lvc.cx = col.width;
        ListView_InsertColumn(connectionsListView, i++, &lvc);
    }
}



void MainWindow::AddPacketToList(const PacketInfo& packet) {
    connectionTracker.AddPacket(packet);

    ListView_DeleteAllItems(connectionsListView);

    int itemIndex = 0;
    for (const auto& pair : connectionTracker.GetConnections()) {
        const auto& key = pair.first;
        const auto& info = pair.second;

        LVITEM lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = itemIndex;

        wchar_t timeStr[32];
        swprintf_s(timeStr, sizeof(timeStr) / sizeof(wchar_t),
            L"%04d-%02d-%02d %02d:%02d:%02d",
            info.lastSeen.wYear, info.lastSeen.wMonth, info.lastSeen.wDay,
            info.lastSeen.wHour, info.lastSeen.wMinute, info.lastSeen.wSecond);

        std::wstring source = std::wstring(key.sourceIp.begin(), key.sourceIp.end()) +
            L":" + std::to_wstring(key.sourcePort);
        std::wstring dest = std::wstring(key.destIp.begin(), key.destIp.end()) +
            L":" + std::to_wstring(key.destPort);

        const struct {
            const wchar_t* text;
        } items[] = {
            {timeStr},
            {info.application.empty() ? L"Unknown" : std::wstring(info.application.begin(), info.application.end()).c_str()},
            {info.service.empty() ? L"Unknown" : std::wstring(info.service.begin(), info.service.end()).c_str()},
            {source.c_str()},
            {dest.c_str()},
            {std::wstring(key.protocol.begin(), key.protocol.end()).c_str()},
            {std::wstring(key.direction.begin(), key.direction.end()).c_str()},
            {std::to_wstring(info.packetsCount).c_str()},
            {std::to_wstring(info.bytesSent).c_str()}
        };

        for (int j = 0; j < _countof(items); j++) {
            lvi.iSubItem = j;
            lvi.pszText = const_cast<LPWSTR>(items[j].text);
            if (j == 0) {
                ListView_InsertItem(connectionsListView, &lvi);
            }
            else {
                ListView_SetItem(connectionsListView, &lvi);
            }
        }
        itemIndex++;
    }
}


bool MainWindow::Initialize() {
    // Инициализация Common Controls
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES | ICC_WIN95_CLASSES;
    if (!InitCommonControlsEx(&icex)) {
        return false;
    }

    if (!RegisterWindowClass()) {
        return false;
    }

    return true;
}


LRESULT CALLBACK MainWindow::WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    MainWindow& window = MainWindow::Instance();

    switch (message) {
    case WM_SIZE: {
        // Сначала позволяем панели инструментов обновиться
        SendMessage(window.toolBar, TB_AUTOSIZE, 0, 0);

        // Затем обновляем layout
        window.UpdateLayout();
        break;
    }
    case WM_COMMAND: {
        switch (LOWORD(wParam)) {
        case ID_SELECT_ADAPTER: {
            DialogBoxParam(
                window.hInstance,
                MAKEINTRESOURCE(IDD_ADAPTER_DIALOG),
                hwnd,
                AdapterDialogProc,
                reinterpret_cast<LPARAM>(window.packetInterceptor.get())
            );
            break;
        }
        case IDM_ADD_RULE:
            window.AddRule();
            break;
        case IDM_DELETE_RULE:
            window.DeleteRule();
            break;
        case IDM_START_CAPTURE:
            window.StartCapture();
            break;
        case IDM_STOP_CAPTURE:
            window.StopCapture();
            break;
        }
        break;
    }

    case WM_DESTROY: {
        window.StopCapture();
        PostQuitMessage(0);
        break;
    }

    case WM_UPDATE_PACKET: {
        std::lock_guard<std::mutex> lock(window.packetMutex);
        while (!window.packetQueue.empty()) {
            PacketInfo info = window.packetQueue.front();
            window.AddPacketToList(info);
            window.packetQueue.pop();
        }
        break;
    }

    default:
        return DefWindowProc(hwnd, message, wParam, lParam);
    }
    return 0;
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