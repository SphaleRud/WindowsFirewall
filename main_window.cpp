#define WIN32_LEAN_AND_MEAN
#include "main_window.h"
#include <commctrl.h>
#include <windowsx.h>
#include <ctime>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// ID компонентов
#define ID_RULES_LIST 1001
#define ID_CONNECTIONS_LIST 1002
#define ID_ADD_RULE 1003
#define ID_DELETE_RULE 1004
#define ID_START_CAPTURE 1005
#define ID_STOP_CAPTURE 1006

std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

std::wstring StringToWString(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

MainWindow::MainWindow() : hwnd(nullptr), hInstance(nullptr), adapterInfoLabel(nullptr) {
}

MainWindow::~MainWindow() {
    if (packetInterceptor.IsCapturing()) {
        packetInterceptor.StopCapture();
    }
}

bool MainWindow::Initialize(HINSTANCE hInst) {
    hInstance = hInst;

    if (!packetInterceptor.Initialize()) {
        return false;
    }

    UpdateAdapterInfo();
    return CreateControls();
}


bool MainWindow::CreateMainWindow() {
    WNDCLASSEXW wc = { sizeof(WNDCLASSEXW) };
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"WindowsFirewallClass";

    if (!RegisterClassExW(&wc)) {
        return false;
    }

    hwnd = CreateWindowExW(
        0,
        L"WindowsFirewallClass",
        L"Windows Firewall",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        800, 600,
        nullptr,
        nullptr,
        hInstance,
        this
    );

    if (!hwnd) {
        return false;
    }

    // Создаем контролы
    return CreateControls();
}

LRESULT MainWindow::HandleCommand(WPARAM wParam, LPARAM lParam) {
    switch (LOWORD(wParam)) {
    case IDC_SELECT_ADAPTER:
        OnSelectAdapter();
        break;

    case IDC_START_CAPTURE:
        OnStartCapture();
        break;
    }
    return 0;
}

LRESULT MainWindow::HandlePacketUpdate(WPARAM wParam, LPARAM lParam) {
    HWND listView = GetDlgItem(hwnd, IDC_PACKET_LIST);
    PacketInfo* packetInfo = reinterpret_cast<PacketInfo*>(lParam);
    
    if (packetInfo && listView) {
        LVITEM lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = ListView_GetItemCount(listView);

        // Время
        wchar_t timeStr[32];
        _snwprintf_s(timeStr, _countof(timeStr), L"%02d:%02d:%02d.%03d",
            packetInfo->systemTime.wHour,
            packetInfo->systemTime.wMinute,
            packetInfo->systemTime.wSecond,
            packetInfo->systemTime.wMilliseconds);
        
        lvi.pszText = timeStr;
        int pos = ListView_InsertItem(listView, &lvi);

        // IP и порты
        std::wstring sourceStr = StringToWString(
            packetInfo->sourceIp + ":" + std::to_string(packetInfo->sourcePort));
        ListView_SetItemText(listView, pos, 1, const_cast<LPWSTR>(sourceStr.c_str()));

        std::wstring destStr = StringToWString(
            packetInfo->destIp + ":" + std::to_string(packetInfo->destPort));
        ListView_SetItemText(listView, pos, 2, const_cast<LPWSTR>(destStr.c_str()));

        // Протокол
        std::wstring protoStr = StringToWString(packetInfo->protocol);
        ListView_SetItemText(listView, pos, 3, const_cast<LPWSTR>(protoStr.c_str()));

        // Размер
        wchar_t sizeStr[16];
        _snwprintf_s(sizeStr, _countof(sizeStr), L"%zu", packetInfo->size);
        ListView_SetItemText(listView, pos, 4, sizeStr);

        delete packetInfo;
    }
    return 0;
}

void MainWindow::ProcessPacket(const PacketInfo& info) {
    // Форматируем информацию о пакете для отображения
    std::wstring direction = std::wstring(info.direction.begin(), info.direction.end());
    std::wstring sourceIp = std::wstring(info.sourceIp.begin(), info.sourceIp.end());
    std::wstring destIp = std::wstring(info.destIp.begin(), info.destIp.end());
    std::wstring protocol = std::wstring(info.protocol.begin(), info.protocol.end());
    std::wstring processName = std::wstring(info.processName.begin(), info.processName.end());

    // Форматируем строку для отображения
    std::wstring packetInfo = direction + L" | " +
        sourceIp + L":" + std::to_wstring(info.sourcePort) + L" → " +
        destIp + L":" + std::to_wstring(info.destPort) + L" | " +
        protocol + L" | " +
        std::to_wstring(info.size) + L" bytes | " +
        processName;

    AddSystemMessage(packetInfo);
}



void MainWindow::UpdateAdapterInfo(const std::string& adapterInfo) {
    if (!adapterInfoLabel) {
        return;
    }

    std::wstring wstr = StringToWString(adapterInfo);
    std::wstring formattedText = L"Current adapter: " + wstr;
    SetWindowText(adapterInfoLabel, formattedText.c_str());
}

std::wstring MainWindow::GetAdapterDisplayName() const {
    if (!packetInterceptor) {
        return L"Initializing...";
    }

    if (selectedAdapterIp.empty()) {
        return L"Not selected";
    }

    auto adapters = packetInterceptor->GetNetworkAdapters();
    if (adapters.empty()) {
        return L"No adapters available";
    }

    for (const auto& adapter : adapters) {
        if (adapter.ipAddress == selectedAdapterIp) {
            return adapter.name + L" (" +
                std::wstring(adapter.ipAddress.begin(), adapter.ipAddress.end()) + L")";
        }
    }

    return L"Unknown Adapter";
}

void MainWindow::OnStartCapture() {
    // Было: if (!packetInterceptor->IsCapturing())
    // Стало: использование точки вместо стрелки
    if (!packetInterceptor.IsCapturing()) {
        if (packetInterceptor.StartCapture()) {  // тоже изменено с -> на .
            HWND startButton = GetDlgItem(hwnd, IDC_START_CAPTURE);
            SetWindowText(startButton, L"Stop Capture");
        }
    }
    else {
        if (packetInterceptor.StopCapture()) {   // тоже изменено с -> на .
            HWND startButton = GetDlgItem(hwnd, IDC_START_CAPTURE);
            SetWindowText(startButton, L"Start Capture");
        }
    }
}

void MainWindow::OnSelectAdapter() {
    ShowAdapterSelectionDialog();
}

INT_PTR CALLBACK MainWindow::AdapterDialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    MainWindow* self = nullptr;

    if (uMsg == WM_INITDIALOG) {
        SetWindowLongPtr(hwndDlg, GWLP_USERDATA, lParam);
        self = reinterpret_cast<MainWindow*>(lParam);
    }
    else {
        self = reinterpret_cast<MainWindow*>(GetWindowLongPtr(hwndDlg, GWLP_USERDATA));
    }

    if (!self) return FALSE;

    switch (uMsg) {
    case WM_INITDIALOG: {
        HWND hCombo = GetDlgItem(hwndDlg, IDC_ADAPTER_COMBO);
        std::vector<NetworkAdapter> adapters = self->packetInterceptor.GetNetworkAdapters();

        for (const auto& adapter : adapters) {
            std::wstring wdesc = StringToWString(adapter.description);
            std::wstring wname = StringToWString(adapter.name);
            std::wstring adapterInfo = wdesc + L" (" + wname + L")";

            int idx = (int)SendMessage(hCombo, CB_ADDSTRING, 0, (LPARAM)adapterInfo.c_str());
            NetworkAdapter* pAdapter = new NetworkAdapter(adapter);
            SendMessage(hCombo, CB_SETITEMDATA, idx, (LPARAM)pAdapter);
        }
        return TRUE;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDOK: {
            HWND hCombo = GetDlgItem(hwndDlg, IDC_ADAPTER_COMBO);
            int idx = (int)SendMessage(hCombo, CB_GETCURSEL, 0, 0);
            if (idx != CB_ERR) {
                NetworkAdapter* pAdapter = (NetworkAdapter*)SendMessage(hCombo, CB_GETITEMDATA, idx, 0);
                if (pAdapter) {
                    self->packetInterceptor.SetCurrentAdapter(pAdapter->name);
                    self->UpdateAdapterInfo(pAdapter->description);
                    delete pAdapter;
                }
            }
            EndDialog(hwndDlg, IDOK);
            return TRUE;
        }

        case IDCANCEL:
            EndDialog(hwndDlg, IDCANCEL);
            return TRUE;
        }
        break;

    case WM_DESTROY: {
        HWND hCombo = GetDlgItem(hwndDlg, IDC_ADAPTER_COMBO);
        int count = (int)SendMessage(hCombo, CB_GETCOUNT, 0, 0);
        for (int i = 0; i < count; i++) {
            NetworkAdapter* pAdapter = (NetworkAdapter*)SendMessage(hCombo, CB_GETITEMDATA, i, 0);
            delete pAdapter;
        }
        return TRUE;
    }
    }
    return FALSE;
}

bool MainWindow::AutoSelectAdapter() {
    if (!packetInterceptor) return false;

    auto adapters = packetInterceptor->GetNetworkAdapters();
    if (adapters.empty()) {
        AddSystemMessage(L"No network adapters found");
        return false;
    }

    // Предпочитаем Wi-Fi адаптер
    for (const auto& adapter : adapters) {
        if (adapter.isWifi) {
            selectedAdapterIp = adapter.ipAddress;
            UpdateAdapterInfo();
            AddSystemMessage(L"Selected WiFi adapter: " + GetAdapterDisplayName());
            return true;
        }
    }

    // Если Wi-Fi не найден, берем первый доступный
    selectedAdapterIp = adapters[0].ipAddress;
    UpdateAdapterInfo();
    AddSystemMessage(L"Selected adapter: " + GetAdapterDisplayName());
    return true;
}


bool MainWindow::CreateControls() {
    // Получаем размеры клиентской области окна
    RECT clientRect;
    GetClientRect(hwnd, &clientRect);
    int windowWidth = clientRect.right - clientRect.left;

    // Создаем шрифт для элементов управления
    HFONT hFont = CreateFont(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

    const int MARGIN = 10;
    const int BUTTON_HEIGHT = 30;
    const int BUTTON_WIDTH = 120;
    const int LABEL_HEIGHT = 40;

    // Создаем метку для отображения текущего адаптера
    adapterInfoLabel = CreateWindowEx(
        0, L"STATIC", L"Current adapter: None",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        MARGIN, MARGIN,
        windowWidth - 2 * MARGIN, LABEL_HEIGHT,
        hwnd, (HMENU)IDC_ADAPTER_LABEL,
        hInstance, nullptr
    );
    SendMessage(adapterInfoLabel, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Создаем кнопки
    int buttonY = MARGIN + LABEL_HEIGHT + MARGIN;

    HWND selectAdapterButton = CreateWindowEx(
        0, L"BUTTON", L"Select Adapter",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
        MARGIN, buttonY,
        BUTTON_WIDTH, BUTTON_HEIGHT,
        hwnd, (HMENU)IDC_SELECT_ADAPTER,
        hInstance, nullptr
    );
    SendMessage(selectAdapterButton, WM_SETFONT, (WPARAM)hFont, TRUE);

    HWND startButton = CreateWindowEx(
        0, L"BUTTON", L"Start Capture",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
        MARGIN + BUTTON_WIDTH + MARGIN, buttonY,
        BUTTON_WIDTH, BUTTON_HEIGHT,
        hwnd, (HMENU)IDC_START_CAPTURE,
        hInstance, nullptr
    );
    SendMessage(startButton, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Создаем ListView
    int listY = buttonY + BUTTON_HEIGHT + MARGIN;
    int listHeight = clientRect.bottom - listY - MARGIN;

    HWND listView = CreateWindowEx(
        0, WC_LISTVIEW, L"",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | WS_BORDER | LVS_SHOWSELALWAYS,
        MARGIN, listY,
        windowWidth - 2 * MARGIN, listHeight,
        hwnd, (HMENU)IDC_PACKET_LIST,
        hInstance, nullptr
    );
    SendMessage(listView, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Устанавливаем расширенные стили ListView
    ListView_SetExtendedListViewStyle(listView,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

    // Добавляем колонки
    LVCOLUMN lvc = { 0 };
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

    const struct {
        LPCWSTR text;
        int width;
    } columns[] = {
        { L"Time", 150 },
        { L"Source", 120 },
        { L"Destination", 120 },
        { L"Protocol", 80 },
        { L"Length", 80 }
    };

    for (int i = 0; i < ARRAYSIZE(columns); i++) {
        lvc.iSubItem = i;
        lvc.pszText = (LPWSTR)columns[i].text;
        lvc.cx = columns[i].width;
        ListView_InsertColumn(listView, i, &lvc);
    }

    return true;
}




void MainWindow::ShowAdapterSelectionDialog() {
    DialogBoxParam(
        hInstance,
        MAKEINTRESOURCE(IDD_ADAPTER_DIALOG),
        hwnd,
        AdapterDialogProc,
        reinterpret_cast<LPARAM>(this)
    );
}

// Инициализация списков
void MainWindow::InitializeRulesList() {
    rulesListView = CreateWindowEx(
        0, WC_LISTVIEW, L"",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | WS_BORDER,
        10, 40, 760, 200,
        hwnd, (HMENU)ID_RULES_LIST,
        hInstance, NULL
    );

    const struct {
        LPCWSTR text;
        int width;
    } columns[] = {
        {L"ID", 50},
        {L"Protocol", 100},
        {L"Source IP", 150},
        {L"Destination IP", 150},
        {L"Action", 100}
    };

    LVCOLUMN lvc = { 0 };
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

    for (int i = 0; i < _countof(columns); i++) {
        lvc.iSubItem = i;
        lvc.cx = columns[i].width;
        lvc.pszText = const_cast<LPWSTR>(columns[i].text);
        ListView_InsertColumn(rulesListView, i, &lvc);
    }
}

void MainWindow::InitializeConnectionsList() {
    connectionsListView = CreateWindowEx(
        0, WC_LISTVIEW, L"",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | WS_BORDER,
        10, 280, 760, 200,
        hwnd, (HMENU)ID_CONNECTIONS_LIST,
        hInstance, NULL
    );

    const struct {
        LPCWSTR text;
        int width;
    } columns[] = {
        {L"Time", 150},
        {L"Source IP", 120},
        {L"Destination IP", 120},
        {L"Protocol", 80},
        {L"Description", 150}
    };

    LVCOLUMN lvc = { 0 };
    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;

    for (int i = 0; i < _countof(columns); i++) {
        lvc.iSubItem = i;
        lvc.cx = columns[i].width;
        lvc.pszText = const_cast<LPWSTR>(columns[i].text);
        ListView_InsertColumn(connectionsListView, i, &lvc);
    }
}

// Обработка пакетов
void MainWindow::OnPacketReceived(const PacketInfo& info) {
    {
        std::lock_guard<std::mutex> lock(packetMutex);
        packetQueue.push(info);
    }
    PostMessage(hwnd, WM_UPDATE_PACKET, 0, 0);
}

void MainWindow::AddPacketToList(const PacketInfo& packet) {
    std::wstring direction = std::wstring(packet.direction.begin(), packet.direction.end());
    std::wstring sourceIp = std::wstring(packet.sourceIp.begin(), packet.sourceIp.end());
    std::wstring destIp = std::wstring(packet.destIp.begin(), packet.destIp.end());
    std::wstring protocol = std::wstring(packet.protocol.begin(), packet.protocol.end());
    std::wstring process = std::wstring(packet.processName.begin(), packet.processName.end());

    WCHAR timeStr[64];
    tm tmTime;
    localtime_s(&tmTime, &packet.timestamp);
    swprintf_s(timeStr, L"%02d:%02d:%02d",
        tmTime.tm_hour, tmTime.tm_min, tmTime.tm_sec);

    std::vector<std::wstring> items = {
        timeStr,
        direction,
        sourceIp + L":" + std::to_wstring(packet.sourcePort),
        destIp + L":" + std::to_wstring(packet.destPort),
        protocol,
        std::to_wstring(packet.size),
        process
    };

    connectionsListView.AddItem(items);
}

// Управление захватом
void MainWindow::StartCapture() {
    if (!packetInterceptor || selectedAdapterIp.empty()) {
        MessageBox(hwnd, L"Please select a network adapter first", L"Error", MB_OK | MB_ICONERROR);
        return;
    }

    OutputDebugString((L"Starting capture on adapter: " +
        std::wstring(selectedAdapterIp.begin(), selectedAdapterIp.end()) + L"\n").c_str());

    // Устанавливаем адаптер и запускаем захват
    packetInterceptor->SetCurrentAdapter(selectedAdapterIp);
    if (packetInterceptor->StartCapture()) {
        isCapturing = true;
        EnableWindow(GetDlgItem(hwnd, ID_START_CAPTURE), FALSE);
        EnableWindow(GetDlgItem(hwnd, ID_STOP_CAPTURE), TRUE);

        std::wstring message = L"Started capturing on " + GetAdapterDisplayName();
        AddSystemMessage(message);
        OutputDebugString((L"Started capture: " +
            std::wstring(selectedAdapterIp.begin(), selectedAdapterIp.end()) + L"\n").c_str());
    }
    else {
        MessageBox(hwnd, L"Failed to start capture", L"Error", MB_OK | MB_ICONERROR);
        OutputDebugString((L"Failed to start capture on adapter: " +
            std::wstring(selectedAdapterIp.begin(), selectedAdapterIp.end()) + L"\n").c_str());
    }
}

void MainWindow::StopCapture() {
    if (!packetInterceptor) return;

    packetInterceptor->StopCapture();
    isCapturing = false;
    EnableWindow(GetDlgItem(hwnd, ID_START_CAPTURE), TRUE);
    EnableWindow(GetDlgItem(hwnd, ID_STOP_CAPTURE), FALSE);

    AddSystemMessage(L"Stopped capturing");
    OutputDebugString(L"Stopped capture\n");
}

// Вспомогательные методы
// Добавляем реализацию AddSystemMessage
void MainWindow::AddSystemMessage(const std::wstring& message) {
    if (!connectionsListView) return;

    LVITEM lvi = { 0 };
    lvi.mask = LVIF_TEXT;
    lvi.iItem = 0;
    lvi.iSubItem = 0;

    // Получаем текущее время
    time_t now = time(nullptr);
    struct tm timeinfo;
    localtime_s(&timeinfo, &now);
    wchar_t timeStr[64];
    swprintf_s(timeStr, L"%04d-%02d-%02d %02d:%02d:%02d",
        timeinfo.tm_year + 1900,
        timeinfo.tm_mon + 1,
        timeinfo.tm_mday,
        timeinfo.tm_hour,
        timeinfo.tm_min,
        timeinfo.tm_sec);

    // Формируем сообщение с временной меткой
    std::wstring fullMessage = std::wstring(timeStr) + L" - " + message;
    lvi.pszText = const_cast<LPWSTR>(fullMessage.c_str());

    ListView_InsertItem(connectionsListView, &lvi);
}


LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    MainWindow* window = reinterpret_cast<MainWindow*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));

    switch (msg) {
    case WM_CREATE: {
        CREATESTRUCT* cs = reinterpret_cast<CREATESTRUCT*>(lParam);
        window = reinterpret_cast<MainWindow*>(cs->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(window));
        return 0;
    }

    case WM_COMMAND:
        if (window) {
            window->HandleCommand(LOWORD(wParam));
        }
        return 0;

    case WM_UPDATE_PACKET:
        if (window) {
            window->HandlePacketUpdate();
        }
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProc(hwnd, msg, wParam, lParam);
}



// Публичные методы
void MainWindow::Show(int nCmdShow) {
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    if (packetInterceptor->Initialize()) {
        auto adapters = packetInterceptor->GetNetworkAdapters();

        if (!adapters.empty()) {
            if (selectedAdapterIp.empty()) {
                AutoSelectAdapter();
            }
            UpdateAdapterInfo();
        }
    }
}


void MainWindow::UpdateRulesList() {
    // TODO: Обновить список правил
}

void MainWindow::UpdateConnectionsList() {
    // TODO: Обновить список соединений
}

void MainWindow::AddRule() {
    // TODO: Добавить реализацию
    MessageBox(hwnd, L"Add Rule functionality will be implemented soon",
        L"Not Implemented", MB_OK | MB_ICONINFORMATION);
}

void MainWindow::DeleteRule() {
    int selectedIndex = ListView_GetNextItem(rulesListView, -1, LVNI_SELECTED);
    if (selectedIndex == -1) {
        MessageBox(hwnd, L"Please select a rule to delete",
            L"No Rule Selected", MB_OK | MB_ICONINFORMATION);
        return;
    }

    if (MessageBox(hwnd, L"Are you sure you want to delete this rule?",
        L"Confirm Delete", MB_YESNO | MB_ICONQUESTION) == IDYES) {
        ListView_DeleteItem(rulesListView, selectedIndex);
    }
}